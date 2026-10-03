'use strict';

const net = require('node:net');
const tls = require('node:tls');

function parseEgressProxy(raw) {
  if (!String(raw).trim()) return null;
  try {
    const url = new URL(raw);
    if (!['http:', 'https:', 'socks5:', 'socks5h:'].includes(url.protocol) || !url.hostname || url.hash || url.search || !['', '/'].includes(url.pathname)) throw new Error();
    const port = Number(url.port || (url.protocol === 'http:' ? 80 : url.protocol === 'https:' ? 443 : 1080));
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error();
    return { type: url.protocol.startsWith('socks') ? 'socks5' : 'http', secure: url.protocol === 'https:', host: url.hostname.replace(/^\[|\]$/g, ''), port, user: decodeURIComponent(url.username), pass: decodeURIComponent(url.password) };
  } catch { throw new Error('Invalid upstreamProxy URL (credentials omitted)'); }
}

function isLoopbackHost(host) {
  return host === 'localhost' || host === '::1' || (net.isIP(host) === 4 && host.startsWith('127.'));
}

function createConnector(proxy, { timeout = 30000, rejectUnauthorized = true } = {}) {
  return function connectEgress(host, port, callback) {
    const p = proxy && !isLoopbackHost(host) ? proxy : null;
    const socket = p?.secure
      ? tls.connect({ host: p.host, port: p.port, servername: net.isIP(p.host) ? undefined : p.host, rejectUnauthorized, minVersion: 'TLSv1.2' })
      : net.connect({ host: p ? p.host : host, port: p ? p.port : port });
    let done = false;
    let buf = Buffer.alloc(0);
    let stage = 0;
    const timer = setTimeout(() => finish(new Error('Egress connection timeout')), timeout);
    const finish = (err, rest) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('close', onClose);
      // Keep an error listener until the caller has attached its own handlers.
      if (err) { socket.destroy(); callback(err); return; }
      socket.pause();
      if (rest?.length) socket.unshift(rest);
      callback(null, socket);
    };
    const onClose = () => finish(new Error('Egress closed during handshake'));
    const sendSocksConnect = () => {
      const hb = Buffer.from(host);
      if (hb.length > 255) return finish(new Error('Egress hostname too long'));
      stage = 2;
      socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, hb.length]), hb, Buffer.from([port >> 8, port & 255])]));
    };
    const onData = chunk => {
      if (done) return;
      // Only handshake bytes are buffered; terminal replies may include early data.
      buf = Buffer.concat([buf, chunk]);
      if (p.type === 'http') {
        const end = buf.indexOf('\r\n\r\n');
        if (end > 16384 || (end < 0 && buf.length > 16384)) return finish(new Error('CONNECT response headers too large'));
        if (end < 0) return;
        if (!/^HTTP\/1\.[01] 2\d\d(?: |\r\n)/.test(buf.subarray(0, end + 2).toString('latin1'))) return finish(new Error('CONNECT rejected'));
        return finish(null, buf.subarray(end + 4));
      }
      for (;;) {
        if (stage === 0) {
          if (buf.length < 2) return;
          if (buf[0] !== 5) return finish(new Error('Invalid SOCKS version'));
          const method = buf[1]; buf = buf.subarray(2);
          if (method === 0 && !p.user) { sendSocksConnect(); continue; }
          if (method !== 2 || !p.user) return finish(new Error('SOCKS authentication method rejected'));
          const user = Buffer.from(p.user), pass = Buffer.from(p.pass);
          if (!user.length || user.length > 255 || pass.length > 255) return finish(new Error('SOCKS credentials too long'));
          stage = 1;
          socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
        } else if (stage === 1) {
          if (buf.length < 2) return;
          if (buf[0] !== 1 || buf[1] !== 0) return finish(new Error('SOCKS authentication rejected'));
          buf = buf.subarray(2); sendSocksConnect();
        } else {
          if (buf.length < 5) return;
          if (buf[0] !== 5 || buf[1] !== 0 || buf[2] !== 0) return finish(new Error('SOCKS connection rejected'));
          const size = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : buf[3] === 3 && buf[4] ? 7 + buf[4] : -1;
          if (size < 0) return finish(new Error('Invalid SOCKS address type'));
          if (buf.length < size) return;
          return finish(null, buf.subarray(size));
        }
        if (buf.length > 4096) return finish(new Error('SOCKS handshake too large'));
      }
    };
    socket.on('error', finish);
    socket.once('close', onClose);
    socket.on('data', onData);
    socket.once(p?.secure ? 'secureConnect' : 'connect', () => {
      if (!p) return finish(null);
      if (p.type === 'http') {
        const authority = `${net.isIP(host) === 6 ? `[${host}]` : host}:${port}`;
        const auth = p.user ? `Proxy-Authorization: Basic ${Buffer.from(`${p.user}:${p.pass}`).toString('base64')}\r\n` : '';
        socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${auth}\r\n`);
      } else socket.write(p.user ? Buffer.from([5, 1, 2]) : Buffer.from([5, 1, 0]));
    });
    return socket;
  };
}

module.exports = { parseEgressProxy, createConnector };
