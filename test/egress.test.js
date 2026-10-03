'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { once } = require('node:events');
const { createConnector, parseEgressProxy } = require('../lib/egress');

async function proxyServer(t, handler) {
  const peers = new Set();
  const server = net.createServer(socket => { peers.add(socket); socket.on('error', () => {}); socket.on('close', () => peers.delete(socket)); handler(socket); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { for (const socket of peers) socket.destroy(); server.close(); });
  return server.address().port;
}
function connect(connector) { return new Promise((resolve, reject) => connector('api.example.test', 443, (e, s) => e ? reject(e) : resolve(s))); }

test('malformed egress configuration never includes credentials in errors', () => {
  for (const input of ['http://user:secret@host:99999', 'socks5://user:%ZZ@localhost', 'file://secret']) {
    assert.throws(() => parseEgressProxy(input), error => !error.message.includes('secret'));
  }
});

test('SOCKS domain reply includes its port and preserves early stream bytes', async t => {
  const port = await proxyServer(t, socket => {
    socket.once('data', () => {
      socket.write(Buffer.from([5, 0]));
      socket.once('data', () => {
        socket.write(Buffer.from([5, 0, 0, 3]));
        setTimeout(() => socket.write(Buffer.concat([Buffer.from([3]), Buffer.from('abc'), Buffer.from([0x12, 0x34]), Buffer.from('hello')])), 10);
      });
    });
  });
  const socket = await connect(createConnector(parseEgressProxy(`socks5://127.0.0.1:${port}`)));
  t.after(() => socket.destroy());
  const data = once(socket, 'data'); socket.resume();
  assert.equal((await data)[0].toString(), 'hello');
});

test('HTTP CONNECT retains early bytes and rejects oversized headers', async t => {
  const port = await proxyServer(t, socket => socket.once('data', () => socket.write('HTTP/1.1 200 Connected\r\n\r\nearly')));
  const socket = await connect(createConnector(parseEgressProxy(`http://127.0.0.1:${port}`)));
  t.after(() => socket.destroy());
  const data = once(socket, 'data'); socket.resume(); assert.equal((await data)[0].toString(), 'early');
  const badPort = await proxyServer(t, s => s.once('data', () => s.write('HTTP/1.1 200 OK\r\nX: ' + 'a'.repeat(17000) + '\r\n\r\n')));
  await assert.rejects(connect(createConnector(parseEgressProxy(`http://127.0.0.1:${badPort}`))), /too large/);
});

test('egress handshake times out and calls back once on early close', async t => {
  const port = await proxyServer(t, () => {});
  await assert.rejects(connect(createConnector(parseEgressProxy(`http://127.0.0.1:${port}`), { timeout: 30 })), /timeout/);
  const closingPort = await proxyServer(t, socket => socket.end());
  await assert.rejects(connect(createConnector(parseEgressProxy(`socks5://127.0.0.1:${closingPort}`))), /closed/);
});
