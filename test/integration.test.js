'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const https = require('node:https');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { wsFrame } = require('../lib/ws-stream');

const root = path.resolve(__dirname, '..');
const credentials = { 'X-Proxy-User': 'test-user', 'X-Proxy-Pass': crypto.randomBytes(24).toString('hex') };
const wsHeaders = { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': Buffer.alloc(16, 3).toString('base64') };
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function freePort() { const s = net.createServer(); const p = await listen(s); await new Promise(r => s.close(r)); return p; }
function masked(payload, opcode = 2) {
  const plain = Buffer.from(payload), frame = wsFrame(opcode, plain);
  const n = frame.length - plain.length; frame[1] |= 128;
  const mask = Buffer.from([2, 3, 5, 7]);
  return Buffer.concat([frame.subarray(0, n), mask, plain.map((v, i) => v ^ mask[i & 3])]);
}
function request(port, url, { headers = credentials, method = 'GET', body, plain = false } = {}) {
  return new Promise((resolve, reject) => {
    const req = (plain ? http : https).request({ host: '127.0.0.1', port, path: url, headers, method, rejectUnauthorized: false, agent: false }, res => {
      const chunks = []; let resolved = false;
      const finish = aborted => { if (resolved) return; resolved = true; resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), aborted }); };
      res.on('data', c => chunks.push(c)); res.on('end', () => finish(false)); res.on('aborted', () => finish(true)); res.on('error', () => finish(true));
    });
    req.setTimeout(5000, () => req.destroy(new Error('test request timeout')));
    req.on('error', reject); req.end(body);
  });
}
function rawRequest(port, text, extra = Buffer.alloc(0), until = data => data.includes('\r\n\r\n')) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false });
    let buffer = Buffer.alloc(0), done = false;
    const finish = err => { if (done) return; done = true; socket.destroy(); err ? reject(err) : resolve(buffer); };
    socket.setTimeout(5000, () => finish(new Error('raw test timeout')));
    socket.on('error', finish); socket.on('end', () => finish());
    socket.on('data', b => { buffer = Buffer.concat([buffer, b]); if (until(buffer)) finish(); });
    socket.once('secureConnect', () => socket.write(Buffer.concat([Buffer.from(text), extra])));
  });
}
function handshake(url, headers = wsHeaders) {
  return `GET ${url} HTTP/1.1\r\nHost: localhost\r\n` + Object.entries({ ...credentials, ...headers }).map(([k, v]) => `${k}: ${v}\r\n`).join('') + '\r\n';
}

test('FlutifyPS HTTPS, WebSocket and tunnel integration', { timeout: 60000 }, async t => {
  fs.mkdirSync(path.join(root, '.tmp'), { recursive: true });
  const temp = fs.mkdtempSync(path.join(root, '.tmp', 'integration-'));
  const processes = new Set(), sockets = new Set(), servers = new Set();
  t.after(async () => {
    for (const child of processes) if (child.exitCode === null && child.signalCode === null) { const done = once(child, 'exit'); child.kill(); await done; }
    for (const socket of sockets) socket.destroy();
    for (const server of servers) await new Promise(resolve => server.close(resolve));
    if (!path.resolve(temp).startsWith(path.join(root, '.tmp') + path.sep)) throw new Error('Unsafe test cleanup');
    fs.rmSync(temp, { recursive: true, force: true });
  });
  const key = path.join(temp, 'key.pem'), cert = path.join(temp, 'cert.pem');
  const opensslConfig = path.join(temp, 'openssl.cnf');
  fs.writeFileSync(opensslConfig, '[req]\ndistinguished_name=dn\n[dn]\n');
  execFileSync('openssl', ['req', '-config', opensslConfig, '-x509', '-nodes', '-newkey', 'rsa:2048', '-sha256', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost'], { stdio: 'pipe' });
  fs.chmodSync(key, 0o600);
  const tlsOptions = { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
  function track(server) { servers.add(server); server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); }); return server; }
  let upstreamHits = 0;
  const upstream = track(https.createServer(tlsOptions, (req, res) => {
    upstreamHits++;
    if (req.url === '/page') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<html>blocked</html>'); }
    if (req.url === '/truncated') {
      res.writeHead(200, { 'Content-Type': 'audio/mpeg', 'Content-Length': 9999 }); res.write('music');
      return setTimeout(() => res.destroy(), 25);
    }
    if (req.url === '/media') {
      res.writeHead(206, { 'Content-Type': 'audio/mpeg', 'Content-Length': 100, 'Content-Range': 'bytes 0-99/9999' }); return res.end(Buffer.alloc(100, 9));
    }
    if (req.url === '/cookies') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': ['sid=abc; Domain=example.com; Path=/v1; HttpOnly'], Connection: 'close, X-Remove', 'X-Remove': 'bad', 'Alt-Svc': 'bad' }); return res.end('{}');
    }
    const chunks = []; req.on('data', b => chunks.push(b)); req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ headers: req.headers, body: Buffer.concat(chunks).toString() }));
    });
  }));
  upstream.on('upgrade', (req, socket, head) => {
    socket.on('error', () => {});
    if (req.url === '/page') return socket.end('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 7\r\n\r\nblocked');
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, X-Remove\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${accept}\r\nAlt-Svc: secret\r\nX-Remove: secret\r\nSet-Cookie: sid=abc; Domain=example.com; Path=/\r\n\r\n`);
    if (head.length) socket.write(head);
    socket.pipe(socket);
  });
  const upPort = await listen(upstream);
  const echo = track(net.createServer(socket => { socket.on('error', () => {}); socket.pipe(socket); }));
  const echoPort = await listen(echo);
  const port = await freePort(), redirectPort = await freePort();
  const config = {
    listen: { host: '127.0.0.1', port, httpRedirectPort: redirectPort, publicOrigin: 'https://music.example.test:443' },
    tls: { key, cert, upstreamRejectUnauthorized: false },
    auth: { username: credentials['X-Proxy-User'], password: credentials['X-Proxy-Pass'] },
    envFile: 'nonexistent.env', disguise: { path: 'test-assets', blockHtml: true },
    limits: { maxConnections: 30, maxUpgradedConnections: 2, maxWsFrameBytes: 1024 },
    whitelist: { domains: ['localhost'], allowPorts: true },
    tunnel: { enabled: true, hosts: ['localhost'], allowedPorts: [echoPort] },
    timeouts: { upstreamMs: 1000, shutdownMs: 100 },
    security: { authFailLimit: 2, globalAuthFailLimit: 4 }, logLevel: 'info'
  };
  const configPath = path.join(temp, 'config.json');
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('PROXY_')));
  async function start(custom = config, waitReady = true) {
    fs.writeFileSync(configPath, JSON.stringify(custom), { mode: 0o600 });
    const child = spawn(process.execPath, ['server.js', '--config', configPath], { cwd: root, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    processes.add(child);
    let output = ''; child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
    if (!waitReady) { const [code] = await once(child, 'exit'); return { child, code, output }; }
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Server startup timed out: ' + output)), 5000);
      child.once('exit', code => { clearTimeout(timer); reject(new Error('Server exited ' + code + ': ' + output)); });
      child.stdout.on('data', () => { if (output.includes('已启动')) { clearTimeout(timer); resolve(); } });
    });
    return { child, output: () => output };
  }
  const running = await start();
  const target = `/test-assets/localhost:${upPort}`;
  await t.test('unauthenticated and malformed targets return fake404; server stays healthy', async () => {
    assert.equal((await request(port, '/')).status, 404);
    assert.equal((await request(port, target + '/', { headers: {} })).status, 404);
    for (const host of ['%E0%A4%A', 'localhost:0', 'localhost:65536', '127.0.0.1', 'a'.repeat(254), 'evil.example.com', 'localhost%2Fbad']) assert.equal((await request(port, `/test-assets/${host}/`)).status, 404);
    const ping = await request(port, '/test-assets/__ping'); assert.equal(ping.status, 200); assert.deepEqual(JSON.parse(ping.body), { ok: true });
  });
  await t.test('framing, hop headers, credentials and real-IP stripping', async () => {
    const response = await request(port, target + '/echo', { method: 'POST', body: 'hello', headers: { ...credentials, Connection: 'close, X-Remove', 'X-Remove': 'bad', 'CF-Connecting-IP': '192.0.2.1', 'X-Real-IP': '192.0.2.2', Authorization: 'Bearer upstream', 'Transfer-Encoding': 'chunked' } });
    const result = JSON.parse(response.body);
    assert.equal(result.body, 'hello'); assert.equal(result.headers.authorization, 'Bearer upstream');
    for (const key of ['x-proxy-pass', 'x-proxy-user', 'x-remove', 'cf-connecting-ip', 'x-real-ip', 'content-length']) assert.equal(result.headers[key], undefined);
    const before = upstreamHits;
    const raw = await rawRequest(port, `POST ${target}/echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n`);
    assert.match(raw.toString(), /^HTTP\/1\.1 400/); assert.equal(upstreamHits, before);
  });
  await t.test('response cookies, HTML block, Range and midstream abort', async () => {
    const cookies = await request(port, target + '/cookies');
    assert.equal(cookies.headers['alt-svc'], undefined); assert.equal(cookies.headers['x-remove'], undefined);
    assert.equal(cookies.headers['set-cookie'][0], `sid=abc; HttpOnly; Path=${target}/v1`);
    assert.equal((await request(port, target + '/page')).status, 404);
    const media = await request(port, target + '/media', { headers: { ...credentials, Range: 'bytes=0-99' } });
    assert.equal(media.status, 206); assert.equal(media.body.length, 100); assert.equal(media.headers['content-range'], 'bytes 0-99/9999');
    const truncated = await request(port, target + '/truncated');
    assert.equal(truncated.aborted, true); assert.equal(truncated.body.toString(), 'music');
  });
  await t.test('redirect uses configured public origin, never client Host', async () => {
    const res = await request(redirectPort, '/path?x=1', { plain: true, headers: { Host: 'evil.example:443' } });
    assert.equal(res.headers.location, 'https://music.example.test/path?x=1');
    assert.equal((await request(redirectPort, '//evil.example', { plain: true })).status, 404);
  });
  await t.test('WebSocket handshake sanitizes response and preserves early frame data', async () => {
    const extra = masked('early');
    const data = await rawRequest(port, handshake(target + '/ws'), extra, b => b.includes(extra));
    const headers = data.toString('latin1').split('\r\n\r\n')[0];
    assert.match(headers, /101 Switching Protocols/); assert.doesNotMatch(headers, /alt-svc|x-remove|Domain=/i); assert.ok(headers.includes(`Path=${target}`));
    assert.equal((await rawRequest(port, handshake(target + '/page'))).toString().startsWith('HTTP/1.1 404'), true);
  });
  await t.test('TCP tunnel and masked WebSocket tunnel preserve head bytes and pong payload', async () => {
    const tunnel = `/test-assets/__tunnel/localhost:${echoPort}`;
    const raw = await rawRequest(port, handshake(tunnel, { Connection: 'Upgrade', Upgrade: 'tcp-tunnel' }), Buffer.from('hello-tcp'), b => b.includes('hello-tcp'));
    assert.match(raw.toString(), /200 Connection Established/);
    const expected = wsFrame(2, Buffer.from('hello-ws'));
    const data = await rawRequest(port, handshake(tunnel), masked('hello-ws'), b => b.includes(expected));
    assert.ok(data.includes(expected));
    const pong = wsFrame(10, Buffer.from('ping'));
    assert.ok((await rawRequest(port, handshake(tunnel), masked('ping', 9), b => b.includes(pong))).includes(pong));
    assert.match((await rawRequest(port, handshake('/test-assets/__tunnel/localhost:1'))).toString(), /^HTTP\/1\.1 404/);
    assert.match((await rawRequest(port, handshake(tunnel, { ...wsHeaders, 'Sec-WebSocket-Key': 'bad' }))).toString(), /^HTTP\/1\.1 404/);
  });
  await t.test('upgrade quota leaves capacity for HTTPS requests', async () => {
    const held = [];
    try {
      for (let i = 0; i < 2; i++) await new Promise((resolve, reject) => {
        const socket = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false }); held.push(socket);
        socket.on('error', reject); socket.once('secureConnect', () => socket.write(handshake(target + '/ws')));
        socket.once('data', b => { assert.match(b.toString(), /101 Switching/); resolve(); });
      });
      assert.match((await rawRequest(port, handshake(target + '/ws'))).toString(), /^HTTP\/1\.1 404/);
      assert.equal((await request(port, '/test-assets/__ping')).status, 200);
    } finally { for (const socket of held) socket.destroy(); }
  });
  await t.test('invalid auth flood cannot lock out valid clients; secrets stay out of logs', async () => {
    for (let i = 0; i < 7; i++) assert.equal((await request(port, '/test-assets/__ping', { headers: { ...credentials, 'X-Proxy-Pass': 'incorrect' } })).status, 404);
    assert.equal((await request(port, '/test-assets/__ping')).status, 200);
    await request(port, target + '/?PASS=sensitive-query');
    assert.ok(!running.output().includes(credentials['X-Proxy-Pass'])); assert.ok(!running.output().includes('sensitive-query'));
  });
  const stopped = once(running.child, 'exit'); running.child.kill(); await stopped;
  await t.test('missing and weak credentials fail closed without opening listener', async () => {
    for (const password of ['', 'short', '12345678', '１２３４５６７８']) {
      const result = await start({ ...config, auth: { username: 'test-user', password } }, false);
      assert.notEqual(result.code, 0); assert.ok(!result.output.includes('已启动'));
    }
  });
  await t.test('eight-character nonnumeric passwords are accepted without extra restrictions', async () => {
    for (const password of ['password', '1234567a']) {
      const auth = { username: password, password };
      const instance = await start({ ...config, auth });
      const ping = await request(port, '/test-assets/__ping', { headers: { 'X-Proxy-User': auth.username, 'X-Proxy-Pass': auth.password } });
      assert.equal(ping.status, 200);
      const done = once(instance.child, 'exit'); instance.child.kill(); await done;
    }
  });
});
