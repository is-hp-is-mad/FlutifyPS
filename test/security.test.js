'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { trustedProxyList, clientIp, equalSecret, redact, stripHeaders, normalizeIp } = require('../lib/security');
const { parseGeosite } = require('../lib/geosite');

test('real client IP requires a trusted peer and traverses XFF from the right', () => {
  const trusted = trustedProxyList(['127.0.0.1/32', '10.0.0.0/8']);
  const req = { socket: { remoteAddress: '192.0.2.1' }, headers: { 'cf-connecting-ip': '198.51.100.8' } };
  assert.equal(clientIp(req, trusted, 'cf-connecting-ip'), '192.0.2.1');
  req.socket.remoteAddress = '::ffff:127.0.0.1';
  assert.equal(clientIp(req, trusted, 'cf-connecting-ip'), '198.51.100.8');
  req.headers['x-forwarded-for'] = '203.0.113.5, 198.51.100.8, 10.0.0.2';
  assert.equal(clientIp(req, trusted, 'x-forwarded-for'), '198.51.100.8');
  req.headers['cf-connecting-ip'] = 'invalid, 198.51.100.8';
  assert.equal(clientIp(req, trusted, 'cf-connecting-ip'), '127.0.0.1');
  assert.equal(normalizeIp('2001:0db8:0:0:0:0:0:1'), '2001:db8::1');
  assert.throws(() => trustedProxyList(['0.0.0.0/nope']));
});

test('headers remove hop-by-hop, Connection-nominated, credentials and real IP', () => {
  const headers = stripHeaders({ connection: 'keep-alive, X-Remove', 'x-remove': 'secret', 'transfer-encoding': 'chunked', 'content-length': '123', 'cf-connecting-ip': '192.0.2.1', forwarded: 'for=192.0.2.1', 'x-forwarded-prefix': 'private', 'x-proxy-pass': 'secret', authorization: 'Bearer upstream', range: 'bytes=1-2' }, { request: true, strip: new Set(['x-proxy-pass']) });
  assert.deepEqual(headers, { authorization: 'Bearer upstream', range: 'bytes=1-2' });
});

test('constant-length credential comparison and log redaction', () => {
  assert.equal(equalSecret('hello', 'hello'), true);
  assert.equal(equalSecret('hello', 'hello world'), false);
  const text = redact('https://u:p@localhost/ PASS=abc SECRET=xyz auth:aaa token=t&other=ok\r\nprivate-password', ['private-password']);
  for (const secret of ['u:p', 'abc', 'xyz', 'aaa', 'private-password']) assert.ok(!text.includes(secret));
  assert.ok(!text.includes('\n'));
  assert.ok(text.includes('other=ok'));
});

test('geosite rejects truncated fixed, nested length and unsafe varint fields', () => {
  for (const data of [[9, 1], [13, 1], [10, 5, 1], [10, 3, 10, 2, 65], [10, 4, 18, 2, 18, 20], [0], [10, 255, 255, 255, 255, 255, 255, 255, 127]]) {
    assert.throws(() => parseGeosite(Buffer.from(data)));
  }
  const domain = Buffer.concat([Buffer.from([8, 2, 18, 11]), Buffer.from('example.com')]);
  const site = Buffer.concat([Buffer.from([10, 4]), Buffer.from('test'), Buffer.from([18, domain.length]), domain]);
  const parsed = parseGeosite(Buffer.concat([Buffer.from([10, site.length]), site]));
  assert.equal(parsed.get('test')[0].value, 'example.com');
});
