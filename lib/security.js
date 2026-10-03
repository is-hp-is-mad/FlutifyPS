'use strict';

const net = require('node:net');
const crypto = require('node:crypto');

function normalizeIp(value) {
  const ip = String(value || '').trim();
  if (!net.isIP(ip)) return '';
  if (ip.toLowerCase().startsWith('::ffff:') && net.isIP(ip.slice(7)) === 4) return ip.slice(7);
  return net.isIP(ip) === 6 ? new URL(`http://[${ip}]/`).hostname.slice(1, -1) : ip;
}

function trustedProxyList(entries = []) {
  const list = new net.BlockList();
  for (const entry of entries) {
    const [raw, bits, extra] = String(entry).split('/');
    const ip = normalizeIp(raw);
    if (!ip || extra !== undefined) throw new Error('Invalid security.trustedProxies entry');
    const type = net.isIP(ip) === 6 ? 'ipv6' : 'ipv4';
    if (bits === undefined) list.addAddress(ip, type);
    else {
      if (!/^\d+$/.test(bits)) throw new Error('Invalid trusted proxy prefix');
      list.addSubnet(ip, Number(bits), type);
    }
  }
  return list;
}

function clientIp(req, trusted, header) {
  const peer = normalizeIp(req.socket.remoteAddress);
  if (!peer || !trusted.check(peer, net.isIP(peer) === 6 ? 'ipv6' : 'ipv4')) return peer;
  const value = req.headers[header];
  if (typeof value !== 'string') return peer;
  // XFF is traversed from the trusted peer toward the first untrusted hop.
  if (header === 'x-forwarded-for') {
    let current = peer;
    for (const item of value.split(',').reverse()) {
      if (!trusted.check(current, net.isIP(current) === 6 ? 'ipv6' : 'ipv4')) break;
      const next = normalizeIp(item);
      if (!next) return peer;
      current = next;
    }
    return current;
  }
  return normalizeIp(value) || peer;
}

function equalSecret(a, b) {
  const digest = value => crypto.createHash('sha256').update(String(value ?? '')).digest();
  return crypto.timingSafeEqual(digest(a), digest(b));
}

function redact(value, secrets = []) {
  let text = String(value);
  for (const secret of secrets) if (secret) text = text.split(secret).join('[REDACTED]');
  return text
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/]*@/gi, '$1[REDACTED]@')
    .replace(/((?:access_token|client_token|refresh_token|password|passwd|pwd|token|secret|auth|pass|code)(?:%3d|\s*[=:]\s*))[^&\s,;]+/gi, '$1[REDACTED]')
    .replace(/[\r\n\x00-\x1f\x7f]/g, ' ');
}

const HOP_HEADERS = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const IP_HEADERS = new Set(['forwarded', 'x-real-ip', 'true-client-ip', 'cf-connecting-ip', 'cf-connecting-ipv6', 'cf-pseudo-ipv4']);
function stripHeaders(input, { strip = new Set(), request = false } = {}) {
  const dynamic = new Set(String(input.connection || '').toLowerCase().split(',').map(v => v.trim()));
  const result = {};
  for (const [name, value] of Object.entries(input)) {
    const key = name.toLowerCase();
    if (HOP_HEADERS.has(key) || dynamic.has(key) || strip.has(key)) continue;
    if (key === 'content-length' && input['transfer-encoding']) continue;
    if (request && (key === 'host' || IP_HEADERS.has(key) || key.startsWith('x-forwarded-'))) continue;
    result[key] = value;
  }
  return result;
}

module.exports = { normalizeIp, trustedProxyList, clientIp, equalSecret, redact, stripHeaders };
