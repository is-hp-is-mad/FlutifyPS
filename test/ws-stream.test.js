'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { WsDecoder } = require('../lib/ws-stream');

function masked(data, opcode = 2, fin = true) {
  const payload = Buffer.from(data);
  const header = Buffer.alloc(payload.length < 126 ? 6 : 8);
  header[0] = (fin ? 128 : 0) | opcode;
  if (payload.length < 126) header[1] = 128 | payload.length;
  else { header[1] = 254; header.writeUInt16BE(payload.length, 2); }
  const mask = Buffer.from([11, 22, 33, 44]); mask.copy(header, header.length - 4);
  return Buffer.concat([header, payload.map((v, i) => v ^ mask[i & 3])]);
}

test('split masked frames, fragments and control payloads decode correctly', async () => {
  const decoder = new WsDecoder(); const result = []; const controls = [];
  decoder.on('data', data => result.push(data));
  decoder.on('control', (opcode, data) => controls.push([opcode, data.toString()]));
  const bytes = Buffer.concat([masked('abc', 2, false), masked('ping', 9), masked('def', 0), masked('', 10)]);
  const done = once(decoder, 'end');
  for (const byte of bytes) decoder.write(Buffer.from([byte]));
  decoder.end(); await done;
  assert.equal(Buffer.concat(result).toString(), 'abcdef');
  assert.deepEqual(controls, [[9, 'ping'], [10, '']]);
});

test('invalid and oversized frames are rejected before a payload allocation', async () => {
  for (const bytes of [Buffer.from([130, 0]), Buffer.from([194, 128]), Buffer.from([130, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]), masked('text', 1), masked('orphan', 0), masked('ping', 9, false), masked('x', 8), masked(Buffer.from([3, 237]), 8)]) {
    const decoder = new WsDecoder(128);
    const error = once(decoder, 'error'); decoder.end(bytes); await error;
    assert.equal(decoder.destroyed, true);
  }
});

test('fragmented message aggregate limit cannot be bypassed', async () => {
  const decoder = new WsDecoder(4); decoder.resume();
  const error = once(decoder, 'error');
  decoder.end(Buffer.concat([masked('abc', 2, false), masked('def', 0)]));
  await error;
});

test('decoder pauses writes under downstream backpressure and resumes without loss', async () => {
  const decoder = new WsDecoder();
  const data = Buffer.alloc(60000, 7);
  const packet = Buffer.concat([masked(data), masked(data), masked(data)]);
  let accepted = false;
  decoder.write(packet, () => { accepted = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(accepted, false);
  assert.ok(decoder.readableLength <= 60000);
  const chunks = []; decoder.on('data', b => chunks.push(b));
  const done = once(decoder, 'end'); decoder.end(); await done;
  assert.deepEqual(Buffer.concat(chunks), Buffer.concat([data, data, data]));
});

module.exports = { masked };
