'use strict';

const { Transform } = require('node:stream');
const { isUtf8 } = require('node:buffer');

function wsFrame(opcode, payload) {
  const len = payload.length;
  const head = Buffer.alloc(len < 126 ? 2 : len < 65536 ? 4 : 10);
  head[0] = 0x80 | opcode;
  if (len < 126) head[1] = len;
  else if (len < 65536) { head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([head, payload]);
}

// Fixed header storage and one bounded payload allocation per frame. Transform's
// readable backpressure stops the TLS source as soon as the upstream stops reading.
class WsDecoder extends Transform {
  constructor(maxFrameBytes = 1024 * 1024) {
    super();
    this.maxFrameBytes = maxFrameBytes;
    this.header = Buffer.alloc(14);
    this.headerUsed = 0;
    this.headerNeed = 2;
    this.payload = null;
    this.payloadUsed = 0;
    this.fragmented = false;
    this.messageBytes = 0;
    this.receivedClose = false;
    this.pending = null;
  }
  _transform(chunk, encoding, callback) { this.consume(chunk, 0, callback); }
  _read(size) {
    if (this.pending) {
      const [chunk, pos, cb] = this.pending;
      this.pending = null;
      this.consume(chunk, pos, cb);
    }
    super._read(size);
  }
  _flush(callback) {
    callback(!this.receivedClose && (this.headerUsed || this.fragmented) ? new Error('Truncated WebSocket message') : null);
  }
  consume(chunk, pos, callback) {
    try {
      while (pos < chunk.length && !this.receivedClose) {
        if (!this.payload) {
          const size = Math.min(this.headerNeed - this.headerUsed, chunk.length - pos);
          chunk.copy(this.header, this.headerUsed, pos, pos + size);
          this.headerUsed += size; pos += size;
          if (this.headerUsed < this.headerNeed) break;
          const first = this.header[0], second = this.header[1];
          if (this.headerNeed === 2) {
            if ((first & 0x70) || !(second & 0x80)) throw new Error('Invalid WebSocket flags');
            const short = second & 127;
            this.headerNeed = (short === 126 ? 4 : short === 127 ? 10 : 2) + 4;
            continue;
          }
          const short = second & 127;
          const length = short === 126 ? this.header.readUInt16BE(2) : short === 127 ? this.header.readBigUInt64BE(2) : short;
          if (length > BigInt(this.maxFrameBytes) || (short === 126 && length < 126) || (short === 127 && length < 65536)) throw new Error('Invalid WebSocket frame size');
          this.opcode = first & 15;
          this.fin = !!(first & 128);
          if (![0, 2, 8, 9, 10].includes(this.opcode)) throw new Error('Binary WebSocket frames required');
          if (this.opcode >= 8 && (!this.fin || length > 125)) throw new Error('Invalid control frame');
          if (this.opcode < 8) {
            if ((this.opcode === 0) !== this.fragmented) throw new Error('Invalid continuation');
            this.messageBytes += Number(length);
            if (this.messageBytes > this.maxFrameBytes) throw new Error('WebSocket message too large');
            this.fragmented = !this.fin;
            if (this.fin) this.messageBytes = 0;
          }
          this.payload = Buffer.alloc(Number(length));
          this.payloadUsed = 0;
        }
        const size = Math.min(this.payload.length - this.payloadUsed, chunk.length - pos);
        const maskOffset = this.headerNeed - 4;
        for (let i = 0; i < size; i++) this.payload[this.payloadUsed + i] = chunk[pos + i] ^ this.header[maskOffset + ((this.payloadUsed + i) & 3)];
        this.payloadUsed += size; pos += size;
        if (this.payloadUsed !== this.payload.length) break;
        const payload = this.payload;
        this.payload = null; this.headerUsed = 0; this.headerNeed = 2;
        if (this.opcode === 8) {
          if (payload.length === 1) throw new Error('Invalid close payload');
          if (payload.length >= 2) {
            const code = payload.readUInt16BE(0);
            if (!((code >= 1000 && code <= 1014 && ![1004, 1005, 1006].includes(code)) || (code >= 3000 && code <= 4999)) || !isUtf8(payload.subarray(2))) throw new Error('Invalid close code/reason');
          }
          this.receivedClose = true;
          this.emit('control', 8, payload);
        } else if (this.opcode >= 8) this.emit('control', this.opcode, payload);
        else if (payload.length && !this.push(payload)) {
          this.pending = [chunk, pos, callback];
          return;
        }
      }
      callback();
    } catch (err) { callback(err); }
  }
}

function pipeWsStream(client, upstream, head, maxFrameBytes) {
  const decoder = new WsDecoder(maxFrameBytes);
  const encoder = new Transform({ transform(chunk, encoding, cb) {
    // Keep server frames below the same bound even if a custom source emits large chunks.
    for (let pos = 0; pos < chunk.length; pos += maxFrameBytes) this.push(wsFrame(2, chunk.subarray(pos, pos + maxFrameBytes)));
    cb();
  } });
  let closed = false;
  const stop = () => {
    if (closed) return;
    closed = true;
    decoder.destroy(); encoder.destroy(); upstream.destroy(); client.destroy();
  };
  decoder.on('error', stop); encoder.on('error', stop);
  client.on('error', stop); upstream.on('error', stop);
  client.on('close', stop); upstream.on('close', stop);
  decoder.on('control', (opcode, payload) => {
    if (opcode === 10) return;
    // Control replies do not pass through pipe(); cap them independently.
    if (client.writableLength > 64 * 1024) return stop();
    if (opcode === 8) {
      client.end(wsFrame(8, payload), stop);
    } else client.write(wsFrame(10, payload));
  });
  decoder.pipe(upstream);
  upstream.pipe(encoder).pipe(client);
  if (head?.length) client.unshift(head);
  client.pipe(decoder);
}

module.exports = { WsDecoder, wsFrame, pipeWsStream };
