/**
 * v2ray/mihomo geosite.dat 解析（protobuf 子集，零依赖）
 *
 * message GeoSiteList { repeated GeoSite entry = 1; }
 * message GeoSite    { string country_code = 1; repeated Domain domain = 2; }
 * message Domain     { Type type = 1; string value = 2; repeated string attribute = 3; }
 *   Type: Plain=0(keyword) Regex=1 Domain=2(subdomains) Full=3(exact)
 */
'use strict';

function readVarint(buf, pos) {
  let result = 0, shift = 0, p = pos;
  while (p < buf.length) {
    const b = buf[p++];
    result += (b & 0x7f) * Math.pow(2, shift);
    if (!Number.isSafeInteger(result)) throw new Error('unsafe varint');
    if ((b & 0x80) === 0) return [result, p];
    shift += 7;
    if (shift > 53) throw new Error('varint too long');
  }
  throw new Error('truncated varint');
}

function readTag(buf, pos) {
  const [key, p] = readVarint(buf, pos);
  if (key < 8 || key > 0xffffffff) throw new Error('invalid protobuf tag');
  return [Math.floor(key / 8), key % 8, p]; // [fieldNumber, wireType, nextPos]
}

function endOfField(buf, pos, length) {
  if (!Number.isSafeInteger(length) || length < 0 || length > buf.length - pos) throw new Error('truncated protobuf field');
  return pos + length;
}

function readLength(buf, pos) {
  const [len, p] = readVarint(buf, pos);
  endOfField(buf, p, len);
  return [len, p];
}

function skipField(buf, pos, wireType) {
  switch (wireType) {
    case 0: return readVarint(buf, pos)[1];
    case 1: return endOfField(buf, pos, 8);
    case 2: { const [len, p] = readLength(buf, pos); return p + len; }
    case 5: return endOfField(buf, pos, 4);
    default: throw new Error('unsupported wire type ' + wireType);
  }
}

const TYPE_MAP = { 0: 'keyword', 1: 'regexp', 2: 'domain', 3: 'full' };

function parseDomain(buf) {
  let pos = 0, type = 'domain', value = '', attributes = [];
  while (pos < buf.length) {
    const [field, wire, p] = readTag(buf, pos);
    if (field === 1 && wire === 0) {
      const [v, np] = readVarint(buf, p);
      type = TYPE_MAP[v] || 'domain';
      pos = np;
    } else if (field === 2 && wire === 2) {
      const [len, np] = readLength(buf, p);
      value = buf.toString('utf8', np, np + len);
      pos = np + len;
    } else if (field === 3 && wire === 2) {
      const [len, np] = readLength(buf, p);
      attributes.push(buf.toString('utf8', np, np + len));
      pos = np + len;
    } else {
      pos = skipField(buf, p, wire);
    }
  }
  return { type, value, attributes };
}

function parseGeoSite(buf) {
  let pos = 0, code = '', domains = [];
  while (pos < buf.length) {
    const [field, wire, p] = readTag(buf, pos);
    if (field === 1 && wire === 2) {
      const [len, np] = readLength(buf, p);
      code = buf.toString('utf8', np, np + len);
      pos = np + len;
    } else if (field === 2 && wire === 2) {
      const [len, np] = readLength(buf, p);
      domains.push(parseDomain(buf.subarray(np, np + len)));
      pos = np + len;
    } else {
      pos = skipField(buf, p, wire);
    }
  }
  return { code: code.toLowerCase(), domains };
}

/** 解析 geosite.dat → Map<category, Array<{type,value,attributes}>> */
function parseGeosite(buf) {
  const map = new Map();
  let pos = 0;
  while (pos < buf.length) {
    const [field, wire, p] = readTag(buf, pos);
    if (field === 1 && wire === 2) {
      const [len, np] = readLength(buf, p);
      const site = parseGeoSite(buf.subarray(np, np + len));
      if (site.code) map.set(site.code, site.domains);
      pos = np + len;
    } else {
      pos = skipField(buf, p, wire);
    }
  }
  return map;
}

module.exports = { parseGeosite };
