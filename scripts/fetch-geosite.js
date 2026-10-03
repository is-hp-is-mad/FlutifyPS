#!/usr/bin/env node
/**
 * 下载 mihomo（Clash Meta）的 geosite.dat 并提取指定分类，生成域名白名单文本。
 *
 * 用法：
 *   node scripts/fetch-geosite.js                          # 默认提取 spotify 分类
 *   node scripts/fetch-geosite.js --categories spotify,netflix
 *   node scripts/fetch-geosite.js --dat rules/geosite.dat   # 用本地 dat，不下载
 *   node scripts/fetch-geosite.js --out rules/spotify-domains.txt
 *
 * 输出格式（server.js 的 whitelist.files 直接可读，兼容 v2fly/mihomo 语法）：
 *   domain:spotify.com        # 含子域
 *   full:audio-ak-spotify-com.akamaized.net
 *   keyword:xxx
 *   regexp:...
 */
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const { parseGeosite } = require('../lib/geosite');

const DEFAULT_URL = 'https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat';

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

const CATEGORIES = arg('categories', 'spotify').split(',').map(s => s.trim()).filter(Boolean);
const DAT_PATH = path.resolve(__dirname, '..', arg('dat', 'rules/geosite.dat'));
const OUT_PATH = path.resolve(__dirname, '..', arg('out', 'rules/spotify-domains.txt'));
const SRC_URL = arg('url', DEFAULT_URL);

function download(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    if (new URL(url).protocol !== 'https:') return reject(new Error('Only HTTPS rule sources are allowed'));
    https.get(url, { timeout: 60000 }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(download(new URL(res.headers.location, url).href, redirects - 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > 64 * 1024 * 1024) return res.destroy(new Error('Rule download exceeds 64 MiB'));
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject).on('timeout', function () { this.destroy(new Error('timeout')); });
  });
}

(async () => {
  let dat;
  if (fs.existsSync(DAT_PATH) && !process.argv.includes('--force')) {
    console.log(`使用本地 geosite: ${DAT_PATH}`);
    dat = fs.readFileSync(DAT_PATH);
  } else {
    console.log(`下载 geosite.dat: ${SRC_URL}`);
    dat = await download(SRC_URL);
    fs.mkdirSync(path.dirname(DAT_PATH), { recursive: true });
    fs.writeFileSync(DAT_PATH, dat);
    console.log(`已缓存: ${DAT_PATH} (${(dat.length / 1024 / 1024).toFixed(1)}MB)`);
  }

  const map = parseGeosite(dat);
  console.log(`geosite 分类总数: ${map.size}`);

  const lines = [
    `# mihomo geosite 域名白名单（分类: ${CATEGORIES.join(', ')}）`,
    `# 生成: node scripts/fetch-geosite.js --categories ${CATEGORIES.join(',')}`,
    `# 语法: domain:x(含子域) / full:x(精确) / keyword:x / regexp:... / 或裸域名(=domain:)`,
    ''
  ];
  let total = 0;
  for (const cat of CATEGORIES) {
    const rules = map.get(cat.toLowerCase());
    if (!rules) {
      console.warn(`警告: geosite 中没有分类 "${cat}"，可用分类示例: ${[...map.keys()].slice(0, 15).join(', ')} ...`);
      continue;
    }
    lines.push(`# ---- geosite:${cat} (${rules.length} 条) ----`);
    for (const r of rules) {
      const v = String(r.value || '').trim();
      if (!v || v.startsWith('geosite:')) continue; // 跳过引用，避免递归
      switch (r.type) {
        case 'full': lines.push('full:' + v); break;
        case 'keyword': lines.push('keyword:' + v); break;
        case 'regexp':
          try { new RegExp(v); lines.push('regexp:' + v); }
          catch (_) { console.warn(`跳过非法正则: ${v}`); }
          break;
        default: lines.push('domain:' + v);
      }
      total++;
    }
    lines.push('');
  }

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, lines.join('\n'), 'utf8');
  console.log(`已写入白名单: ${OUT_PATH}（共 ${total} 条规则）`);
})().catch(err => {
  console.error('失败:', err.message);
  process.exit(1);
});
