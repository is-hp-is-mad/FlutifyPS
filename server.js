#!/usr/bin/env node
/**
 * FlutifyPS HTTPS 反向代理服务器（零依赖，Node.js >= 22）
 *
 * URL 格式：
 *   https://<域名或IP>:<端口>/<伪装路径>/<白名单域名>/<任意路径>?<query>
 *   例：https://music.example.com/media-assets/api.spotify.com/v1/me
 *
 * 鉴权（仅支持用户名头 + 密码头，服务端校验后裁剪，绝不转发给 Spotify）：
 *   X-Proxy-User: <用户名>  +  X-Proxy-Pass: <密码>
 *
 * 范围：Spotify API、媒体文件、WebSocket 与接入点协议：
 *   - 上游返回 text/html / application/xhtml 一律拦截为 404 伪装页（disguise.blockHtml）
 *   - 支持图片与音频 CDN；不支持网页登录、session/Cookie/query/Basic 鉴权
 *   - 校验不通过（鉴权失败 / 目标不在白名单）一律返回 404 伪装页，不细分原因。
 *
 * 三种承载（同一伪装路径、同一用户名头+密码头鉴权）：
 *   - HTTPS 反代：/<伪装路径>/<白名单域名>/<路径>?<query>（JSON / protobuf API）
 *   - WebSocket 反代：同 URL 形态 + Connection: Upgrade（过滤握手头，帧字节双向转发）
 *   - 裸 TCP 隧道：GET /<伪装路径>/__tunnel/<host>:<port> + Connection: Upgrade（接入点 Shannon
 *     协议；仅放行 tunnel.hosts 白名单 + tunnel.allowedPorts 端口）。
 *     两种升级形态：Upgrade: tcp-tunnel（裸管道，直连用）/ Upgrade: websocket（WS 帧装原始字节，
 *     CF 等 CDN 只透传 WS 升级，走 CDN 时用后者）
 *
 * 特性：
 *   - 三层伪装：伪装路径 + 404 nginx 假页 + 白名单域名
 *   - HTTPS 强制（可选 80 端口 301），流式原样透传（含压缩与大响应）
 *   - Set-Cookie 改写（cookies.rewrite）：剥掉 Domain、Path 收敛到 /<伪装路径>/<上游域名段>，
 *     cookie 按路径分流；Path 不是浏览器安全隔离边界
 */
'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { trustedProxyList, clientIp, equalSecret, redact, stripHeaders } = require('./lib/security');
const { parseEgressProxy, createConnector } = require('./lib/egress');
const { pipeWsStream } = require('./lib/ws-stream');
const logSecrets = [];

/* ------------------------ 日志（最先定义，配置加载期就要用） ------------------------ */

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
let LOG_LEVEL = 'warn';
function log(level, ...args) {
  if ((LEVELS[level] ?? 2) > (LEVELS[LOG_LEVEL] ?? 2)) return;
  const tag = { error: 'ERROR', warn: 'WARN ', info: 'INFO ', debug: 'DEBUG' }[level] || 'INFO ';
  const line = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ');
  process.stdout.write(`[${new Date().toISOString()}] [${tag}] ${redact(line, logSecrets)}\n`);
}

/* ============================ 配置 ============================ */

const CONFIG_PATH = process.argv.includes('--config')
  ? process.argv[process.argv.indexOf('--config') + 1]
  : (process.env.PROXY_CONFIG || path.join(__dirname, 'config.json'));

const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const BASE_DIR = path.dirname(path.resolve(CONFIG_PATH));

for (const group of ['limits', 'timeouts']) {
  for (const [key, value] of Object.entries(cfg[group] || {})) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 0x7fffffff) throw new Error(`Invalid ${group}.${key}`);
  }
}

function cfgGet(obj, dotted, def) {
  let cur = obj;
  for (const k of dotted.split('.')) {
    if (cur == null || typeof cur !== 'object') return def;
    cur = cur[k];
  }
  return cur === undefined ? def : cur;
}

/* ============================ .env / 环境变量 ============================
 * 优先级：环境变量 > .env（与 config 同目录，`envFile` 可改）> config.json > 内置默认。
 * 鉴权凭据、证书口令、伪装路径等敏感项放 .env（见 .env.example，scripts/gen-env.js 一键生成）。
 * ===================================================================== */
function loadDotEnv(file) {
  const out = {};
  try {
    if (!fs.existsSync(file)) return out;
    for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const s = raw.trim();
      if (!s || s.startsWith('#')) continue;
      const eq = s.indexOf('=');
      if (eq <= 0) continue;
      let v = s.slice(eq + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      out[s.slice(0, eq).trim()] = v;
    }
  } catch (e) {
    log('warn', `读取 .env 失败: ${e.message}`);
  }
  return out;
}

const ENV_FILE = path.resolve(BASE_DIR, cfgGet(cfg, 'envFile', '.env'));
const DOT_ENV = loadDotEnv(ENV_FILE);

/** 取配置：环境变量 > .env > config.json(dotted) > 默认值（空字符串视为未设置） */
function envGet(name, dotted, def) {
  const v = process.env[name] !== undefined ? process.env[name] : DOT_ENV[name];
  if (v !== undefined && v !== null && String(v) !== '') return v;
  return cfgGet(cfg, dotted, def);
}

const LISTEN_HOST = envGet('PROXY_LISTEN_HOST', 'listen.host', '0.0.0.0');
const LISTEN_PORT = Number(envGet('PROXY_LISTEN_PORT', 'listen.port', 443));
const HTTP_REDIRECT_PORT = Number(envGet('PROXY_HTTP_REDIRECT_PORT', 'listen.httpRedirectPort', 0));
for (const [name, port, min] of [['listen.port', LISTEN_PORT, 1], ['listen.httpRedirectPort', HTTP_REDIRECT_PORT, 0]]) {
  if (!Number.isInteger(port) || port < min || port > 65535) throw new Error(`Invalid ${name}`);
}

const DISGUISE = String(envGet('PROXY_DISGUISE_PATH', 'disguise.path', 'media-assets')).replace(/^\/+|\/+$/g, '');
const FAKE_STATUS = Number(cfgGet(cfg, 'disguise.fakeStatus', 404));
const FAKE_SERVER = String(cfgGet(cfg, 'disguise.fakeServer', 'nginx'));
const FAKE_BODY_FILE = cfgGet(cfg, 'disguise.fakeBodyFile', '');

/* ---- 鉴权（仅用户名头 + 密码头；凭据优先从 .env / 环境变量取） ---- */
const AUTH_USER = String(envGet('PROXY_AUTH_USERNAME', 'auth.username', ''));
const AUTH_PASS = String(envGet('PROXY_AUTH_PASSWORD', 'auth.password', ''));
const USER_HEADER = String(envGet('PROXY_AUTH_USER_HEADER', 'auth.userHeader', 'X-Proxy-User')).toLowerCase();
const PASS_HEADER = String(envGet('PROXY_AUTH_PASS_HEADER', 'auth.passHeader', 'X-Proxy-Pass')).toLowerCase();

const UPSTREAM_TIMEOUT = Number(cfgGet(cfg, 'timeouts.upstreamMs', 30000));
const UPSTREAM_REJECT_UNAUTHORIZED = cfgGet(cfg, 'tls.upstreamRejectUnauthorized', true) !== false;
LOG_LEVEL = String(envGet('PROXY_LOG_LEVEL', 'logLevel', 'warn'));

/* ---- 内容与 Cookie 策略 ---- */
const BLOCK_HTML = cfgGet(cfg, 'disguise.blockHtml', true) !== false;    // 绝不反代网页：HTML 响应拦截为伪装页
const COOKIE_REWRITE = cfgGet(cfg, 'cookies.rewrite', true) !== false;   // Set-Cookie 剥 Domain、Path 收敛到反代路径

/* ---- 升级通道（WebSocket / 裸 TCP 隧道）空闲超时 ---- */
const WS_IDLE_MS = Number(cfgGet(cfg, 'timeouts.wsIdleMs', 300000)) || 300000;
const TUNNEL_IDLE_MS = Number(cfgGet(cfg, 'timeouts.tunnelIdleMs', 300000)) || 300000;
// 媒体大文件下载友好：响应开始后放宽空闲超时（Range/续传/慢速客户端不被中途切断）
const STREAM_IDLE_MS = Number(cfgGet(cfg, 'timeouts.streamIdleMs', 120000)) || 120000;

/* ============================ 上游出口（可选：WARP / HTTP CONNECT / SOCKS5 代理） ============================
 * upstreamProxy（或 PROXY_UPSTREAM_PROXY）：如 socks5://127.0.0.1:40000（Cloudflare WARP 代理模式）、
 * http://127.0.0.1:1080（sing-box / clash 等），可带 user:pass@。
 * 配置后所有上游流量（API 反代 / WS 反代 / 裸 TCP 隧道 / 媒体 CDN）统一经该代理出站；
 * 回环目标（127.x / localhost）始终直连。
 * ===================================================================== */
const UPSTREAM_PROXY_RAW = String(envGet('PROXY_UPSTREAM_PROXY', 'upstreamProxy', ''));

const EGRESS = parseEgressProxy(UPSTREAM_PROXY_RAW);
logSecrets.push(AUTH_PASS, UPSTREAM_PROXY_RAW, EGRESS?.pass);
const connectEgress = createConnector(EGRESS, { timeout: UPSTREAM_TIMEOUT, rejectUnauthorized: UPSTREAM_REJECT_UNAUTHORIZED });

/* ============================ 安全加固 ============================ */

// 密码至少 8 个 Unicode 字符，且不能是纯数字。
if (!AUTH_USER || !AUTH_PASS) {
  log('error', '未配置鉴权凭据，拒绝启动。请复制 .env.example 为 .env 并填写（scripts/gen-env.js 一键生成强随机凭据），' +
    '或在 config.json 的 auth 中设置。');
  process.exit(1);
}
if ([...AUTH_PASS].length < 8 || /^\p{N}+$/u.test(AUTH_PASS)) {
  log('error', 'auth.password 必须至少 8 个字符，且不能是纯数字。');
  process.exit(1);
}
if (DISGUISE === 'media-assets') {
  log('warn', 'disguise.path 为默认值 media-assets，正式部署请修改（推荐放 .env：PROXY_DISGUISE_PATH）');
}

// TLS 最低版本（更旧的握手直接失败）
const TLS_MIN_VERSION = String(cfgGet(cfg, 'tls.minVersion', 'TLSv1.2'));
if (!['TLSv1.2', 'TLSv1.3'].includes(TLS_MIN_VERSION)) throw new Error('tls.minVersion must be TLSv1.2 or TLSv1.3');
if (!/^[a-zA-Z0-9_-]{1,128}$/.test(DISGUISE)) throw new Error('Invalid disguise.path');
for (const header of [USER_HEADER, PASS_HEADER]) http.validateHeaderName(header);
if (USER_HEADER === PASS_HEADER || [USER_HEADER, PASS_HEADER].some(h => ['host', 'connection', 'content-length', 'transfer-encoding', 'authorization', 'cookie', 'upgrade'].includes(h))) throw new Error('Invalid auth header configuration');
const TRUSTED_PROXIES = trustedProxyList(cfgGet(cfg, 'security.trustedProxies', []));
const REAL_IP_HEADER = String(cfgGet(cfg, 'security.realIpHeader', 'cf-connecting-ip')).toLowerCase();
if (!['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for'].includes(REAL_IP_HEADER)) throw new Error('Unsupported realIpHeader');
const MAX_UPGRADES = Number(cfgGet(cfg, 'limits.maxUpgradedConnections', 256));
const MAX_WS_FRAME_BYTES = Number(cfgGet(cfg, 'limits.maxWsFrameBytes', 1048576));
let activeUpgrades = 0;

// 并发连接上限（防句柄/内存耗尽）
const MAX_CONNECTIONS = Number(cfgGet(cfg, 'limits.maxConnections', 1024)) || 1024;

// 鉴权失败限速：窗口内失败 N 次封禁该 IP（fail-closed，响应仍是伪装页、不暴露原因）
const AUTH_FAIL_LIMIT = Number(cfgGet(cfg, 'security.authFailLimit', 10)) || 10;
const AUTH_FAIL_WINDOW_MS = Number(cfgGet(cfg, 'security.authFailWindowMs', 60000)) || 60000;
const AUTH_FAIL_BAN_MS = Number(cfgGet(cfg, 'security.authFailBanMs', 120000)) || 120000;

// 文件权限检查（POSIX）：凭据 / 私钥不应对同机其他用户可读
function warnFilePerms(file, label) {
  try {
    if (process.platform === 'win32') return;
    const mode = fs.statSync(file).mode & 0o777;
    if (mode & 0o007 || mode & 0o030) throw new Error(`${label} permissions must be 600 or 640`);
  } catch (err) { throw new Error(`Unsafe ${label} file: ${err.message}`); }
}
if (fs.existsSync(ENV_FILE)) warnFilePerms(ENV_FILE, '.env');

/* ============================ 白名单规则引擎 ============================
 * 规则类型：exact(精确) / suffix(含子域) / keyword(包含) / regexp(正则)
 * 来源：config.whitelist.domains（支持 *.x）+ whitelist.files + whitelist.geosite
 * 默认放行配置的 Spotify API 与媒体域名，其余目标拒绝（404 伪装页）
 * ===================================================================== */

const RULES = makeRuleSet();

function makeRuleSet() { return { exact: new Set(), suffix: new Set(), keywords: [], regexps: [] }; }

function addRule(kind, value, rules = RULES) {
  const v = String(value || '').trim();
  if (!v) return;
  switch (kind) {
    case 'exact': rules.exact.add(v.toLowerCase()); break;
    case 'suffix': {
      const s = v.toLowerCase().replace(/^\./, '');
      rules.suffix.add(s);
      rules.exact.add(s);          // 后缀规则同时精确匹配自身
      break;
    }
    case 'keyword': rules.keywords.push(v.toLowerCase()); break;
    case 'regexp':
      try { rules.regexps.push(new RegExp(v, 'i')); }
      catch (e) { log('warn', `非法正则规则跳过: ${v}`); }
      break;
    case 'exactOnly': rules.exact.add(v.toLowerCase()); break;
  }
}

/** 解析一行规则（兼容 v2fly/mihomo geosite 语法 与 Clash/Surge 规则） */
function parseRuleLine(line, rules = RULES) {
  let s = String(line).trim();
  if (!s || s.startsWith('#') || s.startsWith('//') || s.startsWith(';')) return;
  s = s.replace(/^-\s+/, '').replace(/^['"]|['"]$/g, '').trim();   // yaml 列表项 / 引号
  if (!s || s.startsWith('#')) return;

  // Clash/Surge: DOMAIN,x / DOMAIN-SUFFIX,x / DOMAIN-KEYWORD,x / DOMAIN-REGEX,x
  const cs = /^(DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN-REGEX|DOMAIN|IP-CIDR|GEOIP|PROCESS-NAME)\s*,\s*(.+)$/i.exec(s);
  if (cs) {
    const kind = cs[1].toUpperCase();
    const val = cs[2].split(',')[0].trim();
    if (kind === 'DOMAIN-SUFFIX') return addRule('suffix', val, rules);
    if (kind === 'DOMAIN') return addRule('exactOnly', val, rules);
    if (kind === 'DOMAIN-KEYWORD') return addRule('keyword', val, rules);
    if (kind === 'DOMAIN-REGEX') return addRule('regexp', val, rules);
    return; // IP-CIDR / GEOIP 等不适用于域名白名单
  }

  // v2fly geosite 语法: domain: / full: / keyword: / regexp: / geosite:
  const m = /^(domain|full|keyword|regexp|regex|geosite|geolocation-!cn)\s*:\s*(.+)$/i.exec(s);
  if (m) {
    const kind = m[1].toLowerCase();
    const val = m[2].trim();
    if (kind === 'domain') return addRule('suffix', val, rules);
    if (kind === 'full') return addRule('exactOnly', val, rules);
    if (kind === 'keyword') return addRule('keyword', val, rules);
    if (kind === 'regexp' || kind === 'regex') return addRule('regexp', val, rules);
    return log('warn', `规则 "${s}" 需要 geosite 数据源，请用 scripts/fetch-geosite.js 提取后放入文件`);
  }

  // 裸域名（支持 *.x）
  if (s.startsWith('*.')) return addRule('suffix', s.slice(2), rules);
  addRule('suffix', s, rules);
}

function loadRuleFile(file) {
  const p = path.resolve(BASE_DIR, file);
  if (!fs.existsSync(p)) return log('warn', `白名单文件不存在: ${p}`);
  let n = 0;
  for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
    const before = RULES.exact.size + RULES.suffix.size + RULES.keywords.length + RULES.regexps.length;
    parseRuleLine(line);
    if (RULES.exact.size + RULES.suffix.size + RULES.keywords.length + RULES.regexps.length > before) n++;
  }
  log('info', `白名单文件 ${file}: 载入 ${n} 条规则`);
}

// 1) config 中的 domains（裸域名 / *.x / domain: / full: / keyword: / regexp: 语法均可）
for (const raw of cfgGet(cfg, 'whitelist.domains', ['api.spotify.com'])) parseRuleLine(raw, RULES);
for (const raw of cfgGet(cfg, 'whitelist.exactOnly', [])) addRule('exactOnly', raw, RULES);

// 2) 规则文件（mihomo geosite 导出文本 / 自定义）
for (const f of cfgGet(cfg, 'whitelist.files', [])) loadRuleFile(f);

// 3) 直接读 geosite.dat（mihomo 数据源）
const GEOSITE_FILE = cfgGet(cfg, 'whitelist.geosite.file', null);
if (GEOSITE_FILE) {
  const gp = path.resolve(BASE_DIR, GEOSITE_FILE);
  if (fs.existsSync(gp)) {
    const { parseGeosite } = require('./lib/geosite');
    const map = parseGeosite(fs.readFileSync(gp));
    for (const cat of cfgGet(cfg, 'whitelist.geosite.categories', ['spotify'])) {
      const rules = map.get(String(cat).toLowerCase());
      if (!rules) { log('warn', `geosite 中没有分类 "${cat}"`); continue; }
      for (const r of rules) {
        if (!r.value || r.value.startsWith('geosite:')) continue;
        if (r.type === 'full') addRule('exactOnly', r.value);
        else if (r.type === 'keyword') addRule('keyword', r.value);
        else if (r.type === 'regexp') addRule('regexp', r.value);
        else addRule('suffix', r.value);
      }
      log('info', `geosite:${cat} 载入 ${rules.length} 条规则（${GEOSITE_FILE}）`);
    }
  } else {
    log('warn', `geosite 文件不存在: ${gp}（可运行 node scripts/fetch-geosite.js 下载）`);
  }
}

const ALLOW_PORTS = !!cfgGet(cfg, 'whitelist.allowPorts', false);
const ALLOW_IP_TARGETS = !!cfgGet(cfg, 'whitelist.allowIpTargets', false);

/* ---- 裸 TCP 隧道（接入点 Shannon 协议）：独立白名单，默认仅接入点域名 + 固定端口 ---- */
const TUNNEL_ENABLED = cfgGet(cfg, 'tunnel.enabled', true) !== false;
const TUNNEL_PORTS = new Set(
  [].concat(cfgGet(cfg, 'tunnel.allowedPorts', [4070, 443, 80]))
    .map(Number).filter(n => n > 0 && n <= 65535)
);
const TUNNEL_RULES = makeRuleSet();
const tunnelHosts = [].concat(cfgGet(cfg, 'tunnel.hosts', []));
if (tunnelHosts.length) {
  for (const line of tunnelHosts) parseRuleLine(line, TUNNEL_RULES);
} else {
  // apresolve 返回的接入点主机名（实测形态：ap-gae2.spotify.com / ap-hose1.spotify.com / *.ap.spotify.com）
  addRule('regexp', '^ap(-[a-z0-9]+)?(\\.[a-z0-9-]+)*\\.spotify\\.com$', TUNNEL_RULES);
  addRule('regexp', '^[a-z0-9-]*accesspoint[a-z0-9-]*(\\.[a-z0-9-]+)*\\.spotify\\.com$', TUNNEL_RULES);
  addRule('suffix', 'ap.spotify.com', TUNNEL_RULES);
}

function isAllowedHost(host, rules = RULES) {
  if (!host) return false;
  host = host.toLowerCase();
  if (rules.exact.has(host)) return true;
  for (let s = host; s.includes('.');) {
    s = s.slice(s.indexOf('.') + 1);
    if (rules.suffix.has(s)) return true;
  }
  for (const k of rules.keywords) if (host.includes(k)) return true;
  for (const r of rules.regexps) if (r.test(host)) return true;
  return false;
}

const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
function validHost(host) { return host.length <= 253 && HOST_RE.test(host) && host.split('.').every(label => label.length <= 63); }

/* ============================ 鉴权（仅用户名头 + 密码头） ============================ */

const timingSafeEqualStr = equalSecret;

/**
 * 校验请求鉴权：只认用户名头 + 密码头，其余方式（session/Cookie/query/Basic/网页登录）一律不支持。
 * 头部缺失或校验失败 → 拒绝（fail-closed，返回 404 伪装页）。调用方负责裁剪相关头。
 */
function checkAuth(req) {
  const hUser = req.headers[USER_HEADER];
  const hPass = req.headers[PASS_HEADER];
  if (hUser === undefined && hPass === undefined) {
    return { ok: false, reason: '缺少用户名/密码头' };
  }
  const userOk = timingSafeEqualStr(hUser, AUTH_USER);
  const passOk = timingSafeEqualStr(hPass, AUTH_PASS);
  if (userOk && passOk) {
    return { ok: true, method: 'userpass' };
  }
  return { ok: false, reason: '用户名/密码头错误' };
}

/* ---- 鉴权失败限速（按 IP；封禁期内一律伪装页，不区分原因） ---- */
const authFails = new Map();
let failureWindow = { start: Date.now(), count: 0 };
const GLOBAL_FAIL_LIMIT = Number(cfgGet(cfg, 'security.globalAuthFailLimit', 1000));
function checkAuthLimited(req) {
  const now = Date.now();
  const ip = clientIp(req, TRUSTED_PROXIES, REAL_IP_HEADER);
  const result = checkAuth(req);
  // A distributed password attack must not lock out clients with valid credentials.
  if (result.ok) return result;
  if (now - failureWindow.start >= AUTH_FAIL_WINDOW_MS) failureWindow = { start: now, count: 0 };
  if (++failureWindow.count > GLOBAL_FAIL_LIMIT) return { ok: false, reason: 'global-rate-limited' };
  let rec = authFails.get(ip);
  if (rec?.bannedUntil > now) return { ok: false, reason: 'rate-limited' };
  if (!rec || rec.bannedUntil || now - rec.firstAt > AUTH_FAIL_WINDOW_MS) rec = { count: 0, firstAt: now, bannedUntil: 0 };
  if (++rec.count >= AUTH_FAIL_LIMIT) rec.bannedUntil = now + AUTH_FAIL_BAN_MS;
  if (authFails.size >= 4096 && !authFails.has(ip)) {
    for (const [key, entry] of authFails) if (entry.bannedUntil <= now && now - entry.firstAt > AUTH_FAIL_WINDOW_MS) authFails.delete(key);
    if (authFails.size >= 4096) return { ok: false, reason: 'rate-limit-capacity' };
  }
  authFails.set(ip, rec);
  return result;
}

/* ============================ URL / 目标解析 ============================ */

/**
 * /<伪装路径>/<目标域名>[/路径][?query] → { host, port, upstreamPath }
 */
function parseTarget(reqUrl) {
  const u = reqUrl || '/';
  if (u.length > 16384 || !u.startsWith('/') || /[\x00-\x20\x7f]/.test(u)) return { error: 'bad-url' };
  const qi = u.indexOf('?');
  const pathname = qi < 0 ? u : u.slice(0, qi);
  const query = qi < 0 ? '' : u.slice(qi + 1);

  const segs = pathname.split('/'); // ['', disguise, host, ...rest]
  if (segs.length < 3 || segs[1] !== DISGUISE) return { error: 'bad-disguise' };

  let hostPart;
  try { hostPart = decodeURIComponent(segs[2]); } catch { return { error: 'bad-encoding' }; }
  const hostSegment = hostPart.toLowerCase();   // 客户端 URL 里的原始域名段（含 :port，Cookie Path 收敛用）
  let port = 443;
  const mi = hostPart.lastIndexOf(':');
  if (mi > 0 && /^\d+$/.test(hostPart.slice(mi + 1))) {
    port = Number(hostPart.slice(mi + 1));
    hostPart = hostPart.slice(0, mi);
    if (!ALLOW_PORTS) return { error: 'port-not-allowed' };
  }
  const host = hostPart.toLowerCase();

  if (net.isIP(host) && !ALLOW_IP_TARGETS) return { error: 'ip-not-allowed' };
  if (!validHost(host)) return { error: 'bad-host' };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: 'bad-port' };
  const rest = segs.slice(3).join('/');
  // Android Widevine 首次设备 provisioning；只放行具体 API，不开放整个 Google 域。
  const provisioning = port === 443 && (
    host === 'www.googleapis.com' && rest === 'certificateprovisioning/v1/devicecertificates/create' ||
    host === 'provisioning.googleapis.com' && rest === 'v1/devicecertificates/create'
  );
  const webTokenApi = port === 443 && (
    host === 'open.spotify.com' && ['api/token', 'api/server-time'].includes(rest) ||
    host === 'accounts.spotify.com' && rest === 'api/token'
  );
  if (!isAllowedHost(host) && !provisioning && !webTokenApi) return { error: 'host-not-allowed' };
  return {
    host,
    port,
    hostSegment,
    upstreamPath: '/' + rest + (query ? '?' + query : '')
  };
}

/* ============================ 转发 ============================ */

// 这些响应头可能泄露真实域名或引导客户端绕过反代，剥掉
const STRIP_RESP_HEADERS = new Set(['alt-svc']);

/** 永远裁剪掉本反代自己的鉴权头，凭据绝不泄漏给上游 */
const AUTH_STRIP_HEADERS = new Set([USER_HEADER, PASS_HEADER, 'x-proxy-session', 'x-proxy-auth', 'proxy-authorization']);

function buildUpstreamHeaders(req, target) {
  const headers = stripHeaders(req.headers, { strip: AUTH_STRIP_HEADERS, request: true });
  headers.host = target.host + (target.port !== 443 ? ':' + target.port : '');
  return headers;
}

function buildResponseHeaders(input, target) {
  const headers = stripHeaders(input, { strip: STRIP_RESP_HEADERS });
  if (COOKIE_REWRITE && headers['set-cookie']) headers['set-cookie'] = [].concat(headers['set-cookie']).map(c => rewriteSetCookie(c, target));
  return headers;
}

function handleRequest(req, res) {
  const pathname = ((req.url || '/').split('?')[0]);
  const segs = pathname.split('/');

  // 伪装：路径不含正确的伪装路径 → 返回伪装页（不暴露任何信息）
  if (segs[1] !== DISGUISE) {
    log('debug', `${req.method} ${req.url} → 伪装页`);
    return fakePage(res);
  }

  // 鉴权（仅用户名头 + 密码头；内部接口同样要求）
  // 校验失败 / 目标被拒统一返回 404 伪装页，不细分原因、不暴露细节
  const authInfo = checkAuthLimited(req);
  if (!authInfo.ok) {
    log('info', `鉴权失败(${authInfo.reason}) ${req.method} ${req.url} [${req.socket.remoteAddress}]`);
    return fakePage(res);
  }

  // 内部接口：健康检查（其余内部接口如 __login/__session 已移除）
  if (segs[2] === '__ping') {
    const body = JSON.stringify({ ok: true });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    return res.end(body);
  }

  const target = parseTarget(req.url);
  if (target.error) {
    log('warn', `目标被拒绝(${target.error}) ${req.method} ${req.url}`);
    return fakePage(res);
  }

  const headers = buildUpstreamHeaders(req, target);
  const opts = {
    hostname: target.host,
    port: target.port,
    path: target.upstreamPath,
    method: req.method,
    headers,
    agent: upstreamAgent,
    servername: target.host,
    rejectUnauthorized: UPSTREAM_REJECT_UNAUTHORIZED,
    timeout: UPSTREAM_TIMEOUT
  };

  log('info', `${req.method} https://${target.host}${target.upstreamPath}`);

  const upReq = https.request(opts, upRes => {
    // 响应开始后放宽空闲超时：媒体大文件（音频/视频）Range / 慢速客户端不被中途切断
    if (upRes.socket) upRes.socket.setTimeout(STREAM_IDLE_MS);
    res.on('close', () => upRes.destroy());
    forwardResponse(req, res, upRes, target);
  });

  upReq.on('timeout', () => upReq.destroy(new Error('upstream timeout')));
  upReq.on('error', err => {
    log('error', `上游错误 https://${target.host}${target.upstreamPath}: ${err.message}`);
    if (res.headersSent) return res.destroy();
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad Gateway');
  });

  req.pipe(upReq);
  req.on('error', () => upReq.destroy());
  req.on('aborted', () => upReq.destroy());
  res.on('close', () => upReq.destroy());
}

/** 响应流式透传（API 无内容改写；仅按策略拦截 HTML、收敛 Set-Cookie 域/路径） */
function forwardResponse(req, res, upRes, target) {
  const status = upRes.statusCode || 502;
  const ctype = String(upRes.headers['content-type'] || '');

  // 绝不反代出网页：HTML 响应一律按伪装页处理（fail-closed，不区分原因）
  if (BLOCK_HTML && /^\s*(text\/html|application\/xhtml)/i.test(ctype)) {
    log('warn', `拦截 HTML 响应 https://${target.host}${target.upstreamPath} (${ctype})`);
    upRes.destroy();
    return fakePage(res);
  }

  log('info', `← ${status} https://${target.host}${target.upstreamPath} (${upRes.headers['content-type'] || '-'})`);

  const rawHeaders = buildResponseHeaders(upRes.headers, target);

  res.writeHead(status, rawHeaders);
  if (status === 204 || status === 304 || req.method === 'HEAD') return res.end();
  upRes.on('aborted', () => res.destroy());
  upRes.pipe(res);

  upRes.on('error', err => {
    log('error', `上游响应错误: ${err.message}`);
    res.destroy();
  });
}

/**
 * Set-Cookie 收敛到反代域名：剥掉 Domain（变成反代域的 host-only cookie），
 * Path 收敛为 /<伪装路径>/<上游域名段>[原 Path]，同一反代域名下不同上游的 cookie 互不串。
 */
function rewriteSetCookie(value, target) {
  const parts = String(value).split(';');
  const nameValue = parts.shift();
  const attrs = [];
  let cookiePath = '';
  for (const raw of parts) {
    const t = raw.trim();
    const eq = t.indexOf('=');
    const k = (eq < 0 ? t : t.slice(0, eq)).trim().toLowerCase();
    if (k === 'domain') continue;                       // 剥掉 Domain → 落在反代域名
    if (k === 'path') { cookiePath = eq < 0 ? '/' : t.slice(eq + 1).trim(); continue; }
    attrs.push(t);
  }
  const prefix = `/${DISGUISE}/${target.hostSegment}`;
  const scoped = (!cookiePath || cookiePath === '/') ? prefix : prefix + (cookiePath.startsWith('/') ? cookiePath : '/' + cookiePath);
  return [nameValue, ...attrs, `Path=${scoped}`].join('; ');
}

/* ============================ 升级通道（WebSocket / 裸 TCP 隧道） ============================
 * 同一伪装路径 + 同一头鉴权，失败一律 404 伪装页（与普通请求完全一致）：
 *   - 非 __tunnel 路径：按 WebSocket 反代处理（目标白名单与反代共用，握手与帧字节原样双向转发）
 *   - /<伪装路径>/__tunnel/<host>:<port>：裸 TCP 隧道（接入点 Shannon 协议），
 *     仅放行 tunnel.hosts + tunnel.allowedPorts
 * ===================================================================== */

function handleUpgrade(req, socket, head) {
  socket.on('error', () => { });
  socket.pause();
  socket.setTimeout(UPSTREAM_TIMEOUT, () => socket.destroy());
  const upgrade = String(req.headers.upgrade || '').toLowerCase();
  if (req.method !== 'GET' || !['websocket', 'tcp-tunnel'].includes(upgrade) || req.headers['transfer-encoding'] || Number(req.headers['content-length'] || 0) !== 0) return fakePageRaw(socket);
  if (upgrade === 'websocket' && (req.headers['sec-websocket-version'] !== '13' || !/^[A-Za-z0-9+/]{22}==$/.test(String(req.headers['sec-websocket-key'] || '')))) return fakePageRaw(socket);
  if (activeUpgrades >= MAX_UPGRADES) return fakePageRaw(socket);
  activeUpgrades++;
  socket.once('close', () => activeUpgrades--);
  const pathname = ((req.url || '/').split('?')[0]);
  const segs = pathname.split('/');

  if (segs[1] !== DISGUISE) {
    log('debug', 'UPGRADE 伪装路径错误 → 伪装页');
    return fakePageRaw(socket);
  }

  const authInfo = checkAuthLimited(req);
  if (!authInfo.ok) {
    log('info', `鉴权失败(${authInfo.reason}) UPGRADE ${req.url} [${req.socket.remoteAddress}]`);
    return fakePageRaw(socket);
  }

  if (segs[2] === '__tunnel') return openTunnel(req, socket, segs.slice(3).join('/'), head);
  if (upgrade !== 'websocket') return fakePageRaw(socket);
  openWebSocket(req, socket, head);
}

/** 裸 TCP 隧道：GET /<伪装路径>/__tunnel/<host>:<port> + Connection: Upgrade
 *  - Upgrade: tcp-tunnel → 200 Connection Established 后裸双向管道（直连场景）
 *  - Upgrade: websocket  → 101 WebSocket，原始字节装在 WS 二进制帧里收发
 *    （CF 等 CDN 只透传 websocket 升级、丢弃任意 Upgrade，走 CDN 必须用此模式）
 */
function openTunnel(req, socket, hostPort, head) {
  const wsMode = String(req.headers['upgrade'] || '').toLowerCase() === 'websocket';
  if (!TUNNEL_ENABLED) {
    log('warn', '隧道已禁用 → 伪装页');
    return fakePageRaw(socket);
  }
  const qi = hostPort.indexOf('?');
  if (qi >= 0) hostPort = hostPort.slice(0, qi);

  let host = hostPort;
  let port = 443;
  const mi = hostPort.lastIndexOf(':');
  if (mi > 0 && /^\d+$/.test(hostPort.slice(mi + 1))) {
    port = Number(hostPort.slice(mi + 1));
    host = hostPort.slice(0, mi);
  } else {
    log('warn', `隧道目标缺端口 → 伪装页: ${hostPort}`);
    return fakePageRaw(socket);
  }
  try { host = decodeURIComponent(host).toLowerCase(); } catch { return fakePageRaw(socket); }

  if (net.isIP(host) && !ALLOW_IP_TARGETS) return fakePageRaw(socket);
  if (!validHost(host) || !Number.isInteger(port) || port < 1 || port > 65535) return fakePageRaw(socket);
  if (!TUNNEL_PORTS.has(port)) {
    log('warn', `隧道端口被拒绝: ${host}:${port}`);
    return fakePageRaw(socket);
  }
  if (!isAllowedHost(host, TUNNEL_RULES)) {
    log('warn', `隧道目标被拒绝: ${host}:${port}`);
    return fakePageRaw(socket);
  }

  log('info', `TUNNEL → ${host}:${port}${wsMode ? ' (ws)' : ''}${EGRESS ? ' via-proxy' : ''}`);
  let up = null;
  const destroyPair = () => {
    try { if (up) up.destroy(); } catch (_) { }
    try { socket.destroy(); } catch (_) { }
  };
  socket.setTimeout(TUNNEL_IDLE_MS, destroyPair);
  socket.on('close', () => { try { if (up) up.destroy(); } catch (_) { } });

  const pending = connectEgress(host, port, (err, upSock) => {
    if (err || socket.destroyed) {
      upSock?.destroy();
      log('error', `隧道上游错误 ${host}:${port}: ${err ? err.message : '客户端已断开'}`);
      return destroyPair();
    }
    up = upSock;
    up.setTimeout(TUNNEL_IDLE_MS, destroyPair);
    up.on('error', e => {
      log('error', `隧道上游错误 ${host}:${port}: ${e.message}`);
      destroyPair();
    });
    up.on('close', () => { try { socket.destroy(); } catch (_) { } });
    try {
      if (wsMode) {
        const key = String(req.headers['sec-websocket-key'] || '');
        const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
        socket.write(
          'HTTP/1.1 101 Switching Protocols\r\n' +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
        pipeWsStream(socket, up, head, MAX_WS_FRAME_BYTES);
      } else {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) socket.unshift(head);
        socket.pipe(up);
        up.pipe(socket);
      }
    } catch (e) {
      log('error', `隧道转发错误 ${host}:${port}: ${e.message}`);
      destroyPair();
    }
  });
  socket.once('close', () => pending.destroy());
}

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';



/** WebSocket 反代：握手与帧字节原样双向转发（ping/pong、扩展、压缩全部透明） */
function openWebSocket(req, socket, head) {
  const target = parseTarget(req.url);
  if (target.error) {
    log('warn', `WS 目标被拒绝(${target.error}) ${req.url}`);
    return fakePageRaw(socket);
  }

  const headers = buildUpstreamHeaders(req, target);
  headers.connection = 'Upgrade'; headers.upgrade = 'websocket';
  const upReq = https.request({ hostname: target.host, port: target.port, path: target.upstreamPath, method: 'GET', headers, agent: upstreamAgent, rejectUnauthorized: UPSTREAM_REJECT_UNAUTHORIZED, timeout: UPSTREAM_TIMEOUT });
  const timer = setTimeout(() => { upReq.destroy(); socket.destroy(); }, UPSTREAM_TIMEOUT);
  socket.once('close', () => { clearTimeout(timer); upReq.destroy(); });
  upReq.on('timeout', () => upReq.destroy(new Error('WebSocket handshake timeout')));
  upReq.on('error', () => { clearTimeout(timer); socket.destroy(); });
  upReq.on('response', upRes => { clearTimeout(timer); upRes.destroy(); fakePageRaw(socket); });
  upReq.on('upgrade', (upRes, up, upHead) => {
    clearTimeout(timer);
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + WS_GUID).digest('base64');
    if (socket.destroyed || upRes.statusCode !== 101 || String(upRes.headers.upgrade).toLowerCase() !== 'websocket' || upRes.headers['sec-websocket-accept'] !== accept || (BLOCK_HTML && /^\s*(text\/html|application\/xhtml)/i.test(upRes.headers['content-type'] || ''))) {
      up.destroy(); return fakePageRaw(socket);
    }
    const responseHeaders = buildResponseHeaders(upRes.headers, target);
    responseHeaders.connection = 'Upgrade'; responseHeaders.upgrade = 'websocket';
    delete responseHeaders['content-length'];
    let response = 'HTTP/1.1 101 Switching Protocols\r\n';
    for (const [key, value] of Object.entries(responseHeaders)) for (const item of [].concat(value)) response += key + ': ' + item + '\r\n';
    socket.write(response + '\r\n');
    const stop = () => { socket.destroy(); up.destroy(); };
    socket.on('close', stop); up.on('close', stop); up.on('error', stop);
    socket.setTimeout(WS_IDLE_MS, stop); up.setTimeout(WS_IDLE_MS, stop);
    if (head?.length) socket.unshift(head);
    if (upHead?.length) up.unshift(upHead);
    socket.pipe(up); up.pipe(socket);
  });
  upReq.end();
}



/* ============================ 伪装页 ============================ */

let FAKE_BODY_CACHE = null;
function fakeBody() {
  if (FAKE_BODY_CACHE === null) {
    if (FAKE_BODY_FILE && fs.existsSync(path.resolve(BASE_DIR, FAKE_BODY_FILE))) {
      FAKE_BODY_CACHE = fs.readFileSync(path.resolve(BASE_DIR, FAKE_BODY_FILE));
    } else {
      FAKE_BODY_CACHE = Buffer.from(
        '<html>\n<head><title>404 Not Found</title></head>\n' +
        '<body>\n<center><h1>404 Not Found</h1></center>\n<hr><center>' +
        FAKE_SERVER + '</center>\n</body>\n</html>\n', 'utf8');
    }
  }
  return FAKE_BODY_CACHE;
}

function fakePage(res, extraHeaders) {
  const body = fakeBody();
  res.writeHead(FAKE_STATUS, Object.assign({
    'Server': FAKE_SERVER,
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': body.length
  }, extraHeaders || {}));
  res.end(body);
}

/** 裸 socket（WebSocket / 隧道升级）上的伪装页：与 HTTP 响应完全一致后关连接 */
function fakePageRaw(socket) {
  const body = fakeBody();
  try {
    socket.write(
      `HTTP/1.1 ${FAKE_STATUS} ${FAKE_STATUS === 404 ? 'Not Found' : 'Error'}\r\n` +
      `Server: ${FAKE_SERVER}\r\n` +
      `Content-Type: text/html; charset=utf-8\r\n` +
      `Content-Length: ${body.length}\r\n` +
      `Connection: close\r\n\r\n`);
    socket.end(body);
  } catch (_) { try { socket.destroy(); } catch (_) { } }
}

/* ============================ 启动 ============================ */

/** 上游 HTTPS Agent：配置 upstreamProxy 时所有 API/媒体连接经代理隧道建立（回环直连） */
function makeEgressAgent() {
  const agent = new https.Agent({ keepAlive: true, maxSockets: Number(cfgGet(cfg, 'limits.maxSockets', 64)), maxTotalSockets: Number(cfgGet(cfg, 'limits.maxTotalSockets', 256)), maxFreeSockets: Number(cfgGet(cfg, 'limits.maxFreeSockets', 16)), keepAliveMsecs: Number(cfgGet(cfg, 'timeouts.keepAliveMsecs', 1000)), minVersion: TLS_MIN_VERSION });
  agent.createConnection = (options, callback) => {
    const host = options.servername || options.host || options.hostname;
    connectEgress(host, Number(options.port) || 443, (err, raw) => {
      if (err) return callback(err);
      let finished = false;
      const tlsSock = tls.connect({ socket: raw, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: UPSTREAM_REJECT_UNAUTHORIZED, minVersion: TLS_MIN_VERSION });
      const finish = error => { if (finished) return; finished = true; clearTimeout(timer); if (error) tlsSock.destroy(); callback(error, error ? undefined : tlsSock); };
      const timer = setTimeout(() => finish(new Error('Upstream TLS handshake timeout')), UPSTREAM_TIMEOUT);
      tlsSock.once('secureConnect', () => finish(null));
      tlsSock.on('error', finish);
      tlsSock.once('close', () => finish(new Error('Upstream TLS closed during handshake')));
    });
    return undefined;
  };
  return agent;
}

const upstreamAgent = makeEgressAgent();

function loadTls() {
  const keyPath = path.resolve(BASE_DIR, envGet('PROXY_TLS_KEY', 'tls.key', 'cert/server.key'));
  const certPath = path.resolve(BASE_DIR, envGet('PROXY_TLS_CERT', 'tls.cert', 'cert/server.crt'));
  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    log('error', `找不到 TLS 证书：${keyPath} / ${certPath}`);
    log('error', '请先执行 scripts/gen-cert.sh（或 gen-cert.ps1）生成自签证书，或在 config.json 指定你的证书。');
    process.exit(1);
  }
  warnFilePerms(keyPath, 'TLS 私钥');
  return {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
    passphrase: envGet('PROXY_TLS_PASSPHRASE', 'tls.passphrase', null) || undefined
  };
}

const server = https.createServer({ ...loadTls(), minVersion: TLS_MIN_VERSION, ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305', honorCipherOrder: true, sessionTimeout: 300, maxHeaderSize: 16384 }, handleRequest);
const sockets = new Set();
function configureServer(instance) {
  instance.headersTimeout = Number(cfgGet(cfg, 'timeouts.headersMs', 15000));
  instance.requestTimeout = Number(cfgGet(cfg, 'timeouts.requestMs', 60000));
  instance.keepAliveTimeout = Number(cfgGet(cfg, 'timeouts.keepAliveMs', 5000));
  instance.maxRequestsPerSocket = 1000;
  instance.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
}
configureServer(server);
server.maxConnections = MAX_CONNECTIONS;
server.on('error', err => {
  log('error', `监听失败 ${LISTEN_HOST}:${LISTEN_PORT}: ${err.message}`);
  process.exit(1);   // 端口冲突等致命错误直接退出，交给 systemd/守护进程重启，不僵活着
});
server.on('upgrade', handleUpgrade);
server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (_) { }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  const ruleCount = RULES.exact.size + RULES.suffix.size + RULES.keywords.length + RULES.regexps.length;
  const tunnelRuleCount = TUNNEL_RULES.exact.size + TUNNEL_RULES.suffix.size + TUNNEL_RULES.keywords.length + TUNNEL_RULES.regexps.length;
  log('info', `====================================================`);
  log('info', ` FlutifyPS HTTPS 反向代理已启动（用户名头+密码头鉴权）`);
  log('info', ` 监听: https://${LISTEN_HOST}:${LISTEN_PORT}`);
  log('info', ` 伪装路径: /${DISGUISE}/<白名单域名>/<路径>`);
  log('info', ` 承载: HTTPS API/媒体反代 + WebSocket 反代 + TCP 隧道(/${DISGUISE}/__tunnel/<host>:<port>)`);
  log('info', ` 白名单规则: ${ruleCount} 条（exact=${RULES.exact.size} suffix=${RULES.suffix.size} keyword=${RULES.keywords.length} regexp=${RULES.regexps.length}）`);
  log('info', ` 隧道白名单: ${tunnelRuleCount} 条，端口 [${[...TUNNEL_PORTS].join(', ')}]${TUNNEL_ENABLED ? '' : '（已禁用）'}`);
  log('info', ` 内容策略: ${BLOCK_HTML ? '按 Content-Type 拦截 HTML' : '允许 HTML 透传'}；Set-Cookie ${COOKIE_REWRITE ? '收敛到反代路径' : '原样透传'}`);
  log('info', ` 鉴权头: ${USER_HEADER} + ${PASS_HEADER}`);
  log('info', `====================================================`);
});

let redirectServer;
if (HTTP_REDIRECT_PORT) {
  const origin = new URL(String(envGet('PROXY_PUBLIC_ORIGIN', 'listen.publicOrigin', '')));
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('listen.publicOrigin must be an HTTPS origin');
  redirectServer = http.createServer((req, res) => {
    if (!req.url?.startsWith('/') || req.url.startsWith('//') || /[\r\n\\]/.test(req.url)) return fakePage(res);
    res.writeHead(301, { Location: origin.origin + req.url }); res.end();
  });
  configureServer(redirectServer);
  redirectServer.maxConnections = MAX_CONNECTIONS;
  redirectServer.on('error', () => process.exit(1));
  redirectServer.listen(HTTP_REDIRECT_PORT, LISTEN_HOST);
}

let stopping = false;
function shutdown() {
  if (stopping) return;
  stopping = true;
  const timer = setTimeout(() => { for (const socket of sockets) socket.destroy(); upstreamAgent.destroy(); process.exit(0); }, Number(cfgGet(cfg, 'timeouts.shutdownMs', 10000)));
  timer.unref();
  redirectServer?.close(); redirectServer?.closeIdleConnections();
  server.close(() => { clearTimeout(timer); upstreamAgent.destroy(); process.exit(0); });
  server.closeIdleConnections();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);


process.on('uncaughtException', () => { log('error', 'Uncaught exception; exiting for supervisor restart'); process.exit(1); });
process.on('unhandledRejection', () => { log('error', 'Unhandled rejection; exiting for supervisor restart'); process.exit(1); });
