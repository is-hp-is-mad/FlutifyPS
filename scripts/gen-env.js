#!/usr/bin/env node
/**
 * 一键生成 .env（强随机鉴权凭据 + 伪装路径）。已存在则拒绝覆盖（--force 强制覆盖）。
 * 用法: node scripts/gen-env.js [--force]
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const FILE = path.join(ROOT, '.env');
const force = process.argv.includes('--force');

if (fs.existsSync(FILE) && !force) {
  console.error('.env 已存在。如需重新生成请加 --force（会轮换凭据，已接入的客户端需同步更新）。');
  process.exit(1);
}

const rnd = (n) => crypto.randomBytes(n).toString('hex');
const user = 'px_' + rnd(4);
const pass = crypto.randomBytes(24).toString('base64url');   // 32 字符 URL/HTTP 头安全字符
const disguise = 'assets-' + rnd(6);

const body = `# FlutifyPS 凭据 —— 勿提交、勿外传（chmod 600）
# 优先级：环境变量 > 本文件 > config.json
PROXY_AUTH_USERNAME=${user}
PROXY_AUTH_PASSWORD=${pass}

# 伪装路径（URL 首段，越随机越好；客户端接入时需要）
PROXY_DISGUISE_PATH=${disguise}

# ---- 可选覆盖（默认取 config.json）----
# PROXY_LISTEN_HOST=0.0.0.0
# PROXY_LISTEN_PORT=443
# PROXY_UPSTREAM_PROXY=socks5://127.0.0.1:40000
# PROXY_TLS_KEY=cert/server.key
# PROXY_TLS_CERT=cert/server.crt
# PROXY_TLS_PASSPHRASE=
# PROXY_AUTH_USER_HEADER=X-Proxy-User
# PROXY_AUTH_PASS_HEADER=X-Proxy-Pass
# PROXY_LOG_LEVEL=warn
`;

fs.writeFileSync(FILE, body, { mode: 0o600, flag: force ? 'w' : 'wx' });
try { fs.chmodSync(FILE, 0o600); } catch (_) { /* Windows 无 POSIX 权限位 */ }

console.log(`已生成 ${FILE}。请从该文件将凭据保存到密码管理器；终端不回显秘密。`);
