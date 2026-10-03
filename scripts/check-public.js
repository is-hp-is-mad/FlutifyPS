#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const allowed = new Set(require('./public-files.json'));
let files = [...allowed];
if (fs.existsSync(path.join(root, '.git'))) {
  files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
  if (!files.length) throw new Error('Stage the reviewed public files before checking the Git index');
}
const failures = [];
for (const file of files) {
  if (!allowed.has(file)) { failures.push(`${file}: outside public file allowlist`); continue; }
  const full = path.join(root, file);
  if (!fs.existsSync(full) || fs.lstatSync(full).isSymbolicLink()) { failures.push(`${file}: missing file or symlink`); continue; }
  const data = fs.readFileSync(full, 'utf8');
  const sensitive = [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, /\bgh[pousr]_[A-Za-z0-9]{30,}\b/, /github_pat_[A-Za-z0-9_]{30,}/];
  if (sensitive.some(re => re.test(data))) failures.push(`${file}: possible secret (value suppressed)`);
  if (/\u56fd\u5bb6(?!\/地区)/u.test(data)) failures.push(`${file}: use 国家/地区 in public wording`);
  if (file.endsWith('.md')) {
    for (const match of data.matchAll(/\]\(([^)]+)\)/g)) {
      const target = match[1].split('#')[0];
      if (!target || /^[a-z]+:/i.test(target)) continue;
      if (!fs.existsSync(path.resolve(path.dirname(full), target))) failures.push(`${file}: missing local link ${target}`);
    }
  }
}
for (const file of allowed) if (!files.includes(file)) failures.push(`${file}: missing from public file set`);
const config = JSON.parse(fs.readFileSync(path.join(root, 'config.json'), 'utf8'));
if (config.auth.username || config.auth.password || config.upstreamProxy || config.tls.passphrase || config.listen.publicOrigin) failures.push('config.json: deployment-specific values must remain empty');
if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
console.log(`Public source check passed: ${files.length} files. Review diffs separately before publishing.`);
