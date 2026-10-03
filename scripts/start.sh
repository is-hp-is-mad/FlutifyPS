#!/usr/bin/env bash
# 启动 FlutifyPS（Linux / macOS / WSL）；本地建议使用 8443。
set -euo pipefail
cd "$(dirname "$0")/.."
exec node server.js "$@"
