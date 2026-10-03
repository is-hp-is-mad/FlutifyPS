#!/usr/bin/env bash
# Local development certificate; production should use a trusted certificate.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
mkdir -p cert
cd cert
if [[ -e server.key || -e server.crt ]]; then
  echo "Certificate files already exist; refusing to overwrite." >&2
  exit 1
fi
SANS="${SANS:-DNS:localhost,IP:127.0.0.1,IP:::1}"
DAYS="${DAYS:-90}"
openssl req -config ../scripts/openssl.cnf -x509 -nodes -newkey rsa:2048 -sha256 \
  -keyout server.key -out server.crt -days "$DAYS" -subj '/CN=localhost' \
  -addext "subjectAltName=$SANS" -addext 'extendedKeyUsage=serverAuth'
chmod 600 server.key
echo 'Created cert/server.key and cert/server.crt for local development.'
