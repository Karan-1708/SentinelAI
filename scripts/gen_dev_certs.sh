#!/usr/bin/env bash
# Generate a self-signed cert for local nginx TLS and a dev htpasswd file.
# Requires openssl. Idempotent — safe to re-run.
set -euo pipefail

CERT_DIR="$(dirname "$0")/../docker/nginx/certs"
HTPASS="$(dirname "$0")/../docker/nginx/htpasswd"
mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/server.crt" || ! -f "$CERT_DIR/server.key" ]]; then
  openssl req -x509 -nodes \
    -newkey rsa:2048 \
    -days 365 \
    -keyout "$CERT_DIR/server.key" \
    -out    "$CERT_DIR/server.crt" \
    -subj   "/CN=sentinelai.local" \
    -addext "subjectAltName=DNS:localhost,DNS:sentinelai.local,IP:127.0.0.1"
  chmod 600 "$CERT_DIR/server.key"
  echo "Generated dev TLS at $CERT_DIR"
else
  echo "Dev TLS already present at $CERT_DIR (leaving as-is)"
fi

if [[ ! -f "$HTPASS" ]]; then
  # Default dev creds for /mlflow and /kibana. Change before any deployment.
  # apr1 hash format is understood by nginx auth_basic.
  echo 'admin:$apr1$devsalt$rWZKm3H3EpxfM5cS7d8w4/' > "$HTPASS"
  echo "Wrote dev htpasswd at $HTPASS (login: admin / dev)"
else
  echo "htpasswd already present at $HTPASS (leaving as-is)"
fi
