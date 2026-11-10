#!/usr/bin/env bash
# Gera .env com segredos aleatórios (nunca versionado). Idempotente: não sobrescreve.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { echo ".env já existe"; exit 0; }
rnd() { openssl rand -hex "${1:-24}"; }
umask 077
cat > .env <<EOT
UID=$(id -u)
GID=$(id -g)
# HMAC para pseudonimização de crachás (RT-19)
PSEUDO_KEY=$(rnd 32)
POSTGRES_PASSWORD=$(rnd)
DB_INGEST_PASSWORD=$(rnd)
DB_PAINEL_PASSWORD=$(rnd)
DB_PAINEL_VULN_PASSWORD=$(rnd)
FLASK_SECRET_KEY=$(rnd 32)
EOT
echo ".env criado"
