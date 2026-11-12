#!/usr/bin/env bash
# Mede o consumo de banda do nó de borda em MODO DEGRADADO (RT-03/RT-22): derruba a fibra de um
# espaço, coleta por N segundos com a borda no 4G e restabelece.  Uso: metrics/medir_4g.sh [site] [segundos]
set -euo pipefail
cd "$(dirname "$0")/.."
SITE="${1:-escola}"; SECS="${2:-300}"
trap 'docker compose exec -T "wg-$SITE" /opt/edge/link.sh fibra up >/dev/null' EXIT
docker compose exec -T "wg-$SITE" /opt/edge/link.sh fibra down >/dev/null
sleep 20   # tempo do failover
python3 metrics/collect.py "$SECS" 5 metrics-4g
