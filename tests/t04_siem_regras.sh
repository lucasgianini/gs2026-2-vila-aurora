#!/usr/bin/env bash
# E3 — valida cada regra de detecção com eventos de exemplo (wazuh-logtest). RT-13
set -uo pipefail
source "$(dirname "$0")/../scripts/lib.sh"; cd "$ROOT"
docker compose cp tests/siem_samples.txt siem:/tmp/s.txt >/dev/null 2>&1
exp=(100101 100112 100206 100202 100204 100300 100302 100403 100402 100010)
i=0
while IFS= read -r line; do
  out=$(printf '%s\n' "$line" | docker compose exec -T siem /var/ossec/bin/wazuh-logtest 2>&1)
  id=$(grep -oP "^\s+id: '\K\d+" <<<"$out" | tail -1); lvl=$(grep -oP "^\s+level: '\K\d+" <<<"$out" | tail -1)
  desc=$(grep -oP "^\s+description: '\K.*(?='$)" <<<"$out" | tail -1)
  check "regra ${exp[$i]} nível ${lvl:-?}: ${desc:0:90}" "${exp[$i]}" "${id:-nenhuma}"
  i=$((i+1))
done < tests/siem_samples.txt
echo "== Resultado: ${FAILS:-0} falha(s)"; exit "${FAILS:-0}"
