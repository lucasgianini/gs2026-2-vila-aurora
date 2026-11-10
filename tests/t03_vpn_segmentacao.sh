#!/usr/bin/env bash
# E3 — Evidências de VPN, segmentação, MFA de VPN e failover (RT-03, RT-06, RT-07)
set -uo pipefail
source "$(dirname "$0")/../scripts/lib.sh"; cd "$ROOT"
x() { docker compose exec -T "$1" sh -c "$2" 2>/dev/null | tail -1; }
echo "== Segmentação (origem: borda UBS)"
check "borda -> ingest pela WAN sem túnel"   "000" "$(x wg-ubs "curl -sk -m3 -o /dev/null -w '%{http_code}' https://172.30.10.2:8443/healthz")"
check "borda -> ingest pelo túnel"           "200" "$(x wg-ubs "curl -sk -m3 -o /dev/null -w '%{http_code}' https://10.80.0.1:8443/healthz")"
check "borda -> outra borda pelo túnel"      "000" "$(x wg-ubs "curl -s -m3 -o /dev/null -w '%{http_code}' http://10.80.0.12:8080/healthz")"
check "borda -> painel administrativo"       "000" "$(x wg-ubs "curl -sk -m3 -o /dev/null -w '%{http_code}' https://10.90.0.1/")"
check "borda -> banco de dados"              "1"   "$(x wg-ubs "nc -z -w3 172.30.30.3 5432; echo \$?")"
echo "== Acesso administrativo (notebook do admin, chave do bruno.coord)"
make -s restart-hub >/dev/null 2>&1; sleep 10   # zera sessões MFA (gateways vivem no netns do hub)
check "painel antes do MFA da VPN"           "000" "$(acurl -m4 -o /dev/null -w '%{http_code}' $PAINEL/login)"
check "MFA com usuário que não é dono da chave" "401" "$(vpn_mfa marta.coord)"
check "MFA do dono da chave"                 "200" "$(vpn_mfa bruno.coord)"
check "painel após MFA"                      "200" "$(acurl -m4 -o /dev/null -w '%{http_code}' $PAINEL/login)"
check "admin -> banco de dados"              "fechado" "$(acurl -m3 -o /dev/null telnet://172.30.30.3:5432 && echo aberto || echo fechado)"
check "porta administrativa no host (0.0.0.0)" "0" "$(ss -ltnH | awk '{print $4}' | grep -cE '^(0\.0\.0\.0|\*|\[::\]):(443|8443|9443|5432|5601|9000)$')"
echo "== Failover fibra -> 4G (escola)"
st() { curl -s -m3 localhost:8082/api/status | python3 -c 'import sys,json;print(json.load(sys.stdin)["link"])'; }
docker compose exec -T wg-escola /opt/edge/link.sh fibra down >/dev/null; sleep 20
check "link após queda da fibra"             "4g" "$(st)"
docker compose exec -T wg-escola /opt/edge/link.sh fibra up >/dev/null; sleep 15
check "link após retorno da fibra"           "fibra" "$(st)"
echo "== Resultado: ${FAILS:-0} falha(s)"; exit "${FAILS:-0}"
