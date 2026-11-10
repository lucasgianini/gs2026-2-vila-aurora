#!/usr/bin/env bash
# E3 — Ação de ALTO impacto proposta pelo SOAR só executa após aprovação humana no painel (RT-15)
# Uso: tests/t05_soar_aprovacao.sh <id da ação em soc.actions>
set -uo pipefail
source "$(dirname "$0")/../scripts/lib.sh"; cd "$ROOT"
AID="${1:?id da ação}"
check "ação aguardando aprovação" "aguardando_aprovacao" "$(psql_q "select status from soc.actions where id=$AID")"
J=$(mktemp)
check "MFA da VPN (bruno.coord)" "200" "$(vpn_mfa bruno.coord)"
check "login no painel com TOTP" "302" "$(painel_login bruno.coord "$J")"
T=$(acurl -b "$J" -c "$J" "$PAINEL/soc" | csrf)
check "aprovação no painel" "302" "$(acurl -b "$J" -o /dev/null -w '%{http_code}' -d "csrf_token=$T&decisao=aprovar" "$PAINEL/soc/acoes/$AID")"
for _ in $(seq 1 15); do [[ "$(psql_q "select status from soc.actions where id=$AID")" == executada ]] && break; sleep 2; done
check "SOAR executou após aprovação" "executada" "$(psql_q "select status from soc.actions where id=$AID")"
echo "  decisão: $(psql_q "select decided_by||' — '||result from soc.actions where id=$AID")"
check "sessão administrativa encerrada (painel inacessível)" "000" "$(acurl -m4 -o /dev/null -w '%{http_code}' "$PAINEL/login")"
echo "== Resultado: ${FAILS:-0} falha(s)"; exit "${FAILS:-0}"
