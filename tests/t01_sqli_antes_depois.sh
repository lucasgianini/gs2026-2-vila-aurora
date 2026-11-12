#!/usr/bin/env bash
# E3 — SQL Injection antes/depois (RT-08 · C3). SOMENTE contra os painéis deste laboratório.
#
#   ANTES  : painel legado (perfil "legado") — exploração manual + sqlmap.
#   DEPOIS : painel corrigido, camada por camada:
#            1) WAF mínimo no gateway (nginx)       -> 403 antes de chegar à aplicação
#            2) aplicação SEM o WAF na frente       -> validação + consulta parametrizada
#            3) banco                               -> usuário va_painel com privilégio mínimo
#            4) SIEM                                -> regras (b) dispararam durante o teste
#            5) SOAR                                -> encerra a sessão VPN e bloqueia a conta
#
# O SOAR fica pausado nas camadas 1-4: ele encerraria a sessão VPN e bloquearia a conta no primeiro
# alerta, impedindo medir as camadas uma a uma. Na camada 5 ele é religado e a resposta é medida.
# Ao final o teste desfaz os bloqueios de conta que ele mesmo provocou.
#
# Uso: tests/t01_sqli_antes_depois.sh     (requer: make up + docker compose --profile legado up -d)
set -uo pipefail
source "$(dirname "$0")/../scripts/lib.sh"; cd "$ROOT"
EV="docs/evidencias"; LOGS="$EV/sqlmap"; mkdir -p "$LOGS"
exec > >(tee "$EV/t01_sqli_antes_depois.txt") 2>&1
NET="vilaaurora_cloud_svc"
IMG="vilaaurora/sqlmap:dev"
LEG="https://172.30.30.80:9443"          # gateway do painel legado (rede plana da nuvem)
APP="http://painel-app:8000"             # painel corrigido direto na aplicação (sem WAF na frente)
T0=$(date -u +%Y-%m-%dT%H:%M:%S)
in_net() { docker run --rm --network "$NET" "$@"; }
emails() { grep -oE '<td>[^<]+@[^<]+</td>' | sed -e 's/<[^>]*>//g'; }
clean()  { sed -E -e 's/\x1b\[[0-9;]*m//g' -e 's/(session|__Host-va)=[A-Za-z0-9_.-]+/\1=<removido>/g' | grep -vE '^\s*$|^\s+_|___|\|_|legal disclaimer|^\[\*\] (starting|ending)'; }

docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q -t "$IMG" attack/sqlmap >/dev/null
echo "Teste executado em ${T0}Z · $(docker run --rm "$IMG" sqlmap --version 2>/dev/null | tail -1)"
docker compose stop soar >/dev/null 2>&1
restore() {  # religa o SOAR e desfaz os bloqueios de conta causados por este teste
  docker compose start soar >/dev/null 2>&1
  psql_q "update cadastro.operadores set bloqueado_ate=null, falhas=0 where username in
          (select target from audit.log where actor='soar' and action='lock_account' and ts >= '${T0}Z')" >/dev/null 2>&1
}
trap restore EXIT

# ---------------------------------------------------------------- ANTES: painel legado
echo; echo "== ANTES — painel legado (vulnerável, só em laboratório)"
LC=$(in_net -e U=diego.op -e P="$(painel_pw diego.op)" "$IMG" sh -c \
  'curl -sk -c /tmp/j -o /dev/null --data-urlencode "username=$U" --data-urlencode "password=$P" '"$LEG"'/login; awk "/session/{print \$7}" /tmp/j')
[ -n "$LC" ] || { echo "login no painel legado falhou (perfil legado no ar?)"; exit 1; }
lget() { in_net "$IMG" curl -sk -m 20 -H "Cookie: session=$LC" -G "$LEG/acessos" "$@"; }

P_UNION="x' UNION SELECT now(),nome,email,telefone,true,papel FROM cadastro.pessoas--"
P_ERRO="x'"
P_STACK="x'; SELECT pg_sleep(3);--"
echo "  payload 1 (UNION):     q=$P_UNION"
OUT=$(lget --data-urlencode "q=$P_UNION")
N=$(printf '%s' "$OUT" | emails | wc -l)
printf '%s' "$OUT" | emails | head -3 | sed 's/^/      vazado (sintético): /'
[ "$N" -gt 0 ] && ok "legado: UNION extrai o cadastro ($N e-mails sintéticos vazados)" || fail "legado: UNION não extraiu dados"
echo "  payload 2 (erro):      q=$P_ERRO"
OUT=$(lget --data-urlencode "q=$P_ERRO")
printf '%s' "$OUT" | grep -oiE 'Erro: [^<]{0,110}' | head -1 | sed 's/^/      resposta: /'
printf '%s' "$OUT" | grep -qiE 'syntax error|unterminated|psycopg|LINE 1' \
  && ok "legado: erro do banco devolvido ao usuário (vazamento de detalhes)" || fail "legado: erro do banco não apareceu"
echo "  payload 3 (empilhado): q=$P_STACK"
S=$(date +%s%3N); lget -o /dev/null --data-urlencode "q=$P_STACK"; D=$(( $(date +%s%3N) - S ))
echo "      tempo de resposta: ${D} ms (pg_sleep(3) executado pelo banco)"
[ "$D" -ge 3000 ] && ok "legado: comandos empilhados são executados" || fail "legado: empilhado não executou"

echo "  sqlmap (automático) contra o painel legado — log completo em $LOGS/legado.log"
in_net "$IMG" sqlmap -u "$LEG/acessos?q=porta" -p q --cookie "session=$LC" --batch --dbms=PostgreSQL \
  --technique=BEU --flush-session --disable-coloring --current-user --tables -D cadastro \
  --dump -T pessoas -C nome,email,telefone --stop 3 2>&1 | clean > "$LOGS/legado.log"
grep -E "^Parameter:|^\s+Type:|^\s+Title:|current user:|^\[[0-9]+ tables?\]|^Table:|^\[[0-9]+ entr" "$LOGS/legado.log" | sed 's/^/      /'
grep -q "^Parameter: q" "$LOGS/legado.log" && ok "legado: sqlmap confirma o parâmetro q como injetável" || fail "legado: sqlmap não achou a injeção"
grep -qE "^\[[0-9]+ entr" "$LOGS/legado.log" && ok "legado: sqlmap extrai linhas de cadastro.pessoas" || fail "legado: sqlmap não extraiu a tabela"

# ---------------------------------------------------------------- DEPOIS: painel corrigido
echo; echo "== DEPOIS — painel corrigido (mesmos payloads)"
J=$(mktemp)
check "MFA da VPN administrativa" "200" "$(vpn_mfa bruno.coord)"
check "login no painel (senha + TOTP, perfil auditor)" "302" "$(painel_login elisa.aud "$J")"
PC=$(awk '/__Host-va/{print $7}' "$J")
[ "$(acurl -m 10 -b "$J" -o /dev/null -w '%{http_code}' "$PAINEL/acessos")" = 200 ] || {
  echo "sem sessão autenticada no painel corrigido (conta bloqueada pelo SOAR? ver cadastro.operadores) — abortando"; exit 1; }
gw()  { acurl -m 20 -b "$J" -G "$PAINEL/acessos" "$@"; }                                   # com WAF
app() { in_net "$IMG" curl -s -m 20 -H "Cookie: __Host-va=$PC" -G "$APP/acessos" "$@"; }   # sem WAF

echo "  -- camada 1: WAF no gateway (nginx)"
check "busca legítima (q=fechadura) passa pelo WAF" "200" "$(gw -o /dev/null -w '%{http_code}' --data-urlencode "q=fechadura")"
check "payload 1 (UNION) barrado no gateway"     "403" "$(gw -o /dev/null -w '%{http_code}' --data-urlencode "q=$P_UNION")"
check "payload 3 (empilhado) barrado no gateway" "403" "$(gw -o /dev/null -w '%{http_code}' --data-urlencode "q=$P_STACK")"
check "payload 2 (aspa solta) não é assinatura do WAF: segue para a aplicação" "200" \
      "$(gw -o /dev/null -w '%{http_code}' --data-urlencode "q=$P_ERRO")"

echo "  -- camada 2: aplicação SEM o WAF na frente (validação + consulta parametrizada)"
for name in UNION erro empilhado; do
  case $name in UNION) P=$P_UNION;; erro) P=$P_ERRO;; empilhado) P=$P_STACK;; esac
  S=$(date +%s%3N); OUT=$(app --data-urlencode "q=$P"); D=$(( $(date +%s%3N) - S ))
  N=$(printf '%s' "$OUT" | emails | wc -l)
  MSG=$(printf '%s' "$OUT" | grep -oE 'Use apenas letras[^<]*|Não foi possível concluir a busca\.' | head -1)
  LEAK=$(printf '%s' "$OUT" | grep -ciE 'syntax error|psycopg|LINE 1|SELECT ts')
  echo "      payload $name -> mensagem ao usuário: \"$MSG\" · e-mails vazados: $N · tempo: ${D} ms"
  [ "$N" = 0 ] && [ "$LEAK" = 0 ] && [ -n "$MSG" ] && [ "$D" -lt 3000 ] \
    && ok "corrigido: payload $name recusado, mensagem genérica, nada executado" \
    || fail "corrigido: payload $name teve efeito"
done
R=$(app --data-urlencode "q=fechadura" | grep -o '<tr><td>' | wc -l)
[ "$R" -gt 0 ] && ok "corrigido: busca legítima continua funcionando ($R linhas)" || fail "corrigido: busca legítima quebrou"

echo "  sqlmap direto na aplicação (sem WAF), level 3 / risk 2, parâmetros q, site e dia — log em $LOGS/corrigido-app.log"
in_net "$IMG" sqlmap -u "$APP/acessos?q=porta&site=escola&dia=2026-11-10" -p q,site,dia --cookie "__Host-va=$PC" \
  --batch --dbms=PostgreSQL --level=3 --risk=2 --flush-session --disable-coloring 2>&1 | clean > "$LOGS/corrigido-app.log"
grep -E "does not seem to be injectable|do not appear to be injectable|^Parameter:" "$LOGS/corrigido-app.log" | sed 's/^/      /'
! grep -q "^Parameter:" "$LOGS/corrigido-app.log" && grep -q "do not appear to be injectable" "$LOGS/corrigido-app.log" \
  && ok "corrigido: sqlmap NÃO encontra injeção em nenhum parâmetro" || fail "corrigido: sqlmap encontrou injeção (ou não concluiu)"

echo "  sqlmap pelo caminho real (VPN + gateway com WAF) — log em $LOGS/corrigido-gw.log"
docker run --rm --network host "$IMG" sqlmap -u "$PAINEL/acessos?q=porta&site=escola" -p q --cookie "__Host-va=$PC" \
  --proxy="socks5://$SOCKS" --batch --dbms=PostgreSQL --flush-session --disable-coloring 2>&1 | clean > "$LOGS/corrigido-gw.log"
grep -E "403|WAF|does not seem to be injectable|do not appear to be injectable|^Parameter:" "$LOGS/corrigido-gw.log" | cut -c1-170 | sort -u | head -8 | sed 's/^/      /'
! grep -q "^Parameter:" "$LOGS/corrigido-gw.log" && grep -q "do not appear to be injectable" "$LOGS/corrigido-gw.log" \
  && ok "corrigido: sqlmap pelo gateway também não encontra injeção" || fail "corrigido: sqlmap pelo gateway encontrou injeção (ou não concluiu)"
W=$(grep -c '"waf":"1"' data/cloud/logs/painel-gw.jsonl 2>/dev/null || echo 0)
[ "$W" -gt 0 ] && ok "WAF registrou $W requisições barradas (painel-gw.jsonl, \"waf\":\"1\")" || fail "WAF não registrou bloqueios"

echo "  -- camada 3: privilégio mínimo do usuário de banco (va_painel x va_painel_legado)"
priv() { psql_q "select $1"; }
check "va_painel lê cadastro.pessoas (tabela com contatos)"        "f" "$(priv "has_table_privilege('va_painel','cadastro.pessoas','SELECT')")"
check "va_painel_legado lê cadastro.pessoas"                        "t" "$(priv "has_table_privilege('va_painel_legado','cadastro.pessoas','SELECT')")"
check "va_painel pode apagar/alterar o histórico de acessos"       "f" "$(priv "has_table_privilege('va_painel','ops.acessos','UPDATE,DELETE')")"
check "va_painel pode alterar a trilha de auditoria"               "f" "$(priv "has_table_privilege('va_painel','audit.log','UPDATE,DELETE')")"
check "va_painel pode criar objetos (DDL) no schema ops"           "f" "$(priv "has_schema_privilege('va_painel','ops','CREATE')")"

echo "  -- camada 4: detecção no SIEM durante o teste (regras (b), grupo va_b_sqli)"
sleep 8
docker compose exec -T siem cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | python3 -c '
import sys, json, collections
t0 = sys.argv[1]; c = collections.Counter(); d = {}
for ln in sys.stdin:
    try: a = json.loads(ln)
    except Exception: continue
    r = a.get("rule", {})
    if "va_b_sqli" in r.get("groups", []) and a.get("timestamp", "")[:19] >= t0:
        c[r["id"]] += 1; d[r["id"]] = (r["level"], r["description"][:58])
for k in sorted(c): print(f"      regra {k} (nível {d[k][0]}): {c[k]:>5} alertas — {d[k][1]}")
print("TOTAL", sum(c.values()), len(c))' "$T0" | tee /tmp/.t01_siem.$$
TOT=$(awk '/^TOTAL/{print $2}' /tmp/.t01_siem.$$); rm -f /tmp/.t01_siem.$$
[ "${TOT:-0}" -gt 0 ] && ok "SIEM gerou $TOT alertas de SQLi durante o teste" || fail "SIEM não gerou alertas de SQLi"

echo "  -- camada 5: resposta automática (SOAR religado; um único payload pelo caminho real)"
docker compose start soar >/dev/null 2>&1; sleep 6
T1=$(date -u +%Y-%m-%dT%H:%M:%S)
check "payload 1 (UNION) pelo gateway" "403" "$(gw -o /dev/null -w '%{http_code}' --data-urlencode "q=$P_UNION")"
for _ in $(seq 1 15); do
  [ "$(psql_q "select count(*) from soc.actions where status='executada' and done_at >= '${T1}Z'")" -ge 1 ] && break; sleep 2; done
sleep 3
psql_q "select '      ' || action || ' -> ' || target || ' · ' || status || ' · ' || coalesce(result,'')
        from soc.actions where ts >= '${T1}Z' order by id" 2>/dev/null
check "SOAR encerrou a sessão VPN de origem" "1" "$(psql_q "select count(*) from soc.actions where action='revogar_sessao_vpn' and status='executada' and done_at >= '${T1}Z'")"
check "painel inacessível após a contenção (sessão administrativa encerrada)" "000" "$(acurl -m 5 -b "$J" -o /dev/null -w '%{http_code}' "$PAINEL/acessos")"
grep '"action_executed"' data/cloud/logs/soar.jsonl | python3 -c '
import sys, json
for ln in sys.stdin:
    e = json.loads(ln)
    if e["ts"][:19] >= sys.argv[1]:
        print("      %s: MTTD %s s · MTTR %s s (evento -> contenção)" % (e["action"], e.get("mttd_s"), e.get("mttr_s")))' "$T1"
rm -f "$J"

echo "== Resultado: ${FAILS:-0} falha(s)"; exit "${FAILS:-0}"
