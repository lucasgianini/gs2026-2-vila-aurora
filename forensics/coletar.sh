#!/usr/bin/env bash
# Coleta forense do incidente reproduzido (RT-14) — resposta a incidente no laboratório.
#
# Objetivo: preservar evidências de forma íntegra e rastreável para o laudo (E4).
# Para CADA fonte de evidência:
#   - copia o artefato para forensics/cases/<caso>/raw/
#   - calcula SHA-256 no momento da coleta
#   - registra na cadeia de custódia (CSV): o quê, de onde, quem, quando, hash
# Nada é alterado nas fontes; só leitura.
set -euo pipefail
cd "$(dirname "$0")/.."

CASE="${1:-INC-VA-0712}"
DIR="forensics/cases/$CASE"
RAW="$DIR/raw"
CHAIN="$DIR/cadeia-custodia.csv"
COLLECTOR="${COLLECTOR:-$(whoami)@$(hostname)}"
mkdir -p "$RAW"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
[[ -f "$CHAIN" ]] || echo "item;descricao;origem;coletado_por;coletado_em_utc;sha256;tamanho_bytes" > "$CHAIN"

register() {  # register <item> <descrição> <origem> <arquivo_no_raw>
  local item="$1" desc="$2" orig="$3" f="$RAW/$4"
  [[ -f "$f" ]] || { echo "  ! $4 não gerado"; return; }
  local h sz
  h=$(sha256sum "$f" | cut -d' ' -f1)
  sz=$(stat -c%s "$f")
  echo "$item;$desc;$orig;$COLLECTOR;$(ts);$h;$sz" >> "$CHAIN"
  printf '  [%s] %s  (%s, %d bytes)\n' "$item" "$4" "${h:0:16}…" "$sz"
}

echo "== Coleta forense do caso $CASE =="
echo "Coletor: $COLLECTOR"

# E1 — alertas do SIEM (cópia imutável do alerts.json)
docker compose exec -T siem sh -c 'cat /var/ossec/logs/alerts/alerts.json' > "$RAW/siem-alerts.json" 2>/dev/null || true
register E01 "Alertas do SIEM (Wazuh)" "siem:/var/ossec/logs/alerts/alerts.json" siem-alerts.json

# E2 — log bruto de todos os eventos (archives) do dia
docker compose exec -T siem sh -c 'cat /var/ossec/logs/archives/archives.json 2>/dev/null || true' > "$RAW/siem-archives.json" 2>/dev/null || true
register E02 "Arquivo bruto de eventos do SIEM" "siem:/var/ossec/logs/archives/archives.json" siem-archives.json

# E3 — log da VPN legada (autenticação do atacante)
cp -f data/cloud/logs/vpn-legado.log "$RAW/vpn-legado.log" 2>/dev/null || true
register E03 "Log de autenticação da VPN legada" "nuvem:/var/log/vilaaurora/vpn-legado.log" vpn-legado.log

# E4 — log do gateway do painel legado (requisições do SQLi)
cp -f data/cloud/logs/painel-legado-gw.jsonl "$RAW/painel-legado-gw.jsonl" 2>/dev/null || true
register E04 "Acessos HTTP ao painel legado" "nuvem:/var/log/vilaaurora/painel-legado-gw.jsonl" painel-legado-gw.jsonl

# E5 — log do PostgreSQL (SQL executado pelo painel legado)
docker compose exec -T db sh -c 'cat /var/log/vilaaurora/pg/*.json 2>/dev/null || true' > "$RAW/postgresql.json" 2>/dev/null || true
register E05 "Log de consultas do PostgreSQL" "db:/var/log/vilaaurora/pg/postgresql.json" postgresql.json

# E6 — log da borda da escola (recusa do comando malicioso)
cp -f data/escola/logs/edge.jsonl "$RAW/edge-escola.jsonl" 2>/dev/null || true
register E06 "Log da borda da escola (decisões e recusa)" "borda-escola:/var/log/vilaaurora/edge.jsonl" edge-escola.jsonl

# E7 — comandos e auditoria do banco (trilha append-only)
docker compose exec -T db psql -U postgres -d vilaaurora -c \
  "\copy (SELECT * FROM ops.commands ORDER BY created_at) TO STDOUT WITH CSV HEADER" > "$RAW/commands.csv" 2>/dev/null || true
register E07 "Comandos de atuador (banco)" "db:ops.commands" commands.csv
docker compose exec -T db psql -U postgres -d vilaaurora -c \
  "\copy (SELECT * FROM audit.log ORDER BY id) TO STDOUT WITH CSV HEADER" > "$RAW/audit-log.csv" 2>/dev/null || true
register E08 "Trilha de auditoria (banco)" "db:audit.log" audit-log.csv

# E9 — respostas automáticas do SOAR
cp -f data/cloud/logs/soar.jsonl "$RAW/soar.jsonl" 2>/dev/null || true
register E09 "Respostas do SOAR" "nuvem:/var/log/vilaaurora/soar.jsonl" soar.jsonl

# manifesto de integridade: hash de todos os hashes (sela a cadeia)
MANIFEST="$DIR/manifesto-sha256.txt"
( cd "$RAW" && sha256sum ./* 2>/dev/null ) > "$MANIFEST"
SEAL=$(sha256sum "$MANIFEST" | cut -d' ' -f1)
echo "$(ts)  selo do manifesto (SHA-256): $SEAL" | tee "$DIR/selo.txt"
echo
echo "Cadeia de custódia: $CHAIN"
echo "Itens coletados: $(($(wc -l < "$CHAIN") - 1))"
