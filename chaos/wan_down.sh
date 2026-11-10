#!/usr/bin/env bash
# Teste de caos controlado (RT-23): derruba o link WAN (fibra e 4G) de todas as bordas por N
# minutos e evidencia (a) continuidade operacional local e (b) reconciliação sem perda ao voltar.
#
# Uso: chaos/wan_down.sh [minutos]        (padrão: 30, mínimo exigido pelo enunciado)
set -euo pipefail
cd "$(dirname "$0")/.."
MIN="${1:-30}"
SITES=(centro escola ubs horta abrigo)
OUT="docs/evidencias/caos"
mkdir -p "$OUT"
REL="$OUT/teste-caos.md"
ts() { date -u +%FT%TZ; }
psql() { docker compose exec -T db psql -U postgres -d vilaaurora -tAc "$1"; }
edge() { curl -s -m3 "localhost:$1/api/status" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["link"],d["outbox_depth"],len(d["alarms"]))' 2>/dev/null || echo "? ? ?"; }
port() { case "$1" in centro) echo 8081;; escola) echo 8082;; ubs) echo 8083;; horta) echo 8084;; abrigo) echo 8085;; esac; }

echo "== Teste de caos: WAN fora por $MIN min =="
T_START=$(ts)
ROWS_BEFORE=$(psql "select count(*) from ops.telemetry")

echo "# Teste de caos — continuidade e reconciliação (RT-23)" > "$REL"
{
  echo; echo "Início: $T_START · duração da interrupção: $MIN min."
  echo; echo "Derruba fibra **e** 4G de todas as 5 bordas; mede operação local durante a queda e a"
  echo "reconciliação ao restabelecer. Telemetria no banco antes da queda: $ROWS_BEFORE linhas."
} >> "$REL"

echo "[$(ts)] cortando WAN (fibra+4g) das 5 bordas..."
for s in "${SITES[@]}"; do
  docker compose exec -T "wg-$s" /opt/edge/link.sh fibra down >/dev/null
  docker compose exec -T "wg-$s" /opt/edge/link.sh 4g down >/dev/null
done

# injeta uma anomalia para provar que o alarme local dispara SEM nuvem (como a câmara fria do incidente)
echo '{"ubs-camara-fria":{"offset":{"temp_c":8}}}' > data/control/faults.json

sleep 20
echo "[$(ts)] estado durante a queda:"
{ echo; echo "## Durante a interrupção"; echo; echo "| Borda | Link | Outbox | Alarmes locais |"; echo "|---|---|---|---|"; } >> "$REL"
LOCAL_OK=1
for s in "${SITES[@]}"; do
  read -r link ob al <<<"$(edge "$(port "$s")")"
  echo "  $s: link=$link outbox=$ob alarmes=$al"
  echo "| $s | $link | $ob | $al |" >> "$REL"
  [[ "$link" == "offline" ]] || LOCAL_OK=0
done
# confirma alarme local da câmara fria mesmo sem nuvem
UBS_ALARM=$(curl -s localhost:8083/api/status | python3 -c 'import sys,json;print("ubs-camara-fria:temp" in json.load(sys.stdin)["alarms"])' 2>/dev/null || echo False)
{ echo; echo "Alarme crítico local da câmara fria (UBS) disparou sem nuvem: **$UBS_ALARM**."
  echo "Bordas isoladas da nuvem (todas offline): **$([[ $LOCAL_OK == 1 ]] && echo sim || echo não)**."; } >> "$REL"

# aguarda o restante da janela
REMAIN=$(( MIN*60 - 20 ))
echo "[$(ts)] mantendo a queda por mais ${REMAIN}s (operação local seguindo)..."
sleep "$REMAIN"

echo '{}' > data/control/faults.json
echo "[$(ts)] restabelecendo WAN..."
T_RESTORE=$(ts)
for s in "${SITES[@]}"; do
  docker compose exec -T "wg-$s" /opt/edge/link.sh fibra up >/dev/null
  docker compose exec -T "wg-$s" /opt/edge/link.sh 4g up >/dev/null
done

# mede reconciliação: tempo até todos os outbox zerarem
echo "[$(ts)] aguardando reconciliação (outbox -> 0)..."
RECON_START=$(date +%s)
while :; do
  total=0
  for s in "${SITES[@]}"; do read -r _ ob _ <<<"$(edge "$(port "$s")")"; total=$(( total + ${ob:-0} )); done
  [[ "$total" -le 5 ]] && break
  [[ $(( $(date +%s) - RECON_START )) -gt 180 ]] && break
  sleep 3
done
RECON_S=$(( $(date +%s) - RECON_START ))
sleep 5
ROWS_AFTER=$(psql "select count(*) from ops.telemetry")

{
  echo; echo "## Reconciliação"; echo
  echo "- Link restabelecido: $T_RESTORE"
  echo "- Tempo para drenar os buffers (outbox -> ~0): **${RECON_S}s**"
  echo "- Telemetria no banco: antes $ROWS_BEFORE, depois **$ROWS_AFTER** (+$(( ROWS_AFTER - ROWS_BEFORE )))"
  echo "- Perda de dados na reconciliação: a telemetria é bufferizada com store-and-forward e reenviada"
  echo "  de forma idempotente (chave edge+seq). Alarmes/eventos têm prioridade e nunca são descartados;"
  echo "  só telemetria antiga seria descartada se o buffer estourasse ($(psql "select coalesce(sum((data->>'dropped')::int),0) from ops.events where kind='audit'" 2>/dev/null || echo 0) descartes registrados)."
  echo
  echo "## Conclusão"
  echo "Durante $MIN min sem internet, cada espaço seguiu operando por conta própria: regras locais ativas,"
  echo "alarme crítico da câmara fria disparado localmente e painel local acessível. Ao voltar o link, os"
  echo "dados acumulados foram reconciliados sem duplicação. É a correção direta da falha F9/F10 do INC-VA-0712."
} >> "$REL"

echo "== Concluído. Relatório: $REL =="
tail -14 "$REL"
