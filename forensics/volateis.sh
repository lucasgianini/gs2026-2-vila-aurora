#!/usr/bin/env bash
# Aquisição de dados voláteis de um nó (RFC 3227 — ordem de volatilidade) — RT-14 (diferencial).
#
# Em um ambiente de containers, o estado volátil relevante (processos, conexões, mapeamento de
# memória via /proc, módulos) é coletado do namespace do container alvo, com hash no momento da
# coleta e registro na cadeia de custódia. Só leitura.
#
# Para um nó de BORDA baseado em VM, o mesmo caso usaria uma imagem de memória completa + Volatility 3
# (ver nota ao final); aqui o alvo é um container, então coletamos o estado vivo equivalente.
#
# Uso: forensics/volateis.sh <serviço> [caso]      ex.: forensics/volateis.sh vpn-legado INC-VA-0712
set -euo pipefail
cd "$(dirname "$0")/.."
SVC="${1:?uso: volateis.sh <serviço> [caso]}"
CASE="${2:-INC-VA-0712}"
DIR="forensics/cases/$CASE/volateis-$SVC"
CHAIN="forensics/cases/$CASE/cadeia-custodia.csv"
COLLECTOR="${COLLECTOR:-$(whoami)@$(hostname)}"
mkdir -p "$DIR"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
dex() { docker compose exec -T "$SVC" sh -c "$1" 2>/dev/null || echo "(não disponível)"; }

echo "== Dados voláteis de $SVC (ordem de volatilidade, RFC 3227) =="

# 1. mais volátil: conexões de rede e tabela de rotas
{ echo "# conexões (ss -tunap)"; dex 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null'
  echo; echo "# rotas"; dex 'ip route'; echo; echo "# regras NAT/filter"; dex 'iptables -S 2>/dev/null'
} > "$DIR/01-rede.txt"

# 2. processos em execução e argumentos
dex 'ps -eo pid,ppid,user,etime,args 2>/dev/null || ps aux' > "$DIR/02-processos.txt"

# 3. descritores/arquivos abertos e mapeamento de memória do processo principal (via /proc)
dex 'for p in /proc/[0-9]*; do pid=${p#/proc/}; [ -r $p/cmdline ] || continue;
       echo "== PID $pid: $(tr "\0" " " < $p/cmdline)"; ls -l $p/fd 2>/dev/null | head -20;
     done' > "$DIR/03-descritores.txt"
dex 'head -40 /proc/1/maps 2>/dev/null' > "$DIR/04-mapa-memoria-pid1.txt"

# 4. menos volátil: variáveis de ambiente do processo (podem conter indicadores) e uptime
dex 'cat /proc/1/environ 2>/dev/null | tr "\0" "\n"' > "$DIR/05-ambiente-pid1.txt"
dex 'cat /proc/uptime; echo; cat /proc/loadavg' > "$DIR/06-uptime.txt"

# hash de cada artefato -> cadeia de custódia
[[ -f "$CHAIN" ]] || echo "item;descricao;origem;coletado_por;coletado_em_utc;sha256;tamanho_bytes" > "$CHAIN"
i=1
for f in "$DIR"/*.txt; do
  h=$(sha256sum "$f" | cut -d' ' -f1); sz=$(stat -c%s "$f")
  printf 'V%02d;Dados voláteis %s (%s);container:%s;%s;%s;%s;%d\n' \
    "$i" "$(basename "$f")" "$SVC" "$SVC" "$COLLECTOR" "$(ts)" "$h" "$sz" >> "$CHAIN"
  printf '  [V%02d] %s  (%s…)\n' "$i" "$(basename "$f")" "${h:0:16}"
  i=$((i+1))
done
echo "Artefatos em $DIR/ e registrados na cadeia de custódia."
echo
echo "Nota (diferencial completo): para um nó de borda em VM, a aquisição seria uma imagem de memória"
echo "(ex.: via LiME/avml) analisada com Volatility 3 — pslist, netscan, lsof, bash history. O container"
echo "não tem kernel próprio, então o estado vivo acima é o equivalente forense apropriado."
