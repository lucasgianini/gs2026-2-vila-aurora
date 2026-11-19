#!/usr/bin/env bash
# Gera os PDFs de entrega a partir dos Markdown (via pandoc em Docker, sem instalar nada).
# Uso: scripts/build-pdf.sh [GRUPO]          ex.: scripts/build-pdf.sh 07   (padrão: XX)
#      GRUPO numérico vira "G07"; outro texto é usado como está (ex.: RM99921_RM98016).
#      AUTORES="NOME 1 – RM 000001; NOME 2 – RM 000002" scripts/build-pdf.sh 07
#
# E3 e E4 levam as evidências como anexos (saídas reais dos testes, linha do tempo, custódia),
# para que o PDF se sustente sozinho, sem depender de abrir o repositório.
set -euo pipefail
cd "$(dirname "$0")/.."
G="${1:-XX}"
TURMA="4ECS"
REPO="${REPO:-https://github.com/lucasgianini/gs2026-2-vila-aurora}"   # E2 — link do repositório, impresso na capa de todos os PDFs
VIDEO="${VIDEO:-https://youtu.be/4nurz8ffqu4}"                                  # vídeo de demonstração, também na capa
if [[ "$G" =~ ^[0-9]+$ || "$G" == XX ]]; then GID="G$G"; else GID="$G"; fi
PFX="GS2026.2_${TURMA}_${GID}"
OUT="entrega"
TMP="$OUT/.tmp"
CASE="forensics/cases/INC-VA-0712"
EV="docs/evidencias"
rm -rf "$TMP"; mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
IMG="pandoc/latex:3.5"
PD() { docker run --rm -v "$PWD":/data -u "$(id -u):$(id -g)" "$IMG" "$@"; }

# Capa: um integrante por linha (AUTORES separado por ";") e, por último, turma e grupo.
AUTOR_META=()
if [ -n "${AUTORES:-}" ]; then
  IFS=';' read -ra _AUT <<< "$AUTORES"
  for a in "${_AUT[@]}"; do a="${a#"${a%%[![:space:]]*}"}"; AUTOR_META+=(--metadata=author:"$a"); done
fi
AUTOR_META+=(--metadata=author:"Rede Vila Aurora · FIAP GS 2026.2 · Turma $TURMA · Grupo ${GID//_/ }")

common=(--pdf-engine=xelatex -V lang=pt-BR -V geometry:margin=1.8cm -V fontsize=11pt
        -V colorlinks=true -V linkcolor=blue --resource-path=.:docs --lua-filter=scripts/pdf-symbols.lua
        -V header-includes='\usepackage{etoolbox}\AtBeginEnvironment{longtable}{\footnotesize}\AtBeginEnvironment{verbatim}{\scriptsize}'
        --toc --toc-depth=2 -V toc-title="Sumário" --metadata=date:"$(date +%d/%m/%Y)")

# ---------------------------------------------------------------- anexos gerados
anexo() {  # anexo <arquivo.md> <título> — cabeçalho de um anexo (nível 1)
  printf '\n\n# %s\n\n' "$2" > "$TMP/$1"; }
texto() {  # texto <arquivo.md> <origem> — saída de teste como bloco de código, com quebra de linha
  { printf 'Arquivo: `%s`\n\n```\n' "$2"; fold -s -w 112 "$2"; printf '```\n'; } >> "$TMP/$1"; }
corpo() {  # corpo <arquivo.md> <origem.md> — conteúdo de outro Markdown, rebaixando os títulos em um nível
  { printf 'Arquivo: `%s`\n\n' "$2"; sed -e 's/^#/##/' "$2"; printf '\n'; } >> "$TMP/$1"; }
csv_md() { # csv_md <arquivo.md> <origem.csv> — CSV (separador ;) como tabela; hash abreviado
  python3 - "$2" >> "$TMP/$1" <<'PY'
import csv, sys
rows = list(csv.reader(open(sys.argv[1]), delimiter=";"))
head, body = rows[0], rows[1:]
width = {"item": 5, "descricao": 22, "origem": 30, "coletado_por": 13, "coletado_em_utc": 14, "sha256": 15, "tamanho_bytes": 9}
def cell(k, v):
    if k == "sha256" and len(v) > 20:
        return v[:12] + "..."
    if k in ("origem", "coletado_por"):          # caminhos longos: permite quebra de linha no PDF
        v = v.replace("/", "/\\allowbreak{}").replace("@", "@\\allowbreak{}")
    return v.replace("|", "/")
print("| " + " | ".join(h.replace("_", " ") for h in head) + " |")
print("|" + "|".join("-" * width.get(h, 10) for h in head) + "|")
for r in body:
    print("| " + " | ".join(cell(k, v) for k, v in zip(head, r)) + " |")
print()
PY
}

# E3
anexo A.md "Anexo A — SQL Injection antes/depois (saída do teste t01)"
texto A.md "$EV/t01_sqli_antes_depois.txt"
anexo B.md "Anexo B — mTLS, VPN, segmentação, regras do SIEM e SOAR (saídas dos testes)"
texto B.md "$EV/t03_vpn_segmentacao.txt"; texto B.md "$EV/t04_siem_regras.txt"; texto B.md "$EV/t05_soar_aprovacao.txt"
anexo C.md "Anexo C — Autenticação de e-mail (SPF, DKIM, DMARC)";      corpo C.md "$EV/email_spf_dkim_dmarc.md"
anexo D.md "Anexo D — Campanha de phishing simulado";                  corpo D.md "$EV/phishing_campanha.md"
anexo E.md "Anexo E — Plano de conscientização dos voluntários";       corpo E.md "docs/09-plano-conscientizacao.md"
anexo F.md "Anexo F — IA defensiva: detecção de anomalias";            corpo F.md "$EV/ia_anomalias.md"
anexo G.md "Anexo G — IA defensiva: triagem por LLM e prompt injection"; corpo G.md "$EV/ia_triagem_llm.md"
anexo H.md "Anexo H — Teste de caos (30 min sem WAN)";                 corpo H.md "$EV/caos/teste-caos.md"
anexo I.md "Anexo I — Métricas (RT-22)";                               corpo I.md "$EV/metricas.md"
E3_ANEXOS=("$TMP"/{A,B,C,D,E,F,G,H,I}.md)

# E4
anexo L1.md "Anexo 1 — Linha do tempo completa";                       corpo L1.md "$CASE/linha-do-tempo.md"
# colunas da linha do tempo com larguras proporcionais; trechos longos sem espaço (URLs) ganham quebras
python3 - "$TMP/L1.md" <<'PY'
import re, sys
p = sys.argv[1]; out = []
for ln in open(p):
    if ln.startswith("|---"):
        ln = "|---|---------|---------|-----|" + "-" * 60 + "|\n"
    elif ln.startswith("|"):
        ln = re.sub(r"\S{46,}", lambda m: " ".join(m.group(0)[i:i + 44] for i in range(0, len(m.group(0)), 44)), ln)
    out.append(ln)
open(p, "w").writelines(out)
PY
anexo L2.md "Anexo 2 — Cadeia de custódia"
printf 'Arquivo: `%s` (hash SHA-256 abreviado nos 12 primeiros caracteres; valores completos no Anexo 3 e no CSV).\n\n' "$CASE/cadeia-custodia.csv" >> "$TMP/L2.md"
csv_md L2.md "$CASE/cadeia-custodia.csv"
anexo L3.md "Anexo 3 — Manifesto de integridade (SHA-256) e selo"
texto L3.md "$CASE/manifesto-sha256.txt"; texto L3.md "$CASE/selo.txt"
E4_ANEXOS=("$TMP"/{L1,L2,L3}.md)

# ---------------------------------------------------------------- PDFs
build() {  # build <saida> <titulo> <arquivos...>
  local out="$OUT/$1"; local title="$2"; shift 2
  echo "  -> $out"
  PD "$@" -o "/data/$out" "${common[@]}" --metadata=title:"$title" "${AUTOR_META[@]}" \
     --metadata=subtitle:"Repositório (E2): $REPO · Vídeo: $VIDEO"
}

echo "Gerando PDFs (grupo $GID)..."
rm -f "$OUT"/GS2026.2_*.pdf
build "${PFX}_E1.pdf" "E1 — Documento de Arquitetura" docs/01-modelo-ameacas.md docs/02-arquitetura.md
build "${PFX}_E3.pdf" "E3 — Relatório de Testes de Segurança" docs/06-testes-seguranca.md "${E3_ANEXOS[@]}"
build "${PFX}_E4.pdf" "E4 — Laudo Forense do INC-VA-0712" "$CASE/laudo-forense.md" "$CASE/mitre-attack.md" "${E4_ANEXOS[@]}"
build "${PFX}_RelatorioTecnico.pdf" "Relatório Técnico — Rede Vila Aurora" \
      docs/00-indice.md docs/01-modelo-ameacas.md docs/02-arquitetura.md docs/06-testes-seguranca.md \
      "$CASE/laudo-forense.md" "$CASE/mitre-attack.md" \
      docs/03-custos-manutencao.md docs/04-privacidade-ripd.md docs/05-acessibilidade.md \
      docs/09-plano-conscientizacao.md docs/07-uso-de-ia.md
echo "PDFs em $OUT/ (nomeie com o número real do grupo: scripts/build-pdf.sh <N>)"
ls -la "$OUT"
