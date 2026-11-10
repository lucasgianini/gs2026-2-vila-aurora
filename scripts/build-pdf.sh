#!/usr/bin/env bash
# Gera os PDFs de entrega a partir dos Markdown (via pandoc em Docker, sem instalar nada).
# Uso: scripts/build-pdf.sh [NUM_GRUPO]      ex.: scripts/build-pdf.sh 07   (padrão: XX)
set -euo pipefail
cd "$(dirname "$0")/.."
G="${1:-XX}"
TURMA="4ECS"
PFX="GS2026.2_${TURMA}_G${G}"
OUT="entrega"
mkdir -p "$OUT"
IMG="pandoc/latex:3.5"
PD() { docker run --rm -v "$PWD":/data -u "$(id -u):$(id -g)" "$IMG" "$@"; }

common=(--pdf-engine=xelatex -V lang=pt-BR -V geometry:margin=1.8cm -V fontsize=11pt
        -V colorlinks=true -V linkcolor=blue
        -V header-includes='\usepackage{etoolbox}\AtBeginEnvironment{longtable}{\footnotesize}'
        --toc --toc-depth=2 -V toc-title="Sumário" --metadata=date:"$(date +%d/%m/%Y)")

build() {  # build <saida> <titulo> <arquivos...>
  local out="$OUT/$1"; local title="$2"; shift 2
  echo "  -> $out"
  PD "$@" -o "/data/$out" "${common[@]}" --metadata=title:"$title" \
     --metadata=author:"Rede Vila Aurora · FIAP GS 2026.2 · Turma $TURMA · Grupo G$G"
}

echo "Gerando PDFs (grupo G$G)..."
build "${PFX}_E1.pdf" "E1 — Documento de Arquitetura" docs/01-modelo-ameacas.md docs/02-arquitetura.md
build "${PFX}_E3.pdf" "E3 — Relatório de Testes de Segurança" docs/06-testes-seguranca.md
build "${PFX}_E4.pdf" "E4 — Laudo Forense do INC-VA-0712" forensics/cases/INC-VA-0712/laudo-forense.md \
      forensics/cases/INC-VA-0712/mitre-attack.md
build "${PFX}_RelatorioTecnico.pdf" "Relatório Técnico — Rede Vila Aurora" \
      docs/00-indice.md docs/01-modelo-ameacas.md docs/02-arquitetura.md docs/06-testes-seguranca.md \
      forensics/cases/INC-VA-0712/laudo-forense.md forensics/cases/INC-VA-0712/mitre-attack.md \
      docs/03-custos-manutencao.md docs/04-privacidade-ripd.md docs/05-acessibilidade.md docs/07-uso-de-ia.md
echo "PDFs em $OUT/ (nomeie com o número real do grupo: scripts/build-pdf.sh <N>)"
ls -la "$OUT"
