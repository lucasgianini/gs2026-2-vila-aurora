#!/usr/bin/env bash
# PKI do projeto Vila Aurora (RT-04 identidade única por dispositivo, RT-05 revogação/rotação)
#
#   pki/pki.sh init                    cria raiz + intermediária (idempotente)
#   pki/pki.sh issue <tipo> <cn> [san] tipo: device | edge | server | client
#   pki/pki.sh revoke <cn> [motivo]    revoga e regenera a CRL
#   pki/pki.sh rotate <tipo> <cn> [san] revoga o cert atual e emite um novo (mesma CN, nova chave)
#   pki/pki.sh crl                     regenera a CRL (fazer antes de expirar: default_crl_days=7)
#   pki/pki.sh bootstrap               emite todo o inventário do laboratório
#   pki/pki.sh list                    lista certificados (V=válido, R=revogado)
#
# Material gerado vai para pki/out/ (fora do git). Chaves ECDSA P-256.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
export PKI_OUT="${PKI_OUT:-$HERE/out}"
export PKI_SAN="DNS:placeholder"
CNF="$HERE/openssl.cnf"
SITES=(centro escola ubs horta abrigo)

# Inventário de dispositivos por espaço (CN = <site>-<dispositivo>)
declare -A DEVICES=(
  [centro]="energia fechadura qualidade-ar"
  [escola]="nivel-reservatorio bomba turbidez cloro fechadura"
  [ubs]="camara-fria fechadura energia"
  [horta]="nivel-reservatorio bomba umidade-solo"
  [abrigo]="alagamento energia gerador fechadura"
)

log() { printf '[pki] %s\n' "$*" >&2; }

init_dir() {
  local d="$1"
  mkdir -p "$d/newcerts"
  [[ -f "$d/index.txt" ]] || : > "$d/index.txt"
  [[ -f "$d/serial" ]]    || openssl rand -hex 16 > "$d/serial"
  [[ -f "$d/crlnumber" ]] || echo 1000 > "$d/crlnumber"
}

cmd_init() {
  umask 077
  init_dir "$PKI_OUT/root"; init_dir "$PKI_OUT/issuing"
  mkdir -p "$PKI_OUT/certs"
  if [[ ! -f "$PKI_OUT/root/root.crt" ]]; then
    log "gerando CA raiz"
    openssl ecparam -name prime256v1 -genkey -noout -out "$PKI_OUT/root/root.key"
    openssl req -new -x509 -config "$CNF" -key "$PKI_OUT/root/root.key" -sha256 -days 3650 \
      -subj "/O=Rede Comunitaria Vila Aurora/CN=Vila Aurora Root CA" -extensions v3_root \
      -out "$PKI_OUT/root/root.crt"
  fi
  if [[ ! -f "$PKI_OUT/issuing/issuing.crt" ]]; then
    log "gerando CA intermediária (issuing)"
    openssl ecparam -name prime256v1 -genkey -noout -out "$PKI_OUT/issuing/issuing.key"
    openssl req -new -config "$CNF" -key "$PKI_OUT/issuing/issuing.key" \
      -subj "/O=Rede Comunitaria Vila Aurora/CN=Vila Aurora Issuing CA" -out "$PKI_OUT/issuing/issuing.csr"
    openssl ca -batch -config "$CNF" -name root -extensions v3_issuing -days 1825 -notext \
      -in "$PKI_OUT/issuing/issuing.csr" -out "$PKI_OUT/issuing/issuing.crt" 2>/dev/null
  fi
  # cadeia confiável distribuída a todos os componentes
  cat "$PKI_OUT/issuing/issuing.crt" "$PKI_OUT/root/root.crt" > "$PKI_OUT/ca-chain.crt"
  cmd_crl
  chmod 644 "$PKI_OUT/ca-chain.crt" "$PKI_OUT/root/root.crt" "$PKI_OUT/issuing/issuing.crt"
}

cmd_issue() {
  local type="$1" cn="$2" san="${3:-DNS:$2}"
  [[ "$type" =~ ^(device|edge|server|client)$ ]] || { log "tipo inválido: $type"; exit 2; }
  [[ "$cn" =~ ^[a-z0-9][a-z0-9.-]{1,62}$ ]] || { log "CN inválida: $cn"; exit 2; }
  local dir="$PKI_OUT/certs/$cn"
  if [[ -f "$dir/cert.pem" ]]; then log "$cn já existe (use rotate)"; return 0; fi
  mkdir -p "$dir"
  ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$dir/key.pem" )
  openssl req -new -config "$CNF" -key "$dir/key.pem" \
    -subj "/O=Rede Comunitaria Vila Aurora/OU=$type/CN=$cn" -out "$dir/req.csr"
  PKI_SAN="$san" openssl ca -batch -config "$CNF" -extensions "v3_$type" -notext \
    -in "$dir/req.csr" -out "$dir/cert.pem" 2>/dev/null
  rm -f "$dir/req.csr"
  cp "$PKI_OUT/ca-chain.crt" "$dir/ca.pem"
  # chave legível pelo usuário do container (uid não-root); diretório fora do git
  chmod 644 "$dir/cert.pem" "$dir/ca.pem"; chmod 640 "$dir/key.pem"
  log "emitido $type $cn (serial $(openssl x509 -in "$dir/cert.pem" -noout -serial | cut -d= -f2))"
}

cmd_revoke() {
  local cn="$1" reason="${2:-keyCompromise}"
  local dir="$PKI_OUT/certs/$cn"
  [[ -f "$dir/cert.pem" ]] || { log "$cn não encontrado"; exit 1; }
  openssl ca -config "$CNF" -revoke "$dir/cert.pem" -crl_reason "$reason" 2>/dev/null
  mkdir -p "$PKI_OUT/revoked"
  mv "$dir" "$PKI_OUT/revoked/$cn.$(date +%Y%m%dT%H%M%S)"
  cmd_crl
  log "revogado $cn ($reason)"
}

cmd_rotate() {
  local type="$1" cn="$2" san="${3:-DNS:$2}"
  [[ -f "$PKI_OUT/certs/$cn/cert.pem" ]] && cmd_revoke "$cn" superseded
  cmd_issue "$type" "$cn" "$san"
}

cmd_crl() {
  openssl ca -gencrl -config "$CNF" -out "$PKI_OUT/issuing/issuing.crl" 2>/dev/null
  openssl ca -gencrl -config "$CNF" -name root -out "$PKI_OUT/root/root.crl" 2>/dev/null
  # CRL combinada (raiz+intermediária) para o Mosquitto/nginx (crl_check_all)
  cat "$PKI_OUT/issuing/issuing.crl" "$PKI_OUT/root/root.crl" > "$PKI_OUT/crl.pem"
  chmod 644 "$PKI_OUT/crl.pem" "$PKI_OUT/issuing/issuing.crl" "$PKI_OUT/root/root.crl"
  log "CRL atualizada"
}

cmd_bootstrap() {
  cmd_init
  for s in "${SITES[@]}"; do
    cmd_issue server "broker-$s" "DNS:broker-$s,DNS:broker.$s.vilaaurora.test"
    cmd_issue edge "edge-$s" "DNS:edge-$s"
    for d in ${DEVICES[$s]}; do cmd_issue device "$s-$d"; done
  done
  cmd_issue server ingest "DNS:ingest,DNS:ingest.vilaaurora.test"
  cmd_issue server painel "DNS:painel,DNS:painel.vilaaurora.test,DNS:localhost"
  cmd_issue client soar
  cmd_issue client painel-client
  # dispositivo "intruso" para demonstrar recusa (certificado será revogado na demo)
  cmd_issue device escola-sensor-intruso
}

cmd_list() {
  awk -F'\t' '{ match($6,/CN=[^\/]+/); printf "%s  %s  %s\n", $1, $4, substr($6,RSTART+3,RLENGTH-3) }' "$PKI_OUT/issuing/index.txt"
}

case "${1:-}" in
  init)      cmd_init ;;
  issue)     shift; cmd_issue "$@" ;;
  revoke)    shift; cmd_revoke "$@" ;;
  rotate)    shift; cmd_rotate "$@" ;;
  crl)       cmd_crl ;;
  bootstrap) cmd_bootstrap ;;
  list)      cmd_list ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
