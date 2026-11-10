#!/usr/bin/env bash
# Abre sessão no painel corrigido (senha + TOTP) e grava cookies em $2. Uso: scripts/painel-login.sh <usuario> <cookiejar>
set -euo pipefail
cd "$(dirname "$0")/.."
U="$1"; J="$2"; B="${PAINEL_URL:-https://localhost:8443}"
PW=$(awk -v u="$U" '$1==u{sub("senha=","",$3);print $3}' secrets/operadores.txt)
csrf() { grep -oP 'name="csrf_token" value="\K[^"]+' | head -1; }
T=$(curl -sk -c "$J" -b "$J" "$B/login" | csrf)
curl -sk -c "$J" -b "$J" -o /dev/null --data-urlencode "csrf_token=$T" --data-urlencode "username=$U" --data-urlencode "password=$PW" "$B/login"
T=$(curl -sk -c "$J" -b "$J" "$B/login/mfa" | csrf)
curl -sk -c "$J" -b "$J" -o /dev/null -w "%{http_code}\n" --data-urlencode "csrf_token=$T" --data-urlencode "code=$(scripts/totp.sh "$U")" "$B/login/mfa"
