#!/usr/bin/env bash
# Usuários da VPN LEGADA = mesmas senhas do painel (reuso de credencial, como no INC-VA-0712)
set -euo pipefail
cd "$(dirname "$0")/.."
while IFS=$'\t' read -r u _role pw _rest; do
  pw="${pw#senha=}"
  printf '%s:%s\n' "$u" "$(printf '%s' "$pw" | sha256sum | cut -d' ' -f1)"
done < secrets/operadores.txt > vpn/out/legado-users
chmod 644 vpn/out/legado-users
echo "[legado] $(wc -l < vpn/out/legado-users) usuários"
