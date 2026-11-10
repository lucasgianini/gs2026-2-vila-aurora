#!/bin/sh
# Verificação de senha do sistema antigo: compara com a senha do painel (reuso de credencial).
u=$(sed -n 1p "$1"); p=$(sed -n 2p "$1")
hl=$(( ( $(date -u +%H | sed "s/^0//") + 21 ) % 24 ))   # hora local (UTC-3)
h=$(printf '%s' "$p" | sha256sum | cut -d' ' -f1)
if grep -q "^$u:$h$" /vpn-legado/users; then
  echo "$(date -u +%FT%TZ) LEGACY-VPN AUTH OK user=$u src=$untrusted_ip hour_local=$hl" >> /var/log/vilaaurora/vpn-legado.log; exit 0
fi
echo "$(date -u +%FT%TZ) LEGACY-VPN AUTH FAIL user=$u src=$untrusted_ip hour_local=$hl" >> /var/log/vilaaurora/vpn-legado.log; exit 1
