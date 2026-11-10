#!/usr/bin/env bash
# "Notebook do administrador": cliente WireGuard + proxy SOCKS em 127.0.0.1:1080 do host.
# O navegador do host usa o SOCKS => todo acesso administrativo passa pelo túnel.
set -euo pipefail
C="/vpn/admin-$ADMIN_USER.conf"
ip link add wg0 type wireguard
wg setconf wg0 <(grep -vE '^Address' "$C")
ip addr add "$(awk '/^Address/{print $3}' "$C")" dev wg0
ip link set wg0 up
for n in $(awk -F' = ' '/^AllowedIPs/{print $2}' "$C" | tr ',' ' '); do ip route add "$n" dev wg0 2>/dev/null || true; done
echo "[laptop] túnel de $ADMIN_USER ativo"
exec sockd -f /opt/laptop/sockd.conf
