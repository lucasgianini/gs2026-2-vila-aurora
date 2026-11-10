#!/usr/bin/env bash
# Sidecar de rede da borda: túneis WireGuard (fibra e 4G) + firewall local (RT-03/06/07).
# O agente de borda compartilha este namespace de rede (network_mode: service:wg-<site>).
set -euo pipefail
ifc() { ip -o -4 addr | awk -v p="$1" '$4 ~ "^"p {print $2; exit}'; }
IF_FIBRA=$(ifc 172.30.10.); IF_4G=$(ifc 172.30.20.)
up() { # $1=iface $2=conf
  ip link add "$1" type wireguard
  wg setconf "$1" <(grep -vE '^Address' "$2")
  ip addr add "$(awk '/^Address/{print $3}' "$2")" dev "$1"
  ip link set "$1" up
  ip route add "$(awk '/^AllowedIPs/{print $3}' "$2")" dev "$1" 2>/dev/null || true
}
up wg0 "/vpn/edge-$SITE-fibra.conf"
up wg1 "/vpn/edge-$SITE-4g.conf"
# 4G: banda limitada (plano básico) — o agente só envia prioridade nesse link
tc qdisc add dev wg1 root tbf rate "${LTE_RATE:-512kbit}" burst 16kbit latency 300ms 2>/dev/null || true

iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# painel local: só pela LAN do espaço
LAN=$(ip -o -4 addr | awk '$4 ~ /^172\.31\./ {print $2; exit}')
[[ -n "$LAN" ]] && iptables -A INPUT -i "$LAN" -p tcp --dport 8080 -j ACCEPT
# nada entra pelos uplinks além das respostas (ESTABLISHED) — outras bordas na mesma WAN não alcançam esta
echo "[wg-$SITE] fibra=$IF_FIBRA 4g=$IF_4G lan=$LAN"
# utilitário para teste de caos: /opt/edge/link.sh fibra down|up
exec sleep infinity
