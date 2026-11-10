#!/usr/bin/env bash
# Simula queda/retorno de um uplink no underlay. Uso: link.sh fibra|4g down|up
set -euo pipefail
case "$1" in fibra) NET=172.30.10.;; 4g) NET=172.30.20.;; *) exit 2;; esac
IF=$(ip -o -4 addr | awk -v p="$NET" '$4 ~ "^"p {print $2; exit}')
if [[ "$2" == down ]]; then
  iptables -C OUTPUT -o "$IF" -j DROP 2>/dev/null || iptables -I OUTPUT -o "$IF" -j DROP
  iptables -C INPUT -i "$IF" -j DROP 2>/dev/null || iptables -I INPUT -i "$IF" -j DROP
else
  iptables -D OUTPUT -o "$IF" -j DROP 2>/dev/null || true
  iptables -D INPUT -i "$IF" -j DROP 2>/dev/null || true
fi
echo "$1 $2"
