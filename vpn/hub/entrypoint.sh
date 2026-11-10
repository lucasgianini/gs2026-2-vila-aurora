#!/usr/bin/env bash
# Hub VPN da nuvem: concentra túneis das bordas (fibra/4G) e dos administradores
# e aplica a política de segmentação entre segmentos (RT-06/RT-07).
set -euo pipefail
ifc() { ip -o -4 addr | awk -v p="$1" '$4 ~ "^"p {print $2; exit}'; }
IF_FIBRA=$(ifc 172.30.10.); IF_4G=$(ifc 172.30.20.); IF_NET=$(ifc 172.30.99.)
IF_CLOUD=$(ifc 172.30.30.); IF_ADMIN=$(ifc 172.30.40.)
echo "[hub] fibra=$IF_FIBRA 4g=$IF_4G internet=$IF_NET cloud=$IF_CLOUD admin=$IF_ADMIN"

for i in wg0 wg1 wg2; do
  ip link add "$i" type wireguard
  wg setconf "$i" <(grep -vE '^(Address)' "/vpn/hub-$i.conf")
  ip addr add "$(awk '/^Address/{print $3}' "/vpn/hub-$i.conf")" dev "$i"
  ip link set "$i" up
done

# ---------------- política de firewall (padrão: negar) ----------------
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -N ADMIN_IN;  iptables -N ADMIN_FWD;  iptables -N BLOCKLIST
iptables -A INPUT -j BLOCKLIST
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# underlay: somente WireGuard, cada porta só na rede correspondente
iptables -A INPUT -i "$IF_FIBRA" -p udp --dport 51820 -j ACCEPT
iptables -A INPUT -i "$IF_4G"    -p udp --dport 51821 -j ACCEPT
iptables -A INPUT -i "$IF_NET"   -p udp --dport 51822 -j ACCEPT
# túneis das bordas: apenas o ingest (mTLS)
iptables -A INPUT -i wg0 -p tcp --dport 8443 -j ACCEPT
iptables -A INPUT -i wg1 -p tcp --dport 8443 -j ACCEPT
# admins: portal MFA sempre; o resto só após MFA (regras dinâmicas em ADMIN_IN/ADMIN_FWD)
iptables -A INPUT -i wg2 -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -i wg2 -j ADMIN_IN
# API de controle do SOAR (mTLS, só pela rede da nuvem)
iptables -A INPUT -i "$IF_CLOUD" -p tcp --dport 9000 -j ACCEPT
iptables -A INPUT -j NFLOG --nflog-prefix "VA-DROP-IN" 2>/dev/null || true
# encaminhamento: só admin autenticado -> segmento admin (dashboard do SIEM)
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i wg2 -o "$IF_ADMIN" -j ADMIN_FWD
iptables -t nat -A POSTROUTING -s 10.90.0.0/24 -o "$IF_ADMIN" -j MASQUERADE
# bordas nunca falam entre si nem com admins pelo hub (FORWARD padrão DROP)

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
export IF_FIBRA IF_4G IF_NET IF_CLOUD IF_ADMIN
exec python3 /opt/hub/portal.py
