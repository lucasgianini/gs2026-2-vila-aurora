#!/usr/bin/env bash
# VPN LEGADA (reprodução do INC-VA-0712): OpenVPN autenticado SÓ por usuário/senha,
# sem MFA, sem certificado de cliente, com rota plana para a rede da nuvem. NÃO usar fora do lab.
set -euo pipefail
mkdir -p /dev/net; [[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200
IF_CLOUD=$(ip -o -4 addr | awk '$4 ~ /^172\.30\.30\./ {print $2; exit}')
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o "$IF_CLOUD" -j MASQUERADE
cat > /tmp/server.conf <<CONF
port 1194
proto udp
dev tun
topology subnet
server 10.99.0.0 255.255.255.0
push "route 172.30.30.0 255.255.255.0"
ca /certs/ca.pem
cert /certs/cert.pem
key /certs/key.pem
dh none
verify-client-cert none
username-as-common-name
auth-user-pass-verify /opt/legado/check.sh via-file
script-security 2
keepalive 10 60
status /tmp/status.log 10
log-append /var/log/vilaaurora/vpn-legado.log
verb 3
CONF
exec openvpn --config /tmp/server.conf
