# Imagem única: hub WireGuard, sidecar de borda e "notebook do admin"
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools-wg wireguard-tools-wg-quick iptables ip6tables iproute2 iproute2-tc conntrack-tools \
      python3 curl dante-server openvpn bash openssl
COPY hub/ /opt/hub/
COPY edge/ /opt/edge/
COPY laptop/ /opt/laptop/
COPY legado/ /opt/legado/
RUN chmod +x /opt/*/*.sh
