#!/usr/bin/env bash
# Gera chaves e configurações WireGuard do laboratório (RT-06). Saída em vpn/out/ (fora do git).
#
#   wg0  10.80.0.0/24  bordas via FIBRA   (hub 172.30.10.2:51820)
#   wg1  10.81.0.0/24  bordas via 4G      (hub 172.30.20.2:51821)
#   wg2  10.90.0.0/24  administradores    (hub 172.30.99.2:51822) — exige MFA no portal após o túnel
#
# Uma chave por borda e por pessoa (nada compartilhado). Idempotente.
set -euo pipefail
cd "$(dirname "$0")"
OUT=out; mkdir -p "$OUT"; umask 077
SITES=(centro escola ubs horta abrigo)
ADMINS=(marta.coord bruno.coord carla.tec diego.op elisa.aud)

key() { [[ -f "$OUT/$1.key" ]] || wg genkey > "$OUT/$1.key"; wg pubkey < "$OUT/$1.key" > "$OUT/$1.pub"; }
key hub
for s in "${SITES[@]}"; do key "edge-$s"; done
for a in "${ADMINS[@]}"; do key "admin-$a"; done
HUBPUB=$(cat "$OUT/hub.pub")

hub_iface() { # $1=nome $2=prefixo $3=porta
  { echo "[Interface]"; echo "Address = $2.1/24"; echo "ListenPort = $3"
    echo "PrivateKey = $(cat "$OUT/hub.key")"; echo; } > "$OUT/hub-$1.conf"
}
hub_iface wg0 10.80.0 51820; hub_iface wg1 10.81.0 51821; hub_iface wg2 10.90.0 51822

peers='{'
i=11
for s in "${SITES[@]}"; do
  for pair in "wg0 10.80.0 172.30.10.2 51820 fibra" "wg1 10.81.0 172.30.20.2 51821 4g"; do
    read -r ifc pre ep port name <<<"$pair"
    printf '[Peer]\n# edge-%s\nPublicKey = %s\nAllowedIPs = %s.%d/32\n\n' "$s" "$(cat "$OUT/edge-$s.pub")" "$pre" $i >> "$OUT/hub-$ifc.conf"
    cat > "$OUT/edge-$s-$name.conf" <<EOF
[Interface]
Address = $pre.$i/32
PrivateKey = $(cat "$OUT/edge-$s.key")

[Peer]
PublicKey = $HUBPUB
Endpoint = $ep:$port
AllowedIPs = $pre.1/32
PersistentKeepalive = 15
EOF
  done
  peers+="\"$(cat "$OUT/edge-$s.pub")\":\"edge-$s\","
  i=$((i+1))
done

i=11
: > "$OUT/admins.tsv"
for a in "${ADMINS[@]}"; do
  printf '[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = 10.90.0.%d/32\n\n' "$a" "$(cat "$OUT/admin-$a.pub")" $i >> "$OUT/hub-wg2.conf"
  cat > "$OUT/admin-$a.conf" <<EOF
[Interface]
Address = 10.90.0.$i/32
PrivateKey = $(cat "$OUT/admin-$a.key")

[Peer]
PublicKey = $HUBPUB
Endpoint = 172.30.99.2:51822
# split tunnel: só a rede administrativa passa pelo túnel
AllowedIPs = 10.90.0.1/32, 172.30.40.0/24
PersistentKeepalive = 25
EOF
  # segredo TOTP próprio da VPN (independente do painel)
  totp=$(grep -P "^$a\t" ../secrets/vpn-admins.txt 2>/dev/null | cut -f3 || true)
  [[ -n "$totp" ]] || totp=$(python3 -c 'import base64,os;print(base64.b32encode(os.urandom(20)).decode())')
  printf '%s\t10.90.0.%d\t%s\n' "$a" $i "$totp" >> "$OUT/admins.tsv"
  peers+="\"$(cat "$OUT/admin-$a.pub")\":\"$a\","
  i=$((i+1))
done
peers="${peers%,}}"
echo "$peers" > "$OUT/peers.json"
mkdir -p ../secrets && cp "$OUT/admins.tsv" ../secrets/vpn-admins.txt
chmod 644 "$OUT"/*.conf "$OUT"/*.json "$OUT"/*.tsv   # lidos por containers (uid diferente); pasta fora do git
echo "[vpn] configs em vpn/out/, TOTP da VPN em secrets/vpn-admins.txt"
