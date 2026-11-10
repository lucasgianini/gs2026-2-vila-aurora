# Funções comuns dos scripts de teste/demonstração (source scripts/lib.sh)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOCKS="${SOCKS:-127.0.0.1:1080}"           # notebook do admin (túnel wg2)
PAINEL="${PAINEL:-https://10.90.0.1}"
totp() { python3 -c "import hmac,hashlib,struct,time,base64,sys;k=base64.b32decode(sys.argv[1]);c=struct.pack('>Q',int(time.time())//30);h=hmac.new(k,c,hashlib.sha1).digest();o=h[-1]&15;print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))" "$1"; }
vpn_totp()    { totp "$(awk -v u="$1" '$1==u{print $3}' "$ROOT/secrets/vpn-admins.txt")"; }
painel_totp() { totp "$(awk -v u="$1" '$1==u{sub("totp=","",$4);print $4}' "$ROOT/secrets/operadores.txt")"; }
painel_pw()   { awk -v u="$1" '$1==u{sub("senha=","",$3);print $3}' "$ROOT/secrets/operadores.txt"; }
acurl() { curl -sk --socks5-hostname "$SOCKS" "$@"; }   # curl "pelo notebook do admin"
vpn_mfa() { acurl -o /dev/null -w '%{http_code}' -d "user=$1&code=$(vpn_totp "$1")" http://10.90.0.1:8080/; }
csrf() { grep -oP 'name="csrf_token" value="\K[^"]+' | head -1; }
painel_login() { # $1=usuario $2=cookiejar  (requer túnel com MFA do dono da chave)
  local T; T=$(acurl -c "$2" -b "$2" "$PAINEL/login" | csrf)
  acurl -c "$2" -b "$2" -o /dev/null --data-urlencode "csrf_token=$T" --data-urlencode "username=$1" \
    --data-urlencode "password=$(painel_pw "$1")" "$PAINEL/login"
  T=$(acurl -c "$2" -b "$2" "$PAINEL/login/mfa" | csrf)
  acurl -c "$2" -b "$2" -o /dev/null -w '%{http_code}' --data-urlencode "csrf_token=$T" \
    --data-urlencode "code=$(painel_totp "$1")" "$PAINEL/login/mfa"
}
psql_q() { docker compose -f "$ROOT/docker-compose.yml" exec -T db psql -U postgres -d vilaaurora -tAc "$1"; }
ok()   { printf '  [OK]   %s\n' "$*"; }
fail() { printf '  [FALHA] %s\n' "$*"; FAILS=$((${FAILS:-0}+1)); }
check() { # check "descrição" "esperado" "obtido"
  if [[ "$3" == "$2" ]]; then ok "$1 (=$3)"; else fail "$1 (esperado $2, obtido $3)"; fi; }
