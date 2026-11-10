#!/usr/bin/env bash
# Mostra o código TOTP atual de um operador do laboratório (substitui o app autenticador na demo)
set -euo pipefail
u="${1:?uso: scripts/totp.sh <usuario>}"
s=$(awk -v u="$u" '$1==u{for(i=1;i<=NF;i++) if($i ~ /^totp=/){sub("totp=","",$i);print $i}}' "$(dirname "$0")/../secrets/operadores.txt")
python3 -c "import hmac,hashlib,struct,time,base64,sys;k=base64.b32decode(sys.argv[1]);c=struct.pack('>Q',int(time.time())//30);h=hmac.new(k,c,hashlib.sha1).digest();o=h[-1]&15;print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))" "$s"
