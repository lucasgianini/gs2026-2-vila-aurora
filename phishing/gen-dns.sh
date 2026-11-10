#!/usr/bin/env bash
# Gera chave DKIM e a zona DNS do domínio fictício vilaaurora.test (RT-10). Chave privada em secrets/ (fora do git).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p secrets/dkim phishing/out
K=secrets/dkim/va2026.key
[[ -f $K ]] || openssl genrsa -out $K 2048 2>/dev/null
chmod 644 $K   # lido pelo container do remetente; diretório secrets/ fora do git
P=$(openssl rsa -in $K -pubout 2>/dev/null | grep -v -- '-----' | tr -d '\n')
SER=$(date +%Y%m%d)01
# TXT longo dividido em pedaços de até 255 caracteres
CH=$(echo "v=DKIM1; k=rsa; p=$P" | fold -w 250 | sed 's/.*/"&"/' | tr '\n' ' ')
cat > phishing/out/db.vilaaurora.test <<ZONE
\$ORIGIN vilaaurora.test.
\$TTL 300
@        IN SOA ns.vilaaurora.test. hostmaster.vilaaurora.test. ($SER 3600 600 86400 300)
@        IN NS  ns.vilaaurora.test.
ns       IN A   172.30.50.2
mail     IN A   172.30.50.10
@        IN MX  10 mail.vilaaurora.test.
; SPF: só o servidor de e-mail oficial pode enviar; o resto falha (-all)
@        IN TXT "v=spf1 ip4:172.30.50.10 -all"
; DKIM: seletor va2026 (RSA 2048)
va2026._domainkey IN TXT ( $CH)
; DMARC: falhou SPF e DKIM alinhados => quarentena; alinhamento estrito; relatórios agregados
_dmarc   IN TXT "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:dmarc-rua@vilaaurora.test; fo=1"
ZONE
cat > phishing/out/Corefile <<'CF'
vilaaurora.test:53 {
    file /zones/db.vilaaurora.test
    log
}
.:53 {
    log
}
CF
echo "[dns] zona gerada em phishing/out/"
