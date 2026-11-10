"""Hub VPN — portal de MFA, monitor de sessões e API de resposta (RT-06, RT-13a, RT-15).

1. Portal MFA (http://10.90.0.1:8080, só dentro do túnel wg2):
   o túnel prova a POSSE da chave do dispositivo; o TOTP prova o segundo fator.
   O IP do túnel identifica a chave => o usuário digitado tem de ser o dono da chave.
   Sucesso libera o painel/SIEM para aquele IP por SESSION_H horas (regras iptables).
2. Monitor: lê `wg show all dump` e registra cada handshake novo (peer, endpoint, horário)
   em JSON para o SIEM — base da regra (a) "login VPN anômalo".
3. API de controle (https://<cloud>:9000, mTLS, só CN=soar): encerrar sessão, bloquear IP.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ssl
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

LOG = open("/var/log/vilaaurora/vpn.jsonl", "a", buffering=1)
PEERS = json.load(open("/vpn/peers.json"))                       # pubkey -> nome
ADMINS = {}                                                       # ip -> (user, totp)
for line in open("/vpn/admins.tsv"):
    u, ip, secret = line.split()
    ADMINS[ip] = (u, secret)
SESSION_H = float(os.environ.get("SESSION_H", "8"))
sessions: dict[str, dict] = {}          # ip -> {user, expires}
lock = threading.Lock()
fails: dict[str, list[float]] = {}


def log(event, severity="info", **kw):
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "app": "va-vpn",
           "host": "vpn-hub", "event": event, "severity": severity, **kw}
    LOG.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(json.dumps(rec, ensure_ascii=False), flush=True)


def ipt(*args, check=True):
    return subprocess.run(["iptables", *args], check=check, capture_output=True, text=True)


def totp_ok(secret: str, code: str) -> bool:
    key = base64.b32decode(secret)
    now = int(time.time()) // 30
    for c in (now - 1, now, now + 1):
        h = hmac.new(key, struct.pack(">Q", c), hashlib.sha1).digest()
        o = h[-1] & 15
        if hmac.compare_digest("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000), code):
            return True
    return False


def grant(ip: str, user: str):
    with lock:
        revoke(ip, reason="renovação", quiet=True)
        tag = f"mfa:{user}"
        ipt("-A", "ADMIN_IN", "-s", ip, "-p", "tcp", "--dport", "443", "-m", "comment", "--comment", tag, "-j", "ACCEPT")
        ipt("-A", "ADMIN_FWD", "-s", ip, "-p", "tcp", "-m", "multiport", "--dports", "443,5601",
            "-m", "comment", "--comment", tag, "-j", "ACCEPT")
        sessions[ip] = {"user": user, "expires": time.time() + SESSION_H * 3600}


def revoke(ip: str, reason: str, quiet=False):
    for chain in ("ADMIN_IN", "ADMIN_FWD"):
        rules = ipt("-S", chain).stdout.splitlines()
        for r in rules:
            if f"-s {ip}/32" in r:
                ipt(*(["-D"] + r.split()[1:]), check=False)
    s = sessions.pop(ip, None)
    if s and not quiet:
        log("vpn_session_revoked", "notice", user=s["user"], tunnel_ip=ip, reason=reason)
    # derruba conexões TCP já estabelecidas daquele IP
    subprocess.run(["conntrack", "-D", "-s", ip], capture_output=True)


def expiry_loop():
    while True:
        now = time.time()
        for ip, s in list(sessions.items()):
            if s["expires"] < now:
                with lock:
                    revoke(ip, reason="expirada")
        time.sleep(30)


def monitor_loop():
    seen: dict[tuple, int] = {}
    while True:
        out = subprocess.run(["wg", "show", "all", "dump"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) != 9:   # linhas de interface têm 5 campos
                continue
            ifc, pub, _psk, endpoint, allowed, hs, rx, tx, _ka = f
            hs = int(hs)
            if hs == 0:
                continue
            k = (ifc, pub)
            if seen.get(k) != hs:
                first = k not in seen or hs - seen.get(k, 0) > 180   # sessão nova (não só rekey)
                seen[k] = hs
                if first:
                    ep_ip = endpoint.rsplit(":", 1)[0]
                    log("vpn_handshake", "info", iface=ifc, peer=PEERS.get(pub, "desconhecido"),
                        endpoint=endpoint, src_ip=ep_ip, tunnel_ip=allowed.split("/")[0],
                        hour_local=datetime.now().hour, rx=int(rx), tx=int(tx))
        time.sleep(5)


PAGE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verificação da VPN – Vila Aurora</title><style>body{{font:17px/1.5 system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;color:#111}}
label{{display:block;font-weight:600;margin-top:1rem}}input,button{{font:inherit;padding:.4rem}}button{{margin-top:1rem;background:#0b4f8a;color:#fff;border:0;padding:.5rem 1rem}}
:focus-visible{{outline:3px solid #ffbf47}}.msg{{padding:.5rem;border-left:6px solid #7a4a00;background:#fff4ce}}</style></head><body>
<h1>Verificação da VPN</h1><p>Seu computador já está no túnel. Confirme que é você com o código do aplicativo autenticador.</p>
{msg}<form method="post"><label for="u">Usuário</label><input id="u" name="user" required autocomplete="username">
<label for="c">Código de 6 números</label><input id="c" name="code" inputmode="numeric" pattern="[0-9]{{6}}" required autocomplete="one-time-code">
<div><button type="submit">Liberar acesso</button></div></form></body></html>"""


class Portal(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, html):
        b = html.encode()
        self.send_response(code)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):  # noqa: N802
        ip = self.client_address[0]
        s = sessions.get(ip)
        msg = f"<p class='msg' role='status'>Acesso liberado para {s['user']}.</p>" if s else ""
        self._send(200, PAGE.format(msg=msg))

    def do_POST(self):  # noqa: N802
        ip = self.client_address[0]
        n = int(self.headers.get("content-length", 0) or 0)
        form = parse_qs(self.rfile.read(min(n, 2048)).decode(errors="replace"))
        user = form.get("user", [""])[0].strip().lower()[:32]
        code = "".join(ch for ch in form.get("code", [""])[0] if ch.isdigit())[:6]
        recent = [t for t in fails.get(ip, []) if t > time.time() - 300]
        if len(recent) >= 5:
            log("vpn_mfa_locked", "high", tunnel_ip=ip, user=user)
            return self._send(429, PAGE.format(msg="<p class='msg' role='alert'>Muitas tentativas. Aguarde 5 minutos.</p>"))
        owner = ADMINS.get(ip)
        if not owner or owner[0] != user or not totp_ok(owner[1], code):
            fails[ip] = recent + [time.time()]
            log("vpn_mfa_failure", "warning", tunnel_ip=ip, user=user, key_owner=owner[0] if owner else None)
            return self._send(401, PAGE.format(msg="<p class='msg' role='alert'>Usuário ou código inválido.</p>"))
        fails.pop(ip, None)
        grant(ip, user)
        log("vpn_mfa_success", "info", tunnel_ip=ip, user=user, hour_local=datetime.now().hour,
            expires_h=SESSION_H)
        self._send(200, PAGE.format(msg=f"<p class='msg' role='status'>Acesso liberado por {SESSION_H:g} h.</p>"))


class Control(BaseHTTPRequestHandler):
    """API do SOAR: POST /revoke {"user"|"tunnel_ip"} | POST /block {"ip"} | GET /sessions"""

    def log_message(self, *_):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _auth(self) -> bool:
        cert = self.connection.getpeercert() or {}
        cn = dict(x[0] for x in cert.get("subject", ())).get("commonName")
        if cn != "soar":
            log("control_denied", "high", cn=cn)
            self._json(403, {"error": "forbidden"})
            return False
        return True

    def do_GET(self):  # noqa: N802
        if self._auth():
            self._json(200, {"sessions": sessions})

    def do_POST(self):  # noqa: N802
        if not self._auth():
            return
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0) or 0)) or b"{}")
        if self.path == "/revoke":
            ips = [ip for ip, s in sessions.items() if s["user"] == body.get("user")]
            if body.get("tunnel_ip"):
                ips.append(body["tunnel_ip"])
            with lock:
                for ip in ips:
                    revoke(ip, reason=body.get("reason", "soar"))
            return self._json(200, {"revoked": ips})
        if self.path == "/block":
            ip = body.get("ip", "")
            if not ip or ip.startswith(("10.", "172.30.10.", "172.30.20.")):   # nunca bloquear bordas
                return self._json(400, {"error": "ip inválido/protegido"})
            ipt("-I", "BLOCKLIST", "-s", ip, "-m", "comment", "--comment", "soar", "-j", "DROP")
            subprocess.run(["conntrack", "-D", "-s", ip], capture_output=True)
            log("vpn_ip_blocked", "notice", ip=ip, reason=body.get("reason", "soar"))
            return self._json(200, {"blocked": ip})
        self._json(404, {"error": "not found"})


def main():
    threading.Thread(target=expiry_loop, daemon=True).start()
    threading.Thread(target=monitor_loop, daemon=True).start()
    ctl = ThreadingHTTPServer((os.environ.get("CONTROL_BIND", "0.0.0.0"), 9000), Control)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile="/certs/ca.pem")
    ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctl.socket = ctx.wrap_socket(ctl.socket, server_side=True)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    log("vpn_hub_start", peers=len(PEERS))
    ThreadingHTTPServer(("10.90.0.1", 8080), Portal).serve_forever()


if __name__ == "__main__":
    main()
