"""Agente de revogação da CA intermediária (RT-05/RT-15).

Única operação exposta: revogar certificado de DISPOSITIVO de campo e regenerar a CRL.
- mTLS obrigatório; só o cliente CN=soar é aceito.
- Nunca revoga servidores, bordas ou CAs (só CNs "<espaço>-<dispositivo>").
- A raiz continua offline (fora deste container); aqui fica apenas a intermediária.
"""
import json
import re
import ssl
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEVICE_CN = re.compile(r"^(centro|escola|ubs|horta|abrigo)-[a-z0-9-]{2,40}$")
LOG = open("/var/log/vilaaurora/pki.jsonl", "a", buffering=1)


def log(event, **kw):
    LOG.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                          "app": "va-pki", "event": event, **kw}) + "\n")


class H(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_POST(self):  # noqa: N802
        cert = self.connection.getpeercert() or {}
        cn = dict(x[0] for x in cert.get("subject", ())).get("commonName")
        if cn != "soar" or self.path != "/revoke":
            log("pki_denied", client=cn, path=self.path)
            return self._json(403, {"error": "forbidden"})
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0) or 0)) or b"{}")
        target = str(body.get("cn", ""))
        if not DEVICE_CN.fullmatch(target):
            log("pki_refused", target=target, reason="não é dispositivo de campo")
            return self._json(400, {"error": "somente certificados de dispositivo"})
        p = subprocess.run(["/pki/pki.sh", "revoke", target, body.get("reason", "keyCompromise")],
                           capture_output=True, text=True)
        ok = p.returncode == 0
        log("pki_revoke", target=target, ok=ok, detail=(p.stderr or p.stdout)[-200:])
        self._json(200 if ok else 409, {"result": f"certificado {target} revogado; CRL atualizada" if ok
                                        else f"falhou: {(p.stderr or p.stdout)[-120:]}"})


srv = ThreadingHTTPServer(("0.0.0.0", 9100), H)
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile="/pki/out/certs/pki-agent/ca.pem")
ctx.load_cert_chain("/pki/out/certs/pki-agent/cert.pem", "/pki/out/certs/pki-agent/key.pem")
ctx.verify_mode = ssl.CERT_REQUIRED
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
