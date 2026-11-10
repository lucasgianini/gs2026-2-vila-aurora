"""Agente do nó de borda de um espaço comunitário.

Responsabilidades
- RT-01/02  Operar de forma autônoma: regras locais de controle e alarme rodam aqui,
            sem depender da nuvem (câmara fria, limites/agenda da bomba, alagamento, energia).
- RT-02     Store-and-forward: tudo vai para um outbox SQLite e é enviado em lotes
            idempotentes (edge, seq) quando houver link; reconcilia ao voltar.
- RT-03     Dois uplinks (fibra -> 4G). No 4G (modo degradado) só sobe o que é prioritário.
- RT-04     mTLS com certificado próprio no MQTT local e no HTTPS para a nuvem (+ CRL).
- RT-12     Logs estruturados JSON (arquivo + stdout) para o SIEM.
- RT-15     Intertravamentos de segurança: comandos remotos são validados localmente
            (agenda, nível mínimo) e rejeições geram evento para a regra de detecção (d).
- RT-19     Pseudonimização dos crachás (HMAC) antes de qualquer armazenamento/envio.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import paho.mqtt.client as mqtt

# ----------------------------------------------------------------- configuração
SITE = os.environ["SITE"]
EDGE_ID = f"edge-{SITE}"
BROKER = os.environ.get("BROKER_HOST", f"broker-{SITE}")
CERT_DIR = Path(os.environ.get("CERT_DIR", f"/certs/{EDGE_ID}"))
CRL_FILE = os.environ.get("CRL_FILE", "/crl/crl.pem")
# lista ordenada de uplinks: "fibra=https://ingest-fibra:8443,4g=https://ingest-4g:8443"
UPLINKS = [tuple(x.split("=", 1)) for x in os.environ.get("UPLINKS", "").split(",") if x]
DB_PATH = os.environ.get("DB_PATH", "/data/outbox.sqlite")
LOG_PATH = os.environ.get("LOG_PATH", "/var/log/vilaaurora/edge.jsonl")
PSEUDO_KEY = os.environ.get("PSEUDO_KEY", "").encode()
PUMP_WINDOWS = os.environ.get("PUMP_WINDOWS", "05:00-07:00,17:00-19:00")
FLUSH_EVERY = float(os.environ.get("FLUSH_EVERY_S", "5"))
BATCH = int(os.environ.get("BATCH", "200"))
MAX_OUTBOX = int(os.environ.get("MAX_OUTBOX", "500000"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

if not PSEUDO_KEY:
    raise SystemExit("PSEUDO_KEY ausente (defina no .env)")

# ----------------------------------------------------------------- logging JSON
Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
_logf = open(LOG_PATH, "a", buffering=1, encoding="utf-8")
_loglock = threading.Lock()
logging.basicConfig(level=logging.WARNING)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def log_event(event: str, severity: str = "info", **fields) -> None:
    rec = {"ts": utcnow(), "app": "va-edge", "host": EDGE_ID, "site": SITE,
           "event": event, "severity": severity, **fields}
    line = json.dumps(rec, ensure_ascii=False)
    with _loglock:
        _logf.write(line + "\n")
        print(line, flush=True)


def pseudonymize(badge: str) -> str:
    return "p_" + hmac.new(PSEUDO_KEY, badge.encode(), hashlib.sha256).hexdigest()[:16]


# ----------------------------------------------------------------- outbox
class Outbox:
    """Fila persistente. seq = rowid (monótono por borda) => idempotência na nuvem."""

    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS outbox(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL, device TEXT, ts TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS ix_prio ON outbox(priority, seq)")
        self.lock = threading.Lock()
        self.stats = {"enqueued": 0, "acked": 0, "dropped": 0}

    def put(self, kind: str, device: str | None, payload: dict, priority: int = 0) -> None:
        with self.lock:
            self.db.execute("INSERT INTO outbox(kind,device,ts,priority,payload) VALUES (?,?,?,?,?)",
                            (kind, device, payload.get("ts", utcnow()), priority, json.dumps(payload)))
            self.stats["enqueued"] += 1
            n = self.db.execute("SELECT count(*) FROM outbox").fetchone()[0]
            if n > MAX_OUTBOX:  # descarta a telemetria mais antiga, nunca alarmes/eventos
                cur = self.db.execute("DELETE FROM outbox WHERE seq IN (SELECT seq FROM outbox "
                                      "WHERE priority=0 ORDER BY seq LIMIT ?)", (n - MAX_OUTBOX,))
                self.stats["dropped"] += cur.rowcount
                log_event("outbox_overflow", "warning", dropped=cur.rowcount)

    def take(self, limit: int, only_priority: bool) -> list[tuple]:
        with self.lock:
            q = "SELECT seq,kind,device,ts,priority,payload FROM outbox "
            q += "WHERE priority>0 ORDER BY seq LIMIT ?" if only_priority else "ORDER BY seq LIMIT ?"
            return self.db.execute(q, (limit,)).fetchall()

    def ack(self, seqs: list[int]) -> None:
        if not seqs:
            return
        with self.lock:
            self.db.executemany("DELETE FROM outbox WHERE seq=?", [(s,) for s in seqs])
            self.stats["acked"] += len(seqs)

    def depth(self) -> int:
        with self.lock:
            return self.db.execute("SELECT count(*) FROM outbox").fetchone()[0]


outbox = Outbox(DB_PATH)

# ----------------------------------------------------------------- estado local
state: dict = {"devices": {}, "alarms": {}, "link": "offline", "pump_auto": True,
               "last_flush": None, "bytes_up": {}, "started": utcnow()}
state_lock = threading.Lock()


def parse_windows(spec: str) -> list[tuple[int, int]]:
    out = []
    for w in spec.split(","):
        a, b = w.strip().split("-")
        ha, ma = map(int, a.split(":"))
        hb, mb = map(int, b.split(":"))
        out.append((ha * 60 + ma, hb * 60 + mb))
    return out


schedule = parse_windows(PUMP_WINDOWS)


def in_window(windows=None) -> bool:
    t = datetime.now()
    m = t.hour * 60 + t.minute
    return any(a <= m < b for a, b in (windows or schedule))


def validate_schedule(windows: list[tuple[int, int]]) -> str | None:
    """Política local: a agenda nunca pode impedir o reabastecimento (lição do INC-VA-0712)."""
    total = sum(b - a for a, b in windows if b > a)
    if any(not (0 <= a < b <= 1440) for a, b in windows):
        return "janela inválida"
    if total < 120:
        return "agenda com menos de 2h/dia de bombeamento"
    return None


# ----------------------------------------------------------------- MQTT
mq = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=EDGE_ID, clean_session=False)
_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CERT_DIR / "ca.pem"))
_ctx.load_cert_chain(str(CERT_DIR / "cert.pem"), str(CERT_DIR / "key.pem"))
_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
mq.tls_set_context(_ctx)
mq.reconnect_delay_set(1, 30)


def send_cmd(device: str, action: str, origin: str, reason: str, cmd_id: str | None = None,
             **extra) -> None:
    cmd = {"id": cmd_id or str(uuid.uuid4()), "action": action, "origin": origin, "reason": reason,
           "ts": utcnow(), **extra}
    mq.publish(f"dev/{device}/cmd", json.dumps(cmd), qos=1)
    log_event("actuator_cmd", "info", device=device, action=action, origin=origin, reason=reason,
              cmd_id=cmd["id"])
    outbox.put("actuator_cmd", device, {"ts": cmd["ts"], **cmd, "device": device}, priority=1)


def raise_alarm(key: str, severity: str, message: str, **data) -> None:
    with state_lock:
        if key in state["alarms"]:
            return
        state["alarms"][key] = {"since": utcnow(), "severity": severity, "message": message, **data}
    log_event("local_alarm", severity, alarm=key, message=message, **data)
    mq.publish(f"site/{SITE}/alarm", json.dumps({"alarm": key, "severity": severity, "message": message}),
               qos=1, retain=True)
    outbox.put("alarm", data.get("device"), {"ts": utcnow(), "alarm": key, "severity": severity,
                                              "message": message, "state": "raised", **data}, priority=2)


def clear_alarm(key: str) -> None:
    with state_lock:
        if state["alarms"].pop(key, None) is None:
            return
    log_event("local_alarm_cleared", "info", alarm=key)
    mq.publish(f"site/{SITE}/alarm", b"", qos=1, retain=True)
    outbox.put("alarm", None, {"ts": utcnow(), "alarm": key, "state": "cleared"}, priority=2)


_cold_bad = {"n": 0}


def apply_rules(dev: str, kind: str, d: dict) -> None:
    """Regras de controle locais (RT-02). Valores alinhados ao plano de operação."""
    if kind == "camara-fria":                        # vacinas: faixa 2–8 °C
        t = d.get("temp_c")
        if t is not None and not (2.0 <= t <= 8.0):
            _cold_bad["n"] += 1
            if _cold_bad["n"] >= 2:
                raise_alarm(f"{dev}:temp", "critical", f"Câmara fria fora da faixa: {t} °C", device=dev,
                            value=t)
        else:
            _cold_bad["n"] = 0
            clear_alarm(f"{dev}:temp")

    elif kind == "nivel-reservatorio" and state["pump_auto"]:
        lvl = d.get("level_pct", 50)
        pump = f"{SITE}-bomba"
        pump_on = state["devices"].get(pump, {}).get("on", False)
        if lvl >= 95 and pump_on:
            send_cmd(pump, "off", "edge-rule", "nível máximo (proteção transbordo)")
        elif lvl <= 20 and not pump_on:                     # intertravamento: ignora agenda
            send_cmd(pump, "on", "edge-rule", "nível crítico (reabastecimento de segurança)")
        elif in_window() and lvl < 80 and not pump_on:
            send_cmd(pump, "on", "edge-rule", "janela agendada")
        elif not in_window() and pump_on and 25 < lvl < 95:
            send_cmd(pump, "off", "edge-rule", "fim da janela agendada")
        if lvl <= 15:
            raise_alarm(f"{dev}:low", "high", f"Reservatório baixo: {lvl}%", device=dev, value=lvl)
        elif lvl >= 30:
            clear_alarm(f"{dev}:low")

    elif kind == "alagamento":
        w = d.get("water_cm", 0)
        if w >= 10:
            raise_alarm(f"{dev}:flood", "critical", f"Alagamento detectado: {w} cm", device=dev, value=w)
        elif w < 5:
            clear_alarm(f"{dev}:flood")

    elif kind == "energia":
        soc = d.get("soc_pct", 100)
        gen = f"{SITE}-gerador"
        gen_on = state["devices"].get(gen, {}).get("on", False)
        if gen in state["devices"] or SITE == "abrigo":
            if soc <= 25 and not gen_on:
                send_cmd(gen, "on", "edge-rule", "bateria baixa")
            elif soc >= 80 and gen_on:
                send_cmd(gen, "off", "edge-rule", "bateria recuperada")
        if soc <= 15:
            raise_alarm(f"{dev}:soc", "high", f"Bateria baixa: {soc}%", device=dev, value=soc)
        elif soc >= 30:
            clear_alarm(f"{dev}:soc")


def on_connect(c, _u, _f, rc, _p):
    log_event("mqtt_connected", "info", rc=str(rc))
    c.subscribe([("dev/+/telemetry", 1), ("dev/+/state", 1), ("dev/+/event", 1)])


def on_disconnect(_c, _u, _f, rc, _p):
    log_event("mqtt_disconnected", "warning", rc=str(rc))


def on_message(_c, _u, msg):
    try:
        d = json.loads(msg.payload)
    except json.JSONDecodeError:
        log_event("mqtt_bad_payload", "warning", topic=msg.topic)
        return
    _, dev, sub = msg.topic.split("/", 2)
    if d.get("device") != dev:  # payload não pode alegar outra identidade
        log_event("mqtt_identity_mismatch", "high", topic=msg.topic, claimed=d.get("device"))
        return
    kind = d.get("type", "?")
    if sub == "event" and "badge" in d:
        d["badge"] = pseudonymize(d.pop("badge"))  # RT-19: crachá cru nunca sai do processo
    with state_lock:
        cur = state["devices"].setdefault(dev, {"type": kind})
        cur.update({k: v for k, v in d.items() if k not in ("device", "site")})
        cur["last_seen"] = utcnow()
    if sub == "telemetry":
        apply_rules(dev, kind, d)
        outbox.put("telemetry", dev, d, priority=0)
    elif sub == "state":
        outbox.put("state", dev, d, priority=1)
    elif sub == "event":
        outbox.put("event", dev, d, priority=1)


mq.on_connect, mq.on_disconnect, mq.on_message = on_connect, on_disconnect, on_message

# ----------------------------------------------------------------- uplink (nuvem)
_https = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CERT_DIR / "ca.pem"))
_https.load_cert_chain(str(CERT_DIR / "cert.pem"), str(CERT_DIR / "key.pem"))
_https.minimum_version = ssl.TLSVersion.TLSv1_3
if Path(CRL_FILE).exists():
    _https.load_verify_locations(CRL_FILE)
    _https.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
http = httpx.Client(verify=_https, timeout=httpx.Timeout(5.0, connect=3.0))


def set_link(name: str) -> None:
    with state_lock:
        old = state["link"]
        state["link"] = name
    if old != name:
        log_event("wan_link_change", "warning" if name != UPLINKS[0][0] else "info", previous=old,
                  current=name, outbox_depth=outbox.depth())


def try_uplinks(fn):
    """Executa fn(base_url, degraded) no primeiro uplink que responder."""
    for i, (name, base) in enumerate(UPLINKS):
        try:
            http.get(f"{base}/healthz", timeout=2.0).raise_for_status()
            r = fn(base, i > 0)
            set_link(name)
            return r
        except (httpx.HTTPError, ssl.SSLError, OSError):
            continue
    set_link("offline")
    return None


def flush_once() -> int:
    def go(base: str, degraded: bool) -> int:
        sent = 0
        while True:
            rows = outbox.take(BATCH, only_priority=degraded)
            if not rows:
                return sent
            body = {"edge": EDGE_ID, "site": SITE, "degraded": degraded, "items": [
                {"seq": s, "kind": k, "device": dv, "ts": ts, "priority": p, "data": json.loads(pl)}
                for s, k, dv, ts, p, pl in rows]}
            raw = json.dumps(body).encode()
            r = http.post(f"{base}/api/v1/ingest", content=raw, headers={"content-type": "application/json"})
            r.raise_for_status()
            outbox.ack(r.json().get("acked", []))
            with state_lock:
                key = "4g" if degraded else "fibra"
                state["bytes_up"][key] = state["bytes_up"].get(key, 0) + len(raw)
                state["last_flush"] = utcnow()
            sent += len(rows)
            if len(rows) < BATCH:
                return sent

    return try_uplinks(go) or 0


def poll_commands() -> None:
    """Comandos remotos (painel/SOAR) — sempre passam pelos intertravamentos locais."""
    def go(base: str, _degraded: bool):
        r = http.get(f"{base}/api/v1/commands", params={"edge": EDGE_ID})
        r.raise_for_status()
        return r.json().get("commands", [])

    for c in try_uplinks(go) or []:
        ok, why = handle_remote(c)
        result = {"status": "applied" if ok else "rejected", "reason": why, "ts": utcnow()}
        try_uplinks(lambda base, _d: http.post(f"{base}/api/v1/commands/{c['id']}/result",
                                               json=result).raise_for_status())


def handle_remote(c: dict) -> tuple[bool, str]:
    action, dev = c.get("action"), c.get("device", "")
    who = c.get("requested_by", "?")
    base = {"cmd_id": c.get("id"), "device": dev, "action": action, "requested_by": who,
            "approved_by": c.get("approved_by")}
    if not dev.startswith(f"{SITE}-") and action != "set_schedule":
        reason = "dispositivo de outro espaço"
    elif action == "set_schedule":
        global schedule
        try:
            win = parse_windows(c["windows"])
            reason = validate_schedule(win)
        except (KeyError, ValueError) as e:
            reason, win = f"formato inválido: {e}", None
        if reason is None:
            schedule = win
            log_event("schedule_changed", "notice", windows=c["windows"], **base)
            outbox.put("audit", None, {"ts": utcnow(), "event": "schedule_changed", **base,
                                       "windows": c["windows"]}, priority=1)
            return True, "ok"
    elif dev.endswith("-bomba") and action == "off":
        lvl = next((v.get("level_pct") for k, v in state["devices"].items()
                    if v.get("type") == "nivel-reservatorio"), None)
        if lvl is not None and lvl < 30:
            reason = f"intertravamento: nível {lvl}% < 30%"
        elif not c.get("approved_by"):
            reason = "ação de alto impacto sem aprovação humana"
        else:
            reason = None
    elif action in ("on", "off", "safe_mode"):
        reason = None
    else:
        reason = "ação desconhecida"

    if reason:
        log_event("actuator_cmd_rejected", "high", reason=reason, **base)
        outbox.put("audit", dev, {"ts": utcnow(), "event": "actuator_cmd_rejected", "reason": reason, **base},
                   priority=2)
        return False, reason
    if action == "safe_mode":   # RT-15: atuador em modo seguro -> automação local assume
        state["pump_auto"] = True
        log_event("safe_mode", "notice", **base)
        return True, "ok"
    send_cmd(dev, action, f"remote:{who}", c.get("reason", "comando remoto"), cmd_id=c.get("id"),
             approved_by=c.get("approved_by"))
    return True, "ok"


def uplink_loop() -> None:
    while True:
        try:
            flush_once()
            poll_commands()
        except Exception as e:  # noqa: BLE001 — a borda nunca pode morrer por causa da nuvem
            log_event("uplink_error", "warning", error=repr(e)[:300])
        time.sleep(FLUSH_EVERY)


# ----------------------------------------------------------------- painel local (supervisão offline)
class Local(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):  # noqa: N802
        with state_lock:
            snap = json.loads(json.dumps(state))
        snap.update(edge=EDGE_ID, outbox_depth=outbox.depth(), outbox_stats=outbox.stats,
                    schedule=PUMP_WINDOWS if schedule == parse_windows(PUMP_WINDOWS) else str(schedule))
        if self.path.startswith("/api/status"):
            body, ctype = json.dumps(snap, ensure_ascii=False).encode(), "application/json"
        elif self.path == "/healthz":
            body, ctype = b"ok", "text/plain"
        else:
            body, ctype = render(snap).encode(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def render(s: dict) -> str:
    from html import escape
    alarms = "".join(f"<li><strong>{escape(a['severity'].upper())}</strong>: {escape(a['message'])}</li>"
                     for a in s["alarms"].values()) or "<li>Nenhum alarme ativo.</li>"
    rows = "".join(f"<tr><th scope='row'>{escape(k)}</th><td>{escape(json.dumps({x: y for x, y in v.items() if x not in ('ts', 'type')}, ensure_ascii=False))}</td></tr>"
                   for k, v in sorted(s["devices"].items()))
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="10">
<title>Painel local – {escape(SITE)}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;margin:1rem;color:#111;background:#fff}}
table{{border-collapse:collapse}}td,th{{border:1px solid #555;padding:.3rem .5rem;text-align:left}}
.ok{{color:#0a5d00}}.warn{{color:#8a1c00}}</style></head><body>
<h1>Painel local – {escape(SITE)}</h1>
<p>Internet: <strong class="{'ok' if s['link'] == 'fibra' else 'warn'}">{escape(s['link'])}</strong>.
Dados aguardando envio: {s['outbox_depth']}.</p>
<h2>Alarmes</h2><ul>{alarms}</ul>
<h2>Equipamentos</h2><table><tbody>{rows}</tbody></table></body></html>"""


def main() -> None:
    log_event("edge_start", "info", uplinks=[n for n, _ in UPLINKS], pump_windows=PUMP_WINDOWS)
    mq.connect_async(BROKER, 8883, keepalive=30)
    mq.loop_start()
    threading.Thread(target=uplink_loop, daemon=True, name="uplink").start()
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Local).serve_forever()


if __name__ == "__main__":
    main()
