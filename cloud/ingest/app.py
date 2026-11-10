"""Ingest da nuvem: recebe lotes das bordas e entrega comandos (RT-01/02/04).

Fica atrás do nginx, que termina o mTLS e repassa a identidade verificada do cliente
(CN/OU do certificado) em cabeçalhos que só ele pode definir (o app só escuta na rede interna).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from flask import Flask, abort, g, jsonify, request
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

app = Flask(__name__)
pool = ConnectionPool(
    f"host={os.environ.get('DB_HOST', 'db')} dbname=vilaaurora user=va_ingest "
    f"password={os.environ['DB_INGEST_PASSWORD']} application_name=ingest",
    min_size=1, max_size=8, open=True)
LOG = open(os.environ.get("LOG_PATH", "/var/log/vilaaurora/ingest.jsonl"), "a", buffering=1)


def log(event: str, severity: str = "info", **kw) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "app": "va-ingest",
           "event": event, "severity": severity, **kw}
    LOG.write(json.dumps(rec, ensure_ascii=False) + "\n")


@app.before_request
def identity():
    if request.path == "/healthz":
        return
    g.cn = request.headers.get("X-Client-CN", "")
    g.ou = request.headers.get("X-Client-OU", "")
    if request.headers.get("X-Client-Verify") != "SUCCESS" or not g.cn:
        log("auth_denied", "high", path=request.path, verify=request.headers.get("X-Client-Verify"))
        abort(401)


@app.get("/healthz")
def healthz():
    return "ok"


def require_edge(edge: str) -> None:
    if g.ou != "edge" or g.cn != edge:
        log("identity_mismatch", "high", cn=g.cn, ou=g.ou, claimed=edge, path=request.path)
        abort(403)


@app.post("/api/v1/ingest")
def ingest():
    body = request.get_json(force=True, silent=True) or {}
    edge, items = body.get("edge", ""), body.get("items", [])
    require_edge(edge)
    if not isinstance(items, list) or len(items) > 1000:
        abort(400)
    site = edge.removeprefix("edge-")
    degraded = bool(body.get("degraded"))
    acked, new = [], 0
    with pool.connection() as conn, conn.cursor() as cur:
        for it in items:
            seq, kind, dev, ts, data = it["seq"], it["kind"], it.get("device"), it["ts"], it["data"]
            if dev and not dev.startswith(f"{site}-"):     # borda só fala pelos próprios dispositivos
                log("foreign_device", "high", edge=edge, device=dev)
                acked.append(seq)
                continue
            if kind == "telemetry":
                cur.execute("INSERT INTO ops.telemetry(edge,seq,device,ts,degraded,data) "
                            "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                            (edge, seq, dev, ts, degraded, Jsonb(data)))
                new += cur.rowcount
            else:
                cur.execute("INSERT INTO ops.events(edge,seq,kind,device,ts,data) VALUES (%s,%s,%s,%s,%s,%s) "
                            "ON CONFLICT DO NOTHING", (edge, seq, kind, dev, ts, Jsonb(data)))
                inserted = cur.rowcount == 1
                new += cur.rowcount
                if inserted and kind == "event" and data.get("event") == "access":
                    cur.execute("INSERT INTO ops.acessos(ts,site,device,pseudonimo,granted,method) "
                                "VALUES (%s,%s,%s,%s,%s,%s)",
                                (ts, site, dev, data["badge"], bool(data.get("granted")), data.get("method", "?")))
                elif inserted and kind == "alarm":
                    if data.get("state") == "raised":
                        cur.execute("INSERT INTO ops.alarms(site,alarm,severity,message,raised_at) "
                                    "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                                    (site, data["alarm"], data.get("severity"), data.get("message"), ts))
                    else:
                        cur.execute("UPDATE ops.alarms SET cleared_at=%s WHERE site=%s AND alarm=%s "
                                    "AND cleared_at IS NULL", (ts, site, data["alarm"]))
            acked.append(seq)
    log("batch", edge=edge, items=len(items), new=new, duplicates=len(items) - new, degraded=degraded,
        bytes=request.content_length)
    return jsonify(acked=acked)


@app.get("/api/v1/commands")
def commands():
    edge = request.args.get("edge", "")
    require_edge(edge)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("""UPDATE ops.commands SET status='entregue', delivered_at=now()
                       WHERE edge=%s AND status='pendente' AND (risk='baixo' OR approved_by IS NOT NULL)
                       RETURNING id, device, action, params, requested_by, approved_by""", (edge,))
        out = [{"id": str(i), "device": d, "action": a, "requested_by": r, "approved_by": ap, **(p or {})}
               for i, d, a, p, r, ap in cur.fetchall()]
    for c in out:
        log("command_delivered", edge=edge, cmd_id=c["id"], action=c["action"], device=c["device"],
            requested_by=c["requested_by"], approved_by=c["approved_by"])
    return jsonify(commands=out)


@app.post("/api/v1/commands/<uuid:cid>/result")
def command_result(cid):
    res = request.get_json(force=True, silent=True) or {}
    status = res.get("status")
    if status not in ("applied", "rejected"):
        abort(400)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE ops.commands SET status=%s, result=%s WHERE id=%s AND edge=%s",
                    (status, Jsonb(res), str(cid), g.cn))
        if cur.rowcount != 1:
            abort(404)
    log("command_result", "high" if status == "rejected" else "info", edge=g.cn, cmd_id=str(cid),
        status=status, reason=res.get("reason"))
    return jsonify(ok=True)
