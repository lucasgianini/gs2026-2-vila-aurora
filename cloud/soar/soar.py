"""SOAR da Rede Vila Aurora (RT-15, RT-22).

Lê os alertas do Wazuh (alerts.json), grava no SOC (soc.alerts) e executa playbooks:
- ações de BAIXO risco: automáticas (encerrar sessão VPN, bloquear IP externo,
  bloquear conta, isolar dispositivo, revogar certificado, atuador em modo seguro);
- ações de ALTO impacto: só são PROPOSTAS (soc.actions = aguardando_aprovacao) e
  executadas depois que alguém da coordenação aprova no painel.
O SOAR nunca liga/desliga bomba, gerador ou portas.

Métricas: MTTD (evento -> alerta) e MTTR (evento -> contenção) vão para soar.jsonl.
"""
from __future__ import annotations

import json
import os
import ssl
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import psycopg
from psycopg.types.json import Jsonb

ALERTS = Path(os.environ.get("ALERTS_FILE", "/wazuh/alerts/alerts.json"))
HUB = os.environ.get("HUB_CONTROL", "https://172.30.30.2:9000")
PKI = os.environ.get("PKI_AGENT", "https://pki-agent:9100")
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "7"))
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
LOG = open("/var/log/vilaaurora/soar.jsonl", "a", buffering=1)
INTERNAL = ("10.", "172.30.10.", "172.30.20.", "172.30.30.", "172.30.40.", "127.")
KNOWN_ADMIN_IPS = {"172.30.99.10", "172.30.99.11"}

ctx = ssl.create_default_context(cafile="/certs/ca.pem")
ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
http = httpx.Client(verify=ctx, timeout=5)
db = psycopg.connect(f"host=db dbname=vilaaurora user=va_soar password={os.environ['DB_SOAR_PASSWORD']} "
                     "application_name=soar", autocommit=True)
recent: dict[tuple, float] = {}       # (ação, alvo) -> quando (deduplicação 10 min)


def now() -> datetime:
    return datetime.now(timezone.utc)


def log(event: str, **kw) -> None:
    rec = {"ts": now().isoformat(timespec="milliseconds"), "app": "va-soar", "event": event, **kw}
    LOG.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    print(json.dumps(rec, ensure_ascii=False, default=str), flush=True)


def parse_ts(v) -> datetime | None:
    if not v:
        return None
    s = str(v).replace(" UTC", "+00:00").replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ------------------------------------------------------------------ ações
def act_revoke_vpn(target: str) -> str:
    body = {"tunnel_ip": target} if target.startswith("10.90.") else {"user": target}
    r = http.post(f"{HUB}/revoke", json={**body, "reason": "soar"})
    r.raise_for_status()
    return f"sessões encerradas: {r.json()['revoked']}"


def act_block_ip(target: str) -> str:
    r = http.post(f"{HUB}/block", json={"ip": target, "reason": "soar"})
    r.raise_for_status()
    return f"bloqueado {target}"


def act_lock_account(target: str) -> str:
    with db.cursor() as c:
        c.execute("UPDATE cadastro.operadores SET bloqueado_ate=%s WHERE username=%s",
                  (now() + timedelta(hours=24), target))
        c.execute("INSERT INTO audit.log(actor,action,target,detail) VALUES ('soar','lock_account',%s,%s)",
                  (target, Jsonb({"horas": 24})))
        return f"conta {target} bloqueada por 24 h" if c.rowcount else f"conta {target} não existe"


def edge_cmd(device: str, action: str) -> str:
    site = device.split("-", 1)[0]
    with db.cursor() as c:
        c.execute("INSERT INTO ops.commands(edge,device,action,risk,requested_by,status) "
                  "VALUES (%s,%s,%s,'baixo','soar','pendente') RETURNING id", (f"edge-{site}", device, action))
        return f"comando {action} enfileirado p/ {device} ({c.fetchone()[0]})"


def act_isolate(target: str) -> str:
    return edge_cmd(target, "isolate")


def act_safe_mode(target: str) -> str:
    return edge_cmd(target, "safe_mode")


def act_revoke_cert(target: str) -> str:
    r = http.post(f"{PKI}/revoke", json={"cn": target, "reason": "keyCompromise"})
    r.raise_for_status()
    return r.json().get("result", "ok")


def act_revoke_all_vpn(_target: str) -> str:
    r = http.post(f"{HUB}/revoke_all", json={"reason": "soar-aprovado"})
    r.raise_for_status()
    return f"todas as sessões administrativas encerradas: {r.json()['revoked']}"


ACTIONS = {"revogar_sessao_vpn": act_revoke_vpn, "bloquear_ip": act_block_ip, "bloquear_conta": act_lock_account,
           "isolar_dispositivo": act_isolate, "modo_seguro": act_safe_mode, "revogar_certificado": act_revoke_cert,
           "encerrar_todas_sessoes_vpn": act_revoke_all_vpn}


# ------------------------------------------------------------------ playbooks
def playbook(alert: dict) -> list[tuple[str, str, str]]:
    """Retorna [(ação, alvo, risco)] para o alerta."""
    groups, d, lvl = set(alert["rule"].get("groups", [])), alert.get("data", {}), alert["rule"]["level"]
    out: list[tuple[str, str, str]] = []
    src = d.get("src_ip") or d.get("srcip") or d.get("remote") or ""
    user = d.get("peer") or d.get("dstuser") or d.get("user") or d.get("username") or ""
    if "va_a_vpn" in groups and lvl >= 10:
        if d.get("tunnel_ip"):
            out.append(("revogar_sessao_vpn", d["tunnel_ip"], "baixo"))
        if src and not src.startswith(INTERNAL) and src not in KNOWN_ADMIN_IPS:
            out.append(("bloquear_ip", src, "baixo"))
        if user and "." in user:
            out.append(("bloquear_conta", user, "baixo"))
        if lvl >= 13:
            out.append(("encerrar_todas_sessoes_vpn", "wg2", "alto"))
    if "va_b_sqli" in groups and lvl >= 10:
        if src.startswith("10.90."):
            out.append(("revogar_sessao_vpn", src, "baixo"))
        elif src and not src.startswith(INTERNAL):
            out.append(("bloquear_ip", src, "baixo"))
        if d.get("user") and "." in str(d["user"]):
            out.append(("bloquear_conta", d["user"], "baixo"))
    if "va_c_cert" in groups and lvl >= 10:
        dev = d.get("claimed") or d.get("device")
        if dev:
            out.append(("isolar_dispositivo", dev, "baixo"))
            out.append(("revogar_certificado", dev, "baixo"))
    if "va_d_atuador" in groups and lvl >= 10:
        if d.get("device"):
            out.append(("modo_seguro", d["device"], "baixo"))
        who = str(d.get("requested_by", "")).split(" ")[0]
        if who and "." in who:
            out.append(("bloquear_conta", who, "baixo"))
    return out


def store_alert(a: dict) -> tuple[int, datetime | None]:
    d = a.get("data", {})
    ev = parse_ts(d.get("ts") or d.get("timestamp"))
    if ev is None and a.get("full_log", "")[:4].isdigit():
        ev = parse_ts(a["full_log"].split(" ")[0].rstrip(":").replace("+0000", "+00:00"))
    with db.cursor() as c:
        c.execute("""INSERT INTO soc.alerts(wazuh_id,ts,event_ts,rule_id,level,description,groups,mitre,location,data)
                     VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (wazuh_id) DO NOTHING RETURNING id""",
                  (a["id"], parse_ts(a["timestamp"].replace("+0000", "+00:00")), ev, int(a["rule"]["id"]),
                   a["rule"]["level"], a["rule"]["description"], a["rule"].get("groups", []),
                   a["rule"].get("mitre", {}).get("id"), a.get("location"), Jsonb(d)))
        row = c.fetchone()
    return (row[0] if row else 0), ev


def run_action(alert_id: int, pb: str, action: str, target: str, risk: str, ev: datetime | None,
               alert_ts: datetime | None) -> None:
    key = (action, target)
    if time.time() - recent.get(key, 0) < 600:
        return
    recent[key] = time.time()
    if risk == "alto":
        with db.cursor() as c:
            c.execute("INSERT INTO soc.actions(alert_id,playbook,action,target,risk,status) "
                      "VALUES (%s,%s,%s,%s,'alto','aguardando_aprovacao')", (alert_id, pb, action, target))
        log("action_proposed", action=action, target=target, risk=risk, alert_id=alert_id,
            result="aguardando aprovação humana")
        return
    try:
        result = "dry-run" if DRY_RUN else ACTIONS[action](target)
        status = "executada"
    except Exception as e:  # noqa: BLE001
        result, status = f"erro: {e!r}"[:300], "falhou"
    done = now()
    with db.cursor() as c:
        c.execute("INSERT INTO soc.actions(alert_id,playbook,action,target,risk,status,done_at,result) "
                  "VALUES (%s,%s,%s,%s,'baixo',%s,%s,%s)", (alert_id, pb, action, target, status, done, result))
    log("action_executed", action=action, target=target, risk=risk, status=status, result=result,
        alert_id=alert_id, mttd_s=round((alert_ts - ev).total_seconds(), 2) if ev and alert_ts else None,
        mttr_s=round((done - ev).total_seconds(), 2) if ev else None)


def approved_loop() -> None:
    """Executa ações de alto impacto aprovadas no painel."""
    with db.cursor() as c:
        c.execute("SELECT id, action, target, decided_by FROM soc.actions WHERE status='aprovada'")
        rows = c.fetchall()
    for aid, action, target, who in rows:
        try:
            res, st = ACTIONS[action](target), "executada"
        except Exception as e:  # noqa: BLE001
            res, st = f"erro: {e!r}"[:300], "falhou"
        with db.cursor() as c:
            c.execute("UPDATE soc.actions SET status=%s, done_at=now(), result=%s WHERE id=%s", (st, res, aid))
        log("approved_action_executed", action=action, target=target, approved_by=who, status=st, result=res)


def follow(path: Path):
    while not path.exists():
        time.sleep(2)
    f = path.open()
    f.seek(0, os.SEEK_END)
    ino = path.stat().st_ino
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        approved_loop()
        time.sleep(1)
        try:
            if path.stat().st_ino != ino:      # rotação do arquivo pelo Wazuh
                f = path.open(); ino = path.stat().st_ino
        except FileNotFoundError:
            pass


def main() -> None:
    log("soar_start", min_level=MIN_LEVEL, dry_run=DRY_RUN)
    for line in follow(ALERTS):
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        if a["rule"]["level"] < MIN_LEVEL or "va_soar" in a["rule"].get("groups", []):
            continue
        alert_id, ev = store_alert(a)
        if not alert_id:
            continue
        alert_ts = parse_ts(a["timestamp"].replace("+0000", "+00:00"))
        pb = ",".join(g for g in a["rule"].get("groups", []) if g.startswith("va_"))
        for action, target, risk in playbook(a):
            run_action(alert_id, pb, action, target, risk, ev, alert_ts)


if __name__ == "__main__":
    main()
