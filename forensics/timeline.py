"""Linha do tempo do incidente a partir das evidências coletadas (RT-14).

Lê os artefatos de forensics/cases/<caso>/raw/ (já com hash na cadeia de custódia),
normaliza o horário (tudo em UTC) e produz uma linha do tempo única e ordenada,
correlacionando VPN, painel legado, banco, SIEM, borda e SOAR.

Saída: forensics/cases/<caso>/linha-do-tempo.md
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = sys.argv[1] if len(sys.argv) > 1 else "INC-VA-0712"
RAW = ROOT / "forensics/cases" / CASE / "raw"


def parse(ts: str) -> datetime | None:
    ts = ts.strip().replace("Z", "+00:00")
    ts = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts)
    for fmt in (None,):
        try:
            d = datetime.fromisoformat(ts)
            return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        return datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


events: list[tuple[datetime, str, str, str]] = []  # (ts, fonte, severidade, descrição)


def add(ts, src, sev, desc):
    d = parse(ts) if isinstance(ts, str) else ts
    if d:
        events.append((d, src, sev, desc))


# VPN legada (texto)
f = RAW / "vpn-legado.log"
if f.exists():
    for ln in f.read_text(errors="replace").splitlines():
        m = re.search(r"(\S+) LEGACY-VPN AUTH (\S+) user=(\S+) src=(\S+)", ln)
        if m:
            add(m[1], "VPN-legada", "alto" if m[2] == "OK" else "medio",
                f"Autenticação {m[2]} na VPN legada (só senha): usuário {m[3]} de {m[4]}")

# Painel legado GW (JSON)
f = RAW / "painel-legado-gw.jsonl"
if f.exists():
    for ln in f.read_text(errors="replace").splitlines():
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        uri = e.get("uri", "")
        sqli = bool(re.search(r"(?i)(union|select|--|%27|'|;)", uri))
        add(e.get("ts", ""), "painel-legado", "alto" if sqli else "info",
            f"HTTP {e.get('method')} {uri[:90]} (status {e.get('status')})" + (" [padrão SQLi]" if sqli else ""))

# PostgreSQL (JSON) — só statements do painel legado com escrita/união
f = RAW / "postgresql.json"
if f.exists():
    for ln in f.read_text(errors="replace").splitlines():
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        msg = e.get("message", "")
        if e.get("application_name") == "painel-legado" and re.search(r"(?i)(union|update\s+ops|information_schema)", msg):
            add(e.get("timestamp", ""), "postgresql", "alto", f"SQL executado: {msg[:120]}")

# Borda da escola (JSON) — decisões relevantes
f = RAW / "edge-escola.jsonl"
if f.exists():
    for ln in f.read_text(errors="replace").splitlines():
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        ev = e.get("event")
        if ev in ("actuator_cmd_rejected", "schedule_changed", "actuator_cmd"):
            sev = "alto" if ev == "actuator_cmd_rejected" else "medio"
            add(e.get("ts", ""), "borda-escola", sev,
                {"actuator_cmd_rejected": f"RECUSOU comando: {e.get('action')} em {e.get('device')} — {e.get('reason')}",
                 "schedule_changed": f"Agenda alterada: {e.get('windows')}",
                 "actuator_cmd": f"Comando aceito: {e.get('action')} em {e.get('device')} (origem {e.get('origin')})"}[ev])

# SIEM (JSON) — alertas de nível >= 10 dos grupos do ataque
f = RAW / "siem-alerts.json"
if f.exists():
    for ln in f.read_text(errors="replace").splitlines():
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        r = e.get("rule", {})
        g = set(r.get("groups", []))
        if r.get("level", 0) >= 10 and g & {"va_a_vpn", "va_b_sqli", "va_c_cert", "va_d_atuador"}:
            mitre = ",".join(r.get("mitre", {}).get("id", []))
            add(e.get("timestamp", ""), "SIEM", "alto",
                f"ALERTA regra {r.get('id')} (nvl {r.get('level')}): {r.get('description','')[:80]}" +
                (f" [MITRE {mitre}]" if mitre else ""))

# SOAR (JSON)
f = RAW / "soar.jsonl"
if f.exists():
    for ln in f.read_text(errors="replace").splitlines():
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if e.get("event") in ("action_executed", "action_proposed"):
            add(e.get("ts", ""), "SOAR", "medio",
                f"Resposta {e.get('event').split('_')[1]}: {e.get('action')} -> {e.get('target')} ({e.get('result','')[:40]})")

events.sort(key=lambda x: x[0])
L = [f"# Linha do tempo — {CASE} (RT-14)", "",
     "Reconstruída a partir das evidências coletadas (ver cadeia de custódia). Todos os horários em UTC.",
     "O sincronismo por NTP em todos os nós é o que torna esta correlação confiável — ao contrário do",
     "incidente original, em que os relógios estavam dessincronizados.", "",
     "| # | Horário (UTC) | Fonte | Sev. | Evento |", "|---|---|---|---|---|"]
for i, (ts, src, sev, desc) in enumerate(events, 1):
    L.append(f"| {i} | {ts.strftime('%H:%M:%S.%f')[:-3]} | {src} | {sev} | {desc.replace('|', '/')} |")
if events:
    span = (events[-1][0] - events[0][0]).total_seconds()
    L += ["", f"**Janela do incidente:** {events[0][0].strftime('%Y-%m-%d %H:%M:%S')} a "
              f"{events[-1][0].strftime('%H:%M:%S')} UTC ({span:.0f} s, {len(events)} eventos correlacionados)."]
out = ROOT / "forensics/cases" / CASE / "linha-do-tempo.md"
out.write_text("\n".join(L) + "\n")
print(f"{len(events)} eventos -> {out}")
print("\n".join(L[:9] + (["..."] if len(L) > 14 else []) + L[-3:]))
