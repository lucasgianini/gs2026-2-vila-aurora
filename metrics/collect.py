"""Coletor de métricas do laboratório (RT-22).

Mede, em intervalos, para cada nó: CPU %, memória, I/O de rede (via docker stats),
e para cada borda: estado do link, profundidade do outbox e nº de alarmes (via /api/status).
Grava séries em metrics/out/metrics.csv para o relatório.

Uso: metrics/collect.py [segundos_total] [intervalo]    (padrão: 60 s a cada 5 s)
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "metrics/out"
OUT.mkdir(parents=True, exist_ok=True)
TOTAL = float(sys.argv[1]) if len(sys.argv) > 1 else 60
STEP = float(sys.argv[2]) if len(sys.argv) > 2 else 5
EDGE_PORTS = {"centro": 8081, "escola": 8082, "ubs": 8083, "horta": 8084, "abrigo": 8085}


def docker_stats() -> list[dict]:
    fmt = "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
    out = subprocess.run(["docker", "stats", "--no-stream", "--format", fmt],
                         capture_output=True, text=True).stdout
    rows = []
    for ln in out.strip().splitlines():
        name, cpu, mem, net, blk = ln.split("\t")
        if not name.startswith("vilaaurora-"):
            continue
        rows.append({"name": name.replace("vilaaurora-", "").rsplit("-", 1)[0],
                     "cpu_pct": cpu.rstrip("%"), "mem": mem.split(" / ")[0],
                     "net_io": net, "blk_io": blk})
    return rows


def edge_status(site: str, port: int) -> dict:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2) as r:
            d = json.load(r)
        return {"link": d.get("link"), "outbox": d.get("outbox_depth"), "alarmes": len(d.get("alarms", {}))}
    except Exception:
        return {"link": "?", "outbox": "", "alarmes": ""}


def main():
    f = (OUT / "metrics.csv").open("w", newline="")
    w = csv.writer(f)
    w.writerow(["ts", "tipo", "alvo", "cpu_pct", "mem", "net_io", "link", "outbox", "alarmes"])
    t0 = time.time()
    samples = 0
    while time.time() - t0 < TOTAL:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for r in docker_stats():
            w.writerow([now, "node", r["name"], r["cpu_pct"], r["mem"], r["net_io"], "", "", ""])
        for site, port in EDGE_PORTS.items():
            s = edge_status(site, port)
            w.writerow([now, "edge", site, "", "", "", s["link"], s["outbox"], s["alarmes"]])
        f.flush()
        samples += 1
        print(f"\r{samples} amostras ({int(time.time()-t0)}s/{int(TOTAL)}s)", end="", flush=True)
        time.sleep(STEP)
    f.close()
    print(f"\n{samples} amostras -> {OUT/'metrics.csv'}")


if __name__ == "__main__":
    main()
