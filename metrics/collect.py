"""Coletor de métricas do laboratório (RT-22).

Mede, em intervalos, para cada nó: CPU %, memória, I/O de rede (via docker stats),
para cada borda: estado do link, profundidade do outbox e nº de alarmes (via /api/status)
e os contadores de bytes de cada interface do nó de borda (fibra, 4G, túneis, LAN) — banda.
Grava séries em metrics/out/<nome>.csv para o relatório.

Uso: metrics/collect.py [segundos_total] [intervalo] [nome]   (padrão: 60 s a cada 5 s, "metrics")
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
NAME = sys.argv[3] if len(sys.argv) > 3 else "metrics"
# interface do nó de borda -> papel, pelo prefixo do endereço (ver docker-compose.yml)
IFACE_ROLE = (("172.30.10.", "wan_fibra"), ("172.30.20.", "wan_4g"), ("10.80.", "tunel_fibra"),
              ("10.81.", "tunel_4g"), ("172.31.", "lan_local"))
NET_SH = ("for i in $(ls /sys/class/net); do echo c $i $(cat /sys/class/net/$i/statistics/rx_bytes) "
          "$(cat /sys/class/net/$i/statistics/tx_bytes); done; ip -o -4 addr | awk '{print \"a\",$2,$4}'")
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


def edge_ifaces(site: str) -> list[tuple[str, int, int]]:
    """Contadores (rx, tx) em bytes de cada interface do nó de borda, rotulados pelo papel."""
    out = subprocess.run(["docker", "exec", f"vilaaurora-wg-{site}-1", "sh", "-c", NET_SH],
                         capture_output=True, text=True).stdout
    counters, addr = {}, {}
    for ln in out.splitlines():
        p = ln.split()
        if p and p[0] == "c" and len(p) == 4:
            counters[p[1]] = (int(p[2]), int(p[3]))
        elif p and p[0] == "a" and len(p) == 3:
            addr[p[1]] = p[2]
    rows = []
    for iface, ip in addr.items():
        role = next((r for pfx, r in IFACE_ROLE if ip.startswith(pfx)), "iot_mqtt")  # rede IoT: sub-rede automática
        if iface != "lo" and iface in counters:
            rows.append((role, *counters[iface]))
    return rows


def main():
    f = (OUT / f"{NAME}.csv").open("w", newline="")
    w = csv.writer(f)
    w.writerow(["ts", "tipo", "alvo", "cpu_pct", "mem", "net_io", "link", "outbox", "alarmes",
                "iface", "rx_bytes", "tx_bytes"])
    t0 = time.time()
    samples = 0
    while time.time() - t0 < TOTAL:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for r in docker_stats():
            w.writerow([now, "node", r["name"], r["cpu_pct"], r["mem"], r["net_io"], "", "", ""])
        for site, port in EDGE_PORTS.items():
            s = edge_status(site, port)
            w.writerow([now, "edge", site, "", "", "", s["link"], s["outbox"], s["alarmes"]])
            for role, rx, tx in edge_ifaces(site):
                w.writerow([time.time(), "net", site, "", "", "", "", "", "", role, rx, tx])
        f.flush()
        samples += 1
        print(f"\r{samples} amostras ({int(time.time()-t0)}s/{int(TOTAL)}s)", end="", flush=True)
        time.sleep(STEP)
    f.close()
    print(f"\n{samples} amostras -> {OUT / (NAME + '.csv')}")


if __name__ == "__main__":
    main()
