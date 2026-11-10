"""IA defensiva 1 — detecção de anomalias na telemetria com Isolation Forest (RT-16).

Método
1. Exporta a telemetria REAL coletada no laboratório (PostgreSQL) por sensor.
2. Remove as janelas dos testes de falha manuais anteriores (valores fisicamente
   implausíveis), para que o treino contenha apenas operação normal.
3. Divide cada série no tempo: 60 % treino (normal), 40 % teste.
4. No teste, injeta anomalias ROTULADAS de 4 tipos: pico, deriva, sensor travado e
   fora de faixa (≈ 6 % dos pontos). Assim é possível MEDIR precisão/revocação/FP.
5. Features por leitura: valor, variação, desvio da média móvel, desvio-padrão móvel,
   contagem de repetições (detecta sensor travado).
6. Limiar: percentil 1 do score no treino (≈ 1 % de FP esperado em operação normal).

Uso:  .venv/bin/python cloud/ai/anomaly.py            # avaliação + relatório
      .venv/bin/python cloud/ai/anomaly.py --online   # analisa os últimos 15 min e loga anomalias
"""
from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parents[2]
SENSORS = {  # dispositivo -> (campo, faixa física plausível p/ limpeza do treino, faixa operacional)
    "ubs-camara-fria":           ("temp_c",    (3.0, 7.0),   (2.0, 8.0)),
    "escola-nivel-reservatorio": ("level_pct", (20.0, 100.0), (0.0, 100.0)),
    "centro-qualidade-ar":       ("co2_ppm",   (300, 1200),  (300, 5000)),
    "abrigo-energia":            ("load_w",    (300, 1000),  (0, 3000)),
    "escola-cloro":              ("mg_l",      (0.8, 1.6),   (0.2, 3.0)),
}
rng = np.random.default_rng(2026)


def export(since: str | None = None) -> dict[str, list[tuple[str, float]]]:
    where = f"AND ts > now() - interval '{since}'" if since else ""
    q = ("COPY (SELECT device, ts, data FROM ops.telemetry WHERE device = ANY(ARRAY[" +
         ",".join(f"'{d}'" for d in SENSORS) + f"]) {where} ORDER BY device, ts) TO STDOUT WITH CSV")
    out = subprocess.run(["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "exec", "-T", "db",
                          "psql", "-U", "postgres", "-d", "vilaaurora", "-c", q],
                         capture_output=True, text=True, check=True).stdout
    series: dict[str, list[tuple[str, float]]] = {d: [] for d in SENSORS}
    for dev, ts, data in csv.reader(io.StringIO(out)):
        v = json.loads(data).get(SENSORS[dev][0])
        if v is not None:
            series[dev].append((ts, float(v)))
    return series


def features(x: np.ndarray, w: int = 6) -> np.ndarray:
    n = len(x)
    f = np.zeros((n, 5))
    for i in range(n):
        win = x[max(0, i - w):i] if i else x[:1]
        mu, sd = win.mean(), win.std() + 1e-6
        rep = 0
        j = i
        while j > 0 and abs(x[j] - x[j - 1]) < 1e-9:
            rep += 1
            j -= 1
        f[i] = [x[i], x[i] - (x[i - 1] if i else x[i]), (x[i] - mu) / sd, sd, rep]
    return f


def inject(x: np.ndarray, frac: float = 0.06) -> tuple[np.ndarray, np.ndarray, list[str], list[tuple]]:
    x = x.copy()
    y = np.zeros(len(x), dtype=int)
    kinds: list[str] = []
    spans: list[tuple] = []
    sd = x.std() + 1e-6
    budget = int(len(x) * frac)
    while y.sum() < budget:
        kind = rng.choice(["pico", "deriva", "travado", "fora_faixa"])
        i = int(rng.integers(10, len(x) - 12))
        if y[i - 2:i + 12].any():
            continue
        if kind == "pico":
            x[i] += rng.choice([-1, 1]) * rng.uniform(6, 10) * sd; y[i] = 1
        elif kind == "deriva":
            for k in range(10):
                x[i + k] += (k + 1) * 0.9 * sd; y[i + k] = 1
        elif kind == "travado":
            x[i:i + 10] = x[i]; y[i + 1:i + 10] = 1
        else:
            x[i] = x[i] + rng.choice([-1, 1]) * rng.uniform(12, 20) * sd; y[i] = 1
        kinds.append(kind)
        spans.append((kind, i, i + (10 if kind in ("deriva", "travado") else 1)))
    return x, y, kinds, spans


def evaluate() -> None:
    series = export()
    lines = ["# IA defensiva — Isolation Forest na telemetria (RT-16)", "",
             f"Gerado em {datetime.now(timezone.utc).isoformat(timespec='seconds')} a partir da telemetria real do laboratório.", "",
             "Métricas por **leitura** (ponto a ponto) e por **evento** (um evento injetado conta como detectado",
             "se ao menos uma de suas leituras for marcada — é o que importa para gerar um alerta).", "",
             "| Sensor | Leituras (treino/teste) | Pontos anômalos | Precisão | Revocação | F1 | Taxa de FP | Matriz [VN FP; FN VP] | Eventos detectados |",
             "|---|---|---|---|---|---|---|---|---|"]
    Y, P = [], []
    ev_tot: dict[str, list[int]] = {}
    for dev, (field, clean, _) in SENSORS.items():
        vals = np.array([v for _, v in series[dev]])
        vals = vals[(vals >= clean[0]) & (vals <= clean[1])]      # remove janelas de testes manuais
        if len(vals) < 200:
            lines.append(f"| {dev} | {len(vals)} | — | dados insuficientes | | | | |")
            continue
        cut = int(len(vals) * 0.6)
        train, test = vals[:cut], vals[cut:]
        xt, yt, kinds, spans = inject(test)
        model = IsolationForest(n_estimators=200, contamination="auto", random_state=7)
        ftr = features(train)
        model.fit(ftr)
        thr = np.percentile(model.score_samples(ftr), 1)
        pred = (model.score_samples(features(xt)) < thr).astype(int)
        tn, fp, fn, tp = confusion_matrix(yt, pred, labels=[0, 1]).ravel()
        Y.append(yt); P.append(pred)
        hit = 0
        for kind, a, b in spans:
            d = int(pred[a:b].any())
            hit += d
            ev_tot.setdefault(kind, [0, 0])
            ev_tot[kind][0] += d; ev_tot[kind][1] += 1
        lines.append(f"| {dev} ({field}) | {len(train)}/{len(test)} | {int(yt.sum())} | "
                     f"{precision_score(yt, pred, zero_division=0):.2f} | {recall_score(yt, pred):.2f} | "
                     f"{f1_score(yt, pred):.2f} | {fp / (fp + tn):.3f} | [{tn} {fp}; {fn} {tp}] | {hit}/{len(spans)} |")
    y, p = np.concatenate(Y), np.concatenate(P)
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    lines += ["", f"**Global:** precisão {precision_score(y, p):.2f} · revocação {recall_score(y, p):.2f} · "
                  f"F1 {f1_score(y, p):.2f} · taxa de falsos positivos {fp / (fp + tn):.3f} "
                  f"({fp} alarmes falsos em {fp + tn} leituras normais).", "",
              "Detecção por tipo de evento: " + " · ".join(f"{k}: {v[0]}/{v[1]}" for k, v in sorted(ev_tot.items())) + ".", "",
              "Leitura crítica: a revocação por leitura é baixa porque as primeiras leituras de uma deriva ou de um",
              "sensor travado parecem normais; por evento o desempenho é bem melhor, que é o que interessa para alertar.",
              "A taxa de falsos positivos (~3 %) seria alta para alertar pessoas a cada leitura, por isso o evento da IA",
              "entra no SIEM com nível 8 (atenção, sem SOAR) e só ganha relevância quando correlacionado. A IA",
              "**complementa** as regras determinísticas da borda (ex.: câmara fria 2–8 °C), que seguem como proteção primária.",
              "A IA não aciona nada: só gera evento `anomaly` para o SIEM (regra 100700) e para triagem humana."]
    out = ROOT / "docs/evidencias/ia_anomalias.md"
    out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def online() -> None:
    """Treina com a última hora e marca anomalias dos últimos 15 min; grava eventos para o SIEM."""
    hist, recent = export("60 minutes"), export("15 minutes")
    log = open(ROOT / "data/cloud/logs/ai.jsonl", "a")
    n = 0
    for dev, (field, clean, _) in SENSORS.items():
        h = np.array([v for _, v in hist[dev]])
        h = h[(h >= clean[0]) & (h <= clean[1])]
        if len(h) < 100 or not recent[dev]:
            continue
        model = IsolationForest(n_estimators=200, random_state=7).fit(features(h))
        thr = np.percentile(model.score_samples(features(h)), 0.5)
        r = np.array([v for _, v in recent[dev]])
        sc = model.score_samples(features(r))
        for (ts, v), s in zip(recent[dev], sc):
            if s < thr:
                n += 1
                log.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                                      "app": "va-ai", "event": "anomaly", "device": dev, "field": field,
                                      "value": v, "reading_ts": ts, "score": round(float(s), 3)}) + "\n")
    print(f"{n} anomalia(s) registradas em data/cloud/logs/ai.jsonl")


if __name__ == "__main__":
    online() if "--online" in sys.argv else evaluate()
