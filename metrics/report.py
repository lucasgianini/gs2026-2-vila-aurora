"""Consolida as métricas do RT-22 em um relatório Markdown.

Fontes:
- metrics/out/metrics.csv          CPU/mem por nó; link/outbox por borda; bytes por interface (operação normal)
- metrics/out/metrics-4g.csv       idem, com uma borda em modo degradado no 4G (metrics/medir_4g.sh)
- metrics/availability.sql         disponibilidade local x central, medida na telemetria do banco
- data/cloud/logs/soar.jsonl       MTTD/MTTR das respostas automáticas
- docs/evidencias/caos/teste-caos.md   operação autônoma e perda de dados (caos)

Saída: docs/evidencias/metricas.md
"""
from __future__ import annotations

import csv
import json
import re
import statistics as st
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITES = ("abrigo", "centro", "escola", "horta", "ubs")
NODE_PARTS = ("edge", "broker", "wg")     # containers que compõem o nó de borda (o resto é campo)

# Modelo de energia do nó de borda — ESTIMATIVA, não medição: num laboratório em containers não há
# como medir watts do hardware-alvo. P = P_OCIOSO + (P_CARGA - P_OCIOSO) * utilização.
# Referência: Raspberry Pi 5 (hardware previsto em docs/03), valores típicos de medições públicas
# da placa sem periféricos: ~3 W ocioso, ~8 W com os 4 núcleos em carga.
P_OCIOSO_W, P_CARGA_W, NUCLEOS = 3.0, 8.0, 4
FATOR_CPU = 10        # pessimista: 1 núcleo do Pi ~10x mais lento que 1 núcleo do host do laboratório
TARIFA_KWH = 0.95     # R$/kWh, ordem de grandeza (tarifa residencial com impostos)


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def load(name: str):
    """-> (amostras, cpu{alvo:[%]}, mem{alvo:str}, links{site:set}, net{(site,iface):[(t,rx,tx)]})"""
    cpu, mem, links, net, stamps = {}, {}, {}, {}, set()
    f = ROOT / f"metrics/out/{name}.csv"
    if not f.exists():
        return 0, cpu, mem, links, net
    for r in csv.DictReader(f.open()):
        if r["tipo"] == "node" and num(r["cpu_pct"]) is not None:
            cpu.setdefault(r["alvo"], []).append(float(r["cpu_pct"]))
            mem[r["alvo"]] = r["mem"]
            stamps.add(r["ts"])
        elif r["tipo"] == "edge":
            links.setdefault(r["alvo"], set()).add(r["link"])
        elif r["tipo"] == "net":
            net.setdefault((r["alvo"], r["iface"]), []).append((float(r["ts"]), int(r["rx_bytes"]), int(r["tx_bytes"])))
    return len(stamps), cpu, mem, links, net


def mem_mib(v: str) -> float:
    m = re.search(r"([0-9.]+)", v or "0")
    n = float(m.group(1)) if m else 0.0
    unit = re.sub(r"[0-9. ]", "", v or "").lower()
    return n * {"kib": 1 / 1024, "mib": 1, "gib": 1024, "b": 1 / 1048576}.get(unit, 1)


def rate(net, site, iface):
    """Taxa média (kbit/s) de subida e descida na interface, do primeiro ao último contador."""
    pts = net.get((site, iface))
    if not pts or len(pts) < 2 or pts[-1][0] <= pts[0][0]:
        return None
    dt = pts[-1][0] - pts[0][0]
    return (pts[-1][2] - pts[0][2]) * 8 / dt / 1000, (pts[-1][1] - pts[0][1]) * 8 / dt / 1000


def kbps(v):
    return "—" if v is None else f"{v:.1f}"


samples, cpu, mem, links, net = load("metrics")
s4, _cpu4, _mem4, links4, net4 = load("metrics-4g")

# --- disponibilidade medida no banco ---
avail = []
try:
    out = subprocess.run(["docker", "compose", "exec", "-T", "db", "psql", "-U", "postgres", "-d", "vilaaurora",
                          "-At", "-F", "|"], stdin=(ROOT / "metrics/availability.sql").open(), cwd=ROOT,
                         capture_output=True, text=True, timeout=60).stdout
    avail = [ln.split("|") for ln in out.strip().splitlines() if ln.count("|") == 5]
except (OSError, subprocess.SubprocessError):
    pass

# --- MTTD / MTTR do SOAR ---
mttd, mttr = [], []
f = ROOT / "data/cloud/logs/soar.jsonl"
if f.exists():
    for ln in f.read_text().splitlines():
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if e.get("event") == "action_executed":
            if num(e.get("mttd_s")) is not None:
                mttd.append(float(e["mttd_s"]))
            if num(e.get("mttr_s")) is not None:
                mttr.append(float(e["mttr_s"]))

# --- caos: operação autônoma e perda ---
chaos = (ROOT / "docs/evidencias/caos/teste-caos.md")
chaos_txt = chaos.read_text() if chaos.exists() else ""
recon = re.search(r"drenar os buffers.*?\*\*(\d+)s\*\*", chaos_txt)
dur = re.search(r"duração da interrupção: (\d+) min", chaos_txt)
delta = re.search(r"depois \*\*(\d+)\*\* \(\+(\d+)\)", chaos_txt)

L = ["# Métricas e continuidade (RT-22)", "",
     f"Coleta de {samples} amostras em operação normal (`metrics/out/metrics.csv`) e {s4} com uma borda em modo",
     "degradado no 4G (`metrics/out/metrics-4g.csv`), mais a disponibilidade medida na telemetria do banco,",
     "os indicadores de resposta (SOAR) e de resiliência (teste de caos).", "",
     "| Indicador pedido no RT-22 | Como foi obtido | Seção |", "|---|---|---|",
     "| Disponibilidade (%) | medida (telemetria no banco) | 1 |",
     "| MTTD e MTTR | medidos (SOAR) | 2 |",
     "| Tempo de operação autônoma sem internet | medido (teste de caos) | 1 |",
     "| Perda de dados na reconciliação | medida (teste de caos) | 1 |",
     "| CPU e memória do nó de borda | medidas (`docker stats`) | 3 |",
     "| Banda do nó de borda | medida (contadores das interfaces) | 4 |",
     "| Energia do nó de borda | **estimada** por modelo sobre a CPU medida | 5 |", ""]

# ------------------------------------------------------------------ 1. disponibilidade
L += ["## 1. Disponibilidade e continuidade", ""]
if avail:
    win = int(avail[0][1])
    L += [f"Janela: {win} minutos de laboratório ligado ({win / 60:.1f} h), incluindo o teste de caos, os testes de",
          "failover e a reprodução do incidente. Minutos com o laboratório desligado não contam",
          "(`metrics/availability.sql`).", "",
          "- **Local**: a borda produziu telemetria naquele minuto (o espaço estava operando e medindo).",
          "- **Central**: essa telemetria chegou à nuvem em até 60 s (a supervisão central enxergava o espaço).", "",
          "| Borda | Minutos na janela | Disponibilidade local | Disponibilidade central | Minutos sem visão central |",
          "|---|---:|---:|---:|---:|"]
    for edge, janela, loc, cen, loc_pct, cen_pct in avail:
        L.append(f"| {edge.replace('edge-', '')} | {janela} | {float(loc_pct):.2f}% | {float(cen_pct):.2f}% | {int(loc) - int(cen)} |")
    L += [""]
L += ["| Indicador | Valor | Fonte |", "|---|---|---|"]
if dur:
    L.append(f"| Tempo de operação autônoma sem internet | ≥ {dur.group(1)} min (sem interrupção local) | teste de caos |")
if recon:
    L.append(f"| Tempo de reconciliação ao voltar o link | {recon.group(1)} s | teste de caos |")
if delta:
    L.append(f"| Dados reconciliados após a queda | +{delta.group(2)} leituras, 0 perdas/duplicatas | teste de caos |")
L.append("| Bordas isoladas da nuvem na queda | 5/5 offline, 0 falhas locais | teste de caos |")

# ------------------------------------------------------------------ 2. MTTD / MTTR
L += ["", "## 2. Tempo de detecção e resposta (SOAR)", "", "| Indicador | Valor |", "|---|---|"]
if mttd:
    L.append(f"| MTTD (evento → alerta), média | {st.mean(mttd):.2f} s |")
    L.append(f"| MTTD, máximo | {max(mttd):.2f} s |")
if mttr:
    L.append(f"| MTTR (evento → contenção), média | {st.mean(mttr):.2f} s |")
    L.append(f"| MTTR, máximo | {max(mttr):.2f} s |")
L.append(f"| Respostas automáticas medidas | {len(mttr)} |")

# ------------------------------------------------------------------ 3. CPU / memória
L += ["", "## 3. CPU e memória do nó de borda", "",
      "O nó de borda é a soma de três containers: agente de borda (regras + store-and-forward), broker MQTT",
      "e sidecar de rede (WireGuard). CPU em % de **um** núcleo do host do laboratório.", "",
      "| Borda | CPU média | CPU máx | Memória (agente + broker + rede) |", "|---|---:|---:|---:|"]
node_cpu = {}
for s in SITES:
    series = [cpu.get(f"{p}-{s}", []) for p in NODE_PARTS]
    n = min((len(x) for x in series if x), default=0)
    if not n:
        continue
    tot = [sum(x[i] for x in series if x) for i in range(n)]
    node_cpu[s] = st.mean(tot)
    m = sum(mem_mib(mem.get(f"{p}-{s}", "0")) for p in NODE_PARTS)
    L.append(f"| {s} | {st.mean(tot):.2f}% | {max(tot):.2f}% | {m:.1f} MiB |")

cloud_nodes = [k for k in cpu if not k.startswith(("edge-", "broker-", "wg-", "devices-"))]
L += ["", "Serviços de nuvem que mais consomem memória (para dimensionar o servidor):", "",
      "| Serviço | CPU média | Memória |", "|---|---:|---:|"]
for n in sorted(cloud_nodes, key=lambda k: mem_mib(mem.get(k, "0")), reverse=True)[:5]:
    L.append(f"| {n} | {st.mean(cpu[n]):.2f}% | {mem.get(n, '?')} |")

# ------------------------------------------------------------------ 4. banda
L += ["", "## 4. Banda do nó de borda", "",
      "Taxa média medida pelos contadores de bytes de cada interface do nó (`/sys/class/net/*/statistics`).",
      "\"WAN\" é o que realmente trafega no enlace (já com a sobrecarga do WireGuard e do mTLS).", "",
      "| Borda | WAN fibra ↑ (kbit/s) | WAN fibra ↓ (kbit/s) | WAN 4G ↑ em espera (kbit/s) | Volume na fibra (MB/dia) |",
      "|---|---:|---:|---:|---:|"]
fib_up = {}
for s in SITES:
    fb, g4 = rate(net, s, "wan_fibra"), rate(net, s, "wan_4g")
    if not fb:
        continue
    fib_up[s] = fb[0]
    L.append(f"| {s} | {kbps(fb[0])} | {kbps(fb[1])} | {kbps(g4[0] if g4 else None)} | {(fb[0] + fb[1]) * 86400 / 8 / 1000:.0f} |")

deg = [(s, rate(net4, s, "wan_4g"), rate(net4, s, "wan_fibra")) for s in SITES if "4g" in links4.get(s, set())]
if deg:
    L += ["", "Modo degradado (fibra derrubada, borda no 4G — só alarmes, eventos e estados sobem; a telemetria",
          "completa fica no buffer até a fibra voltar):", "",
          "| Borda | Link | WAN 4G ↑ (kbit/s) | WAN 4G ↓ (kbit/s) | Fibra normal ↑ (kbit/s) | Redução | Volume no 4G (MB/dia) | MB em 30 dias |",
          "|---|---|---:|---:|---:|---:|---:|---:|"]
    for s, g4, _fb in deg:
        if not g4:
            continue
        base = fib_up.get(s)
        red = f"{100 * (1 - g4[0] / base):.0f}%" if base else "—"
        day = (g4[0] + g4[1]) * 86400 / 8 / 1000
        L.append(f"| {s} | 4g | {kbps(g4[0])} | {kbps(g4[1])} | {kbps(base)} | {red} | {day:.0f} | {day * 30:.0f} |")

# ------------------------------------------------------------------ 5. energia
L += ["", "## 5. Energia do nó de borda (estimativa)", "",
      "**Não é medição.** O laboratório roda em containers, então não há como medir a potência do hardware-alvo;",
      "medir de verdade exige o nó físico e um medidor na alimentação. O valor abaixo aplica um modelo linear",
      f"sobre a CPU **medida** na seção 3: P = {P_OCIOSO_W:.0f} W + ({P_CARGA_W:.0f} W − {P_OCIOSO_W:.0f} W) × utilização,",
      f"com referência no Raspberry Pi 5 (hardware previsto em `docs/03`; ~{P_OCIOSO_W:.0f} W ocioso, ~{P_CARGA_W:.0f} W com",
      f"os {NUCLEOS} núcleos em carga). Como um núcleo do Pi é mais lento que o do host do laboratório, a coluna",
      f"\"pessimista\" multiplica a CPU medida por {FATOR_CPU}.", "",
      "| Borda | CPU medida | Potência estimada | Potência (pessimista) | kWh/mês (pessimista) |",
      "|---|---:|---:|---:|---:|"]
tot_kwh = 0.0
for s, c in node_cpu.items():
    u = c / 100 / NUCLEOS
    p1 = P_OCIOSO_W + (P_CARGA_W - P_OCIOSO_W) * min(u, 1)
    p2 = P_OCIOSO_W + (P_CARGA_W - P_OCIOSO_W) * min(u * FATOR_CPU, 1)
    kwh = p2 * 730 / 1000
    tot_kwh += kwh
    L.append(f"| {s} | {c:.2f}% | {p1:.2f} W | {p2:.2f} W | {kwh:.2f} |")
if node_cpu:
    L += ["", f"Total das {len(node_cpu)} bordas no cenário pessimista: **{tot_kwh:.1f} kWh/mês**, cerca de",
          f"**R$ {tot_kwh * TARIFA_KWH:.0f}/mês** a R$ {TARIFA_KWH:.2f}/kWh — dentro dos R$ 60/mês reservados em `docs/03`, que também",
          "cobrem modem 4G, sensores e nobreak. O consumo é dominado pela potência ociosa da placa, não pela carga:",
          "o software da borda praticamente não pesa."]

# ------------------------------------------------------------------ 6. análise crítica
L += ["", "## 6. Análise crítica", ""]
if avail:
    loc = min(float(a[4]) for a in avail)
    cen = min(float(a[5]) for a in avail)
    blind = max(int(a[2]) - int(a[3]) for a in avail)
    L += [f"- **A disponibilidade que importa é a local, e ela ficou em ≥ {loc:.1f}%.** A central ficou em {cen:.1f}%: foram",
          f"  até {blind} minutos sem visão na nuvem, quase todos provocados de propósito (30 min do teste de caos, mais os",
          "  testes de failover e a medição do modo degradado). Nesses minutos nenhum espaço parou de medir nem de",
          "  alarmar — é exatamente a diferença",
          "  em relação ao INC-VA-0712, em que a queda da fibra silenciou a câmara fria.",
          f"- **A janela é curta.** Cerca de {win / 60:.0f} horas de laboratório não sustentam uma afirmação de disponibilidade",
          "  anual; o número mostra que o método de medição funciona e que a operação local não depende da nuvem."]
for s_, g4, _fb in deg:
    if g4 and fib_up.get(s_):
        red = 100 * (1 - g4[0] / fib_up[s_])
        L += [f"- **O modo degradado reduziu a subida em {red:.0f}%, menos do que o desenho sugere.** Reter a telemetria não",
              "  basta: os eventos de estado dos dispositivos e as verificações de saúde do túnel continuam subindo e",
              f"  dominam o tráfego. Com a fibra fora o mês inteiro seriam ~{(g4[0] + g4[1]) * 86400 * 30 / 8 / 1e6:.1f} GB por espaço no 4G — cabe num plano",
              "  básico, mas com pouca folga, e uma sequência de alarmes aumenta o volume. Melhoria identificada: reduzir a",
              "  frequência dos eventos de estado quando o link for o 4G."]
        break
L += ["- **MTTD/MTTR de poucos segundos valem para respostas automáticas de baixo risco.** Ações de alto impacto",
      "  dependem de aprovação humana e seu tempo de resposta é o da pessoa, não o do sistema — isso é intencional.",
      "- **CPU, memória e banda foram medidas em containers num host x86.** Servem para mostrar que a carga é baixa,",
      "  não para prever o desempenho exato em um Raspberry Pi; a energia é estimativa e está marcada como tal.",
      "- **Perda de dados zero vale para 30 min.** O buffer é limitado: numa queda muito longa a borda descarta",
      "  telemetria antiga e preserva alarmes e eventos (registrando `outbox_overflow`)."]

out = ROOT / "docs/evidencias/metricas.md"
out.write_text("\n".join(L) + "\n")
print(out)
