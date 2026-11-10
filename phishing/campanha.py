"""Campanha de phishing SIMULADO para treinamento (RT-11) — somente no laboratório.

Regras éticas aplicadas (seção 7 do enunciado):
- destinatários: apenas contas FICTÍCIAS criadas pela equipe (@vilaaurora.test, caixa Mailpit local);
- a página de destino NÃO tem campos de senha e NÃO captura dados: só mostra a orientação de treinamento;
- o comportamento dos destinatários é SIMULADO por este script (perfis de risco definidos abaixo),
  pois não há pessoas reais envolvidas. As métricas servem para validar o pipeline e o plano de conscientização.

Fluxo: configura o Gophish pela API -> dispara -> simula abrir/clicar/reportar -> coleta métricas.
Uso: .venv/bin/python phishing/campanha.py
"""
from __future__ import annotations

import json
import random
import re
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
API = "https://127.0.0.1:3333/api"
PHISH = "http://172.30.50.20"           # servidor de páginas do Gophish (rede do laboratório)
MAILPIT = "http://127.0.0.1:8025/api/v1"
random.seed(2026)

# perfis de comportamento simulados: (prob. abrir, prob. clicar | abriu, prob. reportar | abriu)
PERFIS = {"atento": (0.7, 0.05, 0.7), "medio": (0.8, 0.35, 0.25), "apressado": (0.95, 0.7, 0.05)}
DESTINATARIOS = [(f"voluntario{i:02d}@vilaaurora.test", f"Voluntário {i:02d}", p)
                 for i, p in enumerate(["atento"] * 4 + ["medio"] * 8 + ["apressado"] * 4, start=1)]

TEMPLATE_HTML = """<html><body style="font-family:sans-serif">
<p>Olá, {{.FirstName}}.</p>
<p>Recebemos um aviso de que o seu cadastro de voluntário precisa ser <strong>revisado ainda hoje</strong>.</p>
<p><a href="{{.URL}}">Revisar cadastro</a></p>
<p>Equipe de Cadastro</p>{{.Tracker}}</body></html>"""

LANDING_HTML = """<html lang="pt-BR"><head><meta charset="utf-8"><title>Treinamento</title></head>
<body style="font:18px/1.5 sans-serif;max-width:40rem;margin:2rem auto">
<h1>Isto foi um treinamento de segurança da Rede Vila Aurora</h1>
<p>Nenhum dado foi coletado. O e-mail tinha sinais de golpe: <strong>urgência</strong>, remetente fora do
domínio oficial e um link para "revisar cadastro".</p>
<p>Da próxima vez: não clique, use o botão <strong>Reportar phishing</strong> e, se houver dúvida,
ligue para a coordenação no número do cadastro.</p></body></html>"""


def api_key() -> str:
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "cp",
                        "gophish:/opt/gophish/gophish.db", f"{d}/g.db"], check=True, capture_output=True)
        return sqlite3.connect(f"{d}/g.db").execute("SELECT api_key FROM users WHERE id=1").fetchone()[0]


def main():
    key = api_key()
    g = httpx.Client(base_url=API, verify=False, headers={"Authorization": key}, timeout=20)
    sfx = time.strftime("%H%M%S")
    smtp = g.post("/smtp/", json={"name": f"lab-mailpit-{sfx}", "interface_type": "SMTP", "host": "172.30.50.10:1025",
                                  "from_address": "cadastro@vilaaurora-cadastro.test",
                                  "ignore_cert_errors": True}).json()
    grp = g.post("/groups/", json={"name": f"voluntarios-ficticios-{sfx}", "targets": [
        {"email": e, "first_name": n, "last_name": "", "position": p} for e, n, p in DESTINATARIOS]}).json()
    tpl = g.post("/templates/", json={"name": f"treino-cadastro-{sfx}", "subject": "Revisão do seu cadastro — hoje",
                                      "html": TEMPLATE_HTML}).json()
    page = g.post("/pages/", json={"name": f"pagina-treinamento-{sfx}", "html": LANDING_HTML,
                                   "capture_credentials": False, "capture_passwords": False}).json()
    camp = g.post("/campaigns/", json={"name": f"Treinamento novembro {sfx}", "template": {"name": tpl["name"]},
                                       "page": {"name": page["name"]}, "smtp": {"name": smtp["name"]},
                                       "url": PHISH, "groups": [{"name": grp["name"]}]}).json()
    cid = camp["id"]
    print(f"campanha {cid} criada; aguardando envio...")
    time.sleep(15)

    # comportamento simulado: lê cada e-mail na caixa do laboratório e age conforme o perfil
    perfil = {e: p for e, _, p in DESTINATARIOS}
    msgs = httpx.get(f"{MAILPIT}/messages", params={"limit": 200}).json()["messages"]
    acoes = []
    for m in msgs:
        to = m["To"][0]["Address"]
        if to not in perfil:
            continue
        html = httpx.get(f"{MAILPIT}/message/{m['ID']}").json()["HTML"]
        rid = re.search(r"rid=([A-Za-z0-9]+)", html)
        if not rid:
            continue
        rid = rid.group(1)
        po, pc, pr = PERFIS[perfil[to]]
        aberto = random.random() < po
        clicou = aberto and random.random() < pc
        reportou = aberto and not clicou and random.random() < pr
        # o "computador do voluntário" (simulado) acessa o servidor de páginas do Gophish
        if aberto:
            subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://127.0.0.1:3334/track?rid={rid}"], check=False)
        if clicou:
            subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://127.0.0.1:3334/?rid={rid}"], check=False)
        if reportou:
            subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://127.0.0.1:3334/report?rid={rid}"], check=False)
        acoes.append((to, perfil[to], aberto, clicou, reportou))
    time.sleep(3)
    res = g.get(f"/campaigns/{cid}/summary").json()["stats"]
    det = g.get(f"/campaigns/{cid}/results").json()["results"]
    n = res["total"]
    pct = lambda k: f"{100 * res[k] / n:.0f}%"  # noqa: E731
    L = ["# Campanha de phishing simulado (RT-11)", "",
         "Laboratório: Gophish 0.12.1 + caixa Mailpit local. **Destinatários fictícios** (16 contas `voluntarioNN@vilaaurora.test`),",
         "página de destino **sem captura de dados** (`capture_credentials=false`) e comportamento dos destinatários",
         "**simulado** por perfis de risco (atento/médio/apressado). Nenhuma pessoa real foi alvo.", "",
         "| Métrica | Quantidade | % dos enviados |", "|---|---|---|",
         f"| Enviados | {res['sent']} | 100% |", f"| Abertos | {res['opened']} | {pct('opened')} |",
         f"| Clicaram no link | {res['clicked']} | {pct('clicked')} |",
         f"| Enviaram dados | {res['submitted_data']} | {pct('submitted_data')} (a página não coleta nada) |",
         f"| Reportaram | {res['email_reported']} | {pct('email_reported')} |", "",
         "| Perfil | Destinatários | Clicaram | Reportaram |", "|---|---|---|---|"]
    for p in PERFIS:
        a = [x for x in acoes if x[1] == p]
        L.append(f"| {p} | {len(a)} | {sum(x[3] for x in a)} | {sum(x[4] for x in a)} |")
    L += ["", f"Resultados por destinatário coletados da API do Gophish: {len(det)} registros.",
          "Os números validam o pipeline e o plano de conscientização; com voluntários reais, a campanha só",
          "ocorreria com consentimento e comunicação prévia à coordenação."]
    (ROOT / "docs/evidencias/phishing_campanha.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
