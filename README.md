# Rede Comunitária Vila Aurora — Infraestrutura segura e resiliente

**FIAP · Global Solution 2026.2 · Cybersecurity** — Desafio Integrador *Resilient Community
Infrastructure*. Infraestrutura em camadas (campo → borda → nuvem → supervisão) para os cinco
espaços da Rede Vila Aurora, que **continua operando quando a internet cai** e permite **detectar,
responder e investigar** incidentes como o INC-VA-0712.

> ⚠️ **Ambiente de laboratório.** Todo o sistema roda em containers Docker isolados nesta máquina.
> As atividades ofensivas (reprodução do incidente, SQLi, campanha de phishing, testes de LLM) são
> executadas **exclusivamente contra os próprios containers deste repositório**, com **dados
> sintéticos**. Nada acessa sistemas de terceiros, da FIAP ou da internet. Ver seção *Ética*.

## Entregáveis

| ID | Entregável | Onde |
|---|---|---|
| E1 | Documento de Arquitetura | `docs/01-modelo-ameacas.md`, `docs/02-arquitetura.md` |
| E2 | Protótipo Funcional | este repositório — <https://github.com/lucasgianini/gs2026-2-vila-aurora> (`make up`) |
| E3 | Relatório de Testes de Segurança | `docs/06-testes-seguranca.md` + `docs/evidencias/` + `tests/` |
| E4 | Laudo Forense do INC-VA-0712 | `forensics/cases/INC-VA-0712/` |

Documentos de apoio: custos (`docs/03`), privacidade/RIPD (`docs/04`), acessibilidade (`docs/05`),
plano de conscientização (`docs/09`), uso de IA (`docs/07-uso-de-ia.md`). Índice e rastreabilidade
requisito → evidência: `docs/00-indice.md`. PDFs de entrega: `scripts/build-pdf.sh <nº do grupo>`.

## Pré-requisitos

- Docker + Docker Compose, Linux com módulo `wireguard` e `/dev/net/tun`.
- ~8 GB de RAM livres (Wazuh é o mais pesado). Para a IA: Python 3.12 + `cloud/ai/requirements.txt`
  (opcional) e, para a triagem por LLM, [Ollama](https://ollama.com) com um modelo pequeno.

## Subir o laboratório

```bash
make bootstrap    # gera segredos (.env), PKI completa, chaves WireGuard e diretórios
make up           # sobe campo + borda + nuvem + SIEM
make status       # estado das 5 bordas (link, buffer, alarmes)
```

O painel corrigido fica em `https://localhost:8443` (via VPN no cenário real; exposto em localhost
para avaliação). As credenciais dos operadores e os segredos TOTP de laboratório são gerados em
`secrets/operadores.txt` (fora do git). O código TOTP atual sai de `make -s totp U=<usuario>` *(ou
`scripts/lib.sh`)*.

### Perfis opcionais

```bash
docker compose --profile legado up -d     # painel vulnerável + VPN legada (reprodução do incidente)
docker compose --profile phishing up -d   # DNS, caixa de e-mail e Gophish
```

## Reproduzir e investigar o incidente (E4)

```bash
make legado-users                         # (1x) deriva os usuários da VPN legada
attack/inc-va-0712.sh                     # encena phishing → VPN legada → SQLi → agenda da bomba
forensics/coletar.sh INC-VA-0712          # coleta evidências com hash + cadeia de custódia
python3 forensics/timeline.py             # linha do tempo correlacionada por NTP
```

Resultado esperado: o SIEM gera alertas das regras (a), (b) e (d), e **a borda recusa a agenda
maliciosa** — mesmo com o painel e o banco comprometidos, o reservatório fica protegido.

## Testes de segurança (E3)

```bash
tests/t01_sqli_antes_depois.sh  # SQLi antes/depois: payloads + sqlmap, WAF, privilégio mínimo (27 verificações; perfil legado)
tests/t03_vpn_segmentacao.sh    # mTLS, segmentação, MFA da VPN, failover (13 verificações)
tests/t04_siem_regras.sh        # valida as 4 regras de detecção (wazuh-logtest)
tests/t05_soar_aprovacao.sh <id># ação de alto impacto só executa após aprovação humana
.venv/bin/python cloud/ai/anomaly.py        # Isolation Forest (métricas)
.venv/bin/python cloud/ai/triagem_llm.py    # triagem por LLM com guardrails
.venv/bin/python phishing/check_email_auth.py  # SPF/DKIM/DMARC
chaos/wan_down.sh 30            # teste de caos: WAN fora 30 min + reconciliação
metrics/collect.py 300 5 && metrics/medir_4g.sh escola 300 && python3 metrics/report.py   # métricas (RT-22)
```

## Estrutura

```
sites/        campo (simuladores) + borda (broker, edge-agent)
cloud/        ingest, banco, painel (corrigido/legado), SOAR, IA
vpn/          hub WireGuard, sidecar de borda, portal MFA, VPN legada
siem/         Wazuh (config, decoders, regras, listas)
attack/       reprodução controlada do INC-VA-0712
phishing/     DNS (SPF/DKIM/DMARC), Gophish, verificador de e-mail
forensics/    coleta, linha do tempo, dados voláteis, casos
chaos/ metrics/  teste de caos e coleta de métricas
pki/          CA própria (raiz + intermediária), emissão/revogação/rotação
docs/         E1, E3, E4 e documentos de apoio; docs/evidencias/
tests/        testes automatizados reproduzíveis
```

## Vídeo de demonstração

`scripts/video/gravar-demo.js` (Playwright) grava a demonstração da plataforma de ponta a ponta
(≈3 min, 1080p60), com legendas indicando o requisito de cada trecho: VPN + MFA (RT-06), login com
TOTP e RBAC (RT-09), visão geral e acessibilidade (RT-01/RT-21), comando de alto impacto aguardando
aprovação (RT-15), SOC/SOAR e alertas (RT-13/RT-15), auditoria (RT-12), SQLi no painel legado ×
corrigido + WAF (RT-08) e revogação automática da sessão VPN pelo SOAR. Cada quadro é uma captura
real do laboratório. A cena final bloqueia `bruno.coord` por 24 h: depois de gravar, desbloquear a
conta no banco.

## Ética e legalidade

Conforme a seção 7 do enunciado: toda atividade ofensiva ocorre **somente** no ambiente próprio e
isolado da equipe; o phishing simulado usa **apenas contas fictícias** e a página de destino **não
captura credenciais**; todos os dados são **sintéticos** (LGPD); nenhuma voz/imagem real é usada.
Segredos (chaves, senhas, TOTP) **não** são versionados — ficam em `.env`, `secrets/`, `pki/out/` e
`vpn/out/`, todos no `.gitignore`.

## Uso de IA

Declarado em `docs/07-uso-de-ia.md` (ferramentas e finalidade), conforme exigido pelo enunciado.
```bash
make down     # derruba (mantém dados)   |   make clean  # apaga dados de runtime (mantém a PKI)
```
