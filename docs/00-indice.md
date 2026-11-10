# Relatório Técnico — Índice e Rastreabilidade

Rede Comunitária Vila Aurora · FIAP Global Solution 2026.2 · Cybersecurity.

Este relatório consolida os entregáveis E1, E3 e E4 em seções próprias, cada uma identificada pelo
ID, conforme permitido pelo enunciado. O protótipo (E2) é o próprio repositório (ver `README.md`).

## Documentos

| Documento | Conteúdo | Entregável |
|---|---|---|
| `docs/01-modelo-ameacas.md` | Ativos, adversários, decomposição do incidente, STRIDE | E1 |
| `docs/02-arquitetura.md` | Camadas, fluxos, segmentação, decisões, redundância | E1 |
| `docs/06-testes-seguranca.md` | Resultados de todos os testes de segurança | E3 |
| `forensics/cases/INC-VA-0712/laudo-forense.md` | Laudo forense completo | E4 |
| `docs/03-custos-manutencao.md` | CAPEX/OPEX 12 meses e manutenção | apoio |
| `docs/04-privacidade-ripd.md` | RIPD simplificado (LGPD) | apoio |
| `docs/05-acessibilidade.md` | Conformidade WCAG 2.1 AA | apoio |
| `docs/07-uso-de-ia.md` | Declaração de uso de IA | apoio |

## Rastreabilidade: requisito → onde está → evidência

| RT | Requisito | Implementação | Evidência |
|---|---|---|---|
| RT-01 | Arquitetura em camadas, borda autônoma | `sites/edge-agent/`, `docs/02` | `make status`; teste de caos |
| RT-02 | Operação local em falha de link | `edge.py` (regras, store-and-forward) | `docs/evidencias/caos/` |
| RT-03 | Redundância proporcional (4G, modo degradado) | `vpn/`, `tc`, `docs/02 §6` | teste de failover (`t03`) |
| RT-04 | Identidade única + mTLS | `pki/`, `sites/broker/` | `t03` (sem cert/revogado) |
| RT-05 | Revogação e rotação | `pki/pki.sh`, `pki/agent.py` | `t03`; SOAR revoga cert |
| RT-06 | VPN moderna, sem porta exposta | `vpn/` (WireGuard) | `t03` (segmentação, MFA) |
| RT-07 | Segmentação, menor privilégio | redes Docker, firewall do hub | `t03` (5 verificações) |
| RT-08 | Painel sem SQLi (antes/depois) | `cloud/painel/` (2 variantes) | `docs/06 §1`; `attack/` |
| RT-09 | MFA + RBAC | `cloud/painel/app/` | `t05`; `docs/06 §3` |
| RT-10 | SPF/DKIM/DMARC | `phishing/gen-dns.sh` | `docs/evidencias/email_spf_dkim_dmarc.md` |
| RT-11 | Campanha de phishing simulado | `phishing/campanha.py` | `docs/evidencias/phishing_campanha.md` |
| RT-12 | Coleta centralizada + NTP | `siem/`, logs JSON | `forensics/` (linha do tempo) |
| RT-13 | Regras de detecção (a–d) | `siem/etc/rules/` | `t04` (10/10) |
| RT-14 | Investigação forense | `forensics/` | `forensics/cases/INC-VA-0712/` |
| RT-15 | Respostas automatizadas de baixo risco | `cloud/soar/` | `t05`; `docs/06 §5` |
| RT-16 | IA defensiva com métricas | `cloud/ai/` | `docs/evidencias/ia_*.md` |
| RT-17 | Guardrails de LLM | `cloud/ai/triagem_llm.py` | `docs/evidencias/ia_triagem_llm.md` |
| RT-18 | Ameaças de IA do cenário | triagem, fora de banda | `docs/01 §3`, `docs/06 §4` |
| RT-19 | Privacidade (LGPD) | HMAC, segregação, retenção | `docs/04` |
| RT-20 | Custos + manutenção | — | `docs/03` |
| RT-21 | Acessibilidade | `cloud/painel/app/` | `docs/05` |
| RT-22 | Métricas | `metrics/collect.py` | `metrics/out/`, `docs/evidencias/caos/` |
| RT-23 | Teste de caos | `chaos/wan_down.sh` | `docs/evidencias/caos/teste-caos.md` |

## Rastreabilidade: critério de avaliação → evidência

| Critério | Pontos | Onde é demonstrado |
|---|---|---|
| C1 Arquitetura resiliente e modular | 1,5 | `docs/02`, teste de caos |
| C2 Identidade, VPN e segmentação | 1,5 | `t03`, `pki/`, `vpn/` |
| C3 Segurança de aplicação (SQLi) | 1,5 | `docs/06 §1`, `attack/` |
| C4 Phishing e fator humano | 1,5 | `docs/06 §4`, `phishing/` |
| C5 Detecção, resposta e forense | 1,5 | `siem/`, `cloud/soar/`, `forensics/` |
| C6 IA & Cyber | 1,0 | `cloud/ai/`, `docs/evidencias/ia_*` |
| C7 Métricas, resiliência e continuidade | 0,5 | `chaos/`, `metrics/` |
| C8 Custos, privacidade, acessibilidade | 0,5 | `docs/03`, `docs/04`, `docs/05` |
| C9 Comunicação e documentação | 0,5 | `README.md`, este índice, `docs/` |

## Diferenciais implementados

- **Modelagem de ameaças formal (STRIDE)** com rastreabilidade até os controles (`docs/01`).
- **Infraestrutura como código**: todo o ambiente em `docker-compose.yml` versionado + `Makefile`.
- **Captura e análise de dados voláteis** de um nó (RFC 3227), com nota sobre Volatility 3 para VM.
