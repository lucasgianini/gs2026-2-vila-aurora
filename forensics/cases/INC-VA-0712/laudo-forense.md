# E4 — Laudo Forense do Incidente INC-VA-0712

Rede Comunitária Vila Aurora · Relatório de resposta a incidente (laboratório).

> Documento produzido a partir da **reprodução controlada** do incidente no ambiente isolado do
> laboratório, para fins acadêmicos (FIAP GS 2026.2) e com dados sintéticos. Serve para demonstrar a
> capacidade de investigação da arquitetura redesenhada, não como relato de um evento real.

## 1. Resumo executivo

O incidente INC-VA-0712 teve origem em um **phishing** apoiado por IA que levou à captura de uma
credencial de operador. A credencial foi reusada em uma **VPN legada protegida apenas por senha**,
a partir da qual o atacante alcançou o **painel de supervisão** e explorou uma **injeção de SQL**
para extrair o cadastro e alterar a agenda da bomba de água. No ambiente **original**, a falta de
operação local e de sincronismo de logs agravou o impacto (reservatório esvaziado, câmara fria sem
alarme, investigação inconclusiva).

Na arquitetura **redesenhada**, a mesma cadeia de ataque foi reproduzida e: (1) todas as fases foram
**detectadas** pelo SIEM; (2) a borda **recusou** a agenda maliciosa, protegendo o reservatório; e
(3) as evidências foram preservadas de forma íntegra e correlacionadas no tempo.

## 2. Escopo e metodologia

- **Ambiente:** laboratório em containers, redes isoladas, dados sintéticos.
- **Preservação:** cada evidência foi copiada e teve o **SHA-256** calculado no momento da coleta,
  com registro em cadeia de custódia (`cadeia-custodia.csv`) e manifesto selado (`selo.txt`).
- **Correlação temporal:** todos os nós sincronizados por NTP; horários em UTC.
- **Referências:** MITRE ATT&CK (Enterprise e ICS) — ver `mitre-attack.md`.

## 3. Evidências coletadas

Nove fontes, mais dados voláteis de um nó (ver cadeia de custódia para hashes completos):

| Item | Evidência | Fonte |
|---|---|---|
| E01 | Alertas do SIEM (Wazuh) | `siem:/var/ossec/logs/alerts/alerts.json` |
| E02 | Arquivo bruto de eventos | `siem:/var/ossec/logs/archives` |
| E03 | Autenticação da VPN legada | `vpn-legado.log` |
| E04 | Acessos HTTP ao painel legado | `painel-legado-gw.jsonl` |
| E05 | Consultas do PostgreSQL | `postgresql.json` |
| E06 | Decisões da borda (recusa) | `edge-escola.jsonl` |
| E07/E08 | Comandos e trilha de auditoria | `ops.commands`, `audit.log` |
| E09 | Respostas do SOAR | `soar.jsonl` |
| V01–V06 | Dados voláteis de um nó (RFC 3227) | container do caso |

A integridade é verificável a qualquer momento recalculando os hashes e comparando com a cadeia de
custódia; o manifesto selado detecta alteração de qualquer item.

## 4. Linha do tempo (resumo)

A linha do tempo completa e correlacionada está em `linha-do-tempo.md`. Em resumo:

1. Autenticação na VPN legada (só senha) a partir de IP externo → alerta (a).
2. Acesso ao painel legado com a credencial reusada.
3. Requisições com padrão de SQL Injection no histórico de acessos → alerta (b).
4. Execução, no banco, de `UNION SELECT` (extração) e `UPDATE` da agenda (alteração).
5. A borda recebe a nova agenda como comando e a **recusa** (política < 2h/dia) → alerta (d).
6. SOAR registra e aplica respostas de baixo risco; ação de alto impacto fica para aprovação humana.

O sincronismo por NTP permitiu ordenar eventos de seis fontes distintas em uma única linha do tempo
— exatamente o que não foi possível no incidente original (relógios dessincronizados, logs
sobrescritos).

## 5. Causa raiz e fatores contribuintes

- **Causa raiz:** autenticação fraca exposta (VPN só-senha, sem MFA) combinada com uma vulnerabilidade
  de injeção de SQL no painel e ausência de validação local dos comandos de atuador.
- **Fatores contribuintes:** reuso de credencial entre sistemas; rede plana (da VPN se alcançava o
  banco); dependência da nuvem para funções críticas; logs dispersos e sem sincronismo.

## 6. Contenção e correção

| Falha | Correção aplicada (verificada) |
|---|---|
| VPN só-senha | WireGuard com chave por pessoa + MFA; VPN legada removida |
| SQL Injection | Consultas parametrizadas, validação, usuário de BD mínimo, erro genérico, filtro |
| Rede plana | Segmentação com política padrão-negar |
| Comando de atuador sem barreira | Validação na borda (agenda, intertravamento de nível) + aprovação humana |
| Logs dispersos/sem sincronia | Coleta centralizada (SIEM), NTP, log append-only com hash |
| Sem operação local | Regras e alarmes na borda, store-and-forward, painel local |

## 7. Conclusão

A arquitetura redesenhada **detectou** as três fases ofensivas (regras a/b/d), **conteve** o impacto
físico (a bomba não recebeu a agenda maliciosa) e **preservou** evidências íntegras e correlacionáveis.
A diferença decisiva em relação ao incidente original é a independência da borda: a segurança deixou
de depender de um único ponto.

## 8. Recomendações

1. Desativar em definitivo qualquer autenticação só-senha exposta.
2. Impedir, via CI, o retorno da versão vulnerável do painel.
3. Revisar periodicamente listas de acesso e janelas de operação dos atuadores.
4. Exercitar resposta e restauração de evidências em simulações trimestrais (ver plano de manutenção).
