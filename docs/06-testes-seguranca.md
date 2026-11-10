# E3 — Relatório de Testes de Segurança

Consolida as evidências dos testes executados no laboratório, cada uma com o requisito (RT) e o
critério (C) correspondentes. As evidências brutas estão em `docs/evidencias/` e `forensics/cases/`;
os testes automatizados ficam em `tests/` e são reproduzíveis com `make`.

## 1. SQL Injection — antes e depois (RT-08 · C3)

Duas versões do painel na mesma base de código: `legado` (vulnerável, só em laboratório) e
`corrigido` (produção).

| Teste | Painel legado | Painel corrigido |
|---|---|---|
| `UNION SELECT` extraindo cadastro | **vaza** nome/e-mail/telefone (sintéticos) | entrada **recusada** pela validação |
| SQL empilhado alterando a agenda da bomba | **executa** no banco | não aplicável (parametrizado) |
| Erro de sintaxe | devolve o **erro do banco** (vazamento) | mensagem **genérica** |

Correção na causa raiz: consultas parametrizadas, validação no servidor, usuário de banco com
privilégio mínimo, mensagens de erro genéricas e camada extra (filtro de padrões). Evidência:
`docs/evidencias/t03_*`, reprodução em `attack/inc-va-0712.sh`.

## 2. Identidade, mTLS e VPN (RT-04/05/06/07 · C2)

`tests/t03_vpn_segmentacao.sh` — **13/13 verificações**:

- Conexão MQTT **sem certificado**: recusada. Certificado **revogado**: recusado (CRL).
- Dispositivo publicando em tópico de outro: bloqueado pela ACL por identidade.
- Borda alcança a nuvem **só pelo túnel** WireGuard; não alcança outras bordas nem o banco.
- Painel administrativo **inacessível sem MFA** da VPN; MFA vinculado ao dono da chave.
- Nenhuma porta administrativa exposta em `0.0.0.0` no host.
- Revogação de certificado e rotação demonstradas (`pki/pki.sh`, agente de revogação do SOAR).

## 3. Autenticação e RBAC do painel (RT-09 · C2)

- Login exige senha (argon2id) **e** TOTP; bloqueio após 5 falhas.
- Quatro perfis (operador, técnico, coordenação, auditor); auditor em `/comandos` → **403**.
- CSRF obrigatório; POST sem token → **400**.
- Ação de alto impacto exige aprovação de **segunda pessoa** (quatro olhos): autor aprovando o
  próprio pedido → 403. Evidência: `tests/t05_soar_aprovacao.sh` (**7/7**).

## 4. Phishing e fator humano (RT-10/11/18 · C4)

- **SPF/DKIM/DMARC** (`p=quarantine`) publicados no DNS do domínio fictício. Verificador com 5 casos:
  legítimo (pass), spoofing do domínio (quarentena), adulteração (DKIM fail), domínio parecido
  (sem proteção → exige controles humanos). Evidência: `docs/evidencias/email_spf_dkim_dmarc.md`.
- **Campanha Gophish** só com contas fictícias, página sem captura de dados, comportamento simulado
  por perfis: 16 enviados, 75% abertos, 31% clicaram, 12% reportaram, **0 dados capturados**.
- Verificação **fora de banda** e palavra-código contra voz clonada (página Segurança do painel).

## 5. Detecção, resposta e forense (RT-12/13/14/15 · C5)

- **4 regras de detecção** validadas (`tests/t04_siem_regras.sh`, 10/10): (a) login VPN anômalo,
  (b) SQLi, (c) certificado inválido, (d) atuador fora de horário/perfil.
- **SOAR**: respostas de baixo risco automáticas (bloquear IP/conta, isolar dispositivo, revogar
  certificado, modo seguro); alto impacto só após aprovação humana. MTTD ~1 s, MTTR ~2 s.
- **Forense**: coleta de 9 fontes com SHA-256 e cadeia de custódia selada, linha do tempo
  correlacionada por NTP, mapeamento MITRE ATT&CK (Enterprise + ICS). Ver `forensics/cases/INC-VA-0712/`.

## 6. IA & Cyber (RT-16/17/18 · C6)

- **Detecção de anomalias** (Isolation Forest) na telemetria real, com anomalias rotuladas injetadas:
  métricas por leitura e por evento (picos/fora de faixa detectados; deriva/travado são o limite).
  A IA só gera alerta, **nunca atua** (RT-17 garantido por arquitetura).
- **Triagem de e-mails por LLM local** com guardrails (pré-filtro, delimitação, JSON Schema,
  canário anti-vazamento, sem ferramentas): resistência a prompt injection **8/8** vs. 7/8 do prompt
  ingênuo; ganho mensurável no vazamento de prompt. Evidência: `docs/evidencias/ia_*`.

## 7. Resiliência e métricas (RT-22/23 · C7)

- **Teste de caos**: WAN (fibra+4G) fora por >=30 min; as 5 bordas seguiram operando, alarme crítico
  da câmara fria disparou **sem nuvem**, reconciliação sem perda e sem duplicação ao voltar.
- **Métricas**: disponibilidade, MTTD/MTTR, tempo de operação autônoma, consumo de CPU/memória/banda
  do nó de borda. Ver `docs/evidencias/caos/` e `metrics/out/`.

## 8. Como reproduzir

Tudo sobe de um clone limpo com `make bootstrap && make up`. Cada teste tem um alvo em `tests/` e as
evidências são regeneradas pelos scripts. Detalhes no `README.md`.
