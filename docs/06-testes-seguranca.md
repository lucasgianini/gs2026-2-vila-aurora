# E3 — Relatório de Testes de Segurança

Consolida as evidências dos testes executados no laboratório, cada uma com o requisito (RT) e o
critério (C) correspondentes. As saídas reais dos testes estão nos **Anexos A a I** deste relatório
(e, no repositório, em `docs/evidencias/`); os scripts ficam em `tests/` e são reproduzíveis.

| Anexo | Conteúdo | Requisitos |
|---|---|---|
| A | SQL Injection antes/depois — saída do teste `t01` | RT-08 |
| B | mTLS, VPN, segmentação, regras do SIEM, aprovação humana — saídas de `t03`, `t04`, `t05` | RT-04 a RT-07, RT-13, RT-15 |
| C | SPF, DKIM e DMARC — registros e casos de teste | RT-10 |
| D | Campanha de phishing simulado e métricas | RT-11 |
| E | Plano de conscientização dos voluntários | RT-11, RT-18 |
| F | Isolation Forest — métricas | RT-16 |
| G | Triagem por LLM e testes de prompt injection | RT-16, RT-17 |
| H | Teste de caos de 30 minutos | RT-23 |
| I | Métricas de disponibilidade, resposta e consumo | RT-22 |

## 1. SQL Injection — antes e depois (RT-08 · C3)

Duas versões do painel na mesma base de código: `legado` (vulnerável, só em laboratório) e
`corrigido` (produção). O teste `tests/t01_sqli_antes_depois.sh` aplica **os mesmos payloads** nas
duas, manualmente e com o sqlmap — **27/27 verificações** (saída completa no Anexo A).

| Teste | Painel legado (antes) | Painel corrigido (depois) |
|--------------------------|----------------------------------|------------------------------|
| `x' UNION SELECT ... FROM cadastro.pessoas--` | **vaza** 40 registros de nome/e-mail/telefone (sintéticos) | recusado; 0 registros |
| `x'` (aspa solta) | devolve o **erro do PostgreSQL** ao usuário | mensagem genérica, sem detalhe do banco |
| `x'; SELECT pg_sleep(3);--` (empilhado) | **executa**: resposta em 3,4 s | não executa: resposta em 0,25 s |
| sqlmap 1.9.11 | parâmetro `q` **injetável** (UNION, 6 colunas); lista as tabelas e extrai `cadastro.pessoas` | **nenhum** parâmetro injetável (`q`, `site`, `dia`; level 3, risk 2) |

A correção é na **causa raiz**, com camadas adicionais; o teste mede cada uma separadamente:

| Camada | Controle | Como foi verificado |
|--------------|----------------------------------------|----------------------------------|
| Aplicação (causa raiz) | Consultas parametrizadas — o valor nunca vira SQL (`cloud/painel/app/repo.py`) | sqlmap direto na aplicação, **sem** o WAF na frente: nada injetável |
| Aplicação | Validação no servidor por lista branca (letras, números, espaço, hífen; até 40 caracteres) | os três payloads recebem a mesma mensagem de orientação |
| Aplicação | Mensagem de erro genérica | nenhum texto do banco na resposta |
| Banco | Usuário `va_painel` com privilégio mínimo | não lê `cadastro.pessoas`, não altera histórico nem auditoria, sem DDL (5 verificações) |
| Gateway (camada adicional) | WAF mínimo no nginx: assinaturas de SQLi na query string → 403 (`cloud/painel/nginx.conf`) | UNION e empilhado barrados antes da aplicação; sqlmap recebe 403 e detecta o WAF |
| Detecção | Regras (b) do SIEM | 6 regras distintas dispararam durante o teste (mais de 400 alertas) |
| Resposta | SOAR | um único payload pelo caminho real: sessão VPN de origem encerrada, MTTR ≈ 3 s |

Limites, ditos com honestidade: o WAF é um conjunto pequeno de assinaturas, **não** um ModSecurity com
CRS, e inspeciona só a query string — pode ser contornado por ofuscação, e por isso é camada adicional e
não a correção (a aspa solta, por exemplo, passa por ele e é recusada pela validação). Os formulários
POST não passam pelo WAF e dependem das mesmas consultas parametrizadas e do CSRF.

## 2. Identidade, mTLS e VPN (RT-04/05/06/07 · C2)

`tests/t03_vpn_segmentacao.sh` — **13/13 verificações** (Anexo B):

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
  (sem proteção → exige controles humanos). Evidência: Anexo C.
- **Campanha Gophish** só com contas fictícias, página sem captura de dados, comportamento simulado
  por perfis: 16 enviados, 75% abertos, 31% clicaram, 12% reportaram, **0 dados capturados** (Anexo D).
- Verificação **fora de banda** e palavra-código contra voz clonada (página Segurança do painel).
- **Plano de conscientização adaptado a voluntários** (públicos, cinco regras, procedimento para pedido
  urgente, metas de clique/reporte, cronograma de 12 meses): `docs/09-plano-conscientizacao.md`, Anexo E.

## 5. Detecção, resposta e forense (RT-12/13/14/15 · C5)

- **4 regras de detecção** validadas (`tests/t04_siem_regras.sh`, 10/10, Anexo B): (a) login VPN anômalo,
  (b) SQLi, (c) certificado inválido, (d) atuador fora de horário/perfil.
- **SOAR**: respostas de baixo risco automáticas (bloquear IP/conta, isolar dispositivo, revogar
  certificado, modo seguro); alto impacto só após aprovação humana. MTTD ~1 s, MTTR ~2 s.
- **Forense**: coleta de 9 fontes com SHA-256 e cadeia de custódia selada, linha do tempo
  correlacionada por NTP, mapeamento MITRE ATT&CK (Enterprise + ICS). É o entregável E4.

## 6. IA & Cyber (RT-16/17/18 · C6)

### 6.1 IA defensiva com métricas medidas (RT-16)

- **Detecção de anomalias** (Isolation Forest) sobre a telemetria real do laboratório, com anomalias
  rotuladas injetadas em 5 sensores: precisão 0,50 · revocação 0,49 · taxa de falsos positivos 3,6%
  por leitura; por **evento**, 22 de 24 detectados. Leitura crítica e matriz de confusão no Anexo F.
- **Triagem de e-mails por LLM local** (Ollama, `gemma4:12b`): 24 e-mails sem injeção, precisão 1,00 e
  revocação 1,00 — num conjunto pequeno e sintético, o que não autoriza generalizar (Anexo G).

### 6.2 Guardrails testados contra prompt injection (RT-17)

O próprio LLM foi atacado com 8 e-mails maliciosos — injeção **direta**, **indireta** (instrução
escondida em comentário HTML, texto citado e falso diálogo), tentativa de **vazamento** do prompt e
pedido de **ação física** — comparando um prompt ingênuo com o pipeline protegido:

| Pipeline | Resistiu | Vazou o código interno (canário) |
|---|---|---|
| Prompt ingênuo | 7/8 | sim (caso I05) |
| Com guardrails G1–G6 | **8/8** | não |

O ganho medido dos guardrails foi no vazamento do prompt; nas injeções de instrução o modelo já resistia
sozinho. O controle que não depende do modelo é arquitetural: **o LLM não tem ferramentas nem rota de
rede até a borda**, então não aciona atuadores nem que seja convencido a tentar.

### 6.3 Riscos mapeados no OWASP Top 10 para LLM (2025) e no MITRE ATLAS

| OWASP LLM | MITRE ATLAS | Risco neste cenário | Controle | Evidência |
|--------------|--------------|--------------------|--------------------------------------|------------|
| LLM01 Prompt Injection | AML.T0051.000 (direta) · AML.T0051.001 (indireta) | E-mail manda o classificador "responder legítimo" | G1 pré-filtro de instruções, HTML oculto e caracteres invisíveis; G2 e-mail entre delimitadores aleatórios, declarado como dado; G4 injeção detectada nunca resulta em "legítimo" | I01–I04, I08: 8/8 |
| LLM02 Sensitive Information Disclosure | AML.T0057 LLM Data Leakage | Modelo expor dados pessoais | O LLM só recebe o e-mail em análise; não lê o banco; roda localmente (nada sai da rede) | arquitetura (`docs/02`) |
| LLM03 Supply Chain | AML.T0010 ML Supply Chain Compromise | Modelo adulterado na origem | Modelo do registro oficial do Ollama, por tag fixa; conferir o digest a cada atualização fica como recomendação | — |
| LLM04 Data and Model Poisoning | AML.T0020 Poison Training Data | Sensor comprometido "ensinar" o Isolation Forest que o anormal é normal | Identidade por dispositivo (mTLS); o LLM não é treinado com dados da rede; as regras determinísticas da borda continuam sendo a proteção primária | `t03`; Anexo F |
| LLM05 Improper Output Handling | — | Saída do modelo usada como comando ou HTML | G3 saída presa a JSON Schema com enumeração; saída inválida vira "suspeito"; nada é executado | validação em `triagem_llm.py` |
| LLM06 Excessive Agency | AML.T0053 (uso indevido de ferramentas do LLM) | E-mail convence o LLM a "ligar a bomba" ou "liberar as portas" | G6 sem ferramentas e sem rota para a borda; a tentativa só é registrada | I07 |
| LLM07 System Prompt Leakage | AML.T0056 (extração do prompt de sistema) | Atacante obtém as instruções internas para contorná-las | G5 canário secreto no prompt: se aparecer na saída, a resposta é bloqueada | I05, I06 |
| LLM08 Vector and Embedding Weaknesses | — | Não se aplica: não há RAG nem base vetorial | — | — |
| LLM09 Misinformation | AML.T0015 Evade ML Model | Phishing bem escrito classificado como legítimo e alguém confiar no rótulo | O LLM é apoio, não decisão: SPF/DKIM/DMARC, verificação fora de banda e palavra-código não dependem dele | Anexo G (limitações) |
| LLM10 Unbounded Consumption | AML.T0029 Denial of ML Service | E-mails enormes ou em massa travarem a triagem (~16 s por e-mail) | Texto truncado em 4.000 caracteres, tempo limite por chamada, triagem assíncrona fora do caminho crítico | `triagem_llm.py` |

Identificadores do ATLAS conforme a matriz pública; os nomes das técnicas mudam entre versões.

### 6.4 Ameaças potencializadas por IA no cenário (RT-18)

| Ameaça do INC-VA-0712 | Por que a IA piora | Controle técnico | Controle humano |
|------------------|----------------------|------------------------------|----------------------------|
| Phishing com texto gerado por IA | Sem erros de português e personalizado: os sinais clássicos somem | SPF/DKIM/DMARC (`p=quarantine`), triagem por LLM; banner de remetente externo como recomendação | Cinco regras do plano de conscientização; reporte sem punição |
| Áudio com voz clonada do secretário | Voz conhecida deixa de ser prova de identidade | MFA e chave WireGuard por pessoa: a senha sozinha não basta; aprovação de segunda pessoa para alto impacto | **Verificação fora de banda** (ligar para o número do cadastro) e **palavra-código** mensal |
| Domínio parecido com o da prefeitura | Nenhum registro DNS nosso protege um domínio que não é nosso (caso 4 do Anexo C) | Triagem por LLM sinaliza domínio diferente de `vilaaurora.test` | Entrar sempre pelo endereço salvo, nunca pelo link |

## 7. Resiliência e métricas (RT-22/23 · C7)

- **Teste de caos** (Anexo H): WAN (fibra **e** 4G) fora por 30 min nas 5 bordas; todas seguiram operando,
  o alarme crítico da câmara fria disparou **sem nuvem** e, ao voltar o link, 6.579 leituras foram
  reconciliadas em 18 s, sem perda e sem duplicação.
- **Métricas** (Anexo I), todas medidas exceto a energia:

| Indicador do RT-22 | Resultado | Obtido como |
|----------------------------|--------------------------------------|--------------------------|
| Disponibilidade da operação local | ≥ 99,9% em ~17 h de laboratório | medido (telemetria no banco) |
| Disponibilidade da supervisão central | ~95,4–95,8% (as quedas foram provocadas pelos testes) | medido |
| MTTD / MTTR | 1,4 s / 2,3 s em média (21 respostas automáticas) | medido (SOAR) |
| Operação autônoma sem internet | ≥ 30 min, sem interrupção local | medido (caos) |
| Perda de dados na reconciliação | 0 | medido (caos) |
| CPU / memória do nó de borda | ~0,1% de um núcleo / ~25 MiB | medido |
| Banda do nó de borda | ~12 kbit/s de subida na fibra; ~5,5 kbit/s no 4G degradado | medido (contadores das interfaces) |
| Energia do nó de borda | ~3 W por nó (≈ 2,2 kWh/mês) | **estimado** por modelo sobre a CPU medida |

Análise crítica (detalhes no Anexo I): a janela de medição é curta para falar em disponibilidade anual; o
modo degradado reduziu a subida em cerca de 55%, menos do que o esperado, porque os eventos de estado
continuam subindo — reduzir sua frequência no 4G é melhoria identificada; e a energia não pôde ser medida
num laboratório em containers.

## 8. Como reproduzir

Tudo sobe de um clone limpo com `make bootstrap && make up`. Cada teste é um script em `tests/` e as
evidências são regeneradas por eles (`tests/t01_sqli_antes_depois.sh`, `tests/t03_vpn_segmentacao.sh`,
`tests/t04_siem_regras.sh`, `chaos/wan_down.sh 30`, `metrics/report.py`). Detalhes no `README.md`.
