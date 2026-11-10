# Modelo de Ameaças — Rede Comunitária Vila Aurora

> Parte do **E1 – Documento de Arquitetura**. Metodologia: (1) decomposição do incidente INC-VA-0712 em falhas,
> (2) STRIDE por elemento da arquitetura, (3) rastreabilidade ameaça → controle → requisito → evidência.

## 1. Ativos e o que está em jogo

| Ativo | Por que importa | Impacto se comprometido |
|---|---|---|
| Câmara fria de vacinas (UBS) | Perda de lote de vacinas | Saúde pública, custo alto |
| Bomba e reservatórios (Escola, Horta) | Água para alunos e cozinha | Escola sem água, aulas suspensas |
| Abrigo (energia, alagamento) | Usado em enchentes | Risco à vida |
| Fechaduras RFID/QR | Acesso físico aos espaços | Invasão, furto de vacinas/equipamentos |
| Cadastro de voluntários e moradores | Dados pessoais (LGPD) | Vazamento, fraude, golpe direcionado |
| Credenciais de operadores | Porta de entrada para tudo acima | Controle total da infraestrutura |
| Logs e evidências | Capacidade de investigar | Incidente sem conclusão (como no INC-VA-0712) |

## 2. Adversários considerados

| Ator | Capacidade | Motivação |
|---|---|---|
| Golpista oportunista | Phishing com IA, voz clonada, kits prontos | Dados para fraude, extorsão |
| Atacante técnico remoto | SQLi automatizado (sqlmap), credential stuffing, abuso de VPN | Dados, sabotagem, notoriedade |
| Insider/voluntário mal-intencionado | Acesso físico ao espaço e à rede local | Vingança, furto |
| Falha não-maliciosa | Queda de fibra, falta de energia, erro humano | — (mesmo impacto operacional) |

## 3. Decomposição do INC-VA-0712

Cada falha do incidente tem pelo menos um controle preventivo **e** um detectivo na nova arquitetura.

| # | Falha que permitiu o ataque | Controle preventivo | Controle detectivo/resposta | RT |
|---|---|---|---|---|
| F1 | E-mail "da prefeitura" com texto gerado por IA aceito como legítimo | SPF/DKIM/DMARC `p=quarantine`; banner de remetente externo; triagem de e-mails por LLM | Métricas da campanha Gophish; reporte de phishing com 1 clique | RT-10, RT-16, RT-18 |
| F2 | Áudio com voz clonada reforçou a urgência | Palavra-código e **verificação fora de banda** (ligar de volta para número do cadastro) para pedidos urgentes | Registro de pedidos urgentes no painel | RT-18 |
| F3 | Credencial digitada em página falsa era suficiente | MFA (TOTP) no painel; WireGuard com chave por pessoa (credencial não-phishável); sem VPN por senha | Alerta de login de origem/horário anômalo | RT-06, RT-09 |
| F4 | VPN legada só com senha, exposta | Remoção da VPN legada; WireGuard + MFA; nenhuma porta administrativa exposta | Regra (a): login VPN anômalo | RT-06 |
| F5 | Rede plana: da VPN se alcançava o painel e o banco | Segmentação (IoT / borda / nuvem / admin), menor privilégio entre segmentos | Bloqueios registrados no firewall do hub | RT-07 |
| F6 | SQL Injection na busca do "histórico de acessos" | Consultas parametrizadas/ORM, validação no servidor, usuário de banco com privilégio mínimo, erro genérico, WAF | Regra (b): padrão de SQLi | RT-08 |
| F7 | Tabela de usuários em claro, com dados de moradores | Minimização e pseudonimização (crachá = HMAC na borda); segregação das tabelas; RBAC | Auditoria de consultas por perfil | RT-19, RT-09 |
| F8 | Agendamento da bomba alterado sem barreira | Mudança de agenda só com perfil técnico+MFA; **borda valida a agenda** (mínimo de 2 h/dia) e mantém intertravamento de nível (<= 20 % ⇒ liga) | Regra (d): comando de atuador fora do horário/perfil; evento `actuator_cmd_rejected` | RT-15, RT-13 |
| F9 | Alertas da câmara fria dependiam da nuvem | Regras locais na borda (2–8 °C), alarme local, painel local, store-and-forward | Alarme local + envio prioritário pelo 4G | RT-01, RT-02, RT-03 |
| F10 | Sem link alternativo | Uplink 4G em modo degradado (só alarmes/eventos) | Evento `wan_link_change` | RT-03 |
| F11 | Logs espalhados, relógios dessincronizados, logs sobrescritos | NTP em todos os nós, coleta centralizada (Wazuh), logs JSON com UTC, retenção definida, cópia imutável com hash | Laudo com cadeia de custódia | RT-12, RT-14 |
| F12 | Sem identidade de dispositivo (qualquer um publica) | Certificado X.509 único por dispositivo, mTLS, ACL por CN, CRL | Regra (c): dispositivo sem certificado válido | RT-04, RT-05 |

## 4. STRIDE por elemento

Legenda dos controles implementados: (impl.) no protótipo · (doc.) documentado/processo.

| Elemento | S (falsificação) | T (adulteração) | R (repúdio) | I (vazamento) | D (negação) | E (elevação) |
|---|---|---|---|---|---|---|
| Dispositivo de campo | Sensor falso publicando → (impl.) mTLS + CN única (RT-04) | Leitura forjada → (impl.) ACL por CN + checagem `device` = tópico na borda | (impl.) seq + ts por dispositivo | Telemetria em claro → (impl.) TLS 1.3 | Flood MQTT → (doc.) rate-limit do broker | Dispositivo publicando comando → (impl.) ACL (`cmd` só leitura) |
| Broker local | Broker falso → (impl.) dispositivo valida cert do broker | Mensagem alterada → (impl.) TLS | (impl.) log de conexões | (impl.) sem listener em claro | Queda do broker → (impl.) restart + buffer do dispositivo (QoS 1) | (impl.) container sem root, `read_only`, `cap_drop: ALL` |
| Nó de borda | Nuvem falsa → (impl.) mTLS + CRL | Agenda maliciosa → (impl.) validação local | (impl.) log JSON de toda decisão | Crachá cru → (impl.) HMAC antes de armazenar | Perda de WAN → (impl.) operação autônoma + 4G | Comando perigoso → (impl.) intertravamentos + aprovação humana |
| Uplink WAN | Borda falsa → (impl.) cert por borda | (impl.) WireGuard (dia 3) | — | (impl.) túnel cifrado | Corte da fibra → (impl.) failover 4G | — |
| Ingest/API nuvem | (impl.) mTLS (só bordas válidas) | Reenvio/duplicação → (impl.) idempotência (edge, seq) | (impl.) auditoria | (impl.) segmento sem acesso externo | Volume → (doc.) limite de lote | (impl.) usuário de banco só `INSERT` |
| Painel | Login roubado → (impl.) MFA TOTP | SQLi → (impl.) parametrização + WAF | (impl.) trilha de auditoria por usuário | Erro com stack → (impl.) mensagens genéricas | (doc.) rate-limit de login | (impl.) RBAC 4 perfis |
| Banco de dados | — | (impl.) usuários por serviço com mínimo privilégio | (impl.) `log_statement` p/ DDL/mod | (impl.) pseudonimização, rede interna | (doc.) backup diário | (impl.) painel sem `DROP/ALTER` |
| Acesso administrativo | (impl.) chave WG por pessoa + TOTP | — | (impl.) log de sessão VPN | — | — | (impl.) segmento admin separado |
| SIEM/logs | Log falso → (impl.) origem autenticada por agente | Apagar rastros → (impl.) envio imediato + hash | (impl.) NTP | (doc.) acesso só auditor | Disco cheio → (doc.) retenção 90 dias | — |
| LLM (triagem) | — | Prompt injection indireto → (impl.) guardrails, saída JSON validada | (impl.) log de prompts/decisões | Vazamento de dados → (impl.) dados pseudonimizados, sem tool de leitura do banco | — | **LLM não aciona atuadores** (RT-17) (impl.) |

## 5. Riscos aceitos (e por quê)

- **Sem redundância de nuvem multi-região:** o essencial roda na borda; a nuvem guarda histórico e análise. Uma indisponibilidade de nuvem degrada a supervisão central, não a operação.
- **4G compartilhado entre espaços (1 modem por espaço, plano básico):** suficiente para alarmes/eventos; a telemetria completa espera a fibra.
- **Ataque físico ao nó de borda:** mitigado parcialmente (chave em arquivo com permissão restrita, gabinete trancado (doc.)); TPM/secure element fica como evolução.
