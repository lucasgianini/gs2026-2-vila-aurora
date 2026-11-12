# Custos e Plano de Manutenção (RT-20)

Estimativa de implantação e de operação por 12 meses para a Rede Vila Aurora (5 espaços), mais o
plano de manutenção. Valores em reais, referência novembro/2026, como **ordem de grandeza** para um
projeto comunitário de orçamento limitado — não são cotação. Premissa central: software livre e
hardware acessível, aproveitando a internet já existente em cada espaço.

## 1. Implantação (CAPEX, uma vez)

| Item | Qtd. | Unit. (R$) | Total (R$) | Observação |
|---|---:|---:|---:|---|
| Nó de borda (Raspberry Pi 5 8GB + fonte + cartão/SSD + gabinete) | 5 | 900 | 4.500 | 1 por espaço |
| Modem/roteador 4G + chip (plano de dados anual à parte) | 5 | 350 | 1.750 | uplink alternativo |
| Sensores e módulos (nível, temperatura, qualidade do ar, alagamento, relés) | — | — | 3.000 | conjunto p/ os 5 espaços |
| Leitoras RFID/QR para fechaduras | 5 | 250 | 1.250 | reaproveitar onde possível |
| Nobreak pequeno p/ a borda e o modem | 5 | 300 | 1.500 | continuidade em queda de energia |
| Servidor da nuvem (mini-PC p/ nuvem local do laboratório) | 1 | 4.000 | 4.000 | ou VM doada/cedida |
| Mão de obra de instalação e configuração inicial | — | — | 6.000 | serviço técnico pontual |
| **Total de implantação** | | | **22.000** | |

Se a nuvem for uma VM cedida (prefeitura/universidade parceira) e parte dos sensores for doada, a
implantação cai para a faixa de **R$ 12.000–15.000**.

## 2. Operação — 12 meses (OPEX)

| Item | Mensal (R$) | 12 meses (R$) | Observação |
|---|---:|---:|---|
| Planos de dados 4G (5 chips, plano básico) | 250 | 3.000 | só backup/modo degradado |
| Energia adicional dos equipamentos | 60 | 720 | baixo consumo |
| Hospedagem da nuvem (se em VM alugada) | 150 | 1.800 | R$ 0 se VM cedida |
| Certificado/domínio (domínio `.test` é fictício; em produção, domínio real) | — | 60 | ~R$ 60/ano |
| Manutenção técnica (visitas trimestrais + suporte) | 400 | 4.800 | voluntário técnico + fundo |
| Reserva para reposição de hardware (sensores, cartões) | 100 | 1.200 | ~5% do CAPEX/ano |
| Material de conscientização (cartazes, listas impressas) | 20 | 240 | plano em `docs/09` |
| **Total de operação (12 meses)** | | **11.820** | **R$ 10.020 com VM cedida** |

Software é 100% livre (Linux, Mosquitto, PostgreSQL, WireGuard, Wazuh, Gophish, Ollama, OpenSSL),
então não há custo de licença. A IA roda **localmente** (Ollama), sem custo por chamada nem envio de
dados para fora — o que também favorece a LGPD.

## 3. Plano de manutenção

| Frequência | Atividade | Responsável |
|---|---|---|
| Contínuo | SIEM coleta logs; SOAR responde a baixo risco; backup diário do banco | Automático |
| Semanal | Revisar alertas do SOC; conferir alarmes e filas (outbox) das bordas | Técnico voluntário |
| Mensal | Reunião da equipe com momento de segurança; trocar a palavra-código; revisar lista de acessos | Coordenação |
| Trimestral | Atualização de firmware/pacotes; teste de restauração de backup; simulado de resposta; simulação de phishing (`docs/09`) | Técnico |
| Semestral | **Rotação de certificados** de dispositivos e revisão da PKI; teste de caos | Técnico |
| Anual | Revisão do RIPD e do modelo de ameaças; troca presencial de senhas; balanço do plano de conscientização | Coordenação + técnico |

**Responsáveis.** A manutenção é feita por voluntários com apoio técnico pontual. Pontos críticos
(PKI, backups, SIEM) têm pelo menos duas pessoas capazes de operar, para não depender de uma só.
Procedimentos ficam documentados no repositório (README e `docs/`), em linguagem simples.

## 4. Sustentabilidade financeira

O custo recorrente (~R$ 1.000/mês, ou menos com recursos cedidos) é compatível com rateio entre a
associação, a prefeitura e parceiros. A escolha por software livre, IA local e redundância
proporcional mantém o custo baixo e a operação dentro da capacidade da comunidade — coerente com o
pedido do enunciado por uma solução **consciente**, não a mais cara nem a mais complexa.
