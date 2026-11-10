# Uso de IA

Declaração do uso de inteligência artificial neste trabalho, conforme exigido pelo enunciado
(seção 7 — "Trabalho em equipe e autoria"). A equipe responde integralmente pelo conteúdo entregue.

## 1. IA como componente da solução (defensiva)

Faz parte da arquitetura entregue; roda **localmente**, sem enviar dados para fora da rede.

| Uso | Ferramenta | Finalidade | Onde |
|---|---|---|---|
| Detecção de anomalias na telemetria | scikit-learn (Isolation Forest) | Sinalizar leituras fora do padrão para o SIEM; nunca atua sobre atuadores | `cloud/ai/anomaly.py` |
| Triagem de e-mails (apoio) | LLM local via Ollama (`gemma4:12b`) | Classificar e-mails como phishing/suspeito/legítimo, com guardrails contra prompt injection; só rotula, sem executar ações | `cloud/ai/triagem_llm.py` |

Decisão de projeto (RT-17): nenhum componente de IA tem permissão para acionar atuadores físicos ou
ler o banco diretamente — a restrição é **arquitetural**, não apenas instruída no prompt.

## 2. IA como apoio ao desenvolvimento

O desenvolvimento deste projeto foi apoiado por um assistente de IA (Claude, da Anthropic, via
Claude Code), usado como par de programação para:

- gerar e revisar código dos serviços, scripts e configurações;
- redigir e revisar a documentação (arquitetura, laudo, este e os demais documentos de `docs/`);
- sugerir a estrutura dos testes e das evidências.

Todo o conteúdo gerado foi **revisado, testado e validado** pela equipe no laboratório antes de
entrar na entrega. As decisões de arquitetura, os ajustes e a verificação dos resultados são de
responsabilidade da equipe. Não foi usada nenhuma informação pessoal real em prompts: o cenário, os
dados e os domínios são fictícios/sintéticos.

## 3. Ameaças de IA tratadas no cenário (lado ofensivo, defendido)

O incidente INC-VA-0712 envolve IA usada pelo atacante (texto de phishing gerado por IA e voz
clonada). O projeto trata essas ameaças com controles específicos — SPF/DKIM/DMARC, banner de
remetente externo, triagem por LLM, verificação fora de banda e palavra-código — detalhados no
modelo de ameaças (`docs/01`) e nos testes (`docs/06`). Os testes de prompt injection contra o
próprio LLM defensivo estão em `cloud/ai/triagem_llm.py` e `docs/evidencias/ia_triagem_llm.md`.
