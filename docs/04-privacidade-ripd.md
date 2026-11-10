# Privacidade e RIPD simplificado (RT-19)

Relatório de Impacto à Proteção de Dados Pessoais (RIPD) simplificado da Rede Vila Aurora, conforme
a LGPD (Lei 13.709/2018). Privacidade desde a concepção (*privacy by design*) e por padrão.

> No protótipo, **todos os dados pessoais são sintéticos** (gerados com Faker). Nenhum dado real de
> morador ou voluntário aparece no código, nos logs ou neste documento.

## 1. Dados pessoais tratados

| Dado | Titular | Finalidade | Base legal (LGPD) |
|---|---|---|---|
| Nome, e-mail, telefone | Voluntário / equipe | Comunicação e organização dos espaços | Art. 7º, IX (interesse legítimo) / consentimento |
| Identificador de crachá (RFID/QR) | Voluntário / morador | Controle de acesso aos espaços | Art. 7º, II (execução de política pública) |
| Registro de acesso (quem, quando, onde) | Voluntário / morador | Segurança física e auditoria | Art. 7º, IX (interesse legítimo) |
| Credenciais de operador | Equipe técnica | Autenticação no painel | Art. 7º, IX |
| Telefone de verificação | Equipe | Verificação fora de banda (antifraude) | Art. 7º, IX |

Não há tratamento de dados sensíveis. A UBS monitora a **temperatura da câmara fria**, não dados de
saúde de pessoas.

## 2. Minimização e pseudonimização (privacy by design)

- **Crachá nunca é armazenado em claro.** Na própria borda, o identificador do crachá é convertido
  em um pseudônimo por **HMAC-SHA256** com chave secreta antes de qualquer registro ou envio. O
  painel e os logs mostram só o pseudônimo; ligar pseudônimo a pessoa exige acesso separado à tabela
  de cadastro, restrito por RBAC.
- **Segregação:** dados de contato ficam em um esquema (`cadastro`) separado da operação (`ops`); o
  usuário de banco do painel corrigido **não** tem acesso às colunas de contato.
- **Coleta mínima:** a telemetria é de equipamentos, não de pessoas. O registro de acesso guarda o
  pseudônimo, não o nome.

## 3. Retenção e descarte

| Dado | Retenção | Descarte |
|---|---|---|
| Telemetria de equipamentos | 90 dias (operacional) | Expurgo automático |
| Registros de acesso (pseudonimizados) | 2 anos | Expurgo; `reter_ate` por registro |
| Logs de segurança (SIEM) | 90 dias | Rotação do SIEM |
| Cadastro de pessoas | Enquanto durar o vínculo + 1 ano | Revisão anual; campo `reter_ate` |

## 4. Direitos dos titulares

A associação é a controladora. Pedidos de acesso, correção, portabilidade ou exclusão são recebidos
pela coordenação (canal presencial e e-mail) e atendidos em até 15 dias. Como o crachá é
pseudonimizado, a exclusão de uma pessoa remove o vínculo pseudônimo→identidade no cadastro.

## 5. Riscos e medidas (resumo do RIPD)

| Risco à privacidade | Probabilidade | Impacto | Medida |
|---|---|---|---|
| Vazamento do cadastro por SQLi (como no incidente) | Média | Alto | Consultas parametrizadas, usuário de BD mínimo, pseudonimização, WAF |
| Acesso indevido ao painel | Média | Alto | MFA, RBAC, VPN, auditoria append-only |
| Reidentificação pelo pseudônimo | Baixa | Médio | HMAC com chave secreta; chave fora do repositório |
| Uso dos dados por IA externa | Baixa | Médio | IA roda **local** (Ollama); nada sai da rede; dados sintéticos |
| Retenção além do necessário | Média | Médio | Prazos definidos e expurgo automático |

## 6. Decisão

O tratamento é **adequado e proporcional** à finalidade (operar os espaços com segurança), com
medidas técnicas e organizacionais compatíveis com o risco. O RIPD deve ser revisado anualmente e a
cada mudança relevante na arquitetura. Encarregado (DPO): papel atribuído a uma pessoa da
coordenação, com contato divulgado aos titulares.
