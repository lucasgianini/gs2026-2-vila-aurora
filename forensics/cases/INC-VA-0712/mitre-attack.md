# Mapeamento MITRE ATT&CK — INC-VA-0712 (RT-14)

Técnicas observadas na reprodução do incidente, com a evidência que as sustenta, a detecção
correspondente no SIEM e o controle que mitiga cada uma na arquitetura redesenhada. Usa ATT&CK
Enterprise e, onde cabe, ATT&CK for ICS (atuadores da bomba/gerador).

| Tática | Técnica (ID) | O que o atacante fez | Evidência | Detecção (regra) | Controle na nova arquitetura |
|---|---|---|---|---|---|
| Reconhecimento / Acesso inicial | Phishing (T1566) | E-mail "da prefeitura" com IA + áudio de voz clonada induziram a entrega da credencial | (cenário) campanha simulada, triagem por IA | 100701 (IA) | SPF/DKIM/DMARC, banner externo, triagem LLM, verificação fora de banda (RT-10/16/18) |
| Acesso inicial | Contas válidas (T1078) | Reuso da credencial de phishing na VPN | E03 vpn-legado.log | 100110–100112 | MFA obrigatório; WireGuard com chave por pessoa (credencial não-phishável) (RT-06/09) |
| Acesso inicial | Serviços remotos externos (T1133) | Login na VPN legada exposta, só com senha | E03, E01 (alerta) | 100111/100112 | Remoção da VPN legada; nenhuma porta administrativa exposta (RT-06) |
| Movimentação lateral | Exploração de serviço (T1190) | SQL Injection no painel de supervisão | E04 painel-gw, E05 postgresql | 100200/100204/100206 | Consultas parametrizadas, validação, usuário de BD mínimo, WAF (RT-08) |
| Coleta / Exfiltração | Dados do repositório (T1213/T1119) | Extração da tabela de usuários via UNION | E05 (statement UNION) | 100200/100205 | Pseudonimização (HMAC), segregação de tabelas, RBAC, menor privilégio (RT-07/09/19) |
| Impacto (ICS) | Manipulação de controle (T0831/T0855) | Alteração da agenda da bomba por SQL empilhado | E05, E07 commands | 100403 (recusa) | Mudança de agenda vira comando validado na borda; intertravamento de nível (RT-15) |
| Impacto (ICS) | Negação de controle (T0813) | Objetivo: esvaziar o reservatório | E06 edge (recusa) | 100403 | Borda recusa agenda < 2h/dia e liga a bomba em nível crítico, mesmo offline (RT-01/02/15) |
| Evasão de defesa | Indicadores comprometidos (T1070) | No incidente original: logs sobrescritos, relógios fora de sincronia | (comparação) | — | NTP em todos os nós, coleta centralizada imediata, log append-only com hash (RT-12/14) |

## Observação sobre a contenção

A diferença central em relação ao incidente original está na última linha de impacto: as técnicas de
acesso inicial e exploração **ainda poderiam ocorrer** contra um componente mal configurado, mas o
objetivo físico do atacante (esvaziar o reservatório) é bloqueado na borda, de forma independente da
nuvem. A segurança deixou de depender de um único ponto (o painel) e passou a ter o intertravamento
local como última barreira — exatamente o que faltou no INC-VA-0712.

## Recomendações (resumo; detalhe no laudo E4)

1. Desativar em definitivo a VPN legada e qualquer autenticação só-senha exposta.
2. Manter o painel apenas na versão parametrizada; bloquear o retorno da versão vulnerável em CI.
3. Rever periodicamente as listas de IP/pessoas autorizadas e as janelas de operação dos atuadores.
4. Exercitar a resposta (SOAR) e a restauração de evidências em simulações trimestrais.
