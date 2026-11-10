# Campanha de phishing simulado (RT-11)

Laboratório: Gophish 0.12.1 + caixa Mailpit local. **Destinatários fictícios** (16 contas `voluntarioNN@vilaaurora.test`),
página de destino **sem captura de dados** (`capture_credentials=false`) e comportamento dos destinatários
**simulado** por perfis de risco (atento/médio/apressado). Nenhuma pessoa real foi alvo.

| Métrica | Quantidade | % dos enviados |
|---|---|---|
| Enviados | 16 | 100% |
| Abertos | 12 | 75% |
| Clicaram no link | 5 | 31% |
| Enviaram dados | 0 | 0% (a página não coleta nada) |
| Reportaram | 2 | 12% |

| Perfil | Destinatários | Clicaram | Reportaram |
|---|---|---|---|
| atento | 4 | 0 | 2 |
| medio | 8 | 3 | 0 |
| apressado | 4 | 2 | 0 |

Resultados por destinatário coletados da API do Gophish: 16 registros.
Os números validam o pipeline e o plano de conscientização; com voluntários reais, a campanha só
ocorreria com consentimento e comunicação prévia à coordenação.
