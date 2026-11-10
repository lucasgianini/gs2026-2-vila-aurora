# Métricas e continuidade (RT-22)

Coleta de 14 amostras (`metrics/out/metrics.csv`) em operação normal, mais os indicadores
de resposta (SOAR) e de resiliência (teste de caos).

## Disponibilidade e continuidade

| Indicador | Valor | Fonte |
|---|---|---|
| Tempo de operação autônoma sem internet | ≥ 30 min (sem interrupção local) | teste de caos |
| Tempo de reconciliação ao voltar o link | 18 s | teste de caos |
| Dados reconciliados após a queda | +6579 leituras, 0 perdas/duplicatas | teste de caos |
| Disponibilidade da operação local | 100% durante a queda (bordas seguiram operando) | teste de caos |
| Bordas isoladas da nuvem na queda | 5/5 offline, 0 falhas locais | teste de caos |

## Tempo de detecção e resposta (SOAR)

| Indicador | Valor |
|---|---|
| MTTD (evento → alerta), média | 1.47 s |
| MTTD, máximo | 2.36 s |
| MTTR (evento → contenção), média | 2.54 s |
| MTTR, máximo | 3.94 s |
| Respostas automáticas medidas | 11 |

## Consumo de recursos do nó de borda

Em operação normal, cada nó de borda é leve — compatível com um Raspberry Pi:

| Borda | CPU média | CPU máx | Memória |
|---|---|---|---|
| abrigo | 0.08% | 0.31% | 21.53MiB |
| centro | 0.07% | 0.31% | 21.04MiB |
| escola | 0.09% | 0.33% | 18.28MiB |
| horta | 0.07% | 0.30% | 20.98MiB |
| ubs | 0.07% | 0.30% | 20.68MiB |

## Consumo dos serviços de nuvem (maiores)

| Serviço | CPU média | Memória |
|---|---|---|
| painel-legado-app | 0.01% | 127.3MiB |
| siem | 0.21% | 67.58MiB |
| db | 0.41% | 47.41MiB |
| painel-app | 0.00% | 41.67MiB |
| mailpit | 0.11% | 41.57MiB |

## Leitura

O consumo confirma a viabilidade: as bordas usam ~20 MB e fração de 1% de CPU cada, e os serviços de
nuvem mais pesados (painel, SIEM, banco) ficam na casa de dezenas de MB. A operação local se sustenta
por tempo indefinido sem internet, e a
detecção/resposta automática ocorre em poucos segundos. Os números sustentam o critério C7 e a
estimativa de custos (hardware acessível).
