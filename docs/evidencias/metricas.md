# Métricas e continuidade (RT-22)

Coleta de 42 amostras em operação normal (`metrics/out/metrics.csv`) e 42 com uma borda em modo
degradado no 4G (`metrics/out/metrics-4g.csv`), mais a disponibilidade medida na telemetria do banco,
os indicadores de resposta (SOAR) e de resiliência (teste de caos).

| Indicador pedido no RT-22 | Como foi obtido | Seção |
|---|---|---|
| Disponibilidade (%) | medida (telemetria no banco) | 1 |
| MTTD e MTTR | medidos (SOAR) | 2 |
| Tempo de operação autônoma sem internet | medido (teste de caos) | 1 |
| Perda de dados na reconciliação | medida (teste de caos) | 1 |
| CPU e memória do nó de borda | medidas (`docker stats`) | 3 |
| Banda do nó de borda | medida (contadores das interfaces) | 4 |
| Energia do nó de borda | **estimada** por modelo sobre a CPU medida | 5 |

## 1. Disponibilidade e continuidade

Janela: 1015 minutos de laboratório ligado (16.9 h), incluindo o teste de caos, os testes de
failover e a reprodução do incidente. Minutos com o laboratório desligado não contam
(`metrics/availability.sql`).

- **Local**: a borda produziu telemetria naquele minuto (o espaço estava operando e medindo).
- **Central**: essa telemetria chegou à nuvem em até 60 s (a supervisão central enxergava o espaço).

| Borda | Minutos na janela | Disponibilidade local | Disponibilidade central | Minutos sem visão central |
|---|---:|---:|---:|---:|
| abrigo | 1015 | 99.90% | 95.76% | 42 |
| centro | 1015 | 100.00% | 95.76% | 43 |
| escola | 1015 | 99.90% | 95.37% | 46 |
| horta | 1015 | 99.90% | 95.76% | 42 |
| ubs | 1015 | 99.90% | 95.76% | 42 |

| Indicador | Valor | Fonte |
|---|---|---|
| Tempo de operação autônoma sem internet | ≥ 30 min (sem interrupção local) | teste de caos |
| Tempo de reconciliação ao voltar o link | 18 s | teste de caos |
| Dados reconciliados após a queda | +6579 leituras, 0 perdas/duplicatas | teste de caos |
| Bordas isoladas da nuvem na queda | 5/5 offline, 0 falhas locais | teste de caos |

## 2. Tempo de detecção e resposta (SOAR)

| Indicador | Valor |
|---|---|
| MTTD (evento → alerta), média | 1.36 s |
| MTTD, máximo | 2.36 s |
| MTTR (evento → contenção), média | 2.28 s |
| MTTR, máximo | 3.94 s |
| Respostas automáticas medidas | 21 |

## 3. CPU e memória do nó de borda

O nó de borda é a soma de três containers: agente de borda (regras + store-and-forward), broker MQTT
e sidecar de rede (WireGuard). CPU em % de **um** núcleo do host do laboratório.

| Borda | CPU média | CPU máx | Memória (agente + broker + rede) |
|---|---:|---:|---:|
| abrigo | 0.09% | 0.36% | 26.2 MiB |
| centro | 0.09% | 0.33% | 25.4 MiB |
| escola | 0.10% | 0.34% | 26.1 MiB |
| horta | 0.10% | 0.35% | 24.5 MiB |
| ubs | 0.10% | 0.35% | 24.0 MiB |

Serviços de nuvem que mais consomem memória (para dimensionar o servidor):

| Serviço | CPU média | Memória |
|---|---:|---:|
| siem | 0.16% | 171.5MiB |
| painel-app | 0.00% | 101.1MiB |
| painel-legado-app | 0.00% | 80.05MiB |
| db | 0.36% | 68.14MiB |
| ingest-app | 0.14% | 36.47MiB |

## 4. Banda do nó de borda

Taxa média medida pelos contadores de bytes de cada interface do nó (`/sys/class/net/*/statistics`).
"WAN" é o que realmente trafega no enlace (já com a sobrecarga do WireGuard e do mTLS).

| Borda | WAN fibra ↑ (kbit/s) | WAN fibra ↓ (kbit/s) | WAN 4G ↑ em espera (kbit/s) | Volume na fibra (MB/dia) |
|---|---:|---:|---:|---:|
| abrigo | 11.8 | 8.7 | 0.1 | 222 |
| centro | 11.4 | 8.7 | 0.1 | 218 |
| escola | 12.3 | 8.7 | 0.1 | 227 |
| horta | 11.4 | 8.8 | 0.1 | 219 |
| ubs | 11.3 | 8.7 | 0.1 | 216 |

Modo degradado (fibra derrubada, borda no 4G — só alarmes, eventos e estados sobem; a telemetria
completa fica no buffer até a fibra voltar):

| Borda | Link | WAN 4G ↑ (kbit/s) | WAN 4G ↓ (kbit/s) | Fibra normal ↑ (kbit/s) | Redução | Volume no 4G (MB/dia) | MB em 30 dias |
|---|---|---:|---:|---:|---:|---:|---:|
| escola | 4g | 5.5 | 4.8 | 12.3 | 55% | 111 | 3336 |

## 5. Energia do nó de borda (estimativa)

**Não é medição.** O laboratório roda em containers, então não há como medir a potência do hardware-alvo;
medir de verdade exige o nó físico e um medidor na alimentação. O valor abaixo aplica um modelo linear
sobre a CPU **medida** na seção 3: P = 3 W + (8 W − 3 W) × utilização,
com referência no Raspberry Pi 5 (hardware previsto em `docs/03`; ~3 W ocioso, ~8 W com
os 4 núcleos em carga). Como um núcleo do Pi é mais lento que o do host do laboratório, a coluna
"pessimista" multiplica a CPU medida por 10.

| Borda | CPU medida | Potência estimada | Potência (pessimista) | kWh/mês (pessimista) |
|---|---:|---:|---:|---:|
| abrigo | 0.09% | 3.00 W | 3.01 W | 2.20 |
| centro | 0.09% | 3.00 W | 3.01 W | 2.20 |
| escola | 0.10% | 3.00 W | 3.01 W | 2.20 |
| horta | 0.10% | 3.00 W | 3.01 W | 2.20 |
| ubs | 0.10% | 3.00 W | 3.01 W | 2.20 |

Total das 5 bordas no cenário pessimista: **11.0 kWh/mês**, cerca de
**R$ 10/mês** a R$ 0.95/kWh — dentro dos R$ 60/mês reservados em `docs/03`, que também
cobrem modem 4G, sensores e nobreak. O consumo é dominado pela potência ociosa da placa, não pela carga:
o software da borda praticamente não pesa.

## 6. Análise crítica

- **A disponibilidade que importa é a local, e ela ficou em ≥ 99.9%.** A central ficou em 95.4%: foram
  até 46 minutos sem visão na nuvem, quase todos provocados de propósito (30 min do teste de caos, mais os
  testes de failover e a medição do modo degradado). Nesses minutos nenhum espaço parou de medir nem de
  alarmar — é exatamente a diferença
  em relação ao INC-VA-0712, em que a queda da fibra silenciou a câmara fria.
- **A janela é curta.** Cerca de 17 horas de laboratório não sustentam uma afirmação de disponibilidade
  anual; o número mostra que o método de medição funciona e que a operação local não depende da nuvem.
- **O modo degradado reduziu a subida em 55%, menos do que o desenho sugere.** Reter a telemetria não
  basta: os eventos de estado dos dispositivos e as verificações de saúde do túnel continuam subindo e
  dominam o tráfego. Com a fibra fora o mês inteiro seriam ~3.3 GB por espaço no 4G — cabe num plano
  básico, mas com pouca folga, e uma sequência de alarmes aumenta o volume. Melhoria identificada: reduzir a
  frequência dos eventos de estado quando o link for o 4G.
- **MTTD/MTTR de poucos segundos valem para respostas automáticas de baixo risco.** Ações de alto impacto
  dependem de aprovação humana e seu tempo de resposta é o da pessoa, não o do sistema — isso é intencional.
- **CPU, memória e banda foram medidas em containers num host x86.** Servem para mostrar que a carga é baixa,
  não para prever o desempenho exato em um Raspberry Pi; a energia é estimativa e está marcada como tal.
- **Perda de dados zero vale para 30 min.** O buffer é limitado: numa queda muito longa a borda descarta
  telemetria antiga e preserva alarmes e eventos (registrando `outbox_overflow`).
