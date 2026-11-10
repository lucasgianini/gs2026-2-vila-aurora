# IA defensiva — Isolation Forest na telemetria (RT-16)

Gerado em 2026-11-10T17:53:54+00:00 a partir da telemetria real do laboratório.

Métricas por **leitura** (ponto a ponto) e por **evento** (um evento injetado conta como detectado
se ao menos uma de suas leituras for marcada — é o que importa para gerar um alerta).

| Sensor | Leituras (treino/teste) | Pontos anômalos | Precisão | Revocação | F1 | Taxa de FP | Matriz [VN FP; FN VP] | Eventos detectados |
|---|---|---|---|---|---|---|---|---|
| ubs-camara-fria (temp_c) | 525/351 | 30 | 0.58 | 0.50 | 0.54 | 0.034 | [310 11; 15 15] | 4/4 |
| escola-nivel-reservatorio (level_pct) | 529/354 | 25 | 0.37 | 0.80 | 0.51 | 0.103 | [295 34; 5 20] | 7/8 |
| centro-qualidade-ar (co2_ppm) | 534/357 | 21 | 0.56 | 0.48 | 0.51 | 0.024 | [328 8; 11 10] | 4/4 |
| abrigo-energia (load_w) | 532/355 | 21 | 0.50 | 0.19 | 0.28 | 0.012 | [330 4; 17 4] | 3/4 |
| escola-cloro (mg_l) | 530/354 | 21 | 0.82 | 0.43 | 0.56 | 0.006 | [331 2; 12 9] | 4/4 |

**Global:** precisão 0.50 · revocação 0.49 · F1 0.49 · taxa de falsos positivos 0.036 (59 alarmes falsos em 1653 leituras normais).

Detecção por tipo de evento: deriva: 6/6 · fora_faixa: 5/6 · pico: 7/7 · travado: 4/5.

Leitura crítica: a revocação por leitura é baixa porque as primeiras leituras de uma deriva ou de um
sensor travado parecem normais; por evento o desempenho é bem melhor, que é o que interessa para alertar.
A taxa de falsos positivos (~3 %) seria alta para alertar pessoas a cada leitura, por isso o evento da IA
entra no SIEM com nível 8 (atenção, sem SOAR) e só ganha relevância quando correlacionado. A IA
**complementa** as regras determinísticas da borda (ex.: câmara fria 2–8 °C), que seguem como proteção primária.
A IA não aciona nada: só gera evento `anomaly` para o SIEM (regra 100700) e para triagem humana.
