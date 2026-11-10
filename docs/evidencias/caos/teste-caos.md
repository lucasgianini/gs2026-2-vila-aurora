# Teste de caos — continuidade e reconciliação (RT-23)

Início: 2026-11-10T18:36:14Z · duração da interrupção: 30 min.

Derruba fibra **e** 4G de todas as 5 bordas; mede operação local durante a queda e a
reconciliação ao restabelecer. Telemetria no banco antes da queda: 25079 linhas.

## Durante a interrupção

| Borda | Link | Outbox | Alarmes locais |
|---|---|---|---|
| centro | offline | 15 | 1 |
| escola | offline | 24 | 0 |
| ubs | offline | 15 | 1 |
| horta | offline | 15 | 0 |
| abrigo | offline | 20 | 0 |

Alarme crítico local da câmara fria (UBS) disparou sem nuvem: **True**.
Bordas isoladas da nuvem (todas offline): **sim**.
