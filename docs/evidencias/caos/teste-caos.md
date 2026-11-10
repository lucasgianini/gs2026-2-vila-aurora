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

## Reconciliação

- Link restabelecido: 2026-11-10T19:06:15Z
- Tempo para drenar os buffers (outbox -> ~0): **18s**
- Telemetria no banco: antes 25079, depois **31658** (+6579)
- Perda de dados na reconciliação: a telemetria é bufferizada com store-and-forward e reenviada
  de forma idempotente (chave edge+seq). Alarmes/eventos têm prioridade e nunca são descartados;
  só telemetria antiga seria descartada se o buffer estourasse (0 descartes registrados).

## Conclusão
Durante 30 min sem internet, cada espaço seguiu operando por conta própria: regras locais ativas,
alarme crítico da câmara fria disparado localmente e painel local acessível. Ao voltar o link, os
dados acumulados foram reconciliados sem duplicação. É a correção direta da falha F9/F10 do INC-VA-0712.
