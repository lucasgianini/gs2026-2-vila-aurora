-- Disponibilidade medida a partir da telemetria (RT-22).
-- Janela = minutos em que o laboratório estava ligado (ao menos uma borda produziu dado).
--   local   : a borda produziu telemetria naquele minuto (carimbo do dispositivo)
--   central : essa telemetria chegou à nuvem em até 60 s (supervisão central "enxergando" o espaço)
-- Os 2 últimos minutos ficam de fora (minuto em curso / lote ainda a caminho). Rodar com as bordas já
-- reconciliadas: telemetria ainda no buffer de uma borda apareceria, erradamente, como indisponibilidade local.
WITH t AS (
  SELECT edge, date_trunc('minute', ts) AS m, min(received - ts) AS lag
  FROM ops.telemetry
  WHERE ts < (SELECT date_trunc('minute', max(ts)) - interval '2 minutes' FROM ops.telemetry)
  GROUP BY 1, 2),
up AS (SELECT DISTINCT m FROM t),
e AS (SELECT DISTINCT edge FROM t)
SELECT e.edge,
       (SELECT count(*) FROM up)                                         AS janela_min,
       count(t.m)                                                        AS local_min,
       count(t.m) FILTER (WHERE t.lag < interval '60 seconds')           AS central_min,
       round(100.0 * count(t.m) / (SELECT count(*) FROM up), 3)          AS local_pct,
       round(100.0 * count(t.m) FILTER (WHERE t.lag < interval '60 seconds')
             / (SELECT count(*) FROM up), 3)                             AS central_pct
FROM e LEFT JOIN t USING (edge)
GROUP BY e.edge ORDER BY e.edge;
