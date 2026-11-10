-- SOC: alertas do SIEM e ações do SOAR (RT-13/RT-15/RT-22)
CREATE SCHEMA soc;

CREATE TABLE soc.alerts (
  id          bigserial PRIMARY KEY,
  wazuh_id    text UNIQUE,
  ts          timestamptz NOT NULL,          -- quando o SIEM gerou o alerta
  event_ts    timestamptz,                   -- quando o evento aconteceu (para MTTD)
  rule_id     int NOT NULL,
  level       int NOT NULL,
  description text NOT NULL,
  groups      text[] NOT NULL,
  mitre       text[],
  location    text,
  data        jsonb
);
CREATE INDEX ON soc.alerts (ts DESC);

CREATE TABLE soc.actions (
  id          bigserial PRIMARY KEY,
  alert_id    bigint REFERENCES soc.alerts(id),
  ts          timestamptz NOT NULL DEFAULT now(),
  playbook    text NOT NULL,
  action      text NOT NULL,
  target      text NOT NULL,
  risk        text NOT NULL CHECK (risk IN ('baixo','alto')),
  status      text NOT NULL CHECK (status IN ('executada','falhou','aguardando_aprovacao','aprovada','negada')),
  decided_by  text,
  decided_at  timestamptz,
  done_at     timestamptz,
  result      text
);
CREATE INDEX ON soc.actions (status);
