-- Vila Aurora — schema da nuvem (PostgreSQL 16)
-- Princípios: menor privilégio por serviço (RT-08), minimização/pseudonimização (RT-19),
-- trilha de auditoria (RT-12/14).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA ops;      -- telemetria, alarmes, comandos (operação)
CREATE SCHEMA cadastro; -- pessoas e operadores (dados pessoais — acesso restrito)
CREATE SCHEMA audit;    -- trilha de auditoria (append-only)

-- ------------------------------------------------------------------ operação
CREATE TABLE ops.telemetry (
  edge     text        NOT NULL,
  seq      bigint      NOT NULL,
  device   text        NOT NULL,
  ts       timestamptz NOT NULL,
  received timestamptz NOT NULL DEFAULT now(),
  degraded boolean     NOT NULL DEFAULT false,
  data     jsonb       NOT NULL,
  PRIMARY KEY (edge, seq)                       -- idempotência do store-and-forward
);
CREATE INDEX ON ops.telemetry (device, ts DESC);

CREATE TABLE ops.events (       -- alarmes, estados, eventos de acesso, auditoria da borda
  edge     text        NOT NULL,
  seq      bigint      NOT NULL,
  kind     text        NOT NULL,
  device   text,
  ts       timestamptz NOT NULL,
  received timestamptz NOT NULL DEFAULT now(),
  data     jsonb       NOT NULL,
  PRIMARY KEY (edge, seq)
);
CREATE INDEX ON ops.events (kind, ts DESC);

-- histórico de acessos (alvo do SQLi no painel legado). Crachá SEMPRE pseudonimizado.
CREATE TABLE ops.acessos (
  id        bigserial PRIMARY KEY,
  ts        timestamptz NOT NULL,
  site      text NOT NULL,
  device    text NOT NULL,
  pseudonimo text NOT NULL,
  granted   boolean NOT NULL,
  method    text NOT NULL
);
CREATE INDEX ON ops.acessos (ts DESC);

CREATE TABLE ops.alarms (
  id        bigserial PRIMARY KEY,
  site      text NOT NULL,
  alarm     text NOT NULL,
  severity  text,
  message   text,
  raised_at timestamptz NOT NULL,
  cleared_at timestamptz,
  ack_by    text,
  ack_at    timestamptz
);
CREATE UNIQUE INDEX alarms_open ON ops.alarms (site, alarm) WHERE cleared_at IS NULL;

CREATE TABLE ops.pump_schedule (
  site       text PRIMARY KEY,
  windows    text NOT NULL,                       -- "05:00-07:00,17:00-19:00"
  updated_by text NOT NULL DEFAULT current_user,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ops.commands (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  edge         text NOT NULL,
  device       text,
  action       text NOT NULL,
  params       jsonb NOT NULL DEFAULT '{}',
  risk         text NOT NULL DEFAULT 'baixo' CHECK (risk IN ('baixo','alto')),
  requested_by text NOT NULL,
  approved_by  text,
  status       text NOT NULL DEFAULT 'pendente'
               CHECK (status IN ('aguardando_aprovacao','pendente','entregue','applied','rejected','cancelado')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  result       jsonb,
  CHECK (risk = 'baixo' OR approved_by IS NOT NULL OR status IN ('aguardando_aprovacao','cancelado')),
  CHECK (approved_by IS NULL OR approved_by <> requested_by)          -- quatro olhos
);
CREATE INDEX ON ops.commands (edge, status);

-- Qualquer mudança de agenda vira um comando set_schedule que a BORDA valida (lição do INC-VA-0712).
CREATE FUNCTION ops.schedule_to_command() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO ops.commands (edge, device, action, params, requested_by)
  VALUES ('edge-' || NEW.site, NEW.site || '-bomba', 'set_schedule',
          jsonb_build_object('windows', NEW.windows), NEW.updated_by || ' (db:' || session_user || ')');
  INSERT INTO audit.log (actor, action, target, detail)
  VALUES (NEW.updated_by || ' (db:' || session_user || ')', 'pump_schedule_update', NEW.site,
          jsonb_build_object('old', OLD.windows, 'new', NEW.windows));
  RETURN NEW;
END $$;

-- ------------------------------------------------------------------ cadastro (dados pessoais sintéticos)
CREATE TABLE cadastro.pessoas (
  id         serial PRIMARY KEY,
  pseudonimo text UNIQUE NOT NULL,     -- = HMAC do crachá (mesma função da borda)
  nome       text NOT NULL,
  email      text NOT NULL,
  telefone   text NOT NULL,
  papel      text NOT NULL CHECK (papel IN ('voluntario','morador','tecnico','equipe_ubs')),
  base_legal text NOT NULL DEFAULT 'execução de políticas públicas (LGPD art. 7º, III) / consentimento',
  criado_em  timestamptz NOT NULL DEFAULT now(),
  reter_ate  date NOT NULL DEFAULT (now() + interval '2 years')::date
);

CREATE TABLE cadastro.operadores (
  id            serial PRIMARY KEY,
  username      text UNIQUE NOT NULL CHECK (username ~ '^[a-z][a-z0-9._-]{2,31}$'),
  nome          text NOT NULL,
  password_hash text NOT NULL,           -- argon2id
  totp_secret   text,                    -- NULL = MFA não cadastrado (bloqueia login no painel novo)
  role          text NOT NULL CHECK (role IN ('operador','tecnico','coordenacao','auditor')),
  telefone_verificacao text,             -- número para verificação fora de banda (RT-18)
  ativo         boolean NOT NULL DEFAULT true,
  falhas        int NOT NULL DEFAULT 0,
  bloqueado_ate timestamptz
);

-- ------------------------------------------------------------------ auditoria
CREATE TABLE audit.log (
  id     bigserial PRIMARY KEY,
  ts     timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor  text NOT NULL,
  action text NOT NULL,
  target text,
  ip     inet,
  detail jsonb
);

CREATE TRIGGER pump_schedule_cmd AFTER UPDATE ON ops.pump_schedule
  FOR EACH ROW WHEN (OLD.windows IS DISTINCT FROM NEW.windows) EXECUTE FUNCTION ops.schedule_to_command();

-- trilha append-only: nem o dono da tabela via painel consegue alterar/apagar
CREATE FUNCTION audit.deny_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit.log é append-only'; END $$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit.log
  FOR EACH ROW EXECUTE FUNCTION audit.deny_change();

-- views mínimas para o painel (sem colunas de contato)
CREATE VIEW cadastro.pessoas_resumo AS
  SELECT pseudonimo, papel FROM cadastro.pessoas;

CREATE VIEW ops.ultima_leitura AS
  SELECT DISTINCT ON (device) device, edge, ts, data FROM ops.telemetry ORDER BY device, ts DESC;
