#!/usr/bin/env bash
# Papéis de banco por serviço — menor privilégio (RT-08).
# Senhas vêm do .env (nunca do repositório).
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v ingest_pw="$DB_INGEST_PASSWORD" -v painel_pw="$DB_PAINEL_PASSWORD" \
  -v legado_pw="$DB_PAINEL_VULN_PASSWORD" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE vilaaurora FROM PUBLIC;

-- ingest: só grava telemetria/eventos e entrega comandos às bordas
CREATE ROLE va_ingest LOGIN PASSWORD :'ingest_pw' CONNECTION LIMIT 20;
GRANT CONNECT ON DATABASE vilaaurora TO va_ingest;
GRANT USAGE ON SCHEMA ops TO va_ingest;
GRANT INSERT ON ops.telemetry, ops.events, ops.acessos TO va_ingest;
GRANT SELECT, INSERT, UPDATE ON ops.alarms TO va_ingest;
GRANT USAGE ON SEQUENCE ops.alarms_id_seq, ops.acessos_id_seq TO va_ingest;
GRANT SELECT, UPDATE (status, delivered_at, result) ON ops.commands TO va_ingest;

-- painel (versão corrigida): leitura operacional, cria comandos, sem DDL, sem contato de pessoas
CREATE ROLE va_painel LOGIN PASSWORD :'painel_pw' CONNECTION LIMIT 20;
GRANT CONNECT ON DATABASE vilaaurora TO va_painel;
GRANT USAGE ON SCHEMA ops, cadastro, audit TO va_painel;
GRANT SELECT ON ops.telemetry, ops.events, ops.acessos, ops.alarms, ops.ultima_leitura,
               ops.pump_schedule, ops.commands TO va_painel;
GRANT UPDATE (ack_by, ack_at) ON ops.alarms TO va_painel;
GRANT INSERT ON ops.commands TO va_painel;
GRANT UPDATE (approved_by, status) ON ops.commands TO va_painel;
GRANT UPDATE (windows, updated_by, updated_at) ON ops.pump_schedule TO va_painel;
GRANT SELECT ON cadastro.pessoas_resumo TO va_painel;
GRANT SELECT (id, username, nome, password_hash, totp_secret, role, ativo, falhas, bloqueado_ate)
  ON cadastro.operadores TO va_painel;
GRANT UPDATE (falhas, bloqueado_ate) ON cadastro.operadores TO va_painel;
GRANT SELECT, INSERT ON audit.log TO va_painel;
GRANT USAGE ON SEQUENCE audit.log_id_seq TO va_painel;
-- o trigger de agenda grava em ops.commands/audit.log como SECURITY DEFINER (dono)

-- painel LEGADO (reprodução do incidente): como era — usuário dono de tudo
CREATE ROLE va_painel_legado LOGIN PASSWORD :'legado_pw';
GRANT CONNECT ON DATABASE vilaaurora TO va_painel_legado;
GRANT USAGE ON SCHEMA ops, cadastro, audit TO va_painel_legado;
GRANT ALL ON ALL TABLES IN SCHEMA ops, cadastro TO va_painel_legado;
GRANT SELECT, INSERT ON audit.log TO va_painel_legado;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ops, cadastro, audit TO va_painel_legado;

-- auditoria de alterações no banco (vai para o SIEM via log do Postgres)
ALTER ROLE va_painel_legado SET log_statement = 'all';
ALTER ROLE va_painel SET log_statement = 'mod';
SQL
