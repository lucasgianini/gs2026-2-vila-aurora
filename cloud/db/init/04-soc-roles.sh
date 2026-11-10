#!/usr/bin/env bash
# Papel do SOAR e permissões do painel sobre o SOC (menor privilégio).
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB:-vilaaurora}" \
  -v soar_pw="$DB_SOAR_PASSWORD" <<'SQL'
CREATE ROLE va_soar LOGIN PASSWORD :'soar_pw' CONNECTION LIMIT 5;
GRANT CONNECT ON DATABASE vilaaurora TO va_soar;
GRANT USAGE ON SCHEMA soc, ops, cadastro, audit TO va_soar;
GRANT SELECT, INSERT, UPDATE ON soc.alerts, soc.actions TO va_soar;
GRANT USAGE ON SEQUENCE soc.alerts_id_seq, soc.actions_id_seq TO va_soar;
GRANT INSERT, SELECT ON ops.commands TO va_soar;
GRANT SELECT (id, username, role, bloqueado_ate) ON cadastro.operadores TO va_soar;
GRANT UPDATE (bloqueado_ate) ON cadastro.operadores TO va_soar;
GRANT INSERT ON audit.log TO va_soar;
GRANT USAGE ON SEQUENCE audit.log_id_seq TO va_soar;

GRANT USAGE ON SCHEMA soc TO va_painel;
GRANT SELECT ON soc.alerts, soc.actions TO va_painel;
GRANT UPDATE (status, decided_by, decided_at) ON soc.actions TO va_painel;
SQL
