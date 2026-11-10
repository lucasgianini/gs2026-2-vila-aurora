from __future__ import annotations

import os

from psycopg_pool import ConnectionPool

VARIANT = os.environ.get("PAINEL_VARIANT", "corrigido")
_user = "va_painel_legado" if VARIANT == "legado" else "va_painel"
_pw = os.environ["DB_PAINEL_VULN_PASSWORD" if VARIANT == "legado" else "DB_PAINEL_PASSWORD"]

pool = ConnectionPool(
    f"host={os.environ.get('DB_HOST', 'db')} dbname=vilaaurora user={_user} password={_pw} "
    f"application_name=painel-{VARIANT}", min_size=1, max_size=8, open=True)


def query(sql: str, args=(), one: bool = False):
    """Consulta parametrizada. Retorna lista de dicts (ou um dict)."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, args)
        if cur.description is None:
            return cur.rowcount
        cols = [c.name for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return (rows[0] if rows else None) if one else rows


def query_raw(sql: str):
    """Somente para o painel legado: executa SQL montado como string (protocolo simples,
    aceita múltiplos comandos separados por ';' — exatamente como o sistema antigo)."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql.encode())   # bytes sem parâmetros => simple query protocol
        rows = []
        while True:
            if cur.description is not None:
                cols = [c.name for c in cur.description]
                rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            if not cur.nextset():
                break
        return rows
