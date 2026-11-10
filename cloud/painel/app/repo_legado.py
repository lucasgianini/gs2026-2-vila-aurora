"""Acesso a dados do painel — versão LEGADA (VULNERÁVEL DE PROPÓSITO).

Reproduz o painel do incidente INC-VA-0712 para o teste "antes/depois" (RT-08).
Só é carregado com PAINEL_VARIANT=legado, no perfil `attack` do docker compose,
em rede isolada do laboratório. NÃO usar fora do laboratório.

Falhas reproduzidas:
  1. concatenação da entrada do usuário direto no SQL (f-string);
  2. sem validação de entrada;
  3. usuário de banco com privilégios amplos (va_painel_legado);
  4. mensagem de erro do banco devolvida ao usuário.
"""
from __future__ import annotations

from .db import query_raw


class InvalidInput(ValueError):
    pass


def validate_search(term: str, site: str, dia: str):
    return term or "", site or None, dia or None   # nenhuma validação


def search_acessos(term: str, site, dia, limit: int = 100):
    sql = (f"SELECT ts, site, device, pseudonimo, granted, method FROM ops.acessos "
           f"WHERE device LIKE '%{term}%'")
    if site:
        sql += f" AND site = '{site}'"
    if dia:
        sql += f" AND ts::date = '{dia}'"
    sql += f" ORDER BY ts DESC LIMIT {limit}"
    return query_raw(sql)
