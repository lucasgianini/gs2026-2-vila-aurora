"""Acesso a dados do painel — versão CORRIGIDA (RT-08).

- Toda consulta usa parâmetros vinculados (%s) — o valor nunca vira SQL.
- Entradas validadas no servidor (lista branca, tamanho, tipo) antes de chegar aqui.
- Conecta como `va_painel`: sem DDL, sem acesso às colunas de contato de pessoas.
"""
from __future__ import annotations

import re
from datetime import date

from .db import query

SITES = ("centro", "escola", "ubs", "horta", "abrigo")
_TERM = re.compile(r"^[\w\- ]{0,40}$", re.UNICODE)


class InvalidInput(ValueError):
    pass


def validate_search(term: str, site: str, dia: str) -> tuple[str, str | None, date | None]:
    term = (term or "").strip()
    if not _TERM.fullmatch(term):
        raise InvalidInput("Use apenas letras, números, espaço ou hífen (até 40 caracteres).")
    if site and site not in SITES:
        raise InvalidInput("Espaço inválido.")
    d = None
    if dia:
        try:
            d = date.fromisoformat(dia)
        except ValueError as e:
            raise InvalidInput("Data inválida.") from e
    return term, site or None, d


def search_acessos(term: str, site: str | None, dia: date | None, limit: int = 100):
    sql = ["SELECT ts, site, device, pseudonimo, granted, method FROM ops.acessos WHERE true"]
    args: list = []
    if term:
        sql.append("AND (device ILIKE %s OR pseudonimo ILIKE %s)")
        like = "%" + term.replace("%", r"\%").replace("_", r"\_") + "%"
        args += [like, like]
    if site:
        sql.append("AND site = %s")
        args.append(site)
    if dia:
        sql.append("AND ts >= %s AND ts < %s + interval '1 day'")
        args += [dia, dia]
    sql.append("ORDER BY ts DESC LIMIT %s")
    args.append(min(limit, 500))
    return query(" ".join(sql), args)
