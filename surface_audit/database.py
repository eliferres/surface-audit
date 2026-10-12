"""The database rules (T1, T2): every table read through the public REST door with the public key.

PostgREST (and Supabase, which runs it) serves an OpenAPI description of the
tables at its root and answers GET /<table> with the rows the caller may
see. Asking with the public anon key and no user session is exactly what a
stranger with the site's JavaScript can do, so any row that comes back is a
row the whole internet can read.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional
from urllib.parse import quote

from .config import Surface, jwt_claims
from .net import Answer, Unreachable, fetch
from .rules import ERROR, FAIL, PASS, WARN, Row

NO_ANSWER = "no answer, so no verdict"


def key_headers(anon_key: str) -> Dict[str, str]:
    """Supabase reads the key from apikey; plain PostgREST reads a JWT from the bearer header."""
    headers = {"apikey": anon_key, "Accept": "application/json"}
    if jwt_claims(anon_key) is not None:
        headers["Authorization"] = "Bearer " + anon_key
    return headers


def rest_root(surface: Surface) -> str:
    return (surface.postgrest_url or "").rstrip("/") + "/rest/v1/"


def tables_from_openapi(answer: Answer) -> Optional[List[str]]:
    """The tables and views the description lists, or None when there is no readable description."""
    if answer.status != 200:
        return None
    try:
        paths = json.loads(answer.body).get("paths")
    except (ValueError, AttributeError):
        return None
    if not isinstance(paths, dict):
        return None
    return [p.strip("/") for p in paths if p.strip("/") and not p.startswith("/rpc/")]


def _rows_in(answer: Answer) -> Optional[int]:
    try:
        rows = json.loads(answer.body)
    except ValueError:
        return None
    return len(rows) if isinstance(rows, list) else None


def table_row(surface: Surface, table: str) -> Row:
    """T2: one table asked for one row with the public key and no session."""
    url = "%s%s?select=*&limit=1" % (rest_root(surface), quote(table, safe=""))
    request = "GET %s (public key, no session)" % url
    try:
        answer = fetch("GET", url, key_headers(surface.anon_key or ""), follow=False, read_body=True)
    except Unreachable as error:
        return Row(surface.name, "T2", ERROR, request, "unreachable (%s)" % error, NO_ANSWER)
    status = answer.status
    if status in (401, 403):
        return Row(surface.name, "T2", PASS, request, str(status), "%s: closed to anonymous reads" % table)
    count = _rows_in(answer) if status in (200, 206) else None
    if count is None:
        return Row(surface.name, "T2", WARN, request, str(status),
                   "%s: answered %d, neither rows nor a refusal" % (table, status))
    line = "%d, %d row%s" % (status, count, "" if count == 1 else "s")
    if count == 0:
        return Row(surface.name, "T2", PASS, request, line,
                   "%s: closed to anonymous reads (no row came back)" % table)
    if table in surface.public_tables:
        return Row(surface.name, "T2", PASS, request, line,
                   "%s: open to anonymous reads, listed in public_tables" % table)
    return Row(surface.name, "T2", FAIL, request, line, "%s: open to anonymous reads" % table)


def database_rows(surface: Surface) -> List[Row]:
    """T1 for the table list, then T2 for each table. No row content is ever kept."""
    url = rest_root(surface)
    request = "GET %s (public key, no session)" % url
    try:
        answer = fetch("GET", url, key_headers(surface.anon_key or ""), read_body=True)
    except Unreachable as error:
        return [Row(surface.name, "T1", ERROR, request, "unreachable (%s)" % error, NO_ANSWER)]
    listed = tables_from_openapi(answer)
    if listed is not None:
        first = Row(surface.name, "T1", PASS, request, "%d, OpenAPI description" % answer.status,
                    "the service lists %d table%s" % (len(listed), "" if len(listed) == 1 else "s"))
    elif surface.tables:
        first = Row(surface.name, "T1", WARN, request, "%d, no OpenAPI description" % answer.status,
                    "no table list from the service; checked the %d tables in the config" % len(surface.tables))
    else:
        return [Row(surface.name, "T1", FAIL, request, "%d, no OpenAPI description" % answer.status,
                    "no table list from the service and no tables in the config, so no table was checked")]
    tables = sorted(set(listed or []) | set(surface.tables))
    return [first] + [table_row(surface, t) for t in tables]
