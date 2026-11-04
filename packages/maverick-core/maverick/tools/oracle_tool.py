"""Oracle Database tool — SQL over Oracle REST Data Services (ORDS).

Runs SQL against an ORDS-enabled Oracle schema via the ``/_/sql`` endpoint.
Read statements run directly; non-read SQL (INSERT/UPDATE/DELETE/DDL) needs
confirm=true, matching Lightwork's mutation gating.

Auth (Bearer / OAuth2 client token, pre-acquired):
  - ``ORACLE_ORDS_URL``    (e.g. https://host/ords/myschema)
  - ``ORACLE_ORDS_TOKEN``

ops:
  - sql(statement, confirm)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool
from .sql_safety import has_unconfirmed_statement_separator

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["sql"]},
        "statement": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean", "description": "required for non-read SQL."},
    },
    "required": ["op", "statement"],
}

_READ_PREFIXES = ("select", "with", "show", "describe", "desc", "explain")


def _config() -> tuple[str, str]:
    url = os.environ.get("ORACLE_ORDS_URL", "").strip().rstrip("/")
    tok = os.environ.get("ORACLE_ORDS_TOKEN", "").strip()
    if not url or not tok:
        raise RuntimeError("Oracle requires ORACLE_ORDS_URL + ORACLE_ORDS_TOKEN.")
    return url, tok


def _op_sql(statement: str, limit: int, confirm: bool) -> str:
    if not statement:
        return "ERROR: sql requires statement"
    is_read = statement.strip().lstrip("(").lower().startswith(_READ_PREFIXES)
    needs_confirm = not is_read or has_unconfirmed_statement_separator(statement)
    if needs_confirm and not confirm:
        return "DRY RUN: non-read SQL. Re-run with confirm=true."
    url, tok = _config()
    import httpx
    r = _governed_sender(httpx.post)(
        f"{url}/_/sql",
        headers={"Authorization": f"Bearer {tok}",
                 "Content-Type": "application/sql", "Accept": "application/json"},
        content=statement,
        timeout=90.0,
    )
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: sql ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: sql ({r.status_code}): {data}"
    items = data.get("items") if isinstance(data, dict) else None
    if items and isinstance(items[0], dict):
        rows = (items[0].get("resultSet") or {}).get("items")
        if rows is not None:
            out = [f"{len(rows)} row(s):"]
            out += ["  " + json.dumps(x, default=str)[:300] for x in rows[: max(1, limit)]]
            return "\n".join(out)
    return json.dumps(data, default=str)[:2000]


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        if op == "sql":
            return _op_sql((args.get("statement") or "").strip(),
                           int(args.get("limit") or 50), as_bool(args.get("confirm")))
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Oracle request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def oracle_tool() -> Tool:
    return Tool(
        name="oracle",
        description=(
            "Oracle Database SQL via ORDS (/_/sql). op: sql (read runs; "
            "INSERT/UPDATE/DELETE/DDL need confirm=true). Auth: ORACLE_ORDS_URL "
            "+ ORACLE_ORDS_TOKEN."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
