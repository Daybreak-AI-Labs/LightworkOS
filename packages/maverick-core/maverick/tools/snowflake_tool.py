"""Snowflake tool — SQL API v2 (query the warehouse).

Runs SQL against Snowflake via the stateless SQL API. Read statements run
directly; anything that isn't a plain read (INSERT/UPDATE/DELETE/MERGE/DDL)
requires confirm=true, matching the rest of Lightwork's mutation gating.

Auth (key-pair JWT or OAuth Bearer, pre-acquired):
  - ``SNOWFLAKE_ACCOUNT``     (account identifier, e.g. xy12345.us-east-1)
  - ``SNOWFLAKE_TOKEN``       (Bearer access token / JWT)
  - ``SNOWFLAKE_TOKEN_TYPE``  ``KEYPAIR_JWT`` (default) or ``OAUTH`` — must
    match the token you supply, or Snowflake rejects it
  - optional defaults: ``SNOWFLAKE_WAREHOUSE`` / ``SNOWFLAKE_DATABASE`` /
    ``SNOWFLAKE_SCHEMA`` / ``SNOWFLAKE_ROLE``

ops:
  - query(statement, warehouse, database, schema, role, confirm)
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["query"]},
        "statement": {"type": "string", "description": "SQL to execute."},
        "warehouse": {"type": "string"},
        "database": {"type": "string"},
        "schema": {"type": "string"},
        "role": {"type": "string"},
        "limit": {"type": "integer", "description": "max rows shown (default 50)."},
        "confirm": {"type": "boolean", "description": "required for non-read SQL."},
    },
    "required": ["op", "statement"],
}

_READ_PREFIXES = ("select", "with", "show", "describe", "desc", "explain", "list")
# A CTE (WITH ...) can prefix a MUTATING main statement (WITH t AS (...) INSERT/
# UPDATE/DELETE/MERGE ...), so the "with" read-prefix alone doesn't prove
# read-only. Treat a CTE containing a DML/DDL keyword as a write (require
# confirm). Safe direction: a false positive only asks for confirm=true.
_MUTATING_KEYWORDS_RE = re.compile(
    r"\b(insert|update|delete|merge|create|drop|alter|truncate|replace|copy|grant|revoke)\b",
    re.IGNORECASE,
)


def _config() -> tuple[str, str]:
    acct = os.environ.get("SNOWFLAKE_ACCOUNT", "").strip()
    tok = os.environ.get("SNOWFLAKE_TOKEN", "").strip()
    if not acct or not tok:
        raise RuntimeError("Snowflake requires SNOWFLAKE_ACCOUNT + SNOWFLAKE_TOKEN.")
    return acct, tok


def _is_read(statement: str) -> bool:
    s = statement.strip().lstrip("(").lower()
    if not s.startswith(_READ_PREFIXES):
        return False
    if s.startswith("with") and _MUTATING_KEYWORDS_RE.search(statement):
        return False
    return True


def _op_query(statement: str, ctx: dict, limit: int, confirm: bool) -> str:
    if not statement:
        return "ERROR: query requires statement"
    if not _is_read(statement) and not confirm:
        return ("DRY RUN: statement is not a read (SELECT/SHOW/...). "
                "Re-run with confirm=true to execute a write/DDL.")
    acct, tok = _config()
    # Token type must match the supplied token: KEYPAIR_JWT for a key-pair JWT,
    # OAUTH for an OAuth Bearer. This was hardcoded to KEYPAIR_JWT, which broke
    # the OAuth path the docstring advertises. Default keeps prior behavior.
    token_type = (os.environ.get("SNOWFLAKE_TOKEN_TYPE", "").strip().upper()
                  or "KEYPAIR_JWT")
    if token_type not in ("KEYPAIR_JWT", "OAUTH"):
        return (f"ERROR: SNOWFLAKE_TOKEN_TYPE must be KEYPAIR_JWT or OAUTH "
                f"(got {token_type!r})")
    import httpx
    body = {"statement": statement, "timeout": 60}
    for k in ("warehouse", "database", "schema", "role"):
        v = (ctx.get(k) or os.environ.get(f"SNOWFLAKE_{k.upper()}", "")).strip()
        if v:
            body[k] = v
    r = _governed_sender(httpx.post)(
        f"https://{acct}.snowflakecomputing.com/api/v2/statements",
        headers={
            "Authorization": f"Bearer {tok}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Snowflake-Authorization-Token-Type": token_type,
        },
        json=body,
        timeout=90.0,
    )
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: query ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: query ({r.status_code}): {data.get('message', data)}"
    if r.status_code == 202:
        # Still executing after the server-side wait: there is no result yet,
        # and a write may still complete.
        return (f"ERROR: statement {data.get('statementHandle', '?')} is still running; "
                "no result was returned and its outcome is unknown")
    meta = (data.get("resultSetMetaData") or {})
    cols = [c.get("name") for c in (meta.get("rowType") or [])]
    rows = data.get("data") or []
    if not rows:
        return f"ok ({data.get('numRows', 0)} rows); columns: {cols}"
    out = [f"columns: {cols}", f"{meta.get('numRows', len(rows))} row(s):"]
    for row in rows[: max(1, limit)]:
        out.append("  " + json.dumps(row, default=str)[:300])
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        if op == "query":
            return _op_query(
                (args.get("statement") or "").strip(),
                args,
                int(args.get("limit") or 50),
                as_bool(args.get("confirm")),
            )
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Snowflake request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def snowflake_tool() -> Tool:
    return Tool(
        name="snowflake",
        description=(
            "Snowflake SQL API v2. op: query (read SQL runs directly; "
            "INSERT/UPDATE/DELETE/DDL need confirm=true). Optional "
            "warehouse/database/schema/role per call or via SNOWFLAKE_* env. "
            "Auth: SNOWFLAKE_ACCOUNT + SNOWFLAKE_TOKEN."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
