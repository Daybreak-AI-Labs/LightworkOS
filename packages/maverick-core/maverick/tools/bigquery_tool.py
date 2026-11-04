"""BigQuery tool — Google Cloud BigQuery query over REST.

Runs SQL via the BigQuery jobs.query endpoint. Read statements run directly;
non-read SQL (DML/DDL) needs confirm=true. Uses a pre-acquired OAuth access
token (e.g. ``gcloud auth print-access-token``) so no GCP SDK is required.

Auth:
  - ``BIGQUERY_ACCESS_TOKEN``  (OAuth 2 Bearer)
  - ``BIGQUERY_PROJECT``       (GCP project id; billing/run project)

ops:
  - query(sql, limit, confirm)
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
        "op": {"type": "string", "enum": ["query"]},
        "sql": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean", "description": "required for non-read SQL."},
    },
    "required": ["op", "sql"],
}

_READ_PREFIXES = ("select", "with", "show", "describe", "explain")


def _config() -> tuple[str, str]:
    tok = os.environ.get("BIGQUERY_ACCESS_TOKEN", "").strip()
    proj = os.environ.get("BIGQUERY_PROJECT", "").strip()
    if not tok or not proj:
        raise RuntimeError("BigQuery requires BIGQUERY_ACCESS_TOKEN + BIGQUERY_PROJECT.")
    return tok, proj


def _op_query(sql: str, limit: int, confirm: bool) -> str:
    if not sql:
        return "ERROR: query requires sql"
    is_read = sql.strip().lstrip("(").lower().startswith(_READ_PREFIXES)
    needs_confirm = not is_read or has_unconfirmed_statement_separator(
        sql, backslash_escapes=True
    )
    if needs_confirm and not confirm:
        return "DRY RUN: non-read SQL (DML/DDL). Re-run with confirm=true."
    tok, proj = _config()
    import httpx
    url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{proj}/queries"
    r = _governed_sender(httpx.post)(url, headers={"Authorization": f"Bearer {tok}",
                                 "Content-Type": "application/json"},
                   json={"query": sql, "useLegacySql": False}, timeout=120.0)
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: query ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: query ({r.status_code}): {data.get('error', data)}"
    cols = [f.get("name") for f in (data.get("schema") or {}).get("fields", [])]
    rows = data.get("rows") or []
    if not rows:
        return f"ok ({data.get('totalRows', 0)} rows); columns: {cols}"
    out = [f"columns: {cols}", f"{data.get('totalRows', len(rows))} row(s):"]
    for row in rows[: max(1, limit)]:
        vals = [c.get("v") for c in row.get("f", [])]
        out.append("  " + json.dumps(vals, default=str)[:300])
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
            return _op_query((args.get("sql") or "").strip(),
                             int(args.get("limit") or 50), as_bool(args.get("confirm")))
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: BigQuery request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def bigquery_tool() -> Tool:
    return Tool(
        name="bigquery",
        description=(
            "Google BigQuery SQL via REST (jobs.query). op: query (read runs; "
            "DML/DDL need confirm=true). Auth: BIGQUERY_ACCESS_TOKEN + "
            "BIGQUERY_PROJECT."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
