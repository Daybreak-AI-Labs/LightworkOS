"""BigQuery tool — Google Cloud BigQuery query over REST.

Runs SQL via the BigQuery jobs.query endpoint. Read statements run directly;
non-read SQL (DML/DDL) needs confirm=true. Uses a pre-acquired OAuth access
token (e.g. ``gcloud auth print-access-token``) so no GCP SDK is required.

Auth:
  - ``BIGQUERY_ACCESS_TOKEN``  (OAuth 2 Bearer)
  - ``BIGQUERY_PROJECT``       (GCP project id; billing/run project)

ops:
  - query(sql, limit, confirm)

Each query is a paid call charged to the run budget (kernel rule 3) through
``_paid_call.charged_call``: priced from ``[budget.tool_prices] bigquery``,
per terabyte scanned (``totalBytesProcessed``) or per request, else the
per-call safety ceiling. Priced per terabyte, the request carries
``maximumBytesBilled`` for what the run has left, so BigQuery refuses a
query that would scan more. A tool built with no run budget refuses before
anything is sent.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool
from ._paid_call import STOP_SIGNALS, charged_call
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


def _scanned(response) -> dict[str, float | None]:
    """Terabytes the query scanned, from the reply; unknown when not given."""
    try:
        data = response.json()
        scanned = int(data.get("totalBytesProcessed")) if isinstance(data, dict) else None
    except (ValueError, TypeError):
        scanned = None
    if scanned is None and getattr(response, "status_code", 200) >= 400:
        scanned = 0  # a refused query scans nothing
    return {"terabyte": None if scanned is None else scanned / 1e12}


def _op_query(sql: str, limit: int, confirm: bool, budget=None) -> str:
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

    def send(max_terabytes):
        body: dict[str, Any] = {"query": sql, "useLegacySql": False}
        if max_terabytes is not None:
            body["maximumBytesBilled"] = str(int(max_terabytes * 1e12))
        return _governed_sender(httpx.post)(url, headers={"Authorization": f"Bearer {tok}",
                                            "Content-Type": "application/json"},
                                            json=body, timeout=120.0)

    r = charged_call("bigquery", send, budget=budget, label="BigQuery", units={"request": 1},
                     measure=_scanned, bounded=True, category="retrieval")
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: query ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: query ({r.status_code}): {data.get('error', data)}"
    if data.get("jobComplete") is False:
        # jobs.query returns before the job finishes once its wait elapses;
        # an absent `rows` then means "not done yet", not "no data". The job
        # is unfinished, not failed, so it is reported INDETERMINATE.
        job = data.get("jobReference") or {}
        return (f"INDETERMINATE: query still running (job {job.get('jobId', '?')}, "
                f"location {job.get('location', '?')}); results are not available "
                "yet. Do not re-run a write; check the job in BigQuery first.")
    cols = [f.get("name") for f in (data.get("schema") or {}).get("fields", [])]
    rows = data.get("rows") or []
    if not rows:
        return f"ok ({data.get('totalRows', 0)} rows); columns: {cols}"
    out = [f"columns: {cols}", f"{data.get('totalRows', len(rows))} row(s):"]
    for row in rows[: max(1, limit)]:
        vals = [c.get("v") for c in row.get("f", [])]
        out.append("  " + json.dumps(vals, default=str)[:300])
    return "\n".join(out)


def _run(args: dict[str, Any], budget=None) -> str:
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
                             int(args.get("limit") or 50), as_bool(args.get("confirm")), budget)
    except STOP_SIGNALS:
        raise
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: BigQuery request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def bigquery_tool(*, budget=None) -> Tool:
    return Tool(
        name="bigquery",
        description=(
            "Google BigQuery SQL via REST (jobs.query). op: query (read runs; "
            "DML/DDL need confirm=true). Auth: BIGQUERY_ACCESS_TOKEN + "
            "BIGQUERY_PROJECT."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, budget),
    )
