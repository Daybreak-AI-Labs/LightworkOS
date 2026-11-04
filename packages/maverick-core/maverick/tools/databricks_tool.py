"""Databricks tool — SQL Statement Execution + Jobs API.

Run SQL against a SQL warehouse and drive Jobs (list / run / inspect). Read
SQL runs directly; non-read SQL and job runs require confirm=true.

Auth (personal access token / OAuth, pre-acquired):
  - ``DATABRICKS_HOST``  (https://your-workspace.cloud.databricks.com)
  - ``DATABRICKS_TOKEN``
  - optional: ``DATABRICKS_WAREHOUSE_ID`` (default warehouse for sql)

ops:
  - sql(statement, warehouse_id, catalog, schema, confirm)
  - jobs_list(limit)
  - job_run(job_id, confirm)
  - run_get(run_id)
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string",
               "enum": ["sql", "jobs_list", "job_run", "run_get"]},
        "statement": {"type": "string"},
        "warehouse_id": {"type": "string"},
        "catalog": {"type": "string"},
        "schema": {"type": "string"},
        "job_id": {"type": "integer"},
        "run_id": {"type": "integer"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}

_READ_PREFIXES = ("select", "with", "show", "describe", "desc", "explain", "list")
# A CTE (WITH ...) can prefix a MUTATING main statement:
#   WITH t AS (SELECT ...) INSERT INTO target SELECT * FROM t
#   WITH t AS (...) DELETE/UPDATE/MERGE ...
# so the "with" read-prefix alone doesn't prove read-only. Scan a CTE for any
# DML/DDL keyword and, if present, treat it as a write (require confirm). Safe
# direction: a false positive only asks for confirm=true.
_MUTATING_KEYWORDS_RE = re.compile(
    r"\b(insert|update|delete|merge|create|drop|alter|truncate|replace|copy|grant|revoke)\b",
    re.IGNORECASE,
)


def _is_read_only(statement: str) -> bool:
    s = statement.strip().lstrip("(").lower()
    if not s.startswith(_READ_PREFIXES):
        return False
    if s.startswith("with") and _MUTATING_KEYWORDS_RE.search(statement):
        return False
    return True


def _config() -> tuple[str, str]:
    host = os.environ.get("DATABRICKS_HOST", "").strip().rstrip("/")
    tok = os.environ.get("DATABRICKS_TOKEN", "").strip()
    if not host or not tok:
        raise RuntimeError("Databricks requires DATABRICKS_HOST + DATABRICKS_TOKEN.")
    return host, tok


def _headers() -> dict[str, str]:
    _h, tok = _config()
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _req(method: str, path: str, *, params: dict | None = None,
         body: dict | None = None) -> tuple[int, Any]:
    import httpx
    host, _t = _config()
    r = httpx.request(method, f"{host}{path}", headers=_headers(),
                      params=params or {}, json=body, timeout=90.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, (r.text or "")[:500]


def _op_sql(statement: str, warehouse_id: str, catalog: str, schema: str,
            confirm: bool) -> str:
    if not statement:
        return "ERROR: sql requires statement"
    wh = warehouse_id or os.environ.get("DATABRICKS_WAREHOUSE_ID", "").strip()
    if not wh:
        return "ERROR: sql requires warehouse_id (or DATABRICKS_WAREHOUSE_ID)"
    is_read = _is_read_only(statement)
    if not is_read and not confirm:
        return "DRY RUN: non-read SQL. Re-run with confirm=true."
    body: dict[str, Any] = {"statement": statement, "warehouse_id": wh,
                            "wait_timeout": "30s"}
    if catalog:
        body["catalog"] = catalog
    if schema:
        body["schema"] = schema
    code, data = _req("POST", "/api/2.0/sql/statements/", body=body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: sql ({code}): {data}"
    state = (data.get("status") or {}).get("state")
    cols = [c.get("name") for c in
            (((data.get("manifest") or {}).get("schema") or {}).get("columns") or [])]
    rows = (data.get("result") or {}).get("data_array") or []
    head = f"state={state} columns={cols}"
    if not rows:
        return head
    out = [head] + ["  " + json.dumps(r, default=str)[:300] for r in rows[:50]]
    return "\n".join(out)


def _op_jobs_list(limit: int) -> str:
    code, data = _req("GET", "/api/2.1/jobs/list", params={"limit": max(1, min(limit or 20, 100))})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: jobs_list ({code}): {data}"
    jobs = data.get("jobs") or []
    if not jobs:
        return "no jobs"
    return "\n".join(
        f"  {j.get('job_id')}: {(j.get('settings') or {}).get('name')}" for j in jobs[:50]
    )


def _op_job_run(job_id: int, confirm: bool) -> str:
    if not job_id:
        return "ERROR: job_run requires job_id"
    if not confirm:
        return f"DRY RUN: would run job {job_id}. Re-run with confirm=true."
    code, data = _req("POST", "/api/2.1/jobs/run-now", body={"job_id": job_id})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: job_run ({code}): {data}"
    return f"started job {job_id}: run_id={data.get('run_id')}"


def _op_run_get(run_id: int) -> str:
    if not run_id:
        return "ERROR: run_get requires run_id"
    code, data = _req("GET", "/api/2.1/jobs/runs/get", params={"run_id": run_id})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: run_get ({code}): {data}"
    state = data.get("state") or {}
    return (f"run {run_id}: life_cycle={state.get('life_cycle_state')} "
            f"result={state.get('result_state')}")


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
            return _op_sql(
                (args.get("statement") or "").strip(),
                (args.get("warehouse_id") or "").strip(),
                (args.get("catalog") or "").strip(),
                (args.get("schema") or "").strip(),
                as_bool(args.get("confirm")),
            )
        if op == "jobs_list":
            return _op_jobs_list(int(args.get("limit") or 20))
        if op == "job_run":
            return _op_job_run(int(args.get("job_id") or 0), as_bool(args.get("confirm")))
        if op == "run_get":
            return _op_run_get(int(args.get("run_id") or 0))
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Databricks request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def databricks_tool() -> Tool:
    return Tool(
        name="databricks",
        description=(
            "Databricks SQL + Jobs. ops: sql (read runs directly; writes/DDL "
            "need confirm=true), jobs_list, job_run (confirm=true), run_get. "
            "Auth: DATABRICKS_HOST + DATABRICKS_TOKEN; sql needs warehouse_id "
            "or DATABRICKS_WAREHOUSE_ID."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
