"""ServiceNow tool — Now Platform Table API (records + workflow data).

Lets the agent read and (with confirm) write records on any ServiceNow
table: incidents, change requests, CMDB CIs, catalog tasks, etc. This is
the strategic-fit surface for ServiceNow / Now Assist deployments.

Auth (pre-acquired Bearer token; we don't bake an OAuth flow so creds don't
sit in the agent's process memory longer than necessary):
  - ``SERVICENOW_INSTANCE_URL`` (e.g. https://dev12345.service-now.com)
  - ``SERVICENOW_TOKEN`` (OAuth Bearer access token)

ops:
  - query(table, query, limit)   — sysparm_query over a table
  - get(table, sys_id)
  - create(table, fields, confirm)
  - update(table, sys_id, fields, confirm)
  - delete(table, sys_id, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..fastjson import dumps_compact
from . import Tool, as_bool

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["query", "get", "create", "update", "delete"],
        },
        "table": {"type": "string", "description": "e.g. incident, change_request, cmdb_ci."},
        "query": {"type": "string", "description": "sysparm_query (query op)."},
        "sys_id": {"type": "string"},
        "fields": {"type": "object"},
        "limit": {"type": "integer", "description": "max rows (query op; default 20)."},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _safe_seg(s: str) -> bool:
    """ServiceNow table names / sys_ids are [A-Za-z0-9_.-]; reject empty, '..',
    and any char outside that set so a model-supplied value can't reshape the
    REST path or inject query params (mirrors home_assistant_tool._safe_seg)."""
    return bool(s) and ".." not in s and all(c.isalnum() or c in "_.-" for c in s)


def _config() -> tuple[str, str]:
    url = os.environ.get("SERVICENOW_INSTANCE_URL", "").strip().rstrip("/")
    tok = os.environ.get("SERVICENOW_TOKEN", "").strip()
    if not url or not tok:
        raise RuntimeError(
            "ServiceNow requires SERVICENOW_INSTANCE_URL + SERVICENOW_TOKEN."
        )
    return url, tok


def _headers() -> dict[str, str]:
    _u, tok = _config()
    return {
        "Authorization": f"Bearer {tok}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _url(path: str) -> str:
    url, _t = _config()
    return f"{url}/api/now{path}"


def _req(method: str, path: str, *, params: dict | None = None,
         body: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = httpx.request(method, _url(path), headers=_headers(),
                      params=params or {}, json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, (r.text or "")[:500]


def _result(data: Any) -> Any:
    return data.get("result") if isinstance(data, dict) else data


def _op_query(table: str, query: str, limit: int) -> str:
    if not _safe_seg(table):
        return "ERROR: query requires a valid table"
    params = {"sysparm_limit": max(1, min(limit or 20, 100)),
              "sysparm_display_value": "true"}
    if query:
        params["sysparm_query"] = query
    code, data = _req("GET", f"/table/{table}", params=params)
    if code >= 400:
        return f"ERROR: query ({code}): {_result(data)}"
    rows = _result(data) or []
    if not rows:
        return "no records"
    out = [f"{len(rows)} record(s):"]
    for r in rows[:50]:
        out.append("  " + dumps_compact(r)[:300])
    return "\n".join(out)


def _op_get(table: str, sys_id: str) -> str:
    if not _safe_seg(table) or not _safe_seg(sys_id):
        return "ERROR: get requires a valid table and sys_id"
    code, data = _req("GET", f"/table/{table}/{sys_id}")
    if code == 404:
        return f"{table}/{sys_id} not found"
    if code >= 400:
        return f"ERROR: get ({code}): {_result(data)}"
    return dumps_compact(_result(data))[:3000]


def _op_create(table: str, fields: dict, confirm: bool) -> str:
    if not _safe_seg(table) or not fields:
        return "ERROR: create requires a valid table and fields"
    if not confirm:
        return f"DRY RUN: would create a {table} record. Re-run with confirm=true."
    code, data = _req("POST", f"/table/{table}", body=fields)
    if code >= 400:
        return f"ERROR: create ({code}): {_result(data)}"
    res = _result(data) or {}
    return f"created {table}/{res.get('sys_id')} (number={res.get('number')})"


def _op_update(table: str, sys_id: str, fields: dict, confirm: bool) -> str:
    if not _safe_seg(table) or not _safe_seg(sys_id) or not fields:
        return "ERROR: update requires a valid table, sys_id, fields"
    if not confirm:
        return f"DRY RUN: would update {table}/{sys_id}. Re-run with confirm=true."
    code, data = _req("PATCH", f"/table/{table}/{sys_id}", body=fields)
    if code >= 400:
        return f"ERROR: update ({code}): {_result(data)}"
    return f"updated {table}/{sys_id}"


def _op_delete(table: str, sys_id: str, confirm: bool) -> str:
    if not _safe_seg(table) or not _safe_seg(sys_id):
        return "ERROR: delete requires a valid table and sys_id"
    if not confirm:
        return f"DRY RUN: would delete {table}/{sys_id}. Re-run with confirm=true."
    code, _data = _req("DELETE", f"/table/{table}/{sys_id}")
    if code >= 400:
        return f"ERROR: delete ({code})"
    return f"deleted {table}/{sys_id}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    fields = args.get("fields") if isinstance(args.get("fields"), dict) else {}
    table = (args.get("table") or "").strip()
    sys_id = (args.get("sys_id") or "").strip()
    try:
        if op == "query":
            return _op_query(table, (args.get("query") or "").strip(),
                             int(args.get("limit") or 20))
        if op == "get":
            return _op_get(table, sys_id)
        if op == "create":
            return _op_create(table, fields, as_bool(args.get("confirm")))
        if op == "update":
            return _op_update(table, sys_id, fields, as_bool(args.get("confirm")))
        if op == "delete":
            return _op_delete(table, sys_id, as_bool(args.get("confirm")))
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: ServiceNow request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def servicenow_tool() -> Tool:
    return Tool(
        name="servicenow",
        description=(
            "ServiceNow Now Platform Table API. ops: query (sysparm_query), "
            "get, create / update / delete (mutations need confirm=true). "
            "Works on any table (incident, change_request, cmdb_ci, ...). "
            "Auth: SERVICENOW_INSTANCE_URL + SERVICENOW_TOKEN."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
