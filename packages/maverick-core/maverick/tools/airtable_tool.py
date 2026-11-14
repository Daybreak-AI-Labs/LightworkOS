"""Airtable tool — read/write records in a base.

Auth: ``AIRTABLE_API_KEY`` (PAT). ``AIRTABLE_BASE_ID`` selects the
default base for convenience.

ops:
  - list(table, view, max_records, formula)
  - get(table, record_id)
  - create(table, fields, confirm)
  - update(table, record_id, fields, confirm)
  - delete(table, record_id, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_AT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["list", "get", "create", "update", "delete"],
        },
        "base_id": {"type": "string"},
        "table": {"type": "string", "description": "Table name or id."},
        "record_id": {"type": "string"},
        "fields": {"type": "object"},
        "view": {"type": "string"},
        "formula": {"type": "string"},
        "max_records": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _config(base_id: str) -> tuple[str, str]:
    key = os.environ.get("AIRTABLE_API_KEY", "").strip()
    bid = (base_id or os.environ.get("AIRTABLE_BASE_ID", "")).strip()
    if not key:
        raise RuntimeError("Airtable requires AIRTABLE_API_KEY.")
    if not bid:
        raise RuntimeError("Airtable requires base_id or AIRTABLE_BASE_ID.")
    return key, bid


def _headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def _enc(name: str) -> str:
    segment = safe_path_segment(name)
    if segment is None:
        raise RuntimeError(f"invalid Airtable id {name!r}")
    return segment


def _url(base: str, table: str, *parts: str) -> str:
    # Every id, the base included, is exactly one encoded path segment, so a
    # model-supplied value cannot retarget the request to another API path.
    path = "/".join([_enc(base), _enc(table), *(_enc(p) for p in parts if p)])
    return f"https://api.airtable.com/v0/{path}"


def _get(url: str, params: dict | None = None, key: str = "") -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(url, headers=_headers(key), params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(url: str, body: dict, key: str) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(url, headers=_headers(key), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _patch(url: str, body: dict, key: str) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.patch)(url, headers=_headers(key), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _delete(url: str, key: str) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.delete)(url, headers=_headers(key), timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_list(args: dict) -> str:
    key, base = _config((args.get("base_id") or "").strip())
    table = (args.get("table") or "").strip()
    if not table:
        return "ERROR: list requires table"
    params: dict = {"pageSize": max(1, min(int(args.get("max_records") or 25), 100))}
    if args.get("view"):
        params["view"] = args["view"]
    if args.get("formula"):
        params["filterByFormula"] = args["formula"]
    code, data = _get(_url(base, table), params, key)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: list ({code}): {data}"
    rows = data.get("records") or []
    if not rows:
        return "no records"
    out = []
    for r in rows:
        out.append(
            f"  {r.get('id')}  " + ", ".join(
                f"{k}={v}" for k, v in (r.get("fields") or {}).items()
            )[:200]
        )
    return "\n".join(out)


def _op_get(args: dict) -> str:
    key, base = _config((args.get("base_id") or "").strip())
    table = (args.get("table") or "").strip()
    rid = (args.get("record_id") or "").strip()
    if not table or not rid:
        return "ERROR: get requires table and record_id"
    code, data = _get(_url(base, table, rid), key=key)
    if code == 404:
        return f"{table}/{rid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: get ({code}): {data}"
    fields = data.get("fields") or {}
    return f"{data.get('id')}\n" + "\n".join(f"  {k}: {v}" for k, v in fields.items())


def _op_create(args: dict) -> str:
    key, base = _config((args.get("base_id") or "").strip())
    table = (args.get("table") or "").strip()
    fields = args.get("fields") if isinstance(args.get("fields"), dict) else None
    if not table or not fields:
        return "ERROR: create requires table and fields"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create record in {table}. Re-run with confirm=true."
    code, data = _post(_url(base, table), {"fields": fields}, key)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: create ({code}): {data}"
    return f"created {data.get('id')}"


def _op_update(args: dict) -> str:
    key, base = _config((args.get("base_id") or "").strip())
    table = (args.get("table") or "").strip()
    rid = (args.get("record_id") or "").strip()
    fields = args.get("fields") if isinstance(args.get("fields"), dict) else None
    if not table or not rid or not fields:
        return "ERROR: update requires table, record_id, fields"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would update {table}/{rid}. Re-run with confirm=true."
    code, data = _patch(_url(base, table, rid), {"fields": fields}, key)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: update ({code}): {data}"
    return f"updated {data.get('id')}"


def _op_delete(args: dict) -> str:
    key, base = _config((args.get("base_id") or "").strip())
    table = (args.get("table") or "").strip()
    rid = (args.get("record_id") or "").strip()
    if not table or not rid:
        return "ERROR: delete requires table and record_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would delete {table}/{rid}. Re-run with confirm=true."
    code, data = _delete(_url(base, table, rid), key)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: delete ({code}): {data}"
    return f"deleted {data.get('id')} ({data.get('deleted')})"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        return {
            "list":   _op_list,
            "get":    _op_get,
            "create": _op_create,
            "update": _op_update,
            "delete": _op_delete,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Airtable request failed: {type(e).__name__}: {e}"


def airtable_tool() -> Tool:
    return Tool(
        name="airtable",
        description=(
            "Airtable records. ops: list (view/formula/max_records), "
            "get, create / update / delete (mutations confirm=true). "
            "Auth: AIRTABLE_API_KEY + optional AIRTABLE_BASE_ID."
        ),
        input_schema=_AT_SCHEMA,
        fn=_run,
    )
