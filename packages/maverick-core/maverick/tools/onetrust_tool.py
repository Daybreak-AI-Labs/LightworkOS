"""OneTrust tool — authenticated REST client for the OneTrust GRC/privacy API.

OneTrust spans many modules (Assessments, Data Mapping, DSAR/Privacy Rights,
Risk, Vendor). Rather than hard-code endpoints that differ per tenant/module,
this is a thin authenticated client: read with ``get`` (the safe default) and,
only with confirm=true, write with ``post``. The agent supplies the API path.

Auth (OAuth Bearer, pre-acquired):
  - ``ONETRUST_HOSTNAME``  (https://app-eu.onetrust.com or your tenant host)
  - ``ONETRUST_TOKEN``

Common read paths:
  - /api/assessment/v2/assessments
  - /api/datasubject/v3/requestqueues   (DSAR / privacy-rights requests)
  - /api/inventory/v2/inventories       (data inventory records)

ops:
  - get(path, params)
  - post(path, body, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..fastjson import dumps_compact
from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["get", "post"]},
        "path": {"type": "string", "description": "API path beginning with /api/..."},
        "params": {"type": "object", "description": "query params (get)."},
        "body": {"type": "object", "description": "JSON body (post)."},
        "confirm": {"type": "boolean"},
    },
    "required": ["op", "path"],
}


def _config() -> tuple[str, str]:
    host = os.environ.get("ONETRUST_HOSTNAME", "").strip().rstrip("/")
    tok = os.environ.get("ONETRUST_TOKEN", "").strip()
    if not host or not tok:
        raise RuntimeError("OneTrust requires ONETRUST_HOSTNAME + ONETRUST_TOKEN.")
    return host, tok


def _headers() -> dict[str, str]:
    _h, tok = _config()
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
            "Accept": "application/json"}


def _norm(path: str) -> str:
    p = path.strip()
    return p if p.startswith("/") else "/" + p


def _op_get(path: str, params: dict) -> str:
    if not path:
        return "ERROR: get requires path"
    import httpx
    host, _t = _config()
    r = _governed_sender(httpx.get)(f"{host}{_norm(path)}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        data = r.json()
    except ValueError:
        data = (r.text or "")[:1000]
    if r.status_code >= 400:
        return f"ERROR: get ({r.status_code}): {data}"
    return dumps_compact(data)[:4000]


def _op_post(path: str, body: dict, confirm: bool) -> str:
    if not path:
        return "ERROR: post requires path"
    if not confirm:
        return f"DRY RUN: would POST {_norm(path)}. Re-run with confirm=true."
    import httpx
    host, _t = _config()
    r = _governed_sender(httpx.post)(f"{host}{_norm(path)}", headers=_headers(),
                   json=body or {}, timeout=30.0)
    try:
        data = r.json()
    except ValueError:
        data = (r.text or "")[:1000]
    if r.status_code >= 400:
        return f"ERROR: post ({r.status_code}): {data}"
    return f"ok ({r.status_code}): " + dumps_compact(data)[:2000]


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    path = (args.get("path") or "").strip()
    params = args.get("params") if isinstance(args.get("params"), dict) else {}
    body = args.get("body") if isinstance(args.get("body"), dict) else {}
    try:
        if op == "get":
            return _op_get(path, params)
        if op == "post":
            return _op_post(path, body, as_bool(args.get("confirm")))
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: OneTrust request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def onetrust_tool() -> Tool:
    return Tool(
        name="onetrust",
        description=(
            "OneTrust GRC/privacy REST client. ops: get (read; e.g. "
            "/api/assessment/v2/assessments, /api/datasubject/v3/requestqueues), "
            "post (write; needs confirm=true). Auth: ONETRUST_HOSTNAME + "
            "ONETRUST_TOKEN."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
