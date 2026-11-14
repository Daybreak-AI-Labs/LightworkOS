"""Workday tool — authenticated REST client for Workday HR/finance APIs.

Workday's REST surface spans many services (Staffing, Absence, Financials,
Common). Rather than hard-code endpoints, this is a thin authenticated client:
read with ``get`` (the safe default) and, with confirm=true, write with
``post``. The agent supplies the path.

Auth (OAuth Bearer, pre-acquired):
  - ``WORKDAY_BASE_URL``   (e.g. https://wd2-impl-services1.workday.com/ccx/api/v1/TENANT)
  - ``WORKDAY_TOKEN``

ops:
  - get(path, params)     e.g. /workers
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
        "path": {"type": "string"},
        "params": {"type": "object"},
        "body": {"type": "object"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op", "path"],
}


def _config() -> tuple[str, str]:
    base = os.environ.get("WORKDAY_BASE_URL", "").strip().rstrip("/")
    tok = os.environ.get("WORKDAY_TOKEN", "").strip()
    if not base or not tok:
        raise RuntimeError("Workday requires WORKDAY_BASE_URL + WORKDAY_TOKEN.")
    return base, tok


def _headers() -> dict[str, str]:
    _b, tok = _config()
    return {"Authorization": f"Bearer {tok}", "Accept": "application/json",
            "Content-Type": "application/json"}


def _norm(path: str) -> str:
    p = path.strip()
    return p if p.startswith("/") else "/" + p


def _escapes_base(path: str) -> bool:
    """True when ``path`` has a dot segment that would climb out of the
    configured WORKDAY_BASE_URL prefix once the client normalises it."""
    from urllib.parse import unquote
    segments = unquote(path.split("?", 1)[0].split("#", 1)[0]).replace("\\", "/").split("/")
    return any(seg in (".", "..") for seg in segments)


def _op_get(path: str, params: dict) -> str:
    if not path:
        return "ERROR: get requires path"
    if _escapes_base(path):
        return "ERROR: path must stay under WORKDAY_BASE_URL (no . or .. segments)"
    import httpx
    base, _t = _config()
    r = _governed_sender(httpx.get)(f"{base}{_norm(path)}", headers=_headers(),
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
    if _escapes_base(path):
        return "ERROR: path must stay under WORKDAY_BASE_URL (no . or .. segments)"
    if not confirm:
        return f"DRY RUN: would POST {_norm(path)}. Re-run with confirm=true."
    import httpx
    base, _t = _config()
    r = _governed_sender(httpx.post)(f"{base}{_norm(path)}", headers=_headers(),
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
        return f"ERROR: Workday request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def workday_tool() -> Tool:
    return Tool(
        name="workday",
        description=(
            "Workday HR/finance REST client. ops: get (read; e.g. /workers), "
            "post (write; needs confirm=true). Auth: WORKDAY_BASE_URL + "
            "WORKDAY_TOKEN."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
