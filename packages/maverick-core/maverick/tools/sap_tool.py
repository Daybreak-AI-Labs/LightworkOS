"""SAP tool — OData client for SAP Gateway (S/4HANA, SuccessFactors, ...).

Reads OData entity sets with ``get``; writes with ``post`` (confirm-gated),
fetching an ``X-CSRF-Token`` first as SAP Gateway requires. The agent supplies
the OData path so this works across SAP services without hard-coding entities.

Auth (Bearer / OAuth2, pre-acquired):
  - ``SAP_BASE_URL``   (e.g. https://my.s4hana.cloud)
  - ``SAP_TOKEN``

ops:
  - get(path, params)   e.g. /sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartner
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
        "path": {"type": "string", "description": "OData path beginning with /sap/..."},
        "params": {"type": "object"},
        "body": {"type": "object"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op", "path"],
}


def _config() -> tuple[str, str]:
    base = os.environ.get("SAP_BASE_URL", "").strip().rstrip("/")
    tok = os.environ.get("SAP_TOKEN", "").strip()
    if not base or not tok:
        raise RuntimeError("SAP requires SAP_BASE_URL + SAP_TOKEN.")
    return base, tok


def _headers() -> dict[str, str]:
    _b, tok = _config()
    return {"Authorization": f"Bearer {tok}", "Accept": "application/json",
            "Content-Type": "application/json"}


def _norm(path: str) -> str:
    p = path.strip()
    return p if p.startswith("/") else "/" + p


def _op_get(path: str, params: dict) -> str:
    if not path:
        return "ERROR: get requires path"
    import httpx
    base, _t = _config()
    q = dict(params or {})
    q.setdefault("$format", "json")
    r = _governed_sender(httpx.get)(f"{base}{_norm(path)}", headers=_headers(), params=q, timeout=30.0)
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
    base, _t = _config()
    headers = _headers()
    # SAP Gateway requires a CSRF token + session cookie for writes; fetch it.
    token, cookie = None, ""
    try:
        g = _governed_sender(httpx.get)(f"{base}{_norm(path)}", headers={**headers, "X-CSRF-Token": "Fetch"},
                      timeout=30.0)
        token = g.headers.get("x-csrf-token") or g.headers.get("X-CSRF-Token")
        cookie = g.headers.get("set-cookie", "")
    except Exception:  # pragma: no cover - some gateways don't require CSRF
        pass
    if token:
        headers["X-CSRF-Token"] = token
    if cookie:
        headers["Cookie"] = cookie
    r = _governed_sender(httpx.post)(f"{base}{_norm(path)}", headers=headers, json=body or {}, timeout=30.0)
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
        return f"ERROR: SAP request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def sap_tool() -> Tool:
    return Tool(
        name="sap",
        description=(
            "SAP OData client (S/4HANA, SuccessFactors, ...). ops: get (read "
            "entity sets; $format=json added), post (write; fetches X-CSRF-Token, "
            "needs confirm=true). Auth: SAP_BASE_URL + SAP_TOKEN."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
