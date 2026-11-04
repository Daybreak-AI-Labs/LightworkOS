"""Microsoft Dynamics 365 tool — Dataverse Web API (OData v4).

Reads and (with confirm) creates rows in Dataverse — the data layer behind
Dynamics 365 / Power Platform. The Microsoft-ecosystem strategic-fit surface.

Auth (OAuth Bearer for the Dataverse resource, pre-acquired):
  - ``DYNAMICS_RESOURCE_URL``   (e.g. https://org.crm.dynamics.com)
  - ``DYNAMICS_TOKEN``
  - optional: ``DYNAMICS_API_VERSION`` (default v9.2)

ops:
  - query(entity, params)            e.g. entity="accounts", params={"$top": 5}
  - create(entity, fields, confirm)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["query", "create"]},
        "entity": {"type": "string", "description": "entity set, e.g. accounts, contacts."},
        "params": {"type": "object", "description": "OData query params (query op)."},
        "fields": {"type": "object"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op", "entity"],
}

_DEFAULT_VERSION = "v9.2"


def _config() -> tuple[str, str]:
    url = os.environ.get("DYNAMICS_RESOURCE_URL", "").strip().rstrip("/")
    tok = os.environ.get("DYNAMICS_TOKEN", "").strip()
    if not url or not tok:
        raise RuntimeError("Dynamics requires DYNAMICS_RESOURCE_URL + DYNAMICS_TOKEN.")
    return url, tok


def _headers() -> dict[str, str]:
    _u, tok = _config()
    return {
        "Authorization": f"Bearer {tok}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }


def _base() -> str:
    url, _t = _config()
    ver = os.environ.get("DYNAMICS_API_VERSION", "").strip() or _DEFAULT_VERSION
    return f"{url}/api/data/{ver}"


def _op_query(entity: str, params: dict) -> str:
    if not entity:
        return "ERROR: query requires entity"
    seg = safe_path_segment(entity)
    if seg is None:
        return "ERROR: query requires a valid entity"
    import httpx
    r = _governed_sender(httpx.get)(f"{_base()}/{seg}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: query ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: query ({r.status_code}): {data.get('error', data)}"
    rows = data.get("value") if isinstance(data, dict) else None
    if rows is None:
        return json.dumps(data, default=str)[:2000]
    if not rows:
        return "no records"
    out = [f"{len(rows)} record(s):"]
    out += ["  " + json.dumps(x, default=str)[:300] for x in rows[:50]]
    return "\n".join(out)


def _op_create(entity: str, fields: dict, confirm: bool) -> str:
    if not entity or not fields:
        return "ERROR: create requires entity and fields"
    seg = safe_path_segment(entity)
    if seg is None:
        return "ERROR: create requires a valid entity"
    if not confirm:
        return f"DRY RUN: would create a {entity} row. Re-run with confirm=true."
    import httpx
    r = _governed_sender(httpx.post)(f"{_base()}/{seg}", headers=_headers(), json=fields, timeout=30.0)
    if r.status_code >= 400:
        try:
            return f"ERROR: create ({r.status_code}): {r.json().get('error', r.text[:300])}"
        except ValueError:
            return f"ERROR: create ({r.status_code})"
    return f"created {entity} ({r.status_code})"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    entity = (args.get("entity") or "").strip()
    params = args.get("params") if isinstance(args.get("params"), dict) else {}
    fields = args.get("fields") if isinstance(args.get("fields"), dict) else {}
    try:
        if op == "query":
            return _op_query(entity, params)
        if op == "create":
            return _op_create(entity, fields, as_bool(args.get("confirm")))
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Dynamics request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def dynamics_tool() -> Tool:
    return Tool(
        name="dynamics",
        description=(
            "Microsoft Dynamics 365 / Dataverse Web API (OData v4). ops: query "
            "(read an entity set), create (needs confirm=true). Auth: "
            "DYNAMICS_RESOURCE_URL + DYNAMICS_TOKEN."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
