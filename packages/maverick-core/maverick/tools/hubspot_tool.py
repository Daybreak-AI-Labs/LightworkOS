"""HubSpot tool — contacts, companies, deals.

Auth: ``HUBSPOT_TOKEN`` (private app access token).

ops:
  - contacts(limit, query)
  - contact_get(contact_id)
  - contact_create(email, firstname, lastname, properties, confirm)
  - contact_update(contact_id, properties, confirm)
  - companies(limit)
  - deals(limit, stage)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_HS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["contacts", "contact_get", "contact_create",
                     "contact_update", "companies", "deals"],
        },
        "limit": {"type": "integer"},
        "query": {"type": "string"},
        "contact_id": {"type": "string"},
        "email": {"type": "string"},
        "firstname": {"type": "string"},
        "lastname": {"type": "string"},
        "properties": {"type": "object"},
        "stage": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://api.hubapi.com"


def _token() -> str:
    t = os.environ.get("HUBSPOT_TOKEN", "").strip()
    if not t:
        raise RuntimeError("HubSpot requires HUBSPOT_TOKEN (private app access token).")
    return t


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token()}",
        "Content-Type": "application/json",
    }


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _patch(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.patch)(f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _get_paginated(path: str, params: dict, limit: int) -> tuple[int, Any, list[dict]]:
    """Follow HubSpot's ``paging.next.after`` cursor on a CRM list endpoint
    until ``limit`` results are collected. Returns (code, error, rows).

    HubSpot caps ``limit`` at 100 per page and returns the next offset token in
    ``paging.next.after``; bounded by a hard page cap.
    """
    rows: list[dict] = []
    after: str | None = None
    max_pages = max(1, (limit // 100) + 2)
    for _ in range(max_pages):
        p = dict(params)
        p["limit"] = min(100, max(1, limit - len(rows)))
        if after:
            p["after"] = after
        code, data = _get(path, p)
        if code >= 400 or not isinstance(data, dict):
            return code, data, rows
        rows.extend(data.get("results") or [])
        after = ((data.get("paging") or {}).get("next") or {}).get("after")
        if len(rows) >= limit or not after:
            break
    return 200, {}, rows[:limit]


def _op_contacts(args: dict) -> str:
    limit = max(1, min(int(args.get("limit") or 25), 100))
    query = (args.get("query") or "").strip()
    if query:
        code, data = _post("/crm/v3/objects/contacts/search", {
            "query": query, "limit": limit,
            "properties": ["email", "firstname", "lastname"],
        })
    else:
        code, err, rows = _get_paginated("/crm/v3/objects/contacts", {
            "properties": "email,firstname,lastname",
        }, limit)
        if code >= 400:
            return f"ERROR: contacts ({code}): {err}"
        if not rows:
            return "no contacts"
        return "\n".join(
            f"  {c.get('id')}  {(c.get('properties') or {}).get('email', '?')}  "
            f"{(c.get('properties') or {}).get('firstname', '')} "
            f"{(c.get('properties') or {}).get('lastname', '')}"
            for c in rows
        )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: contacts ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no contacts"
    return "\n".join(
        f"  {c.get('id')}  {(c.get('properties') or {}).get('email', '?')}  "
        f"{(c.get('properties') or {}).get('firstname', '')} "
        f"{(c.get('properties') or {}).get('lastname', '')}"
        for c in rows
    )


def _op_contact_get(args: dict) -> str:
    cid = (args.get("contact_id") or "").strip()
    if not cid:
        return "ERROR: contact_get requires contact_id"
    seg = safe_path_segment(cid)
    if seg is None:
        return "ERROR: contact_get requires a valid contact_id"
    code, data = _get(f"/crm/v3/objects/contacts/{seg}",
                       {"properties": "email,firstname,lastname,company,phone"})
    if code == 404:
        return f"contact {cid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: contact_get ({code}): {data}"
    p = data.get("properties") or {}
    return (
        f"{data.get('id')}  {p.get('email', '?')}\n"
        f"  name:    {p.get('firstname', '')} {p.get('lastname', '')}\n"
        f"  phone:   {p.get('phone', '?')}\n"
        f"  company: {p.get('company', '?')}\n"
        f"  created: {data.get('createdAt')}\n"
        f"  updated: {data.get('updatedAt')}"
    )


def _op_contact_create(args: dict) -> str:
    email = (args.get("email") or "").strip()
    if not email:
        return "ERROR: contact_create requires email"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create contact {email}. Re-run with confirm=true."
    props = {"email": email}
    if args.get("firstname"):
        props["firstname"] = args["firstname"]
    if args.get("lastname"):
        props["lastname"] = args["lastname"]
    extra = args.get("properties") if isinstance(args.get("properties"), dict) else {}
    props.update({str(k): str(v) for k, v in extra.items()})
    code, data = _post("/crm/v3/objects/contacts", {"properties": props})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: contact_create ({code}): {data}"
    return f"created contact {data.get('id')} ({email})"


def _op_contact_update(args: dict) -> str:
    cid = (args.get("contact_id") or "").strip()
    props = args.get("properties") if isinstance(args.get("properties"), dict) else None
    if not cid or not props:
        return "ERROR: contact_update requires contact_id and properties"
    seg = safe_path_segment(cid)
    if seg is None:
        return "ERROR: contact_update requires a valid contact_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would update {cid}. Re-run with confirm=true."
    code, data = _patch(
        f"/crm/v3/objects/contacts/{seg}",
        {"properties": {str(k): str(v) for k, v in props.items()}},
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: contact_update ({code}): {data}"
    return f"updated {cid}"


def _op_companies(args: dict) -> str:
    limit = max(1, min(int(args.get("limit") or 25), 100))
    code, err, rows = _get_paginated("/crm/v3/objects/companies", {
        "properties": "name,domain,industry",
    }, limit)
    if code >= 400:
        return f"ERROR: companies ({code}): {err}"
    if not rows:
        return "no companies"
    return "\n".join(
        f"  {c.get('id')}  {(c.get('properties') or {}).get('name', '?')}  "
        f"{(c.get('properties') or {}).get('domain', '')}"
        for c in rows
    )


def _op_deals(args: dict) -> str:
    limit = max(1, min(int(args.get("limit") or 25), 100))
    stage = (args.get("stage") or "").strip()
    if stage:
        code, data = _post("/crm/v3/objects/deals/search", {
            "filterGroups": [{"filters": [{
                "propertyName": "dealstage", "operator": "EQ", "value": stage,
            }]}],
            "limit": limit,
            "properties": ["dealname", "amount", "dealstage", "closedate"],
        })
    else:
        code, err, rows = _get_paginated("/crm/v3/objects/deals", {
            "properties": "dealname,amount,dealstage,closedate",
        }, limit)
        if code >= 400:
            return f"ERROR: deals ({code}): {err}"
        if not rows:
            return "no deals"
        return "\n".join(
            f"  {d.get('id')}  {(d.get('properties') or {}).get('dealname', '?'):<40}  "
            f"${(d.get('properties') or {}).get('amount', '?')}  "
            f"stage={(d.get('properties') or {}).get('dealstage', '?')}"
            for d in rows
        )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: deals ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no deals"
    return "\n".join(
        f"  {d.get('id')}  {(d.get('properties') or {}).get('dealname', '?'):<40}  "
        f"${(d.get('properties') or {}).get('amount', '?')}  "
        f"stage={(d.get('properties') or {}).get('dealstage', '?')}"
        for d in rows
    )


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
            "contacts":       _op_contacts,
            "contact_get":    _op_contact_get,
            "contact_create": _op_contact_create,
            "contact_update": _op_contact_update,
            "companies":      _op_companies,
            "deals":          _op_deals,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: HubSpot request failed: {type(e).__name__}: {e}"


def hubspot_tool() -> Tool:
    return Tool(
        name="hubspot",
        description=(
            "HubSpot CRM. ops: contacts (search or list), "
            "contact_get / contact_create / contact_update "
            "(mutations need confirm=true), companies (list), "
            "deals (optional stage filter). Auth: HUBSPOT_TOKEN."
        ),
        input_schema=_HS_SCHEMA,
        fn=_run,
    )
