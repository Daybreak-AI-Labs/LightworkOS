"""PagerDuty tool — incident management.

Lets the agent read on-call status, list active incidents, ack /
resolve them, and trigger fresh incidents via Events API v2.

Auth:
  - ``PAGERDUTY_API_TOKEN`` for REST (read + write).
  - ``PAGERDUTY_EVENTS_KEY`` for the Events API (trigger only).

ops:
  - incidents(status, limit)
  - incident_get(id)
  - acknowledge(id, confirm)
  - resolve(id, confirm)
  - trigger(routing_key, summary, severity)
  - on_call(escalation_policy_id, limit)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_PD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["incidents", "incident_get", "acknowledge",
                     "resolve", "trigger", "on_call"],
        },
        "id": {"type": "string"},
        "status": {"type": "string"},
        "limit": {"type": "integer"},
        "routing_key": {"type": "string"},
        "summary": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "error", "warning", "info"]},
        "escalation_policy_id": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _token() -> str:
    t = os.environ.get("PAGERDUTY_API_TOKEN", "").strip()
    if not t:
        raise RuntimeError("PagerDuty REST requires PAGERDUTY_API_TOKEN.")
    return t


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Token token={_token()}",
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
    }


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"https://api.pagerduty.com{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _from_email() -> str:
    """The requester email for write ops. PagerDuty's PUT /incidents requires a
    ``From`` header identifying a valid user; with an account-level token (not a
    user token) it's mandatory, else the API 400s 'Requester User Not Found'."""
    return (
        os.environ.get("PAGERDUTY_FROM", "")
        or os.environ.get("PAGERDUTY_USER_EMAIL", "")
    ).strip()


def _put(path: str, body: dict, *, from_email: str | None = None) -> tuple[int, Any]:
    import httpx
    headers = _headers()
    if from_email:
        headers["From"] = from_email
    r = _governed_sender(httpx.put)(f"https://api.pagerduty.com{path}", headers=headers,
                  json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _op_incidents(status: str, limit: int) -> str:
    params: dict = {"limit": limit}
    if status:
        params["statuses[]"] = status
    code, data = _get("/incidents", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: incidents ({code}): {data}"
    rows = data.get("incidents") or []
    if not rows:
        return "no incidents"
    return "\n".join(
        f"  {i.get('id')}  [{i.get('status', '?'):>10}]  "
        f"urgency={i.get('urgency', '?'):>4}  "
        f"{(i.get('title') or '')[:80]}"
        for i in rows
    )


def _op_incident_get(iid: str) -> str:
    seg = safe_path_segment(iid)
    if seg is None:
        return "ERROR: incident_get requires a valid id"
    code, data = _get(f"/incidents/{seg}")
    if code == 404:
        return f"incident {iid!r} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: incident_get ({code}): {data}"
    i = data.get("incident") or {}
    service = (i.get("service") or {}).get("summary", "?")
    return (
        f"{i.get('id')}  status={i.get('status')}  urgency={i.get('urgency')}\n"
        f"  title:   {i.get('title')}\n"
        f"  service: {service}\n"
        f"  created: {i.get('created_at')}\n"
        f"  url:     {i.get('html_url')}"
    )


def _set_status(iid: str, status: str, confirm: bool) -> str:
    seg = safe_path_segment(iid)
    if seg is None:
        return "ERROR: a valid incident id is required"
    if not confirm:
        return f"DRY RUN: would set {iid} -> {status}. Re-run with confirm=true."
    from_email = _from_email()
    if not from_email:
        return (
            "ERROR: acknowledge/resolve requires a requester email. Set "
            "PAGERDUTY_FROM (or PAGERDUTY_USER_EMAIL) to a valid PagerDuty "
            "user's email — the REST API rejects the status PUT without a "
            "'From' header when using an account-level token."
        )
    code, data = _put(
        f"/incidents/{seg}",
        {"incident": {"type": "incident_reference", "status": status}},
        from_email=from_email,
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: status update ({code}): {data}"
    i = data.get("incident") or {}
    return f"{iid} -> {i.get('status', status)}"


def _op_trigger(routing_key: str, summary: str, severity: str, confirm: bool) -> str:
    if not confirm:
        return "DRY RUN: would trigger PagerDuty incident. Re-run with confirm=true."
    import httpx
    key = (routing_key or os.environ.get("PAGERDUTY_EVENTS_KEY", "")).strip()
    if not key:
        return "ERROR: trigger requires routing_key or PAGERDUTY_EVENTS_KEY"
    if not summary:
        return "ERROR: trigger requires summary"
    sev = (severity or "error").lower()
    body = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "source": "maverick-agent",
            "severity": sev,
        },
    }
    r = _governed_sender(httpx.post)("https://events.pagerduty.com/v2/enqueue",
                   json=body, timeout=15.0)
    if r.status_code >= 400:
        return f"ERROR: trigger ({r.status_code}): {r.text[:300]}"
    try:
        d = r.json()
    except ValueError:
        d = {}
    return f"triggered (dedup_key={d.get('dedup_key', '?')})"


def _op_on_call(policy_id: str, limit: int) -> str:
    params: dict = {"limit": limit}
    if policy_id:
        params["escalation_policy_ids[]"] = policy_id
    code, data = _get("/oncalls", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: on_call ({code}): {data}"
    rows = data.get("oncalls") or []
    if not rows:
        return "no on-call entries"
    out = []
    for oc in rows:
        user = (oc.get("user") or {}).get("summary", "?")
        sched = (oc.get("schedule") or {}).get("summary", "?")
        out.append(
            f"  {user}  on {sched}  level={oc.get('escalation_level')} "
            f"until {oc.get('end', '?')}"
        )
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    limit = max(1, min(int(args.get("limit") or 25), 100))
    try:
        if op == "incidents":
            return _op_incidents((args.get("status") or "").strip(), limit)
        if op == "incident_get":
            iid = (args.get("id") or "").strip()
            if not iid:
                return "ERROR: incident_get requires id"
            return _op_incident_get(iid)
        if op == "acknowledge":
            iid = (args.get("id") or "").strip()
            if not iid:
                return "ERROR: acknowledge requires id"
            return _set_status(iid, "acknowledged", as_bool(args.get("confirm")))
        if op == "resolve":
            iid = (args.get("id") or "").strip()
            if not iid:
                return "ERROR: resolve requires id"
            return _set_status(iid, "resolved", as_bool(args.get("confirm")))
        if op == "trigger":
            return _op_trigger(
                (args.get("routing_key") or "").strip(),
                (args.get("summary") or "").strip(),
                (args.get("severity") or "").strip(),
                as_bool(args.get("confirm")),
            )
        if op == "on_call":
            return _op_on_call((args.get("escalation_policy_id") or "").strip(), limit)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: PagerDuty request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def pagerduty_tool() -> Tool:
    return Tool(
        name="pagerduty",
        description=(
            "PagerDuty incidents + on-call. ops: incidents, "
            "incident_get, acknowledge (confirm=true), resolve "
            "(confirm=true), trigger (confirm=true; Events API v2 — needs "
            "routing_key or PAGERDUTY_EVENTS_KEY), on_call. REST "
            "auth: PAGERDUTY_API_TOKEN."
        ),
        input_schema=_PD_SCHEMA,
        fn=_run,
    )
