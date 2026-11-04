"""Calendly tool — scheduled events, event types.

Auth: ``CALENDLY_TOKEN`` (Personal Access Token).
``CALENDLY_USER_URI`` optional default ("https://api.calendly.com/users/UUID").

ops:
  - me()                                 — fetch current user URI
  - event_types(user, limit)
  - events(user, status, min_start_time, limit)
  - event_invitees(event_uuid)
  - cancel(event_uuid, reason, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)


_CL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["me", "event_types", "events",
                     "event_invitees", "cancel"],
        },
        "user": {"type": "string"},
        "status": {"type": "string", "enum": ["active", "canceled"]},
        "min_start_time": {"type": "string", "description": "RFC3339"},
        "event_uuid": {"type": "string"},
        "reason": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _token() -> str:
    t = os.environ.get("CALENDLY_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Calendly requires CALENDLY_TOKEN.")
    return t


def _user_default() -> str:
    return os.environ.get("CALENDLY_USER_URI", "").strip()


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"https://api.calendly.com{path}",
                  headers=_headers(), params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"https://api.calendly.com{path}",
                   headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_me(_args: dict) -> str:
    code, data = _get("/users/me")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: me ({code}): {data}"
    u = data.get("resource") or {}
    return f"{u.get('uri')}\n  name: {u.get('name')}\n  email: {u.get('email')}"


def _op_event_types(args: dict) -> str:
    user = (args.get("user") or _user_default()).strip()
    if not user:
        return "ERROR: event_types requires user or CALENDLY_USER_URI"
    code, data = _get("/event_types", {
        "user": user,
        "count": max(1, min(int(args.get("limit") or 25), 100)),
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: event_types ({code}): {data}"
    rows = data.get("collection") or []
    if not rows:
        return "no event types"
    return "\n".join(
        f"  {(et.get('uri') or '').rsplit('/', 1)[-1]}  "
        f"{(et.get('name') or '')[:40]:<40}  "
        f"{et.get('duration')}min  active={et.get('active')}"
        for et in rows
    )


def _op_events(args: dict) -> str:
    user = (args.get("user") or _user_default()).strip()
    if not user:
        return "ERROR: events requires user or CALENDLY_USER_URI"
    params: dict = {
        "user": user,
        "count": max(1, min(int(args.get("limit") or 25), 100)),
    }
    if args.get("status"):
        params["status"] = args["status"]
    if args.get("min_start_time"):
        params["min_start_time"] = args["min_start_time"]
    code, data = _get("/scheduled_events", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: events ({code}): {data}"
    rows = data.get("collection") or []
    if not rows:
        return "no scheduled events"
    return "\n".join(
        f"  {(ev.get('uri') or '').rsplit('/', 1)[-1]}  "
        f"[{ev.get('status', '?'):>8}]  {ev.get('start_time', '?')}  "
        f"{(ev.get('name') or '')[:40]}"
        for ev in rows
    )


def _safe_uuid(uid: str) -> bool:
    """Calendly UUIDs are alphanumeric + dashes; reject slashes/dots so a
    value like 'me/../users' can't traverse to a different API path."""
    return bool(uid) and all(c.isalnum() or c in "-_" for c in uid)


def _op_event_invitees(args: dict) -> str:
    uid = (args.get("event_uuid") or "").strip()
    if not _safe_uuid(uid):
        return "ERROR: event_invitees requires a valid event_uuid"
    code, data = _get(f"/scheduled_events/{uid}/invitees")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: event_invitees ({code}): {data}"
    rows = data.get("collection") or []
    if not rows:
        return "no invitees"
    return "\n".join(
        f"  {i.get('email')}  status={i.get('status')}  "
        f"name={i.get('name')}"
        for i in rows
    )


def _op_cancel(args: dict) -> str:
    uid = (args.get("event_uuid") or "").strip()
    if not _safe_uuid(uid):
        return "ERROR: cancel requires a valid event_uuid"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would cancel {uid}. Re-run with confirm=true."
    code, data = _post(
        f"/scheduled_events/{uid}/cancellation",
        {"reason": args.get("reason") or "Cancelled by Lightwork"},
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: cancel ({code}): {data}"
    return f"cancelled {uid}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        return {
            "me":             _op_me,
            "event_types":    _op_event_types,
            "events":         _op_events,
            "event_invitees": _op_event_invitees,
            "cancel":         _op_cancel,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Calendly request failed: {type(e).__name__}: {e}"


def calendly_tool() -> Tool:
    return Tool(
        name="calendly",
        description=(
            "Calendly events + invitees. ops: me, event_types, "
            "events (status / min_start_time filters), "
            "event_invitees, cancel (confirm=true). Auth: "
            "CALENDLY_TOKEN + optional CALENDLY_USER_URI."
        ),
        input_schema=_CL_SCHEMA,
        fn=_run,
    )
