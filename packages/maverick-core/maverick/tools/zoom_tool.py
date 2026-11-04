"""Zoom tool — meetings + recordings.

Auth: ``ZOOM_OAUTH_TOKEN`` (Server-to-Server OAuth bearer; the agent
caller is expected to refresh it externally, same pattern as
Salesforce). ``ZOOM_USER_ID`` defaults to "me".

ops:
  - meetings(user, type, limit)
  - meeting_get(meeting_id)
  - meeting_create(topic, start_time, duration, confirm)
  - meeting_delete(meeting_id, confirm)
  - recordings(user, from_date, to_date, limit)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_ZOOM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["meetings", "meeting_get", "meeting_create",
                     "meeting_delete", "recordings"],
        },
        "user": {"type": "string"},
        "type": {"type": "string", "enum": ["scheduled", "live", "upcoming"]},
        "meeting_id": {"type": "string"},
        "topic": {"type": "string"},
        "start_time": {"type": "string", "description": "ISO 8601 UTC."},
        "duration": {"type": "integer", "description": "Minutes."},
        "from_date": {"type": "string"},
        "to_date": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _token() -> str:
    t = os.environ.get("ZOOM_OAUTH_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Zoom requires ZOOM_OAUTH_TOKEN.")
    return t


def _user(arg: str) -> str | None:
    """The Zoom user id/email to scope a request to, or None if invalid.

    ``arg`` is model-supplied and interpolated into /users/{user}/... paths,
    so it goes through the same safe_path_segment guard as every other
    connector id (a value like "../../accounts" must not retarget the
    request to a different API path)."""
    raw = (arg or os.environ.get("ZOOM_USER_ID") or "me").strip()
    return safe_path_segment(raw)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"https://api.zoom.us/v2{path}",
                  headers=_headers(), params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"https://api.zoom.us/v2{path}",
                   headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _delete(path: str) -> int:
    import httpx
    r = _governed_sender(httpx.delete)(f"https://api.zoom.us/v2{path}",
                     headers=_headers(), timeout=30.0)
    return r.status_code


def _op_meetings(args: dict) -> str:
    user = _user(args.get("user") or "")
    if user is None:
        return "ERROR: meetings requires a valid user"
    params = {
        "type": (args.get("type") or "upcoming"),
        "page_size": max(1, min(int(args.get("limit") or 25), 100)),
    }
    code, data = _get(f"/users/{user}/meetings", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: meetings ({code}): {data}"
    rows = data.get("meetings") or []
    if not rows:
        return "no meetings"
    return "\n".join(
        f"  {m.get('id')}  {m.get('start_time', '?')}  "
        f"{(m.get('topic') or '')[:60]}"
        for m in rows
    )


def _op_meeting_get(args: dict) -> str:
    mid = (args.get("meeting_id") or "").strip()
    if not mid:
        return "ERROR: meeting_get requires meeting_id"
    seg = safe_path_segment(mid)
    if seg is None:
        return "ERROR: meeting_get requires a valid meeting_id"
    code, data = _get(f"/meetings/{seg}")
    if code == 404:
        return f"meeting {mid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: meeting_get ({code}): {data}"
    return (
        f"#{data.get('id')}  {data.get('topic')}\n"
        f"  start:   {data.get('start_time')}\n"
        f"  duration:{data.get('duration')}min\n"
        f"  join:    {data.get('join_url', '?')}\n"
        f"  host:    {data.get('host_email', '?')}"
    )


def _op_meeting_create(args: dict) -> str:
    topic = (args.get("topic") or "").strip()
    start = (args.get("start_time") or "").strip()
    if not topic or not start:
        return "ERROR: meeting_create requires topic and start_time"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create '{topic}' at {start}. Re-run with confirm=true."
    user = _user(args.get("user") or "")
    if user is None:
        return "ERROR: meeting_create requires a valid user"
    body = {
        "topic": topic,
        "type": 2,  # scheduled
        "start_time": start,
        "duration": int(args.get("duration") or 30),
    }
    code, data = _post(f"/users/{user}/meetings", body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: meeting_create ({code}): {data}"
    return f"created meeting {data.get('id')}: {data.get('join_url', '')}"


def _op_meeting_delete(args: dict) -> str:
    mid = (args.get("meeting_id") or "").strip()
    if not mid:
        return "ERROR: meeting_delete requires meeting_id"
    seg = safe_path_segment(mid)
    if seg is None:
        return "ERROR: meeting_delete requires a valid meeting_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would delete {mid}. Re-run with confirm=true."
    code = _delete(f"/meetings/{seg}")
    if code >= 400:
        return f"ERROR: meeting_delete ({code})"
    return f"deleted meeting {mid}"


def _op_recordings(args: dict) -> str:
    user = _user(args.get("user") or "")
    if user is None:
        return "ERROR: recordings requires a valid user"
    params: dict = {
        "page_size": max(1, min(int(args.get("limit") or 25), 300)),
    }
    if args.get("from_date"):
        params["from"] = args["from_date"]
    if args.get("to_date"):
        params["to"] = args["to_date"]
    code, data = _get(f"/users/{user}/recordings", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: recordings ({code}): {data}"
    rows = data.get("meetings") or []
    if not rows:
        return "no recordings"
    return "\n".join(
        f"  {m.get('id')}  {m.get('start_time', '?')}  "
        f"{(m.get('topic') or '')[:60]:<60}  "
        f"files={len(m.get('recording_files') or [])}"
        for m in rows
    )


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
            "meetings":        _op_meetings,
            "meeting_get":     _op_meeting_get,
            "meeting_create":  _op_meeting_create,
            "meeting_delete":  _op_meeting_delete,
            "recordings":      _op_recordings,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Zoom request failed: {type(e).__name__}: {e}"


def zoom_tool() -> Tool:
    return Tool(
        name="zoom",
        description=(
            "Zoom meetings + recordings. ops: meetings, meeting_get, "
            "meeting_create / meeting_delete (mutations confirm=true), "
            "recordings (from/to date filters). Auth: "
            "ZOOM_OAUTH_TOKEN + optional ZOOM_USER_ID."
        ),
        input_schema=_ZOOM_SCHEMA,
        fn=_run,
    )
