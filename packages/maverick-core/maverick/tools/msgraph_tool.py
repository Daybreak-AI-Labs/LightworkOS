"""Microsoft Graph tool — Outlook mail + calendar + OneDrive.

One tool over the Graph v1.0 API. Auth: ``MSGRAPH_ACCESS_TOKEN``
(OAuth2 bearer, refreshed externally; delegated or app token with the
relevant Mail/Calendars/Files scopes).

ops:
  - me()
  - messages(folder, top)                  — list mail
  - send_mail(to, subject, body, confirm)
  - events(start, end, top)                — calendar
  - drive_list(path, top)                  — OneDrive children
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_MSG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["me", "messages", "send_mail", "events", "drive_list"],
        },
        "folder": {"type": "string", "description": "inbox / sentitems / drafts ..."},
        "to": {"type": "array", "items": {"type": "string"}},
        "subject": {"type": "string"},
        "body": {"type": "string"},
        "start": {"type": "string", "description": "ISO 8601 (events)."},
        "end": {"type": "string"},
        "path": {"type": "string", "description": "OneDrive path (drive_list)."},
        "top": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://graph.microsoft.com/v1.0"


def _token() -> str:
    t = os.environ.get("MSGRAPH_ACCESS_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Microsoft Graph requires MSGRAPH_ACCESS_TOKEN.")
    return t


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    from ..governed_http import request
    r = request("GET", f"{_API}{path}", headers=_headers(),
                params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    from ..governed_http import request
    r = request("POST", f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, (r.json() if r.text else {})
    except ValueError:
        return r.status_code, r.text[:300]


def _op_me(_args: dict) -> str:
    code, data = _get("/me")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: me ({code}): {data}"
    return (
        f"{data.get('displayName')}  <{data.get('mail') or data.get('userPrincipalName')}>\n"
        f"  id:   {data.get('id')}\n"
        f"  tz:   {data.get('mailboxSettings', {}).get('timeZone', '?')}"
    )


def _op_messages(args: dict) -> str:
    folder = (args.get("folder") or "inbox").strip()
    top = max(1, min(int(args.get("top") or 10), 50))
    code, data = _get(
        f"/me/mailFolders/{urllib.parse.quote(folder)}/messages",
        {"$top": top, "$select": "subject,from,receivedDateTime,isRead"},
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: messages ({code}): {data}"
    rows = data.get("value") or []
    if not rows:
        return f"no messages in {folder}"
    return "\n".join(
        f"  [{'·' if m.get('isRead') else '•'}] "
        f"{((m.get('from') or {}).get('emailAddress') or {}).get('address', '?'):<30}  "
        f"{(m.get('subject') or '')[:60]}"
        for m in rows
    )


def _op_send_mail(args: dict) -> str:
    to = [str(x) for x in (args.get("to") or []) if x]
    subject = (args.get("subject") or "").strip()
    body = (args.get("body") or "").strip()
    if not to or not subject or not body:
        return "ERROR: send_mail requires to, subject, body"
    if not as_bool(args.get("confirm")):
        return (
            f"DRY RUN: would email {len(to)} recipient(s). "
            "Re-run with confirm=true."
        )
    message = {
        "subject": subject,
        "body": {"contentType": "Text", "content": body},
        "toRecipients": [{"emailAddress": {"address": a}} for a in to],
    }
    code, data = _post("/me/sendMail", {"message": message, "saveToSentItems": True})
    if code >= 400:
        return f"ERROR: send_mail ({code}): {data}"
    return f"sent to {', '.join(to)}"


def _op_events(args: dict) -> str:
    top = max(1, min(int(args.get("top") or 10), 50))
    params: dict = {"$top": top,
                    "$select": "subject,start,end,location,organizer",
                    "$orderby": "start/dateTime"}
    start = (args.get("start") or "").strip()
    end = (args.get("end") or "").strip()
    path = "/me/events"
    if start and end:
        path = "/me/calendarView"
        params["startDateTime"] = start
        params["endDateTime"] = end
    code, data = _get(path, params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: events ({code}): {data}"
    rows = data.get("value") or []
    if not rows:
        return "no events"
    return "\n".join(
        f"  {((e.get('start') or {}).get('dateTime') or '?')[:16]}  "
        f"{(e.get('subject') or '')[:50]:<50}  "
        f"{((e.get('location') or {}).get('displayName') or '')[:30]}"
        for e in rows
    )


def _op_drive_list(args: dict) -> str:
    path = (args.get("path") or "").strip().strip("/")
    top = max(1, min(int(args.get("top") or 50), 200))
    if path:
        endpoint = f"/me/drive/root:/{urllib.parse.quote(path)}:/children"
    else:
        endpoint = "/me/drive/root/children"
    code, data = _get(endpoint, {"$top": top})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: drive_list ({code}): {data}"
    rows = data.get("value") or []
    if not rows:
        return f"(empty: /{path})"
    return "\n".join(
        f"  {'d' if it.get('folder') else 'f'}  "
        f"{it.get('size', ''):>10}  {it.get('name')}"
        for it in rows
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
            "me":         _op_me,
            "messages":   _op_messages,
            "send_mail":  _op_send_mail,
            "events":     _op_events,
            "drive_list": _op_drive_list,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: MS Graph request failed: {type(e).__name__}: {e}"


def msgraph_tool() -> Tool:
    return Tool(
        name="msgraph",
        description=(
            "Microsoft Graph (Outlook + Calendar + OneDrive). ops: "
            "me, messages (folder + top), send_mail (confirm=true), "
            "events (calendar; optional start/end window), "
            "drive_list (OneDrive). Auth: MSGRAPH_ACCESS_TOKEN."
        ),
        input_schema=_MSG_SCHEMA,
        fn=_run,
    )
