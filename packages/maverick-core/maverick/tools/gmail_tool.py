"""Gmail tool — via the Gmail REST API (distinct from the SMTP/IMAP
email tool).

Auth: ``GMAIL_ACCESS_TOKEN`` (OAuth2 bearer with the relevant
gmail.readonly / gmail.send scopes, refreshed externally).

ops:
  - list(query, limit)              — Gmail search syntax
  - get(message_id)                 — headers + snippet + plain body
  - send(to, subject, body, confirm)
  - labels()
"""
from __future__ import annotations

import base64
import logging
import os
from email.message import EmailMessage
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_GM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list", "get", "send", "labels"]},
        "query": {"type": "string"},
        "message_id": {"type": "string"},
        "to": {"type": "string"},
        "subject": {"type": "string"},
        "body": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://gmail.googleapis.com/gmail/v1/users/me"


def _token() -> str:
    t = os.environ.get("GMAIL_ACCESS_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Gmail requires GMAIL_ACCESS_TOKEN.")
    return t


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


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


def _op_list(args: dict) -> str:
    q = (args.get("query") or "").strip()
    limit = max(1, min(int(args.get("limit") or 10), 50))
    code, data = _get("/messages", {"q": q, "maxResults": limit})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: list ({code}): {data}"
    ids = data.get("messages") or []
    if not ids:
        return "no messages"
    out = []
    for m in ids[:limit]:
        c2, d2 = _get(f"/messages/{m['id']}",
                      {"format": "metadata",
                       "metadataHeaders": ["From", "Subject"]})
        if c2 >= 400 or not isinstance(d2, dict):
            continue
        headers = {h.get("name", ""): h.get("value", "")
                   for h in ((d2.get("payload") or {}).get("headers") or [])}
        out.append(
            f"  {m['id']}  {headers.get('From', '?')[:30]:<30}  "
            f"{headers.get('Subject', '')[:50]}"
        )
    return "\n".join(out)


def _decode_b64url(data: str) -> str:
    """Decode a (sender-controlled) base64url body, never raising.

    Gmail strips padding, so we re-pad to a multiple of 4. A bare ``+ "==="``
    over-pads and raises ``binascii.Error`` for any payload whose length is
    1 (mod 4); correct padding plus a defensive guard keeps a malformed MIME
    body from crashing the whole ``get`` op.
    """
    if not isinstance(data, str):
        return ""
    s = data.rstrip("=")
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _extract_plain(payload: dict, _depth: int = 0) -> str:
    """Walk MIME parts for the first text/plain body."""
    # Depth cap: the MIME tree mirrors the message structure, which the
    # (untrusted) sender controls; a deeply-nested multipart email would
    # otherwise blow the stack (RecursionError) on read. Real nesting is shallow.
    if not payload or _depth > 30:
        return ""
    mime = payload.get("mimeType", "")
    body = payload.get("body") or {}
    if mime == "text/plain" and body.get("data"):
        return _decode_b64url(body["data"])
    for part in payload.get("parts") or []:
        text = _extract_plain(part, _depth + 1)
        if text:
            return text
    return ""


def _op_get(args: dict) -> str:
    mid = (args.get("message_id") or "").strip()
    if not mid:
        return "ERROR: get requires message_id"
    seg = safe_path_segment(mid)
    if seg is None:
        return "ERROR: get requires a valid message_id"
    code, data = _get(f"/messages/{seg}", {"format": "full"})
    if code == 404:
        return f"message {mid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: get ({code}): {data}"
    payload = data.get("payload") or {}
    headers = {h.get("name", ""): h.get("value", "")
               for h in (payload.get("headers") or [])}
    body = _extract_plain(payload) or data.get("snippet", "")
    return (
        f"From:    {headers.get('From', '?')}\n"
        f"To:      {headers.get('To', '?')}\n"
        f"Subject: {headers.get('Subject', '?')}\n"
        f"Date:    {headers.get('Date', '?')}\n\n"
        f"{body[:4000]}"
    )


def _op_send(args: dict) -> str:
    to = (args.get("to") or "").strip()
    subject = (args.get("subject") or "").strip()
    body = (args.get("body") or "").strip()
    if not to or not subject or not body:
        return "ERROR: send requires to, subject, body"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would email {to}. Re-run with confirm=true."
    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
    code, data = _post("/messages/send", {"raw": raw})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: send ({code}): {data}"
    return f"sent (id={data.get('id')})"


def _op_labels(_args: dict) -> str:
    code, data = _get("/labels")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: labels ({code}): {data}"
    rows = data.get("labels") or []
    return "\n".join(
        f"  {(lbl.get('id') or '?'):<25}  {lbl.get('name')}" for lbl in rows
    ) or "no labels"


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
            "list":   _op_list,
            "get":    _op_get,
            "send":   _op_send,
            "labels": _op_labels,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Gmail request failed: {type(e).__name__}: {e}"


def gmail_tool() -> Tool:
    return Tool(
        name="gmail",
        description=(
            "Gmail REST API. ops: list (Gmail search query), get "
            "(headers + plain body), send (confirm=true), labels. "
            "Auth: GMAIL_ACCESS_TOKEN (OAuth2, refreshed externally)."
        ),
        input_schema=_GM_SCHEMA,
        fn=_run,
    )
