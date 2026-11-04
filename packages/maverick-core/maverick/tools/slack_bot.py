"""Slack bot tool — agent-callable Slack API.

Distinct from ``maverick-channels`` Slack adapter (which receives
inbound messages and runs the swarm). This tool lets the agent
SEND messages, post snippets, look up users, and join channels
directly from inside a goal.

Auth: ``SLACK_BOT_TOKEN`` (xoxb-*) — bot must be invited to target
channels.

ops:
  - post(channel, text, thread_ts)        — post a message
  - upload(channel, filename, content)    — upload a code/text snippet
  - lookup_user(email)                    — find user id by email
  - join(channel)                         — bot joins a public channel
  - history(channel, limit)               — last N messages
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_SLACK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["post", "upload", "lookup_user", "join", "history"],
        },
        "channel": {"type": "string", "description": "Channel id (Cxxx) or name (#general)."},
        "text": {"type": "string"},
        "thread_ts": {"type": "string", "description": "Reply in thread."},
        "filename": {"type": "string"},
        "content": {"type": "string", "description": "File content (utf-8)."},
        "email": {"type": "string"},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


_API = "https://slack.com/api"


def _token() -> str:
    t = os.environ.get("SLACK_BOT_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Slack requires SLACK_BOT_TOKEN (xoxb-* bot token).")
    return t


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token()}",
        "Content-Type": "application/json; charset=utf-8",
    }


def _check(payload: dict, action: str) -> str | None:
    if not payload.get("ok"):
        return f"ERROR: slack {action} failed: {payload.get('error', 'unknown')}"
    return None


def _post(method: str, body: dict) -> dict:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}/{method}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.json()
    except ValueError:
        return {"ok": False, "error": f"http_{r.status_code}"}


def _get(method: str, params: dict) -> dict:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}/{method}", headers={
        "Authorization": f"Bearer {_token()}",
    }, params=params, timeout=30.0)
    try:
        return r.json()
    except ValueError:
        return {"ok": False, "error": f"http_{r.status_code}"}


def _op_post(channel: str, text: str, thread_ts: str) -> str:
    payload: dict = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    data = _post("chat.postMessage", payload)
    err = _check(data, "post")
    if err:
        return err
    return f"posted to {data.get('channel')} (ts={data.get('ts')})"


def _op_upload(channel: str, filename: str, content: str) -> str:
    """Use the v2 upload flow (files.getUploadURLExternal + completeUploadExternal)."""
    import httpx
    # Step 1: get an upload URL.
    g = _get("files.getUploadURLExternal", {
        "filename": filename, "length": str(len(content.encode("utf-8"))),
    })
    err = _check(g, "upload (init)")
    if err:
        return err
    upload_url = g.get("upload_url")
    file_id = g.get("file_id")
    if not upload_url or not file_id:
        return f"ERROR: upload init returned no url/id: {g}"
    # Step 2: PUT the bytes (no auth header — pre-signed URL).
    r = _governed_sender(httpx.post)(upload_url, content=content.encode("utf-8"), timeout=30.0)
    if r.status_code >= 400:
        return f"ERROR: upload PUT {r.status_code}: {r.text[:300]}"
    # Step 3: complete the upload + share into the channel.
    done = _post("files.completeUploadExternal", {
        "files": [{"id": file_id, "title": filename}],
        "channel_id": channel,
    })
    err = _check(done, "upload (complete)")
    if err:
        return err
    return f"uploaded {filename} to {channel} (id={file_id})"


def _op_lookup_user(email: str) -> str:
    data = _get("users.lookupByEmail", {"email": email})
    err = _check(data, "lookup_user")
    if err:
        return err
    u = data.get("user") or {}
    return f"{u.get('id', '?')}  {u.get('real_name', '')}  ({email})"


def _op_join(channel: str) -> str:
    data = _post("conversations.join", {"channel": channel})
    err = _check(data, "join")
    if err:
        return err
    ch = (data.get("channel") or {}).get("name", channel)
    return f"joined {ch}"


def _op_history(channel: str, limit: int) -> str:
    # Slack returns up to ~200 messages per page with a `has_more` flag and a
    # `response_metadata.next_cursor`; follow the cursor until `limit` messages
    # are collected, bounded by a hard page cap.
    msgs: list[dict] = []
    cursor: str | None = None
    max_pages = max(1, (limit // 200) + 2)
    for _ in range(max_pages):
        params = {"channel": channel, "limit": str(min(200, max(1, limit - len(msgs))))}
        if cursor:
            params["cursor"] = cursor
        data = _get("conversations.history", params)
        err = _check(data, "history")
        if err:
            return err
        batch = data.get("messages") or []
        msgs.extend(batch)
        cursor = ((data.get("response_metadata") or {}).get("next_cursor") or "").strip()
        if len(msgs) >= limit or not data.get("has_more") or not cursor or not batch:
            break
    msgs = msgs[:limit]
    if not msgs:
        return "no messages"
    return "\n".join(
        f"  [{m.get('ts', '?'):>16}] {(m.get('user') or '?'):>10}: "
        f"{(m.get('text') or '')[:120]}"
        for m in msgs
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    channel = (args.get("channel") or "").strip()
    try:
        if op == "post":
            text = args.get("text") or ""
            if not channel or not text:
                return "ERROR: post requires channel and text"
            return _op_post(channel, text, (args.get("thread_ts") or "").strip())
        if op == "upload":
            filename = (args.get("filename") or "").strip()
            content = args.get("content") or ""
            if not channel or not filename or not content:
                return "ERROR: upload requires channel, filename, content"
            return _op_upload(channel, filename, content)
        if op == "lookup_user":
            email = (args.get("email") or "").strip()
            if not email:
                return "ERROR: lookup_user requires email"
            return _op_lookup_user(email)
        if op == "join":
            if not channel:
                return "ERROR: join requires channel"
            return _op_join(channel)
        if op == "history":
            if not channel:
                return "ERROR: history requires channel"
            return _op_history(channel, max(1, min(int(args.get("limit") or 20), 200)))
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Slack request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def slack_bot() -> Tool:
    return Tool(
        name="slack_bot",
        description=(
            "Slack bot API. ops: post (channel + text [+thread_ts]), "
            "upload (channel + filename + content via v2 flow), "
            "lookup_user (email -> id), join (public channel), "
            "history (last N messages). Auth: SLACK_BOT_TOKEN."
        ),
        input_schema=_SLACK_SCHEMA,
        fn=_run,
    )
