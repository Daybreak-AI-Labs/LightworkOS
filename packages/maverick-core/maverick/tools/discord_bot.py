"""Discord bot tool — agent-callable Discord API.

Distinct from ``maverick-channels`` Discord adapter (which receives
inbound messages and runs the swarm). This tool lets the agent SEND
messages, react, look up users, and pull message history directly.

Auth: ``DISCORD_BOT_TOKEN`` (Bot token; not OAuth). The bot must
have ``Send Messages`` / ``Read Message History`` / ``Add Reactions``
on the target channel.

ops:
  - post(channel_id, content)             — post a plain message
  - reply(channel_id, message_id, content)
  - history(channel_id, limit)
  - react(channel_id, message_id, emoji)
  - lookup_channel(channel_id)
  - lookup_user(user_id)
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_DISCORD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": [
                "post", "reply", "history", "react",
                "lookup_channel", "lookup_user",
            ],
        },
        "channel_id": {"type": "string", "pattern": r"^\d{15,22}$"},
        "message_id": {"type": "string", "pattern": r"^\d{15,22}$"},
        "content": {"type": "string"},
        "emoji": {"type": "string", "description": "Unicode emoji or 'name:id' for custom."},
        "user_id": {"type": "string", "pattern": r"^\d{15,22}$"},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


def _normalize_snowflake(value: Any, field: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.isdigit() and 15 <= len(raw) <= 22:
        return raw
    raise ValueError(f"{field} must be a Discord snowflake ID")


_API = "https://discord.com/api/v10"


def _token() -> str:
    t = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Discord requires DISCORD_BOT_TOKEN (Bot token).")
    return t


def _headers(json_body: bool = True) -> dict[str, str]:
    h = {"Authorization": f"Bot {_token()}"}
    if json_body:
        h["Content-Type"] = "application/json"
    return h


def _post_json(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(False),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def _put(path: str) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.put)(f"{_API}{path}", headers=_headers(False), timeout=30.0)
    try:
        return r.status_code, (r.json() if r.text else {})
    except ValueError:
        return r.status_code, {}


def _op_post(channel: str, content: str) -> str:
    code, data = _post_json(f"/channels/{channel}/messages",
                            {"content": content[:2000]})
    if code >= 400:
        return f"ERROR: post ({code}): {data}"
    return f"posted to {channel} (id={data.get('id')})"


def _op_reply(channel: str, message_id: str, content: str) -> str:
    body = {
        "content": content[:2000],
        "message_reference": {"message_id": message_id},
    }
    code, data = _post_json(f"/channels/{channel}/messages", body)
    if code >= 400:
        return f"ERROR: reply ({code}): {data}"
    return f"replied in {channel} (id={data.get('id')})"


def _op_history(channel: str, limit: int) -> str:
    code, data = _get(f"/channels/{channel}/messages",
                      {"limit": min(max(limit, 1), 100)})
    if code >= 400:
        return f"ERROR: history ({code}): {data}"
    rows = data or []
    if not rows:
        return "no messages"
    lines = []
    for m in rows:
        author = (m.get("author") or {}).get("username", "?")
        lines.append(
            f"  [{m.get('id', '?')}] {author}: {(m.get('content') or '')[:160]}"
        )
    return "\n".join(lines)


def _op_react(channel: str, message_id: str, emoji: str) -> str:
    # Keep ':' literal: custom emoji are passed as name:id and Discord's
    # reaction endpoint wants that colon unencoded (quote(safe="") turned it
    # into %3A, 400ing every custom-emoji reaction). Unicode emoji contain no
    # ':' so this is a no-op for them.
    enc = urllib.parse.quote(emoji, safe=":")
    code, data = _put(
        f"/channels/{channel}/messages/{message_id}/reactions/{enc}/@me",
    )
    if code >= 400:
        return f"ERROR: react ({code}): {data}"
    return f"reacted {emoji} on {message_id}"


def _op_lookup_channel(channel: str) -> str:
    code, data = _get(f"/channels/{channel}")
    if code >= 400:
        return f"ERROR: lookup_channel ({code}): {data}"
    return (
        f"#{data.get('name', '?')} (id={data.get('id')}) "
        f"type={data.get('type')} guild={data.get('guild_id', '?')}"
    )


def _op_lookup_user(user_id: str) -> str:
    code, data = _get(f"/users/{user_id}")
    if code >= 400:
        return f"ERROR: lookup_user ({code}): {data}"
    return (
        f"{data.get('username', '?')}#{data.get('discriminator', '0')} "
        f"(id={data.get('id')}) bot={data.get('bot', False)}"
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
        channel = _normalize_snowflake(args.get("channel_id"), "channel_id")
        if op == "post":
            content = args.get("content") or ""
            if not channel or not content:
                return "ERROR: post requires channel_id and content"
            return _op_post(channel, content)
        if op == "reply":
            mid = _normalize_snowflake(args.get("message_id"), "message_id")
            content = args.get("content") or ""
            if not channel or not mid or not content:
                return "ERROR: reply requires channel_id, message_id, content"
            return _op_reply(channel, mid, content)
        if op == "history":
            if not channel:
                return "ERROR: history requires channel_id"
            return _op_history(channel, int(args.get("limit") or 20))
        if op == "react":
            mid = _normalize_snowflake(args.get("message_id"), "message_id")
            emoji = (args.get("emoji") or "").strip()
            if not channel or not mid or not emoji:
                return "ERROR: react requires channel_id, message_id, emoji"
            return _op_react(channel, mid, emoji)
        if op == "lookup_channel":
            if not channel:
                return "ERROR: lookup_channel requires channel_id"
            return _op_lookup_channel(channel)
        if op == "lookup_user":
            uid = _normalize_snowflake(args.get("user_id"), "user_id")
            if not uid:
                return "ERROR: lookup_user requires user_id"
            return _op_lookup_user(uid)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except ValueError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Discord request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def discord_bot() -> Tool:
    return Tool(
        name="discord_bot",
        description=(
            "Discord bot API. ops: post (channel + content), reply "
            "(channel + message_id + content), history (channel + "
            "limit), react (channel + message_id + emoji), "
            "lookup_channel, lookup_user. Auth: DISCORD_BOT_TOKEN."
        ),
        input_schema=_DISCORD_SCHEMA,
        fn=_run,
    )
