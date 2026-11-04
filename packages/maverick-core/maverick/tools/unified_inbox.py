"""Unified inbox.

Merge messages arriving from multiple channels (slack, email, discord, ...) into
a single chronological view, grouped per thread, with an unread count per
channel. Deterministic and offline: the caller supplies the raw messages; this
sorts, groups, and tallies. A thread is identified by an explicit ``thread`` key
when present, otherwise by ``channel:user`` so a back-and-forth with one person
on one channel stays together.

ops:
  - merge(messages)  — time-sorted, per-thread grouped view + unread counts.

Each message is ``{"channel", "user", "text", "ts"[, "thread"][, "unread"]}``.
``unread`` defaults to false. Messages with a non-numeric ``ts`` sort last
(stable).
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _thread_key(msg: dict) -> str:
    explicit = msg.get("thread")
    if explicit not in (None, ""):
        return str(explicit)
    channel = str(msg.get("channel") or "?")
    user = str(msg.get("user") or "?")
    return f"{channel}:{user}"


def _sort_key(pair: tuple[int, dict]) -> tuple[int, float, int]:
    i, m = pair
    ts = _as_float(m.get("ts"))
    if ts is None:
        return (1, 0.0, i)
    return (0, ts, i)


def _merge(messages: list) -> str:
    valid = [(i, m) for i, m in enumerate(messages) if isinstance(m, dict)]
    ordered = [m for _, m in sorted(valid, key=_sort_key)]
    if not ordered:
        return "INBOX: (empty)"

    # Group into threads, preserving first-seen thread order (which is already
    # chronological because `ordered` is sorted by ts).
    threads: dict[str, list[dict]] = {}
    for m in ordered:
        threads.setdefault(_thread_key(m), []).append(m)

    unread_by_channel: dict[str, int] = {}
    for m in ordered:
        if m.get("unread") is True:
            ch = str(m.get("channel") or "?")
            unread_by_channel[ch] = unread_by_channel.get(ch, 0) + 1

    lines = [f"INBOX: {len(ordered)} message(s) in {len(threads)} thread(s)"]
    for key, msgs in threads.items():
        lines.append(f"thread {key} ({len(msgs)}):")
        for m in msgs:
            ts = m.get("ts")
            ts_str = ts if _as_float(ts) is not None else "?"
            flag = "* " if m.get("unread") is True else "  "
            channel = str(m.get("channel") or "?")
            user = str(m.get("user") or "?")
            text = str(m.get("text") or "")
            lines.append(f"  {flag}[{ts_str}] {channel}/{user}: {text}")

    if unread_by_channel:
        tally = ", ".join(f"{c}={unread_by_channel[c]}" for c in sorted(unread_by_channel))
        lines.append(f"unread: {tally}")
    else:
        lines.append("unread: none")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "merge"):
        return f"ERROR: unknown op {args.get('op')!r}"
    messages = args.get("messages")
    if not isinstance(messages, list):
        return "ERROR: messages (array of {channel, user, text, ts}) is required"
    return _merge(messages)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["merge"]},
        "messages": {
            "type": "array",
            "description": "messages across channels; each {channel, user, text, ts, thread?, unread?}",
            "items": {
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "user": {"type": "string"},
                    "text": {"type": "string"},
                    "ts": {"type": "number"},
                    "thread": {"type": "string"},
                    "unread": {"type": "boolean"},
                },
            },
        },
    },
    "required": ["messages"],
}


def unified_inbox() -> Tool:
    return Tool(
        name="unified_inbox",
        description=(
            "Merge multi-channel messages into one inbox. op=merge with "
            "'messages' (each {channel, user, text, ts, thread?, unread?}). "
            "Returns a time-sorted view grouped per thread (by 'thread' or "
            "channel:user) with an unread count per channel. Deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
