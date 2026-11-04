"""Channel auto-routing.

Pick the best outbound channel for a message from a set of candidate channels,
by simple, explainable rules. Pure and deterministic — no network, no model
call.

A channel is *eligible* when it satisfies the message's hard constraints:
  - media:  the message ``has_media`` -> the channel must ``supports_media``
  - length: the message ``length`` must be <= the channel's ``max_len``
Among eligible channels, an *urgent* message prefers a ``realtime`` channel.
Ties break on the channel's declared order. If no channel is eligible, the
message falls back to the channel with the largest ``max_len`` (so the longest
message still goes somewhere), reported as a fallback.

ops:
  - route(message={urgency, length, has_media}, channels=[{name, supports_media,
    max_len, realtime}])

Stdlib only. No network access anywhere in this tool.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _eligible(msg: dict, ch: dict) -> bool:
    if msg.get("has_media") and not ch.get("supports_media"):
        return False
    max_len = ch.get("max_len")
    if isinstance(max_len, (int, float)) and int(msg.get("length", 0)) > max_len:
        return False
    return True


def _route(message: dict, channels: list) -> dict[str, Any]:
    """Return {channel, fallback, reason}. Pure."""
    urgent = str(message.get("urgency", "")).strip().lower() in {
        "urgent", "high", "critical"
    }
    eligible = [(i, c) for i, c in enumerate(channels) if _eligible(message, c)]

    if eligible:
        if urgent:
            # Prefer realtime among eligible; preserve declared order on ties.
            eligible.sort(key=lambda ic: (0 if ic[1].get("realtime") else 1, ic[0]))
            chosen = eligible[0][1]
            rt = chosen.get("realtime")
            reason = (
                "urgent -> realtime channel"
                if rt else "urgent but no realtime channel eligible; first eligible"
            )
        else:
            chosen = eligible[0][1]
            reason = "first eligible channel"
        return {
            "channel": str(chosen.get("name", "?")),
            "fallback": False,
            "reason": reason,
        }

    # Nothing fits the constraints: fall back to the widest channel.
    widest = max(channels, key=lambda c: c.get("max_len") or 0)
    return {
        "channel": str(widest.get("name", "?")),
        "fallback": True,
        "reason": "no channel satisfies constraints; fallback to widest max_len",
    }


def _op_route(args: dict) -> str:
    message = args.get("message")
    channels = args.get("channels")
    if not isinstance(message, dict):
        return "ERROR: route requires message ({urgency, length, has_media})"
    if not isinstance(channels, list) or not channels:
        return "ERROR: route requires channels (non-empty array)"
    res = _route(message, channels)
    tag = " (fallback)" if res["fallback"] else ""
    return f"{res['channel']}{tag}: {res['reason']}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op not in (None, "route"):
        return f"ERROR: unknown op {op!r}"
    return _op_route(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["route"]},
        "message": {
            "type": "object",
            "description": "The message to route.",
            "properties": {
                "urgency": {"type": "string"},
                "length": {"type": "integer"},
                "has_media": {"type": "boolean"},
            },
        },
        "channels": {
            "type": "array",
            "description": "Candidate channels.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "supports_media": {"type": "boolean"},
                    "max_len": {"type": "integer"},
                    "realtime": {"type": "boolean"},
                },
            },
        },
    },
    "required": ["message", "channels"],
}


def channel_autoroute() -> Tool:
    return Tool(
        name="channel_autoroute",
        description=(
            "Auto-route a message to the best channel. op=route with 'message' "
            "({urgency, length, has_media}) and 'channels' ([{name, "
            "supports_media, max_len, realtime}]). Rules: media needs "
            "supports_media, length<=max_len, urgent prefers realtime; falls "
            "back to the widest channel if none fit. Pure."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
