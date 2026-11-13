"""Notification tool — agent-callable push.

Wraps the existing ``maverick.notifications.notify`` so agents can
fire ntfy/Pushover/Discord/Slack messages directly (status updates,
"task done, please review", "blocked on Q"). Channels + creds are
read from ``[notifications]`` config; the agent only chooses the
message + priority.

ops:
  - send(title, body, priority)
"""
from __future__ import annotations

from typing import Any

from . import Tool

_NOTIFY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "body": {"type": "string"},
        "priority": {
            "type": "string",
            "enum": ["low", "default", "high", "urgent"],
        },
        "category": {
            "type": "string",
            "description": "Tag used by some backends (default 'agent').",
        },
    },
    "required": ["title"],
}


def _run(args: dict[str, Any]) -> str:
    title = (args.get("title") or "").strip()
    if not title:
        return "ERROR: notify requires title"
    body = args.get("body") or ""
    priority = (args.get("priority") or "default").strip().lower()
    if priority not in {"low", "default", "high", "urgent"}:
        priority = "default"
    category = (args.get("category") or "agent").strip()
    try:
        from ..notifications import configured_backends, notify
    except ImportError as e:
        return f"ERROR: notifications module unavailable: {e}"
    # notify() backends use low/default/high/max; the tool exposes "urgent".
    backend_priority = "max" if priority == "urgent" else priority
    states: list[str] = []
    try:
        # notify() counts a backend it queued even when that backend has no
        # destination, and returns 0 for an item held for a batched digest, so
        # the count alone cannot say whether a backend is configured.
        if not configured_backends():
            return (
                "no notification backend is configured. "
                "Set [notifications] backend in ~/.maverick/config.toml."
            )
        # notify() returns an int (count of backends fired) and takes the
        # message as `body` with a separate `title` keyword. The old call
        # jammed title+body into the positional body and then did len() on
        # the int return -- so every successful send raised TypeError and
        # was reported to the agent as an error.
        count = notify(
            body or title,
            title=title,
            priority=backend_priority,
            category=category,
            outcomes=states,
        )
    except Exception as e:
        return f"ERROR: notify failed: {type(e).__name__}: {e}"
    if "batched" in states:
        return "held for the next batched digest; delivery not yet confirmed"
    if not count:
        return "not sent: the notification was not accepted for delivery"
    return f"queued; delivery not yet confirmed ({count} backend{'s' if count != 1 else ''})"


def notify_tool() -> Tool:
    return Tool(
        name="notify",
        description=(
            "Fire a push notification to the user via configured "
            "backends (ntfy / Pushover / Discord / Slack). Args: "
            "title (required), body, priority "
            "(low/default/high/urgent), category. Use sparingly — "
            "good for 'task complete' / 'blocked on Q' / etc."
        ),
        input_schema=_NOTIFY_SCHEMA,
        fn=_run,
    )
