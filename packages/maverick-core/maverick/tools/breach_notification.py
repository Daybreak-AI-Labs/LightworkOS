"""GDPR breach-notification timer (Art. 33/34).

Art. 33 requires a controller to notify the supervisory authority of a personal-
data breach "without undue delay and, where feasible, not later than 72 hours
after having become aware of it." This computes that deadline from the discovery
time, reports whether notification is DUE / OVERDUE / ON_TIME / LATE, and — for a
high-risk breach — reminds that affected individuals must also be notified
(Art. 34). Pure datetime arithmetic — deterministic and offline. Distinct from
``sla_breach`` (service SLOs).

ops:
  - status(discovered, [now], [notified], [high_risk], [deadline_hours])  — all
    timestamps ISO (date or datetime; trailing 'Z' ok). ``now`` defaults to the
    system UTC time. Reports the authority-notification deadline and status.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from . import Tool

_DEFAULT_HOURS = 72


def _parse(s: str, field: str) -> datetime:
    text = str(s).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "T" not in text and " " not in text:
        text += "T00:00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"{field} is not an ISO date/datetime: {s!r}") from None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _hours(delta_seconds: float) -> float:
    return round(delta_seconds / 3600, 1)


def _status(discovered: datetime, now: datetime, notified: datetime | None,
            high_risk: bool, deadline_hours: int) -> str:
    deadline = discovered + timedelta(hours=deadline_hours)
    dstr = deadline.isoformat()

    if notified is not None:
        elapsed = _hours((notified - discovered).total_seconds())
        if notified <= deadline:
            head = f"ON_TIME: notified {notified.isoformat()}, {elapsed}h after discovery (within {deadline_hours}h)"
        else:
            late = _hours((notified - deadline).total_seconds())
            head = f"LATE: notified {notified.isoformat()}, {elapsed}h after discovery (late {late}h past the {deadline_hours}h deadline)"
        # Notifying the supervisory authority does not discharge the Art. 34
        # duty to also notify affected individuals when the breach is high risk.
        # This reminder was silently dropped once a 'notified' timestamp existed.
        if high_risk:
            head += ("\nHIGH RISK: affected individuals must also be notified "
                     "without undue delay (GDPR Art. 34).")
        return head

    remaining = _hours((deadline - now).total_seconds())
    if remaining < 0:
        head = f"OVERDUE: authority notification was due {dstr} ({deadline_hours}h after discovery), overdue {-remaining}h"
    else:
        head = f"DUE: notify the supervisory authority by {dstr} (in {remaining}h)"

    if high_risk:
        head += "\nHIGH RISK: affected individuals must also be notified without undue delay (Art. 34)"
    return head


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "status"):
        return f"ERROR: unknown op {args.get('op')!r}"
    discovered_arg = args.get("discovered")
    if not discovered_arg:
        return "ERROR: discovered (ISO date/datetime) is required"
    deadline_hours = args.get("deadline_hours", _DEFAULT_HOURS)
    try:
        deadline_hours = int(deadline_hours)
    except (TypeError, ValueError):
        return "ERROR: deadline_hours must be an integer"
    if deadline_hours <= 0:
        return "ERROR: deadline_hours must be > 0"

    try:
        discovered = _parse(discovered_arg, "discovered")
        now_arg = args.get("now")
        now = _parse(now_arg, "now") if now_arg is not None else datetime.now(timezone.utc).replace(tzinfo=None)
        notified_arg = args.get("notified")
        notified = _parse(notified_arg, "notified") if notified_arg else None
    except ValueError as e:
        return f"ERROR: {e}"

    if notified is not None and notified < discovered:
        return "ERROR: notified is before discovered"

    return _status(discovered, now, notified, bool(args.get("high_risk", False)), deadline_hours)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["status"]},
        "discovered": {"type": "string", "description": "ISO time the controller became aware of the breach"},
        "now": {"type": "string", "description": "ISO time to evaluate against; defaults to system UTC time"},
        "notified": {"type": "string", "description": "ISO time the authority was notified (if already done)"},
        "high_risk": {"type": "boolean", "description": "breach likely high-risk to individuals (triggers Art. 34)"},
        "deadline_hours": {"type": "integer", "description": f"notification window (default {_DEFAULT_HOURS})"},
    },
    "required": ["discovered"],
}


def breach_notification() -> Tool:
    return Tool(
        name="breach_notification",
        description=(
            "GDPR Art. 33/34 breach-notification timer. op=status with "
            "'discovered' (ISO), optional 'now', 'notified', 'high_risk', and "
            "'deadline_hours' (default 72). Computes the supervisory-authority "
            "deadline and reports DUE / OVERDUE / ON_TIME / LATE, plus an Art. 34 "
            "reminder for high-risk breaches. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
