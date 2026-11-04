"""What a different approval threshold would have done, from the record.

Settings > All settings shows this beside "Actions that can't be undone"
(``[safety] consent_mode``, the approval threshold) when a level is chosen and
before it is saved. It replays the last 30 days of recorded approval checks
(:mod:`maverick.approval_checks`: risk level, agent or specialist and outcome,
never content) through the same rule the approval gate applies
(:func:`maverick.safety.consent.installation_mode_for`). Report only: nothing
is saved or enforced here. With under 30 days of records, or too few checks,
it says so instead of guessing.
"""
from __future__ import annotations

import time
from typing import Any

DAYS = 30
# Fewer checks than this in the window is too little to show a count.
MIN_CHECKS = 20
_ASKS = frozenset({"ask", "dashboard"})
LEVELS = frozenset({"", "dashboard", "ask", "auto-deny", "auto-approve"})


def preview(value: str, *, now: float | None = None) -> dict[str, Any]:
    """The counts for level ``value`` ("" is the default), report-only."""
    from maverick import approval_checks
    from maverick.safety.consent import installation_mode_for
    from maverick.world_model import close_world_if_owned, open_world

    if value not in LEVELS:
        raise ValueError("Choose one of the listed levels.")
    now = time.time() if now is None else float(now)
    since = now - DAYS * 86_400.0
    world = open_world()
    try:
        first = approval_checks.first_check_at(world)
        rows = approval_checks.tally_since(world, since)
    finally:
        close_world_if_owned(world)
    checks = sum(row["checks"] for row in rows)
    result: dict[str, Any] = {"kind": "approval_checks", "days": DAYS, "minimum": MIN_CHECKS,
                              "recording_started_at": first, "recording_on": approval_checks.enabled(),
                              "checks": checks}
    if first is None or first > since:
        return {**result, "enough": False, "reason": "history"}
    if checks < MIN_CHECKS:
        return {**result, "enough": False, "reason": "count"}
    actions = refused = 0
    agents: set[str] = set()
    recorded = dict.fromkeys(("asked", "allowed", "refused"), 0)
    for row in rows:
        recorded[row["outcome"]] = recorded.get(row["outcome"], 0) + row["checks"]
        mode = installation_mode_for(value, row["risk"] or None)
        if mode in _ASKS:
            actions += row["checks"]
            if row["agent"]:
                agents.add(row["agent"])
        elif mode == "auto-deny":
            refused += row["checks"]
    return {**result, "enough": True, "actions": actions, "agents": len(agents),
            "refused": refused, "recorded": recorded}


__all__ = ["DAYS", "LEVELS", "MIN_CHECKS", "preview"]
