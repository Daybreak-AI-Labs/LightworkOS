"""Preview a spending limit against recorded history before saving it.

Report-only: nothing here saves, enforces or changes a limit. It replays the
finished tasks of the last 30 days (their recorded cost, owner and end time)
against a proposed limit and counts the tasks that would have stopped, and
the people they belong to.

A task counts as stopped when, in its day or month (UTC, the windows the
limits use), the spending counted against the limit passes the amount once
that task's cost is added; for a per-task limit, when the task alone costs
more. Work still running is not history yet and is not counted.
"""
from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone

WINDOW_DAYS = 30


def _window(period: str, ended_at: float) -> str:
    from .spending_limits import _window as limit_window

    return limit_window(period, datetime.fromtimestamp(ended_at, timezone.utc))


def preview(scope: str, amount, period: str, *, principal: str = "", world=None,
            now: float | None = None) -> dict:
    """What a proposed limit would have stopped in the last 30 days.

    ``scope`` is ``workspace`` (everyone together), ``default`` (each person
    who has no personal limit of their own) or ``person`` (``principal``).
    The amount and period are validated as saving would validate them."""
    from .spending_limits import PERIODS, WORKSPACE_PERIODS, _limit, _principal, load

    if scope not in ("workspace", "default", "person"):
        raise ValueError("Choose which limit to preview.")
    limit = _limit(amount, period, periods=WORKSPACE_PERIODS if scope == "workspace" else PERIODS)
    who = _principal(principal) if scope == "person" else ""
    personal = set(load()["users"]) if scope == "default" else set()
    if world is None:
        from .world_model import open_world
        world = open_world()
    now = time.time() if now is None else now
    since = now - WINDOW_DAYS * 86400
    totals: dict[tuple[str, str], float] = defaultdict(float)
    considered = stopped = 0
    people: set[str] = set()
    for owner, ended_at, cost in world.episode_costs_since(since):
        if scope == "person" and owner != who:
            continue
        if scope == "default" and (not owner or owner in personal):
            continue
        considered += 1
        if limit["period"] == "task":
            over = cost > limit["amount"]
        else:
            key = ("" if scope == "workspace" else owner, _window(limit["period"], ended_at))
            totals[key] += cost
            over = totals[key] > limit["amount"] + 1e-9
        if over:
            stopped += 1
            if owner:
                people.add(owner)
    return {"scope": scope, "limit": limit, "principal": who, "days": WINDOW_DAYS,
            "since": since, "considered": considered, "tasks": stopped, "people": len(people)}


__all__ = ["WINDOW_DAYS", "preview"]
