"""Glance payload.

One **tiny, fixed-shape** status payload sized for a small screen — active
and today counts, today's spend, and the last terminal result — computed in
one cheap pass and served at ``GET /api/v1/glance``; anything fancier belongs
on the phone or the dashboard.

Pure over an injected world (+ the usage ledger for spend); every field is
bounded so the payload stays glance-sized no matter the history.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def _today_bounds(now: float) -> tuple[float, float]:
    d = datetime.fromtimestamp(now, tz=timezone.utc)
    start = d.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    return start, start + 86400.0


def build_glance(world, *, now: float | None = None, owner: str | None = None) -> dict:
    """The fixed glance shape:

    ``{active, done_today, failed_today, spend_today, last_result, as_of}``
    """
    ts = float(now if now is not None else time.time())
    day_start, day_end = _today_bounds(ts)
    active = done_today = failed_today = 0
    # The newest terminal goal: (updated_at, goal). A world that can read the
    # status columns alone is asked for those, so only the chosen goal is
    # decrypted for its result or title.
    last: tuple[float, object] | None = None
    states = getattr(world, "goal_states", None)
    try:
        if callable(states):
            rows = [(gid, status, float(updated or 0))
                    for gid, status, updated in states(owner=owner, limit=10_000)]
        else:
            rows = [(g, getattr(g, "status", ""), float(getattr(g, "updated_at", 0) or 0))
                    for g in world.list_goals(owner=owner, limit=10_000)]
    except Exception:
        rows = []
    for ref, status, updated in rows:
        if status in ("active", "pending", "running"):
            active += 1
        if day_start <= updated < day_end:
            if status in ("done", "succeeded", "completed"):
                done_today += 1
            elif status in ("failed", "blocked"):
                failed_today += 1
        if status in ("done", "succeeded", "completed", "failed", "blocked"):
            if last is None or updated > last[0]:
                last = (updated, ref)
    last_text = ""
    if last is not None:
        try:
            goal = world.get_goal(last[1]) if isinstance(last[1], int) else last[1]
            last_text = (getattr(goal, "result", "") or getattr(goal, "title", "") or "")
        except Exception as e:
            log.debug("glance: last result lookup failed (%s); reporting no result", e)
    spend = 0.0
    try:
        from .quotas import UsageLedger, _today
        data = UsageLedger()._load()
        day = _today()
        if owner is None:
            spend = sum(float((days.get(day) or {}).get("dollars", 0.0))
                        for days in data.values() if isinstance(days, dict))
        else:
            spend = float((data.get(owner) or {}).get(day, {}).get("dollars", 0.0))
    except Exception as e:
        # Don't let a ledger read error read as a real $0.00 spend with no trace.
        log.debug("glance: spend lookup failed (%s); reporting $0.00", e)
    return {
        "active": active,
        "done_today": done_today,
        "failed_today": failed_today,
        "spend_today": round(spend, 2),
        "last_result": last_text[:60],
        "as_of": int(ts),
    }


__all__ = ["build_glance"]
