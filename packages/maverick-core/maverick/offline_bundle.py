"""Offline snapshot bundle for the mobile companion app.

``build_bundle(world)`` produces a compact, bounded, versioned snapshot the
mobile app caches locally (AsyncStorage) and renders when the dashboard is
unreachable — "as of N minutes ago" instead of a blank screen.

Design rules:
  - **Versioned**: ``schema = "maverick-offline/1"`` so clients can refuse
    shapes they don't understand.
  - **Deterministic field set**: exactly the keys in ``GOAL_FIELDS`` /
    ``EVENT_FIELDS``, nothing else, so the client renderer never guesses.
  - **Bounded everywhere**: goal count, event count, and string lengths are
    all capped; a year-old world produces the same-sized bundle as a fresh one.
  - **No secrets**: only world-DB rows (titles, statuses, event text) — never
    tokens, keys, or environment values. Enforced by test.

The serving endpoint (``GET /api/v1/offline/bundle``) lives in the dashboard
package; this module is dashboard-agnostic so it can be tested with a fake
world and reused by other read-only surfaces (watch, CLI ``--offline``).
"""
from __future__ import annotations

import time
from typing import Any

SCHEMA = "maverick-offline/1"

# The exact, documented field sets — the client contract.
GOAL_FIELDS = ("id", "title", "status", "created_at", "updated_at", "result")
EVENT_FIELDS = ("id", "goal_id", "agent", "kind", "content", "ts")

MAX_GOALS = 1000
MAX_EVENTS = 2000
MAX_ACTIVE = 25          # active runs embedded in the bundle's glance
_EVENT_GOALS = 10        # events come from the N most-recent goals
_TITLE_CHARS = 200
_GLANCE_TITLE_CHARS = 120
_TEXT_CHARS = 400


def build_offline_glance(world, *, now: float | None = None,
                         max_active: int = MAX_ACTIVE,
                         owner: str | None = None) -> dict[str, Any]:
    """The richer, list-bearing glance the offline bundle embeds.

    Distinct from :func:`maverick.glance.build_glance` (the tiny scalar
    watch payload): this carries the *active-run list* + headline counts +
    spend the mobile app renders when offline. Bounded + read-only; only
    world-DB rows, never secrets. When ``owner`` is given the glance is
    scoped to that owner's goals so an owner-bundle never surfaces another
    owner's active titles or open questions.
    """
    as_of = float(now if now is not None else time.time())
    max_active = max(1, min(int(max_active), MAX_ACTIVE))
    active = world.list_goals(status="active", owner=owner, limit=max_active, order="desc")
    spend = world.total_spend()
    if owner is None:
        open_questions = world.open_questions()
    else:
        scoped_goal_ids = {
            g.id for g in world.list_goals(owner=owner, limit=MAX_GOALS, order="desc")
        }
        open_questions = [
            q for q in world.open_questions()
            if getattr(q, "goal_id", None) in scoped_goal_ids
        ]
    # Approvals are a standalone operator queue with no goal/owner linkage, so
    # they can't be owner-scoped; surface the global count (a bare number, no
    # titles) rather than silently reporting zero.
    pending_approvals = world.pending_approvals()
    return {
        "as_of": as_of,
        "active": [
            {
                "id": g.id,
                "title": (g.title or "")[:_GLANCE_TITLE_CHARS],
                "status": g.status,
                "updated_at": g.updated_at,
            }
            for g in active
        ],
        "counts": {
            "active": len(active),
            "pending_approvals": len(pending_approvals),
            "open_questions": len(open_questions),
        },
        "spend": {
            "dollars": round(float(spend.get("dollars") or 0.0), 4),
            "runs": int(spend.get("runs") or 0),
        },
    }


def build_bundle(
    world,
    *,
    now: float | None = None,
    max_goals: int = 200,
    max_events: int = 500,
    owner: str | None = None,
) -> dict[str, Any]:
    """Build the offline snapshot. ``owner`` scopes goals like the REST list."""
    as_of = float(now if now is not None else time.time())
    max_goals = max(1, min(int(max_goals), MAX_GOALS))
    max_events = max(1, min(int(max_events), MAX_EVENTS))

    goals = world.list_goals(owner=owner, limit=max_goals, order="desc")

    events: list[Any] = []
    for g in goals[:_EVENT_GOALS]:
        events.extend(world.recent_goal_events(g.id, limit=max_events))
    # Newest first, deterministic tie-break by id, bounded.
    events.sort(key=lambda e: (e.ts, e.id), reverse=True)
    events = events[:max_events]

    from .mobile_offline_policy import effective_policy
    return {
        "cache_policy": effective_policy(),
        "schema": SCHEMA,
        "as_of": as_of,
        "glance": build_offline_glance(world, now=as_of, owner=owner),
        "goals": [
            {
                "id": g.id,
                "title": (g.title or "")[:_TITLE_CHARS],
                "status": g.status,
                "created_at": g.created_at,
                "updated_at": g.updated_at,
                "result": (g.result or "")[:_TEXT_CHARS] or None,
            }
            for g in goals
        ],
        "recent_events": [
            {
                "id": e.id,
                "goal_id": e.goal_id,
                "agent": e.agent,
                "kind": e.kind,
                "content": (e.content or "")[:_TEXT_CHARS],
                "ts": e.ts,
            }
            for e in events
        ],
    }
