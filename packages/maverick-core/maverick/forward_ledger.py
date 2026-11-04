"""The forward ledger (v1): every known upcoming obligation, pre-staged.

Pending/active goals whose deadline falls inside a horizon, soonest (so
overdue) first, each with the number of open questions a person will be
asked -- so decisions arrive prepared instead of discovered late. Shared by
``maverick forward`` and the dashboard's Tasks page. Read-only.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Obligation:
    goal: Any
    deadline: float
    open_questions: int


def upcoming(world, *, days: float = 30, now: float | None = None,
             owner: str | None = None, limit: int = 2000) -> list[Obligation]:
    """Goals due within ``days`` of ``now`` (overdue included), soonest first.

    ``owner`` narrows to one person's goals the way ``list_goals`` does
    (``None`` = every goal, the CLI's view)."""
    now = time.time() if now is None else now
    horizon = now + days * 86400.0
    rows: list[Obligation] = []
    kwargs = {"limit": limit} if owner is None else {"limit": limit, "owner": owner}
    # A SQLite world filters on status and deadline before decrypting, so only
    # the due goals are decoded (the same window of 2,000 oldest goals).
    due = getattr(world, "goals_due_by", None)
    goals = (due(horizon, owner=owner, limit=limit) if callable(due)
             else world.list_goals(**kwargs))
    for g in goals:
        if g.status not in ("pending", "active"):
            continue
        if not g.deadline or g.deadline > horizon:
            continue
        rows.append(Obligation(g, float(g.deadline), len(world.open_questions(g.id))))
    rows.sort(key=lambda r: r.deadline)
    return rows


__all__ = ["Obligation", "upcoming"]
