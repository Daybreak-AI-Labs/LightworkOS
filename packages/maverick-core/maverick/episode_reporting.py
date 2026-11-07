"""Complete bounded-memory reads of the authorized runtime episode population.

The initial ID ceiling excludes newly inserted episodes from a traversal. This
is a current-state report, not a provider invoice or an immutable ledger close.
"""
from __future__ import annotations

from types import SimpleNamespace


def iter_episodes(world, *, owner=None, since=None, until=None, finished_only=False):
    from .world_model import _dec_fields

    high = int(world.query("SELECT COALESCE(MAX(id), 0) FROM episodes")[0][0])
    cursor = 0
    while cursor < high:
        clauses = ["e.id > ?", "e.id <= ?"]
        values = [cursor, high]
        if owner is not None:
            clauses.append("g.owner = ?")
            values.append(owner)
        if since is not None:
            clauses.append("e.started_at >= ?")
            values.append(since)
        if until is not None:
            clauses.append("e.started_at < ?")
            values.append(until)
        if finished_only:
            clauses.append("e.ended_at IS NOT NULL")
        rows = world.query(
            "SELECT e.id, e.goal_id, e.started_at, e.ended_at, e.outcome, "
            "e.cost_dollars, e.input_tokens, e.output_tokens, e.tool_calls, g.domain "
            "FROM episodes e LEFT JOIN goals g ON e.goal_id = g.id WHERE "
            + " AND ".join(clauses) + " ORDER BY e.id LIMIT 500", tuple(values),
        )
        if not rows:
            break
        # One encryption policy and key lookup per page, not per episode.
        outcomes = _dec_fields([row[4] for row in rows], "episodes.outcome")
        for row, outcome in zip(rows, outcomes, strict=True):
            cursor = int(row[0])
            yield SimpleNamespace(id=cursor, goal_id=row[1], started_at=row[2], ended_at=row[3],
                                  outcome=outcome, cost_dollars=row[5], input_tokens=row[6] or 0,
                                  output_tokens=row[7] or 0, tool_calls=row[8] or 0, domain=row[9] or "")
