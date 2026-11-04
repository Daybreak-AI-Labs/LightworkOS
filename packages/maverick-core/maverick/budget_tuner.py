"""Self-tuning budgets.

``Budget.max_dollars`` defaults to a hand-picked constant. That is either too
loose (a runaway burns the whole cap before anyone notices) or too tight (a
normal goal trips the ceiling and stalls). This learns the default from what
goals *actually* cost: take the per-goal spend distribution from the world
model and recommend a cap at a high percentile plus a margin — so the common
case fits comfortably while a genuine runaway still trips it.

"Per-task-class" is an injected ``classify(goal) -> str`` (role, tag, domain,
…); with none, it learns one global default. Pure, deterministic, offline:
the recommendation math takes plain cost lists, so it is tested without a DB,
and the world integration only reads. Nothing is auto-applied — ``maverick
budget tune`` prints the recommendation for the operator to set.
"""
from __future__ import annotations

from collections import defaultdict

DEFAULT_PERCENTILE = 90.0
DEFAULT_MARGIN = 1.25      # headroom over the percentile
DEFAULT_FLOOR = 0.50       # never recommend below this
DEFAULT_MIN_SAMPLES = 5    # need this many goals before trusting a class


def percentile(values: list[float], p: float) -> float:
    """Linear-interpolated ``p``-th percentile of ``values`` (0 <= p <= 100)."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return float(s[0])
    p = max(0.0, min(100.0, p))
    rank = (p / 100.0) * (len(s) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(s) - 1)
    frac = rank - lo
    return float(s[lo] + (s[hi] - s[lo]) * frac)


def recommend(costs: list[float], *, pct: float = DEFAULT_PERCENTILE,
              margin: float = DEFAULT_MARGIN, floor: float = DEFAULT_FLOOR,
              ceiling: float | None = None) -> float:
    """Recommend a ``max_dollars`` from a per-goal cost sample.

    ``pct``-th percentile × ``margin``, floored (and optionally capped). With no
    data, returns ``floor`` — a conservative default, not zero.
    """
    if not costs:
        return round(floor, 2)
    base = percentile([max(0.0, float(c)) for c in costs], pct)
    rec = max(floor, base * margin)
    if ceiling is not None:
        rec = min(rec, ceiling)
    return round(rec, 2)


def goal_costs(world, *, limit: int = 2000) -> dict[int, float]:
    """Total spend per goal (sum of its episodes' ``cost_dollars``)."""
    from .world_model import episodes_by_goal_batch

    out: dict[int, float] = {}
    goals = list(world.list_goals(limit=limit))
    batch = episodes_by_goal_batch(world, [g.id for g in goals], per_goal=limit)
    for g in goals:
        total = 0.0
        for e in (batch[g.id] if batch is not None and g.id in batch
                  else world.list_episodes(goal_id=g.id, limit=limit)):
            total += float(getattr(e, "cost_dollars", 0.0) or 0.0)
        if total > 0:
            out[g.id] = total
    return out


def recommend_for_world(world, *, classify=None, pct: float = DEFAULT_PERCENTILE,
                        margin: float = DEFAULT_MARGIN,
                        min_samples: int = DEFAULT_MIN_SAMPLES,
                        limit: int = 2000) -> dict[str, dict]:
    """Per-class budget recommendations learned from the world model.

    ``classify(goal) -> str`` keys the task classes (default: one ``"default"``
    class). A class with fewer than ``min_samples`` priced goals is omitted —
    too little data to trust. Returns ``{class: {recommended_max_dollars,
    samples, p<pct>}}``.
    """
    classify = classify or (lambda _g: "default")
    by_id = goal_costs(world, limit=limit)
    buckets: dict[str, list[float]] = defaultdict(list)
    goals = {g.id: g for g in world.list_goals(limit=limit)}
    for gid, cost in by_id.items():
        g = goals.get(gid)
        if g is not None:
            buckets[str(classify(g))].append(cost)
    out: dict[str, dict] = {}
    for cls, costs in buckets.items():
        if len(costs) < min_samples:
            continue
        out[cls] = {
            "recommended_max_dollars": recommend(costs, pct=pct, margin=margin),
            "samples": len(costs),
            f"p{int(pct)}": round(percentile(costs, pct), 2),
        }
    return out


__all__ = ["percentile", "recommend", "goal_costs", "recommend_for_world"]
