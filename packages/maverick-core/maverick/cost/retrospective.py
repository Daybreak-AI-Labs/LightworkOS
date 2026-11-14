"""Cost retrospective.

A spend total tells you *how much*; a retrospective tells you *where it went
and what to do about it*. This reads the world model's per-goal/episode spend
and produces a structured review: the costliest goals, how much went to
**failed** work (spend with nothing to show), how concentrated spend is (a few
goals dominating), and rule-based observations an operator can act on.

Deterministic and offline — every number is an aggregation over the recorded
episodes, so it is tested against a seeded world with no model in the loop.
``maverick cost-retro`` prints it. (A model-narrated summary can sit on top
of this structured core, but the core is what's trustworthy.)
"""
from __future__ import annotations

# Episode outcomes that mean "the work did not succeed", so their spend is
# effort with no delivered result. The orchestrator writes ``failure`` and
# ``blocked``; the other spellings are kept for older and external rows.
# ``interrupted`` is left out: it also marks review checkpoints and waits for
# the user, after which the goal may still succeed.
_FAILURE_OUTCOMES = frozenset({"failure", "blocked", "failed", "error",
                               "aborted", "cancelled", "killed", "timeout",
                               "budget_exceeded"})


def _goal_rows(world, *, limit: int) -> list[dict]:
    from ..world_model import episodes_by_goal_batch

    rows: list[dict] = []
    goals = list(world.list_goals(limit=limit))
    batch = episodes_by_goal_batch(world, [g.id for g in goals], per_goal=limit)
    for g in goals:
        eps = (batch[g.id] if batch is not None and g.id in batch
               else world.list_episodes(goal_id=g.id, limit=limit))
        cost = sum(float(getattr(e, "cost_dollars", 0.0) or 0.0) for e in eps)
        if cost <= 0:
            continue
        outcomes = [(getattr(e, "outcome", None) or "") for e in eps]
        failed = any(o in _FAILURE_OUTCOMES for o in outcomes)
        rows.append({
            "goal_id": g.id,
            "title": (getattr(g, "title", "") or "")[:80],
            "cost": round(cost, 4),
            "episodes": len(eps),
            "status": getattr(g, "status", None),
            "failed": failed,
        })
    rows.sort(key=lambda r: r["cost"], reverse=True)
    return rows


def _concentration(costs: list[float], *, top_frac: float = 0.1) -> float:
    """Share of total spend held by the costliest ``top_frac`` of goals
    (a Pareto signal; 1.0 == all spend in that slice)."""
    if not costs:
        return 0.0
    s = sorted(costs, reverse=True)
    k = max(1, int(len(s) * top_frac))
    return round(sum(s[:k]) / sum(s), 4) if sum(s) else 0.0


def _observations(total: float, failed_cost: float, rows: list[dict]) -> list[str]:
    obs: list[str] = []
    if total <= 0:
        return ["no priced goals yet — nothing to review."]
    if failed_cost > 0:
        share = failed_cost / total
        obs.append(
            f"${failed_cost:.2f} ({share:.0%} of spend) went to goals with a "
            f"failed episode — effort with no delivered result.")
    if rows:
        top = rows[0]
        top_share = top["cost"] / total
        if top_share >= 0.25:
            obs.append(
                f"goal #{top['goal_id']} alone is {top_share:.0%} of all spend "
                f"(${top['cost']:.2f}) — worth a closer look.")
    conc = _concentration([r["cost"] for r in rows])
    if conc >= 0.8 and len(rows) >= 5:
        obs.append(
            f"spend is concentrated: the costliest 10% of goals hold {conc:.0%} "
            "of it.")
    if not obs:
        obs.append("spend looks evenly distributed with no failed-work hotspot.")
    return obs


def retrospective(world, *, top_n: int = 10, limit: int = 2000) -> dict:
    """Structured cost retrospective over the world model's recorded spend."""
    rows = _goal_rows(world, limit=limit)
    total = round(sum(r["cost"] for r in rows), 4)
    failed_cost = round(sum(r["cost"] for r in rows if r["failed"]), 4)
    return {
        "total_spend": total,
        "priced_goals": len(rows),
        "failed_spend": failed_cost,
        "failed_share": round(failed_cost / total, 4) if total else 0.0,
        "top_concentration": _concentration([r["cost"] for r in rows]),
        "top_goals": rows[:max(0, top_n)],
        "observations": _observations(total, failed_cost, rows),
    }


__all__ = ["retrospective"]
