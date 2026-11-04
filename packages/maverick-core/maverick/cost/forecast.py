"""Forecast a goal's cost from similar past runs (``maverick start --dry-cost``).

A cheap, dependency-free estimate: look at the cost of past priced runs, prefer
ones whose goal text overlaps the new goal (lexical Jaccard — no embeddings
needed), and report a weighted estimate plus the observed range. Falls back to a
recent-average when nothing is similar, and to "no history" when there's nothing
priced yet. Pure ``forecast()`` is unit-tested; ``gather_samples()`` adapts a
world model into its input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_WORD = re.compile(r"\w+")


@dataclass
class CostForecast:
    estimate_dollars: float
    low_dollars: float
    high_dollars: float
    n_samples: int
    basis: str  # "similar" | "recent" | "none"


def _tokens(s: str) -> set[str]:
    return set(_WORD.findall((s or "").lower()))


def _similarity(a: str, b: str) -> float:
    """Jaccard overlap of word sets — 0.0 when either side is empty."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def forecast(
    samples: list[tuple[str, float]], goal_text: str, *, k: int = 8
) -> CostForecast:
    """Estimate cost for ``goal_text`` from ``samples`` of ``(past_title, cost)``.

    ``samples`` should be newest-first (so the recent-average fallback uses recent
    runs). Zero/negative costs are ignored. Prefers runs whose title overlaps the
    new goal, weighting each by its similarity; with no overlap anywhere, averages
    the most recent ``k`` priced runs.
    """
    priced = [(t, c) for (t, c) in samples if isinstance(c, (int, float)) and c > 0]
    if not priced:
        return CostForecast(0.0, 0.0, 0.0, 0, "none")
    scored = [(_similarity(goal_text, t), c) for (t, c) in priced]
    similar = sorted((sc for sc in scored if sc[0] > 0), key=lambda x: -x[0])[:k]
    if similar:
        wsum = sum(s for s, _ in similar)
        est = sum(s * c for s, c in similar) / wsum if wsum else 0.0
        costs = [c for _, c in similar]
        basis = "similar"
    else:
        costs = [c for _, c in priced][:k]  # newest-first -> most recent k
        est = sum(costs) / len(costs)
        basis = "recent"
    return CostForecast(
        estimate_dollars=round(est, 4),
        low_dollars=round(min(costs), 4),
        high_dollars=round(max(costs), 4),
        n_samples=len(costs),
        basis=basis,
    )


def gather_samples(world, *, limit: int = 200) -> list[tuple[str, float]]:
    """Build ``(goal_title, cost_dollars)`` pairs from a world model's recent
    priced episodes (newest-first). Duck-typed: needs ``list_episodes(limit=...)``
    yielding objects with ``goal_id`` + ``cost_dollars``, and ``get_goal(id)``."""
    out: list[tuple[str, float]] = []
    titles: dict[int, str] = {}
    for ep in world.list_episodes(limit=limit):
        cost = getattr(ep, "cost_dollars", 0) or 0
        if cost <= 0:
            continue
        gid = getattr(ep, "goal_id", None)
        if gid not in titles:
            g = world.get_goal(gid) if gid is not None else None
            titles[gid] = getattr(g, "title", "") if g else ""
        out.append((titles[gid], float(cost)))
    return out


def render(fc: CostForecast) -> str:
    """One-line human summary for the CLI."""
    if fc.n_samples == 0:
        return ("No priced run history yet — can't forecast a cost. "
                "Run a few goals first, then --dry-cost will estimate from them.")
    return (
        f"Estimated cost: ${fc.estimate_dollars:.4f}  "
        f"(range ${fc.low_dollars:.4f}–${fc.high_dollars:.4f}, "
        f"from {fc.n_samples} {fc.basis} past run(s))"
    )


__all__ = ["CostForecast", "forecast", "gather_samples", "render"]
