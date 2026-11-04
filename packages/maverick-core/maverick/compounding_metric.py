"""The compounding metric -- does the workforce get cheaper and better with use?

A stateless agent runs the same task at the same cost forever; with Lightwork,
per task class, runs should get cheaper and more reliable as skills/reflexions/
learned policy accumulate.
This module computes that as a *live* signal from the world model: for each task
class, compare the earliest runs ("cold") against the most recent ("warm") and
report the cost delta and success-rate delta.

Pure and deterministic: the core works on a list of ``(task_class, cost,
success, ts)`` rows so it is trivially testable; ``from_world`` adapts the world
model. Read-only -- no gating needed, it only reports. ``improving`` is True when
warm runs are cheaper AND no less reliable than cold runs.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Row:
    task_class: str
    cost: float
    success: bool
    ts: float


@dataclass(frozen=True)
class CompoundingReport:
    task_class: str
    runs: int
    cold_cost: float
    warm_cost: float
    cold_success: float
    warm_success: float

    @property
    def cost_delta_pct(self) -> float:
        """Negative = warm is cheaper (good). 0 when cold cost is unknown."""
        if self.cold_cost <= 0:
            return 0.0
        return round((self.warm_cost - self.cold_cost) / self.cold_cost * 100.0, 1)

    @property
    def success_delta(self) -> float:
        return round(self.warm_success - self.cold_success, 3)

    @property
    def improving(self) -> bool:
        # Cheaper AND not less reliable -- the compounding claim.
        return self.warm_cost < self.cold_cost and self.warm_success >= self.cold_success - 1e-9

    def to_dict(self) -> dict:
        return {
            "task_class": self.task_class, "runs": self.runs,
            "cold_cost": round(self.cold_cost, 4), "warm_cost": round(self.warm_cost, 4),
            "cost_delta_pct": self.cost_delta_pct,
            "cold_success": round(self.cold_success, 3), "warm_success": round(self.warm_success, 3),
            "success_delta": self.success_delta, "improving": self.improving,
        }


def _avg(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def compute(rows: Iterable[Row], *, window: int = 5, min_runs: int = 4) -> list[CompoundingReport]:
    """Per task class, compare the first ``window`` runs against the last ``window``.

    Classes with fewer than ``min_runs`` are skipped (too little signal). Within
    a class, rows are ordered by ``ts`` so "cold" is genuinely the early runs.
    """
    by_class: dict[str, list[Row]] = {}
    for r in rows:
        if not r.task_class:
            continue
        by_class.setdefault(r.task_class, []).append(r)

    reports: list[CompoundingReport] = []
    for cls, items in by_class.items():
        if len(items) < min_runs:
            continue
        items.sort(key=lambda r: r.ts)
        w = min(window, len(items) // 2)
        cold, warm = items[:w], items[-w:]
        reports.append(CompoundingReport(
            task_class=cls, runs=len(items),
            cold_cost=_avg([r.cost for r in cold]),
            warm_cost=_avg([r.cost for r in warm]),
            cold_success=_avg([1.0 if r.success else 0.0 for r in cold]),
            warm_success=_avg([1.0 if r.success else 0.0 for r in warm]),
        ))
    reports.sort(key=lambda rep: rep.task_class)
    return reports


_SUCCESS_OUTCOMES = {"done", "success", "completed"}


def rows_from_world(world, *, classify: Callable[[object], str] | None = None,
                    limit: int = 2000) -> list[Row]:
    """Adapt world-model goals+episodes into compounding rows. Fail-open to []."""
    rows: list[Row] = []
    try:
        goals = world.list_goals(limit=limit)
    except Exception:  # pragma: no cover -- read-only, never block
        return rows
    from .world_model import episodes_by_goal_batch

    # The newest 50 runs per goal (list_episodes' default), read in one batch.
    batch = episodes_by_goal_batch(world, [g.id for g in goals], per_goal=50)
    for goal in goals:
        try:
            cls = classify(goal) if classify else _default_class(goal)
            episodes = (batch[goal.id] if batch is not None and goal.id in batch
                        else world.list_episodes(goal_id=goal.id))
            for ep in episodes:
                cost = float(getattr(ep, "cost_dollars", 0.0) or 0.0)
                outcome = str(getattr(ep, "outcome", "") or "").lower()
                ts = float(getattr(ep, "started_at", 0.0) or 0.0)
                rows.append(Row(task_class=cls, cost=cost,
                                success=outcome in _SUCCESS_OUTCOMES, ts=ts))
        except Exception:  # pragma: no cover
            continue
    return rows


def _default_class(goal) -> str:
    """Coarse class key: leading verb of the title (+ domain when present)."""
    title = str(getattr(goal, "title", "") or "").strip().lower()
    verb = title.split()[0] if title else "task"
    domain = str(getattr(goal, "domain", "") or "").strip().lower()
    return f"{domain}:{verb}" if domain else verb


def report_from_world(world, *, classify: Callable[[object], str] | None = None,
                      window: int = 5, min_runs: int = 4) -> list[CompoundingReport]:
    return compute(rows_from_world(world, classify=classify), window=window, min_runs=min_runs)


__all__ = [
    "Row", "CompoundingReport", "compute",
    "rows_from_world", "report_from_world",
]
