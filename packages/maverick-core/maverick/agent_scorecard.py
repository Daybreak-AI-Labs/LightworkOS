"""Read-only specialist activity with human acceptance kept separate from runs.

A finished episode is neither an accepted deliverable nor measured customer
value. Only a current approved goal sign-off counts as delivered. Dollar value
stays unknown unless a caller supplies an explicit comparison assumption.
"""
from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

_DONE = {"done", "succeeded", "success", "completed", "fulfilled", "approved"}
# Historical assumption, retained for callers that explicitly opt into it.
# The job card does not use this as a default or claim it is customer value.
DEFAULT_HUMAN_COST_PER_DELIVERABLE = 120.0


def _is_done(outcome: str | None) -> bool:
    return (outcome or "").strip().lower() in _DONE


def _comparison(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


@dataclass
class AgentScore:
    """One specialist's management scorecard over the window."""

    agent: str
    suite: str = ""
    runs: int = 0
    completed: int = 0
    reviewed: int = 0
    delivered: int = 0
    cost: float = 0.0
    tokens: int = 0
    last_active: float = 0.0
    human_cost_per_deliverable: float | None = None

    @property
    def value(self) -> float | None:
        """An explicit comparison assumption, never measured customer value."""
        if self.human_cost_per_deliverable is None:
            return None
        return self.delivered * self.human_cost_per_deliverable

    @property
    def cost_avoided(self) -> float | None:
        return self.value - self.cost if self.value is not None else None

    @property
    def roi_multiple(self) -> float | None:
        return round(self.value / self.cost, 1) if self.value is not None and self.cost > 0 else None

    @property
    def cost_per_delivered(self) -> float | None:
        return round(self.cost / self.delivered, 4) if self.delivered else None

    @property
    def approval_rate(self) -> float | None:
        return round(100.0 * self.delivered / self.reviewed, 1) if self.reviewed else None

    def to_dict(self) -> dict:
        return {
            "agent": self.agent, "suite": self.suite,
            "runs": self.runs, "completed": self.completed,
            "reviewed": self.reviewed, "delivered": self.delivered,
            "cost": round(self.cost, 4), "tokens": self.tokens,
            "value": round(self.value, 2) if self.value is not None else None,
            "cost_avoided": round(self.cost_avoided, 2) if self.cost_avoided is not None else None,
            "roi_multiple": self.roi_multiple,
            "cost_per_delivered": self.cost_per_delivered,
            "success_rate": None,
            "approval_rate": self.approval_rate,
            "approval_rate_basis": "approved_reviews_over_all_reviews" if self.reviewed else None,
            "value_basis": self.human_cost_per_deliverable,
            "last_active": self.last_active or None,
        }


def _domain_of(world: Any, goal_id: int, cache: dict[int, str]) -> str:
    if goal_id in cache:
        return cache[goal_id]
    dept = ""
    try:
        g = world.get_goal(goal_id)
        dept = (getattr(g, "domain", "") or "") if g else ""
    except Exception:  # pragma: no cover -- a read miss is just "(unattributed)"
        dept = ""
    cache[goal_id] = dept or "(unattributed)"
    return cache[goal_id]


def compute(
    world: Any, *, window_days: int = 90,
    human_cost: float | None = None, human_cost_for: Any = None,
    episode_limit: int = 5000, now: float | None = None,
) -> list[AgentScore]:
    """Per-agent scorecards over ``window_days``, most goals delivered first
    (ties: most recently active first).

    ``human_cost`` overrides the flat baseline; ``human_cost_for(agent)`` is an
    optional per-agent override (e.g. a legal specialist's hour priced above
    support). Never raises."""
    ts_now = now if now is not None else time.time()
    cutoff = ts_now - window_days * 86400.0
    base_hc = None if human_cost is None else _comparison(human_cost)

    def _hc(agent: str) -> float | None:
        if human_cost_for is None:
            return base_hc
        try:
            value = human_cost_for(agent)
            checked = _comparison(value)
            return checked if checked is not None else base_hc
        except Exception:  # pragma: no cover -- a bad override never breaks it
            return base_hc

    try:
        episodes = world.list_episodes(limit=episode_limit)
    except Exception as e:  # pragma: no cover -- report never blocks
        log.debug("agent_scorecard: episode read failed: %s", e)
        return []

    scores: dict[str, AgentScore] = {}
    cache: dict[int, str] = {}
    reviewed_goals: set[int] = set()
    for ep in episodes:
        started = float(getattr(ep, "started_at", 0) or 0)
        if started < cutoff:
            continue
        goal_id = int(getattr(ep, "goal_id", 0) or 0)
        agent = _domain_of(world, goal_id, cache)
        sc = scores.get(agent)
        if sc is None:
            sc = scores[agent] = AgentScore(
                agent=agent, human_cost_per_deliverable=_hc(agent))
        sc.runs += 1
        sc.cost += float(getattr(ep, "cost_dollars", 0) or 0)
        sc.tokens += (int(getattr(ep, "input_tokens", 0) or 0)
                      + int(getattr(ep, "output_tokens", 0) or 0))
        if _is_done(getattr(ep, "outcome", None)):
            sc.completed += 1
            if goal_id not in reviewed_goals:
                reviewed_goals.add(goal_id)
                try:
                    goal = world.get_goal(goal_id)
                    signoff = world.signoff_for(goal_id)
                    decision = signoff.get("decision") if isinstance(signoff, dict) else None
                    if getattr(goal, "status", None) == "done" and decision in {"approved", "rejected"}:
                        sc.reviewed += 1
                        if decision == "approved":
                            sc.delivered += 1
                except Exception:  # pragma: no cover -- unavailable evidence is unknown
                    pass
        sc.last_active = max(sc.last_active, started)

    # Stamp the suite so the manager view can group by department.
    try:
        from .domain import suite_for
        for agent, sc in scores.items():
            if agent != "(unattributed)":
                sc.suite = suite_for(agent) or ""
    except Exception:  # pragma: no cover -- suite lookup is cosmetic
        pass

    return sorted(scores.values(), key=lambda s: (-s.delivered, -s.last_active))


def for_agent(world: Any, agent: str, **kwargs: Any) -> AgentScore:
    """One specialist's scorecard (empty if it hasn't run in the window)."""
    for sc in compute(world, **kwargs):
        if sc.agent == agent:
            return sc
    hc = kwargs.get("human_cost")
    return AgentScore(agent=agent, human_cost_per_deliverable=(None if hc is None else _comparison(hc)))


__all__ = ["AgentScore", "compute", "for_agent",
           "DEFAULT_HUMAN_COST_PER_DELIVERABLE"]
