"""Run health score: a 0–100 summary of a run's quality.

Combines outcome, token efficiency, and tool error/retry penalties into a single
score (+ letter grade + the factor breakdown) for the dashboard / CLI status.
Pure scoring — no I/O — so it's deterministic and unit-tested. The orchestrator
and dashboard call ``compute_health()`` with whatever signals they have; every
field is optional and degrades gracefully.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_ERROR_PENALTY = 8      # per tool error
_RETRY_PENALTY = 3      # per tool retry
_MAX_TOOL_PENALTY = 50  # combined ceiling so a noisy run still scores > 0
_FAIL_BASE = 40         # a failed run starts here, not 100


@dataclass
class Health:
    score: int
    grade: str
    factors: dict = field(default_factory=dict)


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_health(
    *,
    success: bool,
    in_tok: int = 0,
    out_tok: int = 0,
    tool_errors: int = 0,
    tool_retries: int = 0,
    expected_tokens: int | None = None,
) -> Health:
    """Score a run 0–100.

    Base is 100 for a successful run, ``_FAIL_BASE`` for a failure. Tool errors
    and retries subtract (bounded by ``_MAX_TOOL_PENALTY``). When
    ``expected_tokens`` is given, burning materially more than expected costs an
    efficiency penalty up to 15 points (a run under budget is never penalised).
    """
    base = 100 if success else _FAIL_BASE
    factors: dict = {"base": base}

    tool_penalty = min(
        _MAX_TOOL_PENALTY,
        max(0, tool_errors) * _ERROR_PENALTY + max(0, tool_retries) * _RETRY_PENALTY,
    )
    factors["tool_penalty"] = -tool_penalty

    eff_penalty = 0
    used = max(0, int(in_tok or 0)) + max(0, int(out_tok or 0))
    if expected_tokens and expected_tokens > 0 and used > expected_tokens:
        overshoot = (used - expected_tokens) / expected_tokens
        eff_penalty = min(15, round(overshoot * 15))
    factors["efficiency_penalty"] = -eff_penalty
    factors["tokens_used"] = used

    score = max(0, min(100, base - tool_penalty - eff_penalty))
    return Health(score=score, grade=_grade(score), factors=factors)


def goal_health(world, goal_id: int):
    """``(goal, Health)`` for a goal from its recorded runs, or ``None`` when
    the goal does not exist. A goal that finished (``done``) scores as a
    success; tokens come from its most recent 50 runs. Shared by
    ``maverick diag health`` and the task page."""
    goal = world.get_goal(goal_id)
    if goal is None:
        return None
    eps = world.list_episodes(goal_id=goal_id, limit=50)
    in_tok = sum(getattr(e, "input_tokens", 0) for e in eps)
    out_tok = sum(getattr(e, "output_tokens", 0) for e in eps)
    return goal, compute_health(success=goal.status == "done", in_tok=in_tok, out_tok=out_tok)


def render(h: Health) -> str:
    """One-line CLI summary."""
    return f"Run health: {h.score}/100 ({h.grade})"


__all__ = ["Health", "compute_health", "goal_health", "render"]
