"""The Cognitive Data Engine -- outcome-pattern triage (the crank's first stage).

The Tesla autopilot data engine, reborn for a governed AI workforce: production
failures become evidence-prioritised, simulation-reviewed, governance-gated
improvements. This module is the crank's first stage -- turn the raw governed
trajectory corpus into a RANKED queue of failure classes, ordered by how much
fixing each would lift *real outcomes*.

The whole value of a data engine is **triage**: you can't fix everything, so you
fix the failure that moves reality most. The naive move -- rank by frequency --
is a trap (the most common failure is often harmless noise). So this ranks by
an observed outcome gap within recorded context groups. Such a gap is a
hypothesis, not proof of causation: unrecorded task difficulty may explain it.
Each class carries failing exemplars for downstream review.

Pure + dependency-free + ON by default (reads only the governed trajectory store;
``triage`` on an empty corpus returns ``[]``). The later crank stages
(fix-mining, sim-validation, promotion, real-outcome measurement) build on this.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import promotion_effect as pe
from .config import governed_learning_env_flag


@dataclass(frozen=True)
class FailureClass:
    """An observed harmful-looking action pattern, ranked for review."""

    action: str                 # the tool/action that characterises the class
    count: int                  # failing episodes (outcome < threshold) using it
    mean_outcome: float         # mean terminal outcome of episodes using it
    causal_effect: float        # legacy field name: stratified association, not proof
    ci_low: float
    ci_high: float
    trustworthy: bool           # controlled evidence cleared the calibration bar
    exemplars: tuple = field(default_factory=tuple)  # (goal_id, episode_id) for fix-mining


def enabled() -> bool:
    """Whether the default-on data engine may run."""
    _v = governed_learning_env_flag("MAVERICK_DATA_ENGINE")
    if _v is not None:
        return _v
    try:
        from .config import get_data_engine

        return bool(get_data_engine().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def _terminal_outcome(ep) -> float | None:
    """The episode's real outcome: the terminal ``outcome`` (the verifier's
    confidence in the final answer), else the final step's verifier_confidence."""
    for s in reversed(ep):
        if getattr(s, "outcome", None) is not None:
            return float(s.outcome)
        if s.is_final and getattr(s, "verifier_confidence", None) is not None:
            return float(s.verifier_confidence)
    return None


def _episode_role(ep) -> str:
    return next((s.role for s in ep if s.role), "")


def triage(steps, *, failure_threshold: float = 0.5, min_support: int = 8,
           top_k: int = 10, outcome_fn=None) -> list[FailureClass]:
    """Rank candidate actions by observed outcome gaps within recorded contexts.

    For each distinct tool, estimate the confounder-adjusted effect of using it on
    the episode outcome (treatment = episode used the tool, stratum = domain).
    Classes with a negative association are ranked by their upper confidence
    bound, with controlled evidence ahead of observational hypotheses.

    ``outcome_fn`` (default ``_terminal_outcome``) maps an episode to its outcome;
    the flywheel injects a *grounded* one that prefers real consequences over the
    verifier proxy, so triage learns from what actually happened.
    """
    steps = list(steps)
    if not steps:
        return []
    outcome_fn = outcome_fn or _terminal_outcome

    # Group once so we can attach counts + exemplars without re-scanning per tool.
    episodes: dict = {}
    for s in steps:
        episodes.setdefault((s.goal_id, s.episode_id), []).append(s)
    ordered = {k: sorted(v, key=lambda s: s.step) for k, v in episodes.items()}

    tools = {s.tool for s in steps if s.tool}
    out: list[FailureClass] = []
    for tool in tools:
        units = pe.units_from_trajectories(
            steps,
            treatment_fn=lambda ep, t=tool: 1 if any(s.tool == t for s in ep) else 0,
            outcome_fn=outcome_fn,
            stratum_fn=lambda ep: (ep[0].domain,),
        )
        est = pe.estimate_effect(units, adjusted_for=("domain",), min_used=min_support)
        if est.effect >= 0:
            continue  # no negative observed association

        used, fail_outcomes, exemplars = 0, [], []
        for key, ep in ordered.items():
            if not any(s.tool == tool for s in ep):
                continue
            y = outcome_fn(ep)
            if y is None:
                continue
            used += 1
            fail_outcomes.append(y)
            if y < failure_threshold:
                exemplars.append(key)
        mean_outcome = sum(fail_outcomes) / len(fail_outcomes) if fail_outcomes else 0.0
        out.append(FailureClass(
            action=tool, count=sum(1 for y in fail_outcomes if y < failure_threshold),
            mean_outcome=mean_outcome, causal_effect=est.effect,
            ci_low=est.ci_low, ci_high=est.ci_high, trustworthy=est.trustworthy,
            exemplars=tuple(exemplars[:20]),
        ))

    # Most confidently harmful first; trustworthy estimates outrank shaky ones.
    out.sort(key=lambda c: (not c.trustworthy, c.ci_high))
    return out[:top_k]


__all__ = ["FailureClass", "enabled", "triage"]
