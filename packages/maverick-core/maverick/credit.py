"""Counterfactual swarm credit assignment (CSCA).

When a swarm produces a synthesized answer, the data engine
(``donation.should_donate``) and routing have no idea *which* sub-agent
actually moved the needle -- so they learn from noise. CSCA fixes that: ablate
each sub-agent's contribution and re-score; the drop in the verifier's score
when agent *k* is removed **is** agent *k*'s marginal credit (a leave-one-out
Shapley estimate, with the cross-family verifier as the value oracle).

This is the novel primitive (counterfactual/Shapley credit for an LLM
multi-agent system, gated by a calibrated verifier). It is dependency-injected
-- the caller supplies an async ``score(subset_of_contributions) -> float`` --
so this module imports nothing heavy and is trivially testable; ``spawn_swarm``
wires it to ``verifier.verify_proposal`` against the goal brief.

The credit engine is ON by default, but its N+1 verifier calls require the
separate ``[self_learning] allow_provider_egress`` authority. The call site
also budget-gates it and caps the swarm size it will attribute. Credit is only trustworthy when the
verifier is calibrated, so the caller skips it when ``calibration`` is frozen.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from .config import governed_learning_env_flag

log = logging.getLogger(__name__)

_DEFAULTS = {"enable": False, "max_children": 6, "min_budget_headroom": 0.4}


def _settings() -> dict:
    try:
        from .config import get_credit
        return get_credit()
    except Exception:  # pragma: no cover -- config never blocks a run
        return dict(_DEFAULTS)


def enabled() -> bool:
    _v = governed_learning_env_flag("MAVERICK_CREDIT")
    if _v is not None:
        return _v
    return bool(_settings()["enable"])


def passes_required(n: int) -> int:
    """Number of score() calls a full LOO attribution of ``n`` agents costs."""
    return 0 if n < 2 else n + 1


async def counterfactual_credit(
    contributions: dict[str, str],
    score: Callable[[list[str]], Awaitable[float]],
) -> dict[str, float]:
    """Leave-one-out marginal credit for each contributor.

    ``contributions`` maps agent name -> its contribution text. ``score`` takes
    a list of contributions and returns a value in roughly [0,1] (e.g. verifier
    confidence that the combined findings answer the goal). Returns name ->
    marginal credit (``full_score - score_without_k``); credit can be **negative**
    (a contributor that made the answer worse). An empty input returns ``{}``; a
    single contributor trivially gets the full score.
    """
    names = list(contributions)
    if not names:
        return {}
    if len(names) == 1:
        return {names[0]: round(await score(list(contributions.values())), 4)}

    full = await score(list(contributions.values()))
    out: dict[str, float] = {}
    for n in names:
        subset = [v for m, v in contributions.items() if m != n]
        without = await score(subset)
        out[n] = round(full - without, 4)
    return out


def normalize_credit(credit: dict[str, float]) -> dict[str, float]:
    """Normalize positive credit into shares summing to 1 (negatives -> 0).

    Useful for weighting which sub-trajectories to learn from. When no
    contributor has positive credit (all neutral/harmful), returns an equal
    split so a degenerate round doesn't divide by zero.
    """
    if not credit:
        return {}
    pos = {k: max(0.0, v) for k, v in credit.items()}
    total = sum(pos.values())
    if total <= 0:
        share = 1.0 / len(credit)
        return {k: round(share, 4) for k in credit}
    return {k: round(v / total, 4) for k, v in pos.items()}


def build_subtrajectories(
    items: list[tuple[str, str, list[str]]],
    credit_map: dict[str, float],
) -> list[dict]:
    """Assemble per-sub-agent trajectories tagged with credit + learn-weight.

    ``items`` is ``(role, name, action_sequence)`` per sub-agent. Each output
    dict carries the role, name, tool-name action sequence (no args -> no
    secrets), the agent's marginal ``credit``, and a normalized ``weight`` (its
    share of the positive credit) so the data engine can learn MORE from the
    sub-trajectories that actually earned the outcome and skip the freeloaders.
    """
    weights = normalize_credit(credit_map)
    out: list[dict] = []
    for role, name, actions in items:
        out.append({
            "role": role,
            "name": name,
            "actions": list(actions or []),
            "credit": round(float(credit_map.get(name, 0.0)), 4),
            "weight": weights.get(name, 0.0),
        })
    return out


__all__ = [
    "enabled",
    "passes_required",
    "counterfactual_credit",
    "normalize_credit",
    "build_subtrajectories",
]
