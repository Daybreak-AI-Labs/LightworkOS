"""Speculative agent execution -- draft cheap, escalate to the frontier only when
it matters.

Speculative decoding, lifted to the agent's *turn*. When the Operating Twin's
world-model is highly confident about what happens next in the current context --
because the agent has been here many times and the trajectory is near-determi-
nistic -- the turn is *speculatable* and can be drafted by a cheap model,
reserving the expensive frontier model for the novel / uncertain turns where
deliberation actually pays. On repetitive enterprise workflows (the common case)
most turns are predictable, so this is a real cost/latency win; on anything the
model hasn't pinned down, nothing changes -- the frontier model runs as today.

Two layers, like ``rehearsal`` / ``rehearsal_runtime``:
  * the **pure decision core** (:func:`predict`, :func:`accepted`) -- from a
    fitted world-model + the current state, predict the most-likely next action
    and decide whether the turn clears the speculation bar (a dominant action
    with enough support). Deliberately conservative: novelty *and* ambiguity both
    fall through to the frontier model.
  * the **live glue** (:func:`draft_model_for_turn`) -- reuse the rehearsal
    runtime's cached world-model + the ``[speculative]`` config to return the
    operator-configured cheap draft model for a speculatable turn, else ``None``.

Posture (kernel rule 1): OFF by default, fail-open. With ``[speculative]``
disabled, no configured draft model, no world-model, or any error,
``draft_model_for_turn`` returns ``None`` and the agent uses its normal model --
behaviour is byte-identical to today. No model is ever hard-coded; the draft
model is whatever the operator configures (``[speculative] draft_model``).

NOTE: this is the *draft* half only (downshift on confident turns). There is
no verify-and-rollback that re-runs a turn on the frontier model when the cheap
draft's action diverges from the prediction (:func:`accepted` is the hook for
one); the strict confidence gate keeps the downshift conservative.
"""
from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass

from .config import env_flag

# --- pure decision core ----------------------------------------------------


@dataclass(frozen=True)
class TurnSpeculation:
    """The world-model's next-action prediction and whether to draft this turn."""

    action: Hashable | None   # most-likely next action (None if no support)
    confidence: float         # its share of the behaviour-policy mass in this state
    support: int              # observations of this state
    speculatable: bool        # clears the bar -> a cheap draft is safe to try
    reason: str = ""


def predict(model, state, *, min_confidence: float = 0.85, min_support: int = 8) -> TurnSpeculation:
    """Predict the next action and decide if the turn is speculatable.

    Speculatable iff one action dominates the behaviour policy in this state
    (``confidence >= min_confidence``) with enough observations
    (``support >= min_support``). Both novelty (no/low support) and ambiguity
    (no dominant action) fall through to the frontier model.
    """
    pol = model.policy(state)
    if not pol:
        return TurnSpeculation(None, 0.0, 0, False, "no behaviour-policy support for this state")
    total = sum(pol.values())
    action, count = max(pol.items(), key=lambda kv: kv[1])
    confidence = count / total if total else 0.0
    speculatable = total >= min_support and confidence >= min_confidence
    reason = ("speculatable" if speculatable
              else f"not confident enough (confidence={confidence:.2f}, support={total})")
    return TurnSpeculation(action, confidence, total, speculatable, reason)


def accepted(spec: TurnSpeculation, actual_action: Hashable) -> bool:
    """Whether the drafted turn's chosen action matched the prediction.

    The verification signal and the hook for a future verify-and-rollback: a high
    accept rate means the gate is well-calibrated; a low one means the cheap model
    is being trusted where it shouldn't.
    """
    return spec.action is not None and actual_action == spec.action


# --- live glue (config + world-model) --------------------------------------

_DEFAULTS = {"enable": False, "draft_model": None, "min_confidence": 0.85, "min_support": 8}


def _settings() -> dict:
    try:
        from .config import get_speculative

        return get_speculative()
    except Exception:  # pragma: no cover -- config never blocks a run
        return dict(_DEFAULTS)


def enabled() -> bool:
    """Whether speculative drafting may downshift a turn. OFF by default."""
    _v = env_flag("MAVERICK_SPECULATIVE")
    if _v is not None:
        return _v
    return bool(_settings().get("enable", False))


def draft_model_for_turn(domain, role, last_tool) -> str | None:
    """The cheap draft model spec to use THIS turn, or ``None`` for the normal
    (frontier) model.

    ``None`` unless speculation is enabled, a draft model is configured, a
    world-model exists, and the turn is speculatable. Reuses the rehearsal
    runtime's cached world-model so the two share one Operating-Record model.
    """
    if not enabled():
        return None
    s = _settings()
    draft = s.get("draft_model")
    if not draft:
        return None
    try:
        from .rehearsal_runtime import encode_state, world_model

        model = world_model()
        if model is None:
            return None
        spec = predict(model, encode_state(domain, role, last_tool),
                       min_confidence=float(s.get("min_confidence", 0.85)),
                       min_support=int(s.get("min_support", 8)))
        return draft if spec.speculatable else None
    except Exception:  # pragma: no cover -- must never break the loop
        return None


__all__ = ["TurnSpeculation", "predict", "accepted", "enabled", "draft_model_for_turn"]
