"""Unified autonomy gate: one decision over the run's live trust signals.

This is the servo that ties Karpathy's "autonomy slider" to the evaluator:
how far a sub-loop may run unattended is a function of how well its work can
be *verified*, not a static setting. It reads the signals the kernel already
produces -- swarm disagreement entropy (``disagreement.answer_entropy``,
stamped on the context by ``spawn_swarm``) and the verifier's confidence --
and acts on them:

  1. **Escalate verification when the swarm disagrees (Loop 1).** High
     disagreement is exactly the case where the chosen branch most needs an
     independent, lockstep-resistant check, so the FINAL is verified by the
     cross-family ensemble instead of a single judge. This also raises the
     *label* quality on precisely the trajectories the data engine is most
     likely to learn from (``donation.should_donate`` keys on disagreement).

  2. **Tighten the effective risk ceiling when trust is low (Loop 2).** When
     the swarm couldn't agree (or a verifier returned low confidence), drop
     the risk ceiling so an unresolved disagreement can't drive an
     irreversible (high-risk) action unattended -- the agent must resolve the
     disagreement or get a human (``ask_user``) first.

Off by default (kernel rule 1: the kernel runs unchanged out of the box).
Turn it on with ``[autonomy] enable = true`` or ``MAVERICK_AUTONOMY_GATE=1``.
Fail-open: any error here degrades to "no gating" -- the gate can only make
the system MORE careful, never a new way to crash a run.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from .config import env_flag
from .safety.tool_risk import RISK_LEVELS, risk_rank, tool_risk

log = logging.getLogger(__name__)


# Last-resort defaults, used only when config is unreadable. The live values
# come from ``[autonomy]`` (see ``config.get_autonomy``).
_DEFAULTS = {
    "enable": False,
    "min_confidence": 0.5,
    "disagreement_high": 0.5,
    "escalate_verification": True,
    "tighten_on_low_trust": True,
    "headless_assume": False,
    "confirm_plan": False,
}


def _resolve() -> dict:
    """Resolved ``[autonomy]`` settings with the env master-switch applied.

    ``MAVERICK_AUTONOMY_GATE`` overrides ``[autonomy] enable`` either way so an
    operator can flip the whole gate on/off without editing config. Never
    raises: an unreadable config degrades to the off-by-default settings.
    """
    try:
        from .config import get_autonomy
        s = dict(get_autonomy())
    except Exception:  # pragma: no cover -- config must never block a run
        s = dict(_DEFAULTS)
    env = os.environ.get("MAVERICK_AUTONOMY_GATE", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        s["enable"] = True
    elif env in {"0", "false", "no", "off"}:
        s["enable"] = False
    return s


def confirm_plan_enabled() -> bool:
    """``[autonomy] confirm_plan``: show the plan and wait for a person before
    a task's first action that could reach outside Lightwork. Off by default;
    an unreadable config keeps it off (the pre-existing behaviour)."""
    try:
        return bool(_resolve().get("confirm_plan", False))
    except Exception:  # pragma: no cover -- config must never block a run
        return False


def autonomy_enabled() -> bool:
    """Whether the autonomy gate is active. Off by default."""
    return bool(_resolve()["enable"])


def assume_when_headless() -> bool:
    """Whether a run should ASSUME-AND-PROCEED instead of blocking on
    ``ask_user``.

    When no human is available to answer (headless / batch / benchmark runs),
    stalling forever on a clarification nobody will answer is worse than
    stating a reasonable assumption and continuing -- and a blocked run never
    reaches FINAL, so it also never distills what it learned. This is a
    distinct axis from the verification gate, so it is resolved independently
    of ``enable``: ``MAVERICK_AUTONOMOUS`` overrides ``[autonomy]
    headless_assume`` either way. Off by default; never raises (an unreadable
    config degrades to "block", the safe pre-existing behavior)."""
    _v = env_flag("MAVERICK_AUTONOMOUS")
    if _v is not None:
        return _v
    try:
        return bool(_resolve().get("headless_assume", False))
    except Exception:  # pragma: no cover -- config must never block a run
        return False


@dataclass
class AutonomyVerdict:
    """The gate's decision for one high-risk action.

    ``allowed`` False means the action was gated (not executed). ``reason`` is
    a non-leaky, agent-facing explanation. ``effective_max_risk`` is the
    tightened ceiling that produced the decision (for the audit trail).
    """
    allowed: bool
    reason: str = ""
    effective_max_risk: str | None = None
    tightened: bool = False


def should_escalate_verification(disagreement: float) -> bool:
    """Loop 1: escalate FINAL verification to the ensemble on high disagreement.

    Returns False when the gate is off or escalation is disabled, so callers
    can branch on this unconditionally.
    """
    s = _resolve()
    if not s["enable"] or not s["escalate_verification"]:
        return False
    return float(disagreement or 0.0) >= float(s["disagreement_high"])


def tighten_ceiling(
    configured_max_risk: str | None,
    *,
    disagreement: float,
    verifier_confidence: float,
    settings: dict | None = None,
) -> str | None:
    """Loop 2: the (possibly tighter) risk ceiling given live trust signals.

    Each independent low-trust condition -- high disagreement, low verifier
    confidence -- drops the ceiling one rank (``high -> medium -> low``); both
    together drop two. ``configured_max_risk`` (the operator/capability
    ceiling, ``None`` == no cap) is the starting point, treated as ``high`` on
    the rank scale, so this only ever *narrows* and never broadens an existing
    cap. Returns the configured ceiling unchanged when trust is adequate.
    """
    s = settings if settings is not None else _resolve()
    deficit = 0
    if float(disagreement or 0.0) >= float(s["disagreement_high"]):
        deficit += 1
    if float(verifier_confidence) < float(s["min_confidence"]):
        deficit += 1
    if deficit == 0:
        return configured_max_risk
    base_rank = risk_rank(configured_max_risk) if configured_max_risk else risk_rank("high")
    new_rank = max(0, base_rank - deficit)
    return RISK_LEVELS[new_rank]


def gate_tool(
    tool_name: str,
    *,
    disagreement: float,
    verifier_confidence: float,
    configured_max_risk: str | None = None,
) -> AutonomyVerdict:
    """Loop 3 (unified gate): may ``tool_name`` run given the run's trust state?

    Composes the existing per-tool risk classification with the servo ceiling.
    Low-risk tools are never gated (reading/searching is always allowed); a
    medium/high-risk tool is gated when its risk exceeds the tightened ceiling.
    Always allows when the gate is off, so this is a no-op out of the box.
    """
    s = _resolve()
    if not s["enable"] or not s["tighten_on_low_trust"]:
        return AutonomyVerdict(allowed=True)
    try:
        risk = tool_risk(tool_name)
    except Exception:  # pragma: no cover -- fail-open per module contract
        return AutonomyVerdict(allowed=True)
    if risk_rank(risk) == 0:  # low-risk: never gated
        return AutonomyVerdict(allowed=True)

    effective = tighten_ceiling(
        configured_max_risk,
        disagreement=disagreement,
        verifier_confidence=verifier_confidence,
        settings=s,
    )
    tightened = effective != configured_max_risk
    if effective is None:
        return AutonomyVerdict(allowed=True, tightened=tightened)
    if risk_rank(risk) > risk_rank(effective):
        return AutonomyVerdict(
            allowed=False,
            effective_max_risk=effective,
            tightened=tightened,
            reason=(
                f"{risk!r}-risk action held: run trust is low "
                f"(disagreement={float(disagreement or 0.0):.2f}, "
                f"verifier_confidence={float(verifier_confidence):.2f}), so the "
                f"autonomy ceiling tightened to {effective!r}"
            ),
        )
    return AutonomyVerdict(allowed=True, effective_max_risk=effective, tightened=tightened)


__all__ = [
    "autonomy_enabled",
    "assume_when_headless",
    "AutonomyVerdict",
    "should_escalate_verification",
    "tighten_ceiling",
    "gate_tool",
]
