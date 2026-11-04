"""Cascaded model routing — cheap-first escalation.

The cascade: Haiku draft -> Sonnet if verifier confidence < 0.6 OR
tool-call depth > 3 -> Opus with thinking budget on second-pass failure.

This module is a stateless picker: callers ask for a model spec
for a (role, signal) tuple, get back the best fit for the current
cost/quality budget. Defaults follow the Haiku < Sonnet < Opus price ladder.

The cascade is opt-in; the legacy ``model_for_role`` path remains
the default. Turn it on with ``[models] cascade = true`` or
``MAVERICK_CASCADE_ROUTING=1``. The agent loop then consults
:func:`cascade_draft_model` and :func:`should_escalate` for each turn
(``Agent._speculative_turn_model``): a role with no model of its own starts
on the cheaper ``cascade_draft`` model and moves to its normal model once the
verifier rejects an answer with low confidence or the task goes deeper than
the tool-call threshold. The thresholds are read at call time from
``MAVERICK_ESCALATE_BELOW`` / ``MAVERICK_ESCALATE_TOOL_DEPTH`` (environment
wins) or ``[models] cascade_escalate_below`` /
``cascade_escalate_tool_depth``.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from .llm import MODEL_HAIKU, MODEL_OPUS, MODEL_SONNET

log = logging.getLogger(__name__)


@dataclass
class RouteSignal:
    """Per-call info the router uses to escalate."""
    role: str = ""
    verifier_confidence: float | None = None
    tool_call_depth: int = 0
    prior_attempt: int = 0           # 0 = first try, 1 = retry, etc.
    requires_thinking: bool = False  # caller knows the task needs reasoning


# Cascade thresholds (env-tunable). Import-time values kept for callers that
# read them; the live checks use escalate_below() / escalate_tool_depth().
ESCALATE_VERIFIER_BELOW = float(os.environ.get("MAVERICK_ESCALATE_BELOW", "0.6"))
ESCALATE_TOOL_DEPTH = int(os.environ.get("MAVERICK_ESCALATE_TOOL_DEPTH", "3"))

# Roles that anchor the swarm stay on their own model (pick() gives them Opus).
_ANCHOR_ROLES = frozenset({"orchestrator", "revisor"})
DRAFT_ROLE = "cascade_draft"


def escalate_below() -> float:
    """Verifier confidence under which the cascade escalates (0 to 1)."""
    from .env_setting import env_or_config_float

    value = env_or_config_float("MAVERICK_ESCALATE_BELOW", "models",
                                "cascade_escalate_below", 0.6)
    return min(max(value, 0.0), 1.0)


def escalate_tool_depth() -> int:
    """Tool calls after which the cascade escalates."""
    from .env_setting import env_or_config_int

    return max(0, env_or_config_int("MAVERICK_ESCALATE_TOOL_DEPTH", "models",
                                    "cascade_escalate_tool_depth", 3))


def should_escalate(signal: RouteSignal) -> bool:
    """The kernel's low-confidence signals: a retry, a verifier rejection
    under the threshold, a tool chain past the depth, or a task that needs
    reasoning."""
    if signal.prior_attempt >= 1 or signal.requires_thinking:
        return True
    if (signal.verifier_confidence is not None
            and signal.verifier_confidence < escalate_below()):
        return True
    return signal.tool_call_depth > escalate_tool_depth()


def cascade_draft_model(role: str, model: str) -> str | None:
    """The cheaper model a role's turns start on, or None to keep ``model``.

    None unless the cascade is on, the role is not an anchor role, and nobody
    chose a model for the role (a per-role setting or override always wins).
    """
    if role in _ANCHOR_ROLES or not cascade_enabled():
        return None
    try:
        from .llm import _explicit_model_for_role, model_for_role

        if _explicit_model_for_role(role):
            return None
        draft = model_for_role(DRAFT_ROLE)
    except Exception as exc:  # noqa: BLE001 -- routing never breaks the loop
        log.warning("routing: cascade draft model unavailable (%s)", type(exc).__name__)
        return None
    return draft if draft and draft != model else None


def pick(signal: RouteSignal) -> str:
    """Return the model spec for this signal.

    Decision tree:
      1. If this is a retry/revision (prior_attempt >= 1) OR the
         verifier rejected the previous answer with low confidence,
         escalate to Opus with thinking budget.
      2. If the task naturally needs reasoning (proposer requested
         thinking), use Opus.
      3. If the role is one that anchors the swarm (orchestrator,
         revisor), use Opus.
      4. If the role is a cheap tail (summarizer, skill_distiller),
         use Haiku.
      5. Otherwise, default to Sonnet -- the workhorse.

    All defaults can be overridden via ~/.maverick/config.toml
    `[models]` per-role; this picker is read AFTER the config check
    so user wishes win.
    """
    # User-configured per-role wins.
    try:
        from .config import get_role_model
        user_spec = get_role_model(signal.role)
        if user_spec:
            return user_spec
    except Exception as e:
        # Don't silently discard a user's explicit per-role choice: surface the
        # config error so "user wishes win" doesn't fail quietly to the cascade.
        log.warning("routing: per-role model lookup failed for role %r (%s); "
                    "using the default cascade", signal.role, e)

    # Cascade escalation paths.
    if should_escalate(signal):
        return MODEL_OPUS

    # Role-based defaults.
    role = signal.role
    if role in ("orchestrator", "revisor"):
        return MODEL_OPUS
    if role in ("summarizer", "haiku-tail", "skill_distiller"):
        return MODEL_HAIKU
    if role == "verifier":
        return MODEL_SONNET
    return MODEL_SONNET


def cascade_enabled() -> bool:
    """Single source of truth for whether cascaded routing is active."""
    from .config import env_flag

    env_name = "MAVERICK_CASCADE_ROUTING"
    env = env_flag(env_name)
    if env is not None:
        return env
    if os.environ.get(env_name, "").strip():
        log.warning(
            "routing: %s must be one of 1/0, true/false, yes/no, or on/off; "
            "disabling the cascade",
            env_name,
        )
        return False
    try:
        from .config import load_config
        value = load_config().get("models", {}).get("cascade", False)
        if not isinstance(value, bool):
            log.warning(
                "routing: models.cascade must be true or false, got %s; "
                "disabling the cascade",
                type(value).__name__,
            )
            return False
        return value
    except Exception as exc:
        log.warning(
            "routing: could not read models.cascade (%s); disabling the cascade",
            exc,
        )
        return False
