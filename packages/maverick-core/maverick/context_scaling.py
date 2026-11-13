"""Model-scaled context sizing.

Fixed context bounds tuned for a ~200k-window model (the last 10 turns at
300 chars each, a 1500-token compaction target, long-context sharding above
a hard 200k, 32 KB tool results, 4096 output tokens per turn) would not
grow with a 1M-window model, and with a 32k model the router would never
fire before overflow.

This module derives those bounds from the DRIVING MODEL's real context
window (``preflight.context_limit``), so capacity is limited by the LLM
the operator picked, not by constants tuned for a different one. Every
helper:

  - floors at the legacy constant, so small-window models keep today's
    behaviour and nothing ever shrinks below what shipped;
  - is overridable the usual way (the existing ``[context]`` keys and
    env vars still win — these only replace the *defaults*);
  - fails soft to the legacy constant on any error, so a config or
    lookup problem can never take down a run.

Disable wholesale with ``[context] model_scaled = false`` or
``MAVERICK_CONTEXT_MODEL_SCALED=0`` to pin the legacy fixed bounds.

For models the preflight table doesn't know (self-hosted vLLM/TGI,
new releases), declare the window with ``[context] window_override``
or ``MAVERICK_MODEL_CONTEXT_WINDOW`` — that single knob is what "the
context window is whatever my LLM supports" resolves to.
"""
from __future__ import annotations

import logging
import os

from ._envparse import env_bool, env_int

log = logging.getLogger(__name__)

# Legacy fixed bounds — the floors. Keep in sync with the historical
# constants at the call sites they replaced.
LEGACY_HISTORY_TURNS = 10
LEGACY_HISTORY_TURN_CHARS = 300
LEGACY_COMPACT_WINDOW_TURNS = 50
LEGACY_COMPACT_TARGET_TOKENS = 1500
LEGACY_MAX_OUTPUT_TOKENS = 4096
LEGACY_TOOL_RESULT_BYTES = 32_000

# Hard ceilings so a 10M-window model can't turn one goal into an
# unbounded prompt (budget caps still apply on top of all of this).
_MAX_HISTORY_TURNS = 200
_MAX_HISTORY_TURN_CHARS = 8_000
_MAX_COMPACT_WINDOW_TURNS = 500
_MAX_COMPACT_TARGET_TOKENS = 200_000
_MAX_OUTPUT_TOKENS_CEILING = 32_000
_MAX_TOOL_RESULT_BYTES = 2_000_000


def enabled() -> bool:
    """Whether context bounds scale with the driving model. ON by default."""
    raw = os.environ.get("MAVERICK_CONTEXT_MODEL_SCALED")
    if raw is not None:
        return env_bool("MAVERICK_CONTEXT_MODEL_SCALED", True)
    try:
        from .config import load_config
        value = load_config().get("context", {}).get("model_scaled", True)
        return bool(value)
    except Exception:  # pragma: no cover -- config never blocks a run
        return True


def model_window(model: str | None = None) -> int:
    """The driving model's context window, in tokens.

    Resolution order: ``MAVERICK_MODEL_CONTEXT_WINDOW`` env /
    ``[context] window_override`` (operator-declared, for models the
    preflight table doesn't know) -> ``preflight.context_limit`` for
    ``model`` (or the orchestrator role's model when omitted).
    """
    override = env_int("MAVERICK_MODEL_CONTEXT_WINDOW", 0)
    if override <= 0:
        try:
            from .config import load_config
            override = int(load_config().get("context", {}).get("window_override", 0))
        except Exception:  # pragma: no cover
            override = 0
    if override > 0:
        return override
    try:
        if not model:
            from .llm import model_for_role
            model = model_for_role("orchestrator")
        from .preflight import context_limit
        return context_limit(model)
    except Exception:  # pragma: no cover -- sizing must never block a run
        return 32_000


def _clamp(value: int, floor: int, ceiling: int) -> int:
    return max(floor, min(value, ceiling))


def history_turns(model: str | None = None) -> int:
    """How many prior conversation turns the orchestrator brief includes."""
    if not enabled():
        return LEGACY_HISTORY_TURNS
    return _clamp(model_window(model) // 4_000,
                  LEGACY_HISTORY_TURNS, _MAX_HISTORY_TURNS)


def history_turn_chars(model: str | None = None) -> int:
    """Per-turn character cap when replaying prior conversation turns."""
    if not enabled():
        return LEGACY_HISTORY_TURN_CHARS
    return _clamp(model_window(model) // 250,
                  LEGACY_HISTORY_TURN_CHARS, _MAX_HISTORY_TURN_CHARS)


def compact_window_turns(model: str | None = None) -> int:
    """How many recent turns the compactor considers before trimming."""
    if not enabled():
        return LEGACY_COMPACT_WINDOW_TURNS
    return _clamp(model_window(model) // 1_000,
                  LEGACY_COMPACT_WINDOW_TURNS, _MAX_COMPACT_WINDOW_TURNS)


def compact_target_tokens(model: str | None = None) -> int:
    """Token budget compaction trims history toward."""
    if not enabled():
        return LEGACY_COMPACT_TARGET_TOKENS
    return _clamp(model_window(model) // 8,
                  LEGACY_COMPACT_TARGET_TOKENS, _MAX_COMPACT_TARGET_TOKENS)


def router_threshold_tokens(model: str | None = None) -> int:
    """Payload size above which the long-context retrieval router shards.

    90% of the window: the router should fire just before a single payload
    would overflow the driving model, whatever that model is — late on a
    1M-window model, early on a 32k one (which previously never routed
    before overflowing the hard 200k default).
    """
    if not enabled():
        return 200_000
    return max(1, int(model_window(model) * 0.9))


def max_output_tokens(model: str | None = None) -> int:
    """Per-turn ``max_tokens`` for agent LLM calls.

    Overridable with ``MAVERICK_AGENT_MAX_TOKENS`` / ``[context]
    max_output_tokens``; otherwise scales at window/16, floored at the
    legacy 4096 and ceilinged conservatively (provider output limits are
    tighter than input windows). Budget caps still gate actual spend.
    """
    explicit = env_int("MAVERICK_AGENT_MAX_TOKENS", 0)
    if explicit <= 0:
        try:
            from .config import load_config
            explicit = int(load_config().get("context", {}).get("max_output_tokens", 0))
        except Exception:  # pragma: no cover
            explicit = 0
    if explicit > 0:
        return explicit
    if not enabled():
        return LEGACY_MAX_OUTPUT_TOKENS
    return _clamp(model_window(model) // 16,
                  LEGACY_MAX_OUTPUT_TOKENS, _MAX_OUTPUT_TOKENS_CEILING)


def tool_result_bytes(model: str | None = None) -> int:
    """Per-tool-result byte cap before a result enters the context.

    ``MAVERICK_MAX_TOOL_RESULT_BYTES`` (read at the call site) still wins
    outright; this only scales the default, keeping the token-efficiency
    baseline ratio (32 KB at a 200k window = window * 4 // 25) as the
    window grows.
    """
    if not enabled():
        return LEGACY_TOOL_RESULT_BYTES
    return _clamp(model_window(model) * 4 // 25,
                  LEGACY_TOOL_RESULT_BYTES, _MAX_TOOL_RESULT_BYTES)


__all__ = [
    "enabled",
    "model_window",
    "history_turns",
    "history_turn_chars",
    "compact_window_turns",
    "compact_target_tokens",
    "router_threshold_tokens",
    "max_output_tokens",
    "tool_result_bytes",
]
