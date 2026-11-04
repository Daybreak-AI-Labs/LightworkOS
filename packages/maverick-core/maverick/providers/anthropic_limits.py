"""Shared Anthropic request token limits, without importing the provider SDK.

Cost admission and request construction use the same current configuration.
"""
from __future__ import annotations


def _adaptive_max_tokens_floor() -> int:
    """Headroom ceiling for AUTO-adaptive thinking (Opus 4.7/4.8, no explicit
    thinking_budget). Adaptive thinking bills as output (~5x input) and can
    spend up to max_tokens, so this floor is the worst-case output cost of
    every non-thinking-role turn on the default model. 16384 (the earlier
    value) quadrupled the agent loop's 4096 for roles that never asked
    to think; 8192 keeps generous anti-empty-response headroom at half the
    ceiling. Tune via MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR (min 2048)."""
    from ..env_setting import env_or_config_int

    return max(2048, env_or_config_int(
        "MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", "thinking", "adaptive_floor", 8192))


def _is_opus_adaptive(model_id: str) -> bool:
    """Models that ONLY accept adaptive thinking (explicit "enabled" returns
    400) and get the auto-adaptive default: Opus 4.7/4.8 (incl. ``-fast``
    variants) and the current generation (Opus 5, Sonnet 5, Fable 5.x), all
    "Adaptive"-only per each model's own capabilities table at
    https://platform.claude.com/docs/en/about-claude/models/overview.

    This used to match only Opus 4.7/4.8, so an unrecognized
    current-generation id fell through to the manual
    ``{"type": "enabled", "budget_tokens": ...}`` path below -- which those
    models reject with a 400, the same way Opus 4.7/4.8 do. The single
    place to extend when the next generation lands — the request builder
    and the budget estimate both key off this predicate."""
    return (model_id.startswith("claude-opus-4-7")
            or model_id.startswith("claude-opus-4-8")
            or model_id.startswith("claude-opus-5")
            or model_id.startswith("claude-sonnet-5")
            or model_id.startswith("claude-fable-5"))


def effective_max_tokens(model_id: str, max_tokens: int,
                         thinking_budget: int | None = None) -> int:
    """The max_tokens ``_build_request`` sends — and the value it computes it
    with: the builder calls this, so the budget ``reserve()`` estimate that
    also calls it can never drift from the real request. Accepts bare model
    ids or "provider:model" specs.
    """
    mid = (model_id or "").split(":", 1)[-1]
    if thinking_budget and thinking_budget > 0:
        return max(max_tokens, thinking_budget + 1024)
    if _is_opus_adaptive(mid):
        return max(max_tokens, _adaptive_max_tokens_floor())
    return max_tokens
