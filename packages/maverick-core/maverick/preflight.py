"""Token-count preflight.

Before dispatching an LLM call, estimate how many input tokens it will
consume and refuse early if it exceeds the model's context (minus a
safety margin). Cheap to run; saves money + time when an agent is
about to send something that can't possibly fit.

Estimation strategy:
  - Anthropic models: rough heuristic of 3.5 chars/token, since the
    real tokenizer (BPE-derived) lives in the SDK and counting on every
    call is wasteful. Conservative bias upward by 5%.
  - OpenAI models: same heuristic. If tiktoken is installed, prefer it.
  - Other providers: 3.5 chars/token heuristic.

This is intentionally a single function, not a class hierarchy. Hot
path. Keep it dumb.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


# Hard caps per model. Conservative: subtract a safety margin so we
# leave room for the response (max_tokens param) and tools schema.
# Keys are exact model ids; lookups fall back to family prefix.
#
# Every Opus/Sonnet 4.6+ model is actually a 1M-context model per
# https://platform.claude.com/docs/en/build-with-claude/context-windows
# (and each model's own overview page) -- this table had them all capped
# at 200k, silently refusing prompts up to 800k tokens that the real API
# would accept. Only Opus 4.5/Sonnet 4.5 and Haiku 4.5 stay at 200k.
_MODEL_CONTEXT_LIMITS: dict[str, int] = {
    # Anthropic
    "claude-opus-5":        1_000_000,
    "claude-sonnet-5":      1_000_000,
    "claude-fable-5-1":     1_000_000,
    "claude-fable-5-2":     1_000_000,
    "claude-opus-5-5":      1_000_000,
    "claude-sonnet-5-5":    1_000_000,
    "claude-haiku-5-5":     1_000_000,
    "claude-opus-4-8":      1_000_000,   # current default (MODEL_OPUS)
    "claude-opus-4-8-fast": 1_000_000,
    "claude-opus-4-7":      1_000_000,
    "claude-opus-4-6":      1_000_000,
    "claude-opus-4-5":        200_000,
    "claude-sonnet-4-6":    1_000_000,   # current default (MODEL_SONNET)
    "claude-sonnet-4-5":      200_000,
    "claude-haiku-4-5":       200_000,
    # OpenAI
    "gpt-5.5":            128_000,
    "gpt-5.4":            128_000,
    "gpt-5.4-pro":        128_000,
    "gpt-5.4-mini":       128_000,
    "gpt-5.4-nano":        32_000,
    # xAI
    "grok-4-latest":      131_072,
    "grok-4-mini":        131_072,
    "grok-code-fast":     131_072,
    "grok-3":             131_072,
    # DeepSeek
    "deepseek-chat":       64_000,
    "deepseek-reasoner":   64_000,
    "deepseek-v4-pro":    128_000,
    "deepseek-v4-flash":  128_000,
    # Moonshot / Kimi
    "kimi-k2":            128_000,
    "kimi-k1.5":          128_000,
    "moonshot-v1-8k":       8_000,
    "moonshot-v1-32k":     32_000,
    "moonshot-v1-128k":   128_000,
    # Gemini
    "gemini-3-pro":     1_000_000,
    "gemini-3-flash":   1_000_000,
}


def _declared_windows() -> dict[str, int]:
    """Operator-declared per-model windows: ``[context.model_windows]``.

    The escape hatch for models this table doesn't know (self-hosted
    vLLM/TGI, brand-new releases): declare the real window in config and
    both preflight and context_scaling honour it instead of the 32k
    fallback. Fail-soft: a bad config entry is skipped, never raises.
    """
    try:
        from .config import load_config
        raw = (load_config().get("context", {}) or {}).get("model_windows", {})
        out: dict[str, int] = {}
        qualified: dict[str, int] = {}
        for k, v in dict(raw).items():
            try:
                n = int(v)
            except (TypeError, ValueError):
                continue
            if n > 0:
                out[str(k)] = n
                # The dashboard names models as "provider:model-id"; lookups
                # use the bare id, so also index the id (an exact key wins).
                provider, sep, model = str(k).partition(":")
                if sep and provider and model:
                    qualified.setdefault(model, n)
        for model, n in qualified.items():
            out.setdefault(model, n)
        return out
    except Exception:  # pragma: no cover -- config never blocks a call
        return {}


def context_limit(model: str) -> int:
    """Return the (conservative) context limit for ``model``.

    Operator-declared ``[context.model_windows]`` entries win, then the
    built-in table, then the longest table id that the model id extends
    (``claude-sonnet-4-5-20250929`` -> ``claude-sonnet-4-5``), then the
    first table entry of the model's family (text before the first ``-``),
    then 32k as the safe default when we have no clue.
    """
    declared = _declared_windows()
    if model in declared:
        return declared[model]
    if model in _MODEL_CONTEXT_LIMITS:
        return _MODEL_CONTEXT_LIMITS[model]
    best = ""
    for key in _MODEL_CONTEXT_LIMITS:
        if (len(key) > len(best) and model.startswith(key)
                and model[len(key):len(key) + 1] in ("-", "@")):
            best = key
    if best:
        return _MODEL_CONTEXT_LIMITS[best]
    # Family-prefix fallback for ids that extend no table id.
    for prefix, limit in _MODEL_CONTEXT_LIMITS.items():
        if model.startswith(prefix.split("-")[0]):
            return limit
    return 32_000


def estimate_tokens(text: str) -> int:
    """Cheap chars/token estimator. Biases upward 5% for safety."""
    if not text:
        return 0
    return int((len(text) / 3.5) * 1.05)


def estimate_messages_tokens(
    system: str,
    messages: list[dict],
    tools: list[dict] | None = None,
) -> int:
    """Sum estimated tokens for a full request."""
    import json

    total = estimate_tokens(system or "")
    for msg in messages or []:
        content = msg.get("content")
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    txt = block.get("text") or block.get("input")
                    if isinstance(txt, str):
                        total += estimate_tokens(txt)
                    else:
                        total += estimate_tokens(json.dumps(block, default=str))
                else:
                    total += estimate_tokens(str(block))
    if tools:
        for t in tools:
            try:
                total += estimate_tokens(json.dumps(t, default=str))
            except (TypeError, ValueError):
                total += 200  # generous fallback per tool
    return total


class PreflightFailed(Exception):
    """Raised when the estimated request size won't fit the model's context."""

    def __init__(self, model: str, estimated: int, limit: int, max_tokens: int):
        msg = (
            f"preflight: model={model!r} won't fit. "
            f"estimated input tokens={estimated:,}, "
            f"context limit={limit:,}, requested output={max_tokens}. "
            "Compact, split, or pick a larger-context model."
        )
        super().__init__(msg)
        self.model = model
        self.estimated = estimated
        self.limit = limit
        self.max_tokens = max_tokens


def preflight(
    *,
    model: str,
    system: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    max_tokens: int = 4096,
    safety_margin: int = 1024,
    strict: bool = True,
) -> int:
    """Estimate input size; raise PreflightFailed if it won't fit.

    Returns the estimate (so callers can log / surface to the user).

    Set ``strict=False`` to log a warning instead of raising. This is wired
    into ``LLM.complete`` / ``LLM.complete_async`` via ``llm._run_preflight``;
    the mode is chosen by the ``MAVERICK_PREFLIGHT`` env var and defaults to
    ``warn`` (log only) so the live path can't false-refuse a borderline
    request. Set ``MAVERICK_PREFLIGHT=strict`` for a hard refuse.
    """
    limit = context_limit(model)
    budget = limit - max_tokens - safety_margin
    if budget <= 0:
        # Tiny model + huge requested output: nothing's going to fit.
        if strict:
            raise PreflightFailed(model, 0, limit, max_tokens)
        log.warning(
            "preflight: model=%s max_tokens=%d leaves no input room (limit=%d)",
            model, max_tokens, limit,
        )
        return estimate_messages_tokens(system, messages, tools)
    estimated = estimate_messages_tokens(system, messages, tools)
    if estimated > budget:
        if strict:
            raise PreflightFailed(model, estimated, limit, max_tokens)
        log.warning(
            "preflight: model=%s estimated=%d > budget=%d (limit=%d, max_tokens=%d)",
            model, estimated, budget, limit, max_tokens,
        )
    return estimated


__all__ = [
    "context_limit",
    "estimate_tokens",
    "estimate_messages_tokens",
    "preflight",
    "PreflightFailed",
]
