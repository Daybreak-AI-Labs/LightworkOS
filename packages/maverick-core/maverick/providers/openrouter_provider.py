"""OpenRouter provider client.

OpenRouter is OpenAI-compatible at a different base_url and aggregates
200+ models from many vendors. Models follow the format
``vendor/model-id`` (e.g., ``meta-llama/llama-3.3-70b``).

Uses the OpenAIClient implementation; just swaps base_url + api_key.
"""
from __future__ import annotations

import math
import os
from collections.abc import Mapping

from ..budget import UsageAccountingError
from .openai_provider import OpenAIClient, _strict_usage_count


def _gateway_usage(usage):
    """Cache read/write counts are disjoint subsets of total prompt tokens."""
    details = getattr(usage, "prompt_tokens_details", None)
    read = _strict_usage_count(getattr(details, "cached_tokens", 0), "cached_tokens", missing_ok=True)
    if not read:
        read = _strict_usage_count(getattr(usage, "cached_tokens", 0), "cached_tokens", missing_ok=True)
    write = _strict_usage_count(getattr(details, "cache_write_tokens", 0), "cache_write_tokens", missing_ok=True)
    total = _strict_usage_count(getattr(usage, "prompt_tokens", None), "prompt_tokens")
    output = _strict_usage_count(getattr(usage, "completion_tokens", None), "completion_tokens")
    if read + write > total:
        raise UsageAccountingError("Gateway cache token counts exceed total input usage")
    return total - read - write, output, read, write


def _reported_cost(value, label):
    try:
        if isinstance(value, bool) or not math.isfinite(float(value)) or float(value) < 0:
            raise ValueError
        return float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise UsageAccountingError(f"OpenRouter returned an invalid {label}") from exc


def _openrouter_cost(usage):
    cost = getattr(usage, "cost", None)
    if cost is not None:
        cost = _reported_cost(cost, "billed cost")
    byok = getattr(usage, "is_byok", None)
    if byok is not None and type(byok) is not bool:
        raise UsageAccountingError("OpenRouter returned invalid BYOK billing metadata")
    details = getattr(usage, "cost_details", None)
    upstream = (details.get("upstream_inference_cost") if isinstance(details, Mapping)
                else getattr(details, "upstream_inference_cost", None))
    # BYOK inference is billed to the user's provider account; usage.cost is
    # only OpenRouter's fee. Older receipts omit is_byok but include upstream.
    # https://openrouter.ai/docs/guides/overview/auth/byok
    if byok is True or (byok is None and upstream is not None):
        if cost is None or upstream is None:
            raise UsageAccountingError("OpenRouter BYOK cost is incomplete; cannot enforce budget")
        cost = _reported_cost(cost + _reported_cost(upstream, "BYOK upstream cost"), "total BYOK cost")
    return cost


class _GatewayClient(OpenAIClient):
    """Meter gateway cache usage before reusing OpenAI content translation."""

    CACHE_READ_MULT = 1.0  # no unverified discount on an unknown model
    CACHE_READ_MULTIPLIERS: dict[str, float] = {}
    CACHE_WRITE_MULTIPLIERS: dict[str, float] = {}

    @classmethod
    def _cache_pricing(cls, model, usage):
        return (cls.CACHE_READ_MULTIPLIERS.get(model, 1.0),
                cls.CACHE_WRITE_MULTIPLIERS.get(model), None)

    @classmethod
    def _from_response(cls, resp, budget, model=None, price_model_prefix="", usage_required=True):
        usage = getattr(resp, "usage", None)
        if usage is None:
            return super()._from_response(resp, budget, model, price_model_prefix, usage_required)
        if budget is not None:
            incoming, outgoing, read, write = _gateway_usage(usage)
            read_mult, write_mult, cost = cls._cache_pricing(model, usage)
            if write and write_mult is None and cost is None:
                raise UsageAccountingError("Gateway cache-write pricing is unavailable; cannot enforce budget")
            budget.record_tokens(
                incoming, outgoing,
                model=(price_model_prefix + model) if model else model,
                cache_read_tok=read, cache_write_tok=write,
                cache_read_mult=read_mult, cache_write_mult=write_mult,
                cost_dollars=cost,
            )
        return super()._from_response(resp, None, model, price_model_prefix, usage_required)


class OpenRouterClient(_GatewayClient):
    DEFAULT_MODEL = "meta-llama/llama-3.3-70b"
    PRICE_MODEL_PREFIX = "openrouter:"

    @classmethod
    def _cache_pricing(cls, model, usage):
        # OpenRouter routes among vendors and TTL tiers. Total paid USD includes
        # cache pricing and any separately billed BYOK inference charge.
        # https://openrouter.ai/docs/cookbook/administration/usage-accounting
        cost = _openrouter_cost(usage)
        if cost is None:
            _, _, read, write = _gateway_usage(usage)
            if read or write:
                raise UsageAccountingError("OpenRouter cached usage omitted billed cost; cannot enforce budget")
        return 1.0, None, cost

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        super().__init__(
            api_key=api_key or env.get("OPENROUTER_API_KEY"),
            base_url=base_url or "https://openrouter.ai/api/v1",
            allow_openai_env_fallback=False,
            environment=environment,
        )
