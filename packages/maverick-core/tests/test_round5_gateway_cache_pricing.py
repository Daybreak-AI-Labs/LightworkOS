"""Gateway cache accounting follows reported charges or verified model rates."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick.providers.moonshot_provider import MoonshotClient
from maverick.providers.openrouter_provider import OpenRouterClient
from maverick.providers.xai_provider import XaiClient


def _response(*, cost=None, writes=0):
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=10, cost=cost,
                              prompt_tokens_details=SimpleNamespace(cached_tokens=50, cache_write_tokens=writes)),
        choices=[SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=None), finish_reason="stop")],
    )


@pytest.mark.parametrize("provider,model,multiplier", [
    (XaiClient, "grok-4.5", .15),
    (XaiClient, "grok-build-0.1", .2),
    (XaiClient, "grok-4.3", .16),
    (MoonshotClient, "kimi-k3.1-pro", .1),
    (MoonshotClient, "kimi-k3.1-pro-highspeed", .05),
    (MoonshotClient, "kimi-k2.6", .16 / .95),
])
def test_gateway_cache_reads_use_verified_model_rate(provider, model, multiplier):
    calls = []
    budget = SimpleNamespace(record_tokens=lambda *args, **kwargs: calls.append((args, kwargs)))
    provider._from_response(_response(), budget, model=model)
    assert calls[0][1]["cache_read_mult"] == pytest.approx(multiplier)


def test_openrouter_uses_actual_cost_and_counts_cache_writes():
    from maverick.budget import Budget
    from maverick.llm import _response_call_cost

    budget = Budget()
    response = OpenRouterClient._from_response(_response(cost=.004, writes=20), budget, model="gpt-5.5")
    assert (budget.input_tokens, budget.output_tokens, budget.cache_read_tokens, budget.cache_write_tokens) == (30, 10, 50, 20)
    assert budget.dollars == .004
    assert _response_call_cost("openrouter:gpt-5.5", response) == budget.dollars


@pytest.mark.parametrize("cost", [None, -1, float("nan"), float("inf"), True])
def test_unverifiable_gateway_cache_cost_is_refused(cost):
    from maverick.budget import Budget, UsageAccountingError

    with pytest.raises(UsageAccountingError):
        OpenRouterClient._from_response(_response(cost=cost), Budget(), model="gpt-5.5")
