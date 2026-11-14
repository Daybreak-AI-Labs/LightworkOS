"""Canceled paid attempts and local refusals have distinct accounting outcomes."""
from __future__ import annotations

import asyncio

import pytest
from maverick import circuit_breaker
from maverick import llm as llm_module
from maverick.budget import Budget, BudgetExceeded, UnpricedModelError, UsageAccountingError
from maverick.llm import LLM, LLMResponse


@pytest.fixture
def dispatch(monkeypatch):
    from maverick import enterprise, privacy_egress

    monkeypatch.setattr(enterprise, "assert_provider_allowed", lambda _provider: None)
    monkeypatch.setattr(privacy_egress, "maybe_redact_egress", lambda _provider, system, messages: (system, messages))
    monkeypatch.setattr(llm_module, "require_model_allowed", lambda model: model)
    monkeypatch.setattr("maverick.config.load_config", lambda *args, **kwargs: {})
    for name in ("_enforce_provider_cap", "_record_provider_call", "_record_provider_spend", "_run_preflight", "_note_bandit"):
        monkeypatch.setattr(llm_module, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(llm_module, "_reserve_provider_call", lambda *args, **kwargs: None)
    monkeypatch.setattr(llm_module, "_finish_provider_call", lambda *args, **kwargs: True)
    monkeypatch.setattr(llm_module, "_fallback_chain_for_dispatch", lambda *args: [])
    circuit_breaker.reset_all()
    yield LLM(model="openai:gpt-5.5")
    circuit_breaker.reset_all()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("error_type", [UnpricedModelError, UsageAccountingError])
def test_pre_send_refusal_releases_probe_without_health_result(dispatch, monkeypatch, asynchronous, error_type):
    class Client:
        def complete(self, **kwargs):
            raise AssertionError("no send")

        async def complete_async(self, **kwargs):
            raise AssertionError("no send")

    monkeypatch.setattr(dispatch, "_get_client", lambda provider: Client())
    breaker = circuit_breaker.get("llm:openai", failure_threshold=1, cooldown_seconds=0)
    breaker.record_failure()

    def refuse(_self):
        raise error_type("local price check refused")

    monkeypatch.setattr(llm_module._ProviderAttemptTracker, "_fresh_quote", refuse)
    call = dispatch.complete_async if asynchronous else dispatch.complete
    with pytest.raises(error_type):
        result = call("", [])
        if asynchronous:
            asyncio.run(result)
    assert breaker.state is circuit_breaker.CircuitState.HALF_OPEN
    assert breaker.snapshot()["total_successes"] == 0
    assert breaker.snapshot()["total_failures"] == 1
    assert breaker.admit()


@pytest.mark.parametrize("instrumented", [False, True])
@pytest.mark.parametrize("token_cap", [False, True])
def test_canceled_hedge_charges_reserved_tokens_and_cost(dispatch, monkeypatch, instrumented, token_cap):
    from maverick.retry import async_retry

    calls = []

    async def request():
        calls.append(True)
        if len(calls) == 1:
            await asyncio.Event().wait()
        return LLMResponse(text="winner", thinking=None, tool_calls=[], stop_reason="end_turn")

    class Client:
        async def complete_async(self, **kwargs):
            return await async_retry(request) if instrumented else await request()

    monkeypatch.setattr(dispatch, "_get_client", lambda provider: Client())
    monkeypatch.setattr(llm_module, "_hedge_ms_for", lambda callback: 1)
    budget = Budget(max_dollars=10, max_wall_seconds=10)
    estimated = llm_module._estimate_call_cost("openai:gpt-5.5", "1234", [], None, 100)
    if token_cap:
        budget.max_input_tokens = 0
        with pytest.raises(BudgetExceeded):
            asyncio.run(dispatch.complete_async("1234", [], budget=budget, max_tokens=100))
    else:
        result = asyncio.run(dispatch.complete_async("1234", [], budget=budget, max_tokens=100))
        assert result.text == "winner"
    assert len(calls) == 2
    assert budget.dollars == pytest.approx(estimated)
    assert budget.input_tokens >= 1
    assert budget.output_tokens >= 100
    assert budget._reserved == 0
