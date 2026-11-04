"""Budget must bound the dollar overshoot from concurrent sub-agent calls.

`Budget.check()` only raises once `dollars` ALREADY exceeds `max_dollars`. With a
wide parallel fan-out, N sub-agent calls sharing one budget each pass an
individual check while `dollars` is still low, then collectively overshoot --
a $2.50-cap run can reach $6+ with parallel Opus/Sonnet researchers on
200k-token contexts. `Budget.reserve()/release()` hold each call's projected
cost so concurrent callers see the accumulated holds; the LLM layer reserves
before dispatch and releases once the spend lands.
"""
from __future__ import annotations

import asyncio
import threading

import pytest
from maverick.budget import Budget, BudgetExceeded, UnpricedModelError


def test_check_projected_refuses_call_that_would_exceed_cap():
    b = Budget(max_dollars=1.0)
    b.dollars = 0.9
    with pytest.raises(BudgetExceeded):
        b.check_projected(0.2)   # 0.9 + 0.2 > 1.0
    b.check_projected(0.05)      # 0.9 + 0.05 <= 1.0 -> fine
    b.check_projected(0)         # non-positive est -> no-op


def test_estimate_call_cost_scales_with_input():
    from maverick.llm import _estimate_call_cost
    small = _estimate_call_cost(
        "claude-sonnet-4-6", "sys", [{"role": "user", "content": "hi"}], None, 100)
    big = _estimate_call_cost(
        "claude-sonnet-4-6", "sys", [{"role": "user", "content": "x" * 800_000}], None, 100)
    assert big > small > 0


@pytest.mark.parametrize("spec", (
    "azure:gpt-4o-prod",
    "bedrock:anthropic.claude-sonnet-4-20250514-v1:0",
    "openai_compatible:llama-3.3-70b-versatile",
    "moonshot:kimi-k2",
    "openrouter:meta-llama/llama-3.3-70b",
))
def test_estimate_call_cost_keeps_unverified_rates_for_projection(
    monkeypatch, spec,
):
    """A budget hold can use a labeled estimate; dispatch checks the
    billable rate separately before any provider request."""
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    from maverick.llm import _estimate_call_cost
    cost = _estimate_call_cost(spec, "sys", [{"role": "user", "content": "hi"}], None, 100)
    assert cost > 0


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("spec", [
    "azure:gpt-4o-prod",
    "openai_compatible:custom-gateway-model",
    "openai_compatible:claude-sonnet-4-6",
])
def test_complete_refuses_unpriced_hosted_model_before_provider_setup(
    monkeypatch, asynchronous, spec,
):
    """A projection may use an estimate, but strict live accounting cannot.

    Refuse before creating a client or sending paid traffic that record_tokens
    would reject after the provider already charged for it.
    """
    import maverick.llm as llm_mod

    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    llm = llm_mod.LLM(model=spec)
    clients = []
    monkeypatch.setattr(llm, "_get_client", lambda provider: clients.append(provider))
    budget = Budget()
    with pytest.raises(UnpricedModelError, match="strict_pricing=false"):
        result = (llm.complete_async if asynchronous else llm.complete)(
            system="s", messages=[{"role": "user", "content": "hi"}],
            budget=budget, max_tokens=100,
        )
        if asynchronous:
            asyncio.run(result)
    assert clients == []
    assert budget.dollars == budget._reserved == 0


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("spec", [
    "openai_compatible:custom-gateway-model",
    "openai_compatible:claude-sonnet-4-6",
])
def test_custom_gateway_can_explicitly_use_estimate_only_accounting(
    monkeypatch, asynchronous, spec,
):
    import maverick.llm as llm_mod

    monkeypatch.delenv("MAVERICK_BILLING_STRICT", raising=False)
    monkeypatch.setattr("maverick.config.get_budget_overrides",
                        lambda: {"strict_pricing": False})
    sends = []

    class Client:
        def complete(self, *, budget, **kwargs):
            sends.append(kwargs["model"])
            budget.record_tokens(10, 5, model=spec)
            return _SelfHostedClient._resp()

        async def complete_async(self, **kwargs):
            return self.complete(**kwargs)

    llm = llm_mod.LLM(model=spec)
    monkeypatch.setattr(llm, "_get_client", lambda provider: Client())
    budget = Budget()
    result = (llm.complete_async if asynchronous else llm.complete)(
        system="s", messages=[{"role": "user", "content": "hi"}],
        budget=budget, max_tokens=100,
    )
    response = asyncio.run(result) if asynchronous else result
    assert response.text == "ok"
    assert sends == [spec.split(":", 1)[1]]
    assert budget.dollars > 0
    assert budget.pricing_snapshot()[spec]["verified"] is False


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("spec,expected_dollars", [
    ("anthropic:claude-sonnet-4-6", True),
    ("openrouter:stealth/union-alpha", False),
    ("ollama:my-custom-model", False),
])
def test_strict_dispatch_keeps_priced_free_and_selfhosted_models(
    monkeypatch, asynchronous, spec, expected_dollars,
):
    import maverick.llm as llm_mod
    from maverick import model_discovery

    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    monkeypatch.setattr(model_discovery, "free_models",
                        lambda provider: ["stealth/union-alpha"] if provider == "openrouter" else [])
    sends = []

    class Client:
        def complete(self, *, budget, **kwargs):
            sends.append(kwargs["model"])
            budget.record_tokens(10, 5, model=spec)
            return _SelfHostedClient._resp()

        async def complete_async(self, **kwargs):
            return self.complete(**kwargs)

    llm = llm_mod.LLM(model=spec)
    monkeypatch.setattr(llm, "_get_client", lambda provider: Client())
    budget = Budget()
    result = (llm.complete_async if asynchronous else llm.complete)(
        system="s", messages=[{"role": "user", "content": "hi"}],
        budget=budget, max_tokens=100,
    )
    response = asyncio.run(result) if asynchronous else result
    assert response.text == "ok"
    assert len(sends) == 1
    assert (budget.dollars > 0) is expected_dollars


def test_reserve_bounds_total_holds_to_cap():
    b = Budget(max_dollars=1.0)
    held = []
    for _ in range(5):
        try:
            held.append(b.reserve(0.4))
        except BudgetExceeded:
            pass
    assert len(held) == 2          # 0.4 + 0.4 fit; the third (1.2) is refused
    assert b._reserved == pytest.approx(0.8)
    b.release(held[0])
    assert b._reserved == pytest.approx(0.4)
    b.reserve(0.4)                 # frees up room -> fits again
    assert b._reserved == pytest.approx(0.8)
    b.reserve(0.0)                 # zero-cost -> no-op, returns 0
    assert b._reserved == pytest.approx(0.8)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), -1, True, "bad"])
def test_projection_and_reservation_reject_invalid_estimates(bad):
    projected = Budget(max_dollars=1.0)
    reserved = Budget(max_dollars=1.0)

    with pytest.raises(BudgetExceeded, match="projected call cost"):
        projected.check_projected(bad)
    with pytest.raises(BudgetExceeded, match="projected call cost"):
        reserved.reserve(bad)

    assert projected.dollars == 0 and projected._reserved == 0
    assert reserved.dollars == 0 and reserved._reserved == 0


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1, True, "bad"])
def test_release_rejects_invalid_amount_without_changing_hold(bad):
    budget = Budget(max_dollars=2.0)
    budget.reserve(1.0)

    with pytest.raises(BudgetExceeded, match="released reservation"):
        budget.release(bad)

    assert budget._reserved == 1.0


def test_reserve_is_threadsafe_and_bounds_concurrent_holds():
    b = Budget(max_dollars=10.0)
    ok = []
    lk = threading.Lock()

    def worker():
        try:
            h = b.reserve(1.0)
            with lk:
                ok.append(h)
        except BudgetExceeded:
            pass

    ts = [threading.Thread(target=worker) for _ in range(50)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    # At most 10 holds of $1 fit under a $10 cap -- never more, regardless of
    # how the 50 threads interleaved.
    assert len(ok) == 10
    assert b._reserved == pytest.approx(10.0)


class _SelfHostedClient:
    """Fake client returning a usage-bearing response (100k in / 1k out)."""

    @staticmethod
    def _resp():
        from types import SimpleNamespace
        usage = SimpleNamespace(prompt_tokens=100_000, completion_tokens=1_000)
        return SimpleNamespace(raw=SimpleNamespace(usage=usage), text="ok",
                               cache_read_tokens=0, cache_creation_tokens=0)

    def complete(self, **kw):
        return self._resp()

    async def complete_async(self, **kw):
        return self._resp()


def test_selfhosted_model_priced_zero_through_complete(monkeypatch):
    """_parse_spec strips the 'ollama:' prefix, and pricing the BARE id
    defeated budget._lookup_price's self-hosted $0 rule: a free local model
    reserved a phantom Sonnet-rate hold (refusing calls near the cap) and
    recorded phantom dollars into the provider-cap ledger. The estimate and
    ledger paths must price the provider-qualified spec."""
    import maverick.llm as llm_mod

    monkeypatch.delenv("MAVERICK_BILLING_STRICT", raising=False)
    recorded = {}
    monkeypatch.setattr(llm_mod, "_record_provider_spend",
                        lambda provider, dollars: recorded.update({provider: dollars}))
    llm = llm_mod.LLM(model="ollama:my-custom-model")
    monkeypatch.setattr(llm, "_get_client", lambda provider: _SelfHostedClient())
    # Cap far below the phantom Sonnet-rate estimate for an ~800k-char prompt
    # (~$0.60): reserve() must NOT refuse a $0 self-hosted call.
    b = Budget(max_dollars=0.01)
    llm.complete(system="s", messages=[{"role": "user", "content": "x" * 800_000}],
                 budget=b, max_tokens=100)
    assert recorded["ollama"] == 0.0   # ledger spend, not phantom Sonnet dollars
    assert b.dollars == 0.0


def test_strict_pricing_allows_selfhosted_model_through_complete(monkeypatch):
    """[budget] strict_pricing must not refuse an unlisted self-hosted model:
    Budget.record_tokens prices 'ollama:<anything>' at $0 by design, but the
    bare id passed to _estimate_call_cost raised UnpricedModelError before
    dispatch."""
    import maverick.llm as llm_mod

    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    llm = llm_mod.LLM(model="ollama:my-custom-model")
    monkeypatch.setattr(llm, "_get_client", lambda provider: _SelfHostedClient())
    out = llm.complete(system="s", messages=[{"role": "user", "content": "hi"}],
                       budget=Budget(), max_tokens=100)
    assert out.text == "ok"


@pytest.mark.asyncio
async def test_complete_async_selfhosted_model_priced_zero(monkeypatch):
    """Async twin of the $0 self-hosted pricing pin (same estimate/ledger
    paths in complete_async)."""
    import maverick.llm as llm_mod

    monkeypatch.delenv("MAVERICK_BILLING_STRICT", raising=False)
    recorded = {}
    monkeypatch.setattr(llm_mod, "_record_provider_spend",
                        lambda provider, dollars: recorded.update({provider: dollars}))
    llm = llm_mod.LLM(model="ollama:my-custom-model")
    monkeypatch.setattr(llm, "_get_client", lambda provider: _SelfHostedClient())
    b = Budget(max_dollars=0.01)
    await llm.complete_async(
        system="s", messages=[{"role": "user", "content": "x" * 800_000}],
        budget=b, max_tokens=100)
    assert recorded["ollama"] == 0.0
    assert b.dollars == 0.0


@pytest.mark.asyncio
async def test_complete_async_refuses_overbudget_before_calling_provider(monkeypatch):
    from maverick.llm import LLM
    llm = LLM(model="anthropic:claude-sonnet-4-6")

    class _Client:
        async def complete_async(self, **kw):
            raise AssertionError("provider must NOT be called when the budget refuses")

    monkeypatch.setattr(llm, "_get_client", lambda provider: _Client())
    b = Budget(max_dollars=1.0)
    b.dollars = 0.95
    # ~800k chars -> ~200k input tokens -> ~$0.60 on Sonnet -> projected > cap.
    with pytest.raises(BudgetExceeded):
        await llm.complete_async(
            system="s",
            messages=[{"role": "user", "content": "x" * 800_000}],
            budget=b,
            max_tokens=100,
        )
