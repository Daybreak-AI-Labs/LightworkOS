"""Cost and billing accuracy.

Pins four properties:
  1. Provider-aware cache-read multiplier: Anthropic 0.1x (default) vs
     OpenAI/o-series/gpt-5 auto-cache ~0.5x, while record_tokens stays
     backward-compatible (no new required args).
  2. cost_router._PRICING model ids all resolve in llm.MODEL_PRICES
     (one source of truth for prices).
  3. budget_dollars is a lifetime total that callers inc() by the per-call
     delta, so a second goal can't stomp the running total.
  4. cost_router.pick excludes a provider whose recent error rate is over a
     configurable threshold, falling back to the cheapest healthy one.
"""
from __future__ import annotations

import pytest

# --- Task 1: provider-aware cache-read multiplier --------------------------

def test_anthropic_cache_read_default_is_0_1x():
    from maverick.budget import Budget
    b = Budget(max_dollars=1000.0)
    # Sonnet input rate is $3/Mtok. 1M cached read tokens at the default
    # Anthropic 0.1x => $0.30.
    b.record_tokens(0, 0, model="claude-sonnet-4-6", cache_read_tok=1_000_000)
    assert b.dollars == pytest.approx(3.0 * 0.1)


def test_openai_cache_read_mult_is_0_5x():
    from maverick.budget import CACHE_READ_MULT_OPENAI, Budget
    assert CACHE_READ_MULT_OPENAI == 0.5
    b = Budget(max_dollars=1000.0)
    # The flat billing card uses the conservative $5.50/Mtok context/region
    # ceiling. One million cached-read tokens at OpenAI 0.5x => $2.75.
    b.record_tokens(
        0, 0, model="gpt-5.4", cache_read_tok=1_000_000,
        cache_read_mult=CACHE_READ_MULT_OPENAI,
    )
    assert b.dollars == pytest.approx(5.5 * 0.5)


def test_record_tokens_backward_compatible():
    """The legacy positional call (no cache_read_mult) must still bill at the
    Anthropic 0.1x default — many callers rely on it."""
    from maverick.budget import Budget
    b = Budget(max_dollars=1000.0)
    b.record_tokens(100, 50, model="claude-sonnet-4-6", cache_read_tok=1000)
    expected = (
        (100 / 1_000_000) * 3.0
        + (1000 / 1_000_000) * 3.0 * 0.1
        + (50 / 1_000_000) * 15.0
    )
    assert b.dollars == pytest.approx(expected)


def test_openai_provider_passes_openai_cache_mult():
    """End-to-end: the OpenAI provider bills cached reads at 0.5x, not 0.1x."""
    from types import SimpleNamespace

    from maverick.budget import Budget
    from maverick.providers.openai_provider import OpenAIClient

    usage = SimpleNamespace(
        prompt_tokens=1_000_000,
        completion_tokens=0,
        prompt_tokens_details=SimpleNamespace(cached_tokens=1_000_000),
    )
    choice = SimpleNamespace(
        message=SimpleNamespace(content="hi", tool_calls=None),
        finish_reason="stop",
    )
    resp = SimpleNamespace(choices=[choice], usage=usage)
    b = Budget(max_dollars=1000.0)
    OpenAIClient._from_response(resp, b, model="gpt-5.4")
    # All 1M prompt tokens are cached -> billable_in=0, cached at 0.5x of the
    # gpt-5.4 conservative $5.50 input ceiling => $2.75.
    assert b.dollars == pytest.approx(5.5 * 0.5)


# --- Task 2: cost_router ids all resolve in MODEL_PRICES -------------------

def test_router_pricing_ids_resolve_in_model_prices():
    from maverick.cost.router import _PRICING
    from maverick.llm import MODEL_PRICES
    for provider, mid, _tier, in_rate, out_rate in _PRICING:
        assert mid in MODEL_PRICES, f"{provider}:{mid} not in MODEL_PRICES"
        # Rates are derived FROM the canonical catalog, so they must match.
        assert (in_rate, out_rate) == MODEL_PRICES[mid], mid


def test_price_for_model_matches_canonical_catalog():
    from maverick.cost.router import _PRICING, price_for_model
    from maverick.llm import MODEL_PRICES, MODEL_PRICING_PROVIDER
    for _provider, mid, *_ in _PRICING:
        quote = MODEL_PRICING_PROVIDER.rates[mid]
        if quote.verified:
            assert price_for_model(mid) == MODEL_PRICES[mid]
        else:
            assert price_for_model(mid) is None
            assert price_for_model(mid, estimate_only=True) == MODEL_PRICES[mid]


# --- Task 3: lifetime budget_dollars metric isn't stomped across goals -----

def test_budget_dollars_metric_accumulates_across_goals(monkeypatch):
    import maverick.observability as obs

    recorded: list[tuple[str, float]] = []

    def _fake_metric(name, value=1.0, *, labels=None):
        recorded.append((name, value))

    monkeypatch.setattr(obs, "record_metric", _fake_metric, raising=True)

    from maverick.budget import Budget
    from maverick.llm import LLM, LLMResponse

    def _make_client(spend):
        class _C:
            def complete(self, **kw):
                kw["budget"].record_tokens(
                    int(spend / 3.0 * 1_000_000), 0, model="claude-sonnet-4-6"
                )
                return LLMResponse(text="", thinking=None, tool_calls=[],
                                   stop_reason="end_turn")
        return _C()

    llm = LLM()
    monkeypatch.setattr(llm, "_get_client", lambda provider: _make_client(2.0))

    # Goal A: its own fresh budget reaches $2.
    ba = Budget(max_dollars=100.0)
    llm.complete("s", [], budget=ba)
    # Goal B: a SEPARATE fresh budget that also reaches $2 (starts at $0).
    bb = Budget(max_dollars=100.0)
    llm.complete("s", [], budget=bb)

    deltas = [v for (n, v) in recorded if n == "budget_dollars"]
    assert len(deltas) == 2
    # Each emit is the per-call delta (~$2), NOT the per-goal cumulative; a
    # Counter summing these yields ~$4 lifetime instead of being stomped to $2.
    assert all(d == pytest.approx(2.0, rel=1e-3) for d in deltas)
    assert sum(deltas) == pytest.approx(4.0, rel=1e-3)


# --- Task 4: unhealthy provider excluded from routing ----------------------

@pytest.fixture
def _route_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.delenv("MAVERICK_ROUTING_MAX_ERROR_RATE", raising=False)
    for prov in ("ANTHROPIC", "OPENAI", "DEEPSEEK", "MOONSHOT",
                 "XAI", "GEMINI", "GOOGLE"):
        monkeypatch.delenv(f"{prov}_API_KEY", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-465-routing-test")
    from maverick.provider_health import get
    get().reset()
    yield
    get().reset()


def test_unhealthy_cheap_model_excluded(_route_env, monkeypatch):
    # Only openai keyed, with two base-tier models (the cheaper gpt-5.4 and
    # the premium gpt-5.4-pro which also qualifies for base-tier filtering).
    monkeypatch.setenv("OPENAI_API_KEY", "x")

    from maverick.cost.router import TIER_BASE, CostSignal, pick
    from maverick.provider_health import get

    # The cheapest base-tier openai model (gpt-5.4) is down: 5 errors (100%).
    h = get()
    for _ in range(5):
        h.record("openai", "gpt-5.4", latency_ms=10, error=True)

    got = pick(CostSignal(role="coder", tier=TIER_BASE))
    # Health is tracked per (provider, model): the down gpt-5.4 is excluded
    # even though it's the cheapest, so routing falls back to the next
    # cheapest HEALTHY openai model rather than the down one.
    assert got is not None
    assert got.startswith("openai:"), got
    assert got != "openai:gpt-5.4", got


def test_healthy_cheap_provider_still_wins(_route_env, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "x")
    monkeypatch.setenv("OPENAI_API_KEY", "x")

    from maverick.cost.router import TIER_BASE, CostSignal, pick
    from maverick.provider_health import get

    # deepseek healthy (errors below threshold) -> still the cheapest pick.
    h = get()
    for _ in range(10):
        h.record("deepseek", "deepseek-v4-flash", latency_ms=10, error=False)

    got = pick(CostSignal(role="coder", tier=TIER_BASE))
    assert got.startswith("deepseek:"), got


def test_single_early_error_does_not_exclude(_route_env, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "x")
    monkeypatch.setenv("OPENAI_API_KEY", "x")

    from maverick.cost.router import TIER_BASE, CostSignal, pick
    from maverick.provider_health import get

    # 1/1 = 100% error rate, but below the min sample count -> not excluded.
    get().record("deepseek", "deepseek-v4-flash", latency_ms=10, error=True)
    got = pick(CostSignal(role="coder", tier=TIER_BASE))
    assert got.startswith("deepseek:"), got


def test_error_rate_threshold_config_knob(_route_env, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "x")
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    # Tighten the ceiling to 20%; a 40% error rate now excludes deepseek.
    monkeypatch.setenv("MAVERICK_ROUTING_MAX_ERROR_RATE", "0.2")

    from maverick.cost.router import TIER_BASE, CostSignal, pick
    from maverick.provider_health import get

    h = get()
    # Both deepseek base-tier models at 40% error -> both excluded under the
    # 20% ceiling, so routing falls back to the cheapest healthy openai model.
    for mid in ("deepseek-v4-flash", "deepseek-v4-pro"):
        for i in range(10):
            h.record("deepseek", mid, latency_ms=10, error=(i < 4))

    got = pick(CostSignal(role="coder", tier=TIER_BASE))
    assert got.startswith("openai:"), got
