"""Opus 4.8 + Gemini 3.5 model freshness and budget-accounting accuracy.

Regression target: defaults pointed at the prior generation (opus-4-7,
gemini-3) and Opus 4.8 / its fast-mode variant had no MODEL_PRICES entry,
so a run on the newest model silently billed at the Sonnet fallback rate
-- a quiet violation of the "budget caps are not optional" rule.
"""
from __future__ import annotations

import pytest
from maverick.budget import Budget, UnpricedModelError
from maverick.llm import MODEL_OPUS, MODEL_OPUS_FAST, MODEL_PRICES


def test_default_opus_is_4_8():
    assert MODEL_OPUS == "claude-opus-4-8"


def test_opus_48_priced_at_standard_rate():
    # Opus 4.8 standard = $5 in + $25 out per Mtok (unchanged from 4.5-4.7).
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000,
               max_output_tokens=10_000_000)
    b.record_tokens(1_000_000, 1_000_000, model=MODEL_OPUS)
    assert abs(b.dollars - 30.0) < 0.001


def test_opus_48_fast_billed_at_double_not_fallback():
    # Fast mode = $10 in + $50 out. If it weren't in MODEL_PRICES it would
    # silently bill at the Sonnet $3/$15 fallback ($18) -- under-charging 3x.
    b = Budget(max_dollars=1000.0, max_input_tokens=10_000_000,
               max_output_tokens=10_000_000)
    b.record_tokens(1_000_000, 1_000_000, model=MODEL_OPUS_FAST)
    assert abs(b.dollars - 60.0) < 0.001


def test_prior_opus_47_still_priced():
    # Users can still pin the prior Opus; it must keep its real rate.
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000,
               max_output_tokens=10_000_000)
    b.record_tokens(1_000_000, 0, model="claude-opus-4-7")
    assert abs(b.dollars - 5.0) < 0.001


def test_gemini_35_flash_priced_and_uncaptured_pro_is_estimate_only():
    # gemini-3.5-flash present so it bills at its own rate, not Sonnet's.
    assert "gemini-3.5-flash" in MODEL_PRICES
    assert "gemini-3.5-pro" in MODEL_PRICES
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000,
               max_output_tokens=10_000_000)
    b.record_tokens(1_000_000, 1_000_000, model="gemini-3.5-flash")
    assert abs(b.dollars - 10.5) < 0.001
    with pytest.raises(UnpricedModelError, match="unverified"):
        Budget().record_tokens(100, 10, model="gemini-3.5-pro")


# --- provider request shaping: Opus 4.8 was missing from every version
# gate in anthropic_provider, so the default model used the wrong cache
# threshold and the rejected `enabled` thinking mode. ---

def test_opus_48_uses_adaptive_thinking_not_enabled():
    from maverick.providers.anthropic_provider import AnthropicClient
    client = AnthropicClient.__new__(AnthropicClient)
    for mid in ("claude-opus-4-8", "claude-opus-4-8-fast"):
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model=mid,
        )
        thinking = kwargs.get("thinking", {})
        assert thinking.get("type") == "adaptive", (
            f"{mid} must use adaptive thinking, not enabled; got {thinking}"
        )


def test_opus_48_defaults_to_adaptive_without_budget():
    from maverick.providers.anthropic_provider import AnthropicClient
    client = AnthropicClient.__new__(AnthropicClient)
    kwargs = client._build_request(
        system="sys",
        messages=[{"role": "user", "content": "hi"}],
        tools=None,
        max_tokens=4096,
        thinking_budget=None,
        model="claude-opus-4-8",
    )
    assert kwargs.get("thinking", {}).get("type") == "adaptive"


def test_current_generation_uses_adaptive_thinking_not_enabled():
    # Opus 5 / Sonnet 5 / Fable 5.1 were unknown to _is_opus_adaptive,
    # so an explicit thinking_budget took the manual
    # {"type": "enabled", "budget_tokens": ...} path -- which these models
    # reject with a 400, the same way Opus 4.7/4.8 do (all "Adaptive"-only
    # per https://platform.claude.com/docs/en/about-claude/models/overview).
    from maverick.providers.anthropic_provider import AnthropicClient
    client = AnthropicClient.__new__(AnthropicClient)
    for mid in ("claude-opus-5", "claude-sonnet-5", "claude-fable-5-1", "claude-opus-5-5",
                "claude-mythos-5-2", "claude-haiku-5-5"):
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model=mid,
        )
        thinking = kwargs.get("thinking", {})
        assert thinking.get("type") == "adaptive", (
            f"{mid} must use adaptive thinking, not enabled; got {thinking}"
        )
        assert "budget_tokens" not in thinking

        kwargs_no_budget = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=None,
            model=mid,
        )
        assert kwargs_no_budget.get("thinking", {}).get("type") == "adaptive"


def test_opus_48_uses_1024_min_cache_threshold():
    # Opus 4.8's documented minimum cacheable prompt length is 1,024
    # tokens, not the 4,096 the table previously (wrongly) used for every
    # 4.5+/4.6+ model -- see
    # https://platform.claude.com/docs/en/build-with-claude/prompt-caching.
    from maverick.providers.anthropic_provider import (
        _MIN_CACHE_TOKENS_1024,
        _min_cache_tokens,
    )
    assert _min_cache_tokens("claude-opus-4-8") == _MIN_CACHE_TOKENS_1024
    assert _min_cache_tokens("claude-opus-4-8-fast") == _MIN_CACHE_TOKENS_1024


# --- "claude-opus-4-8-fast" is a
# catalog-only id -- the wire shape Anthropic actually requires is
# model="claude-opus-4-8" + speed="fast" + the fast-mode beta, sent through
# the beta messages endpoint. The tests above only ever asserted pricing and
# thinking-mode behaviour; none of them looked at what `model` value actually
# reaches the API. These do. ---

class TestFastModeRequestShape:
    def test_outbound_model_never_contains_fast_suffix(self):
        from maverick.providers.anthropic_provider import AnthropicClient
        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=None,
            model=MODEL_OPUS_FAST,
        )
        assert kwargs["model"] == MODEL_OPUS
        assert "-fast" not in kwargs["model"]

    def test_fast_mode_sets_speed_and_beta_flag(self):
        from maverick.providers.anthropic_provider import AnthropicClient
        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=None,
            model=MODEL_OPUS_FAST,
        )
        assert kwargs["speed"] == "fast"
        assert kwargs["betas"] == ["fast-mode-2026-02-01"]

    def test_non_fast_opus_request_has_no_speed_or_betas(self):
        from maverick.providers.anthropic_provider import AnthropicClient
        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=None,
            model=MODEL_OPUS,
        )
        assert "speed" not in kwargs
        assert "betas" not in kwargs

    def test_complete_routes_fast_mode_through_beta_endpoint_and_bills_fast_sku(self):
        """The request must go to client.beta.messages (only endpoint that
        validates `speed`), while Budget still bills the fast-mode SKU."""
        from types import SimpleNamespace

        from maverick.budget import Budget
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)
        calls = {}

        def fake_create(**kwargs):
            calls["kwargs"] = kwargs
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text="ok")],
                stop_reason="end_turn",
                usage=SimpleNamespace(
                    input_tokens=10, output_tokens=5,
                    cache_creation_input_tokens=0, cache_read_input_tokens=0,
                ),
            )

        # Non-beta client: must NOT be called for a fast-mode request.
        client.client = SimpleNamespace(
            messages=SimpleNamespace(
                create=lambda **kw: (_ for _ in ()).throw(
                    AssertionError("fast-mode request must use the beta endpoint")),
            ),
            beta=SimpleNamespace(messages=SimpleNamespace(create=fake_create)),
        )

        budget = Budget(max_dollars=100.0, max_input_tokens=10_000_000,
                        max_output_tokens=10_000_000)
        client.complete(
            system="sys", messages=[{"role": "user", "content": "hi"}],
            model=MODEL_OPUS_FAST, budget=budget,
        )

        assert calls["kwargs"]["model"] == MODEL_OPUS
        assert calls["kwargs"]["speed"] == "fast"
        # Billed at the fast-mode SKU's $10/$50 rate, not the base $5/$25.
        assert abs(budget.dollars - (10 * 10 / 1_000_000 + 50 * 5 / 1_000_000)) < 0.0001
