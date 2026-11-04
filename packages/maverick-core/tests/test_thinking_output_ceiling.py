"""Output-token ceiling on the adaptive-thinking path (Opus 4.7/4.8).

Regression target: on the default model, roles whose ``_thinking_budget()``
returned None (workers) still got adaptive thinking auto-injected with a
hardcoded ``max_tokens`` floor of 16384 — 4x the caller's 4096 — and the
budget ``reserve()`` estimate priced the call at the pre-bump 4096, so the
cap under-accounted the real worst-case output spend. Thinking tokens bill
at the output rate (~5x input), making this the largest output-cost driver.
"""
from __future__ import annotations

from maverick.providers.anthropic_provider import (
    AnthropicClient,
    _adaptive_max_tokens_floor,
    effective_max_tokens,
)


def _build(mid: str, thinking_budget, max_tokens: int = 4096) -> dict:
    client = AnthropicClient.__new__(AnthropicClient)
    return client._build_request(
        system="sys",
        messages=[{"role": "user", "content": "hi"}],
        tools=None,
        max_tokens=max_tokens,
        thinking_budget=thinking_budget,
        model=mid,
    )


class TestAdaptiveFloor:
    def test_default_floor_is_8192_not_16384(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", raising=False)
        assert _adaptive_max_tokens_floor() == 8192

    def test_env_override_and_sanity_clamp(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", "12000")
        assert _adaptive_max_tokens_floor() == 12000
        monkeypatch.setenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", "10")
        assert _adaptive_max_tokens_floor() == 2048  # floor of the floor
        monkeypatch.setenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", "junk")
        assert _adaptive_max_tokens_floor() == 8192

    def test_worker_turn_ceiling_uses_floor_not_16384(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", raising=False)
        # thinking_budget=None (worker): adaptive still auto-injected (4.8
        # rejects everything else) but the headroom bump is the configured
        # floor, not a hardcoded 16384.
        k = _build("claude-opus-4-8", thinking_budget=None)
        assert k.get("thinking", {}).get("type") == "adaptive"
        assert k["max_tokens"] == 8192

    def test_thinking_role_headroom_unchanged(self):
        # Explicit budget path keeps budget+1024 headroom semantics.
        k = _build("claude-opus-4-8", thinking_budget=8000)
        assert k["max_tokens"] == 9024

    def test_caller_max_tokens_wins_when_larger(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", "4096")
        k = _build("claude-opus-4-8", thinking_budget=None, max_tokens=6000)
        assert k["max_tokens"] == 6000


class TestEffectiveMaxTokens:
    """The budget-reserve estimate must price what the provider will send."""

    def test_matches_worker_bump(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", raising=False)
        assert effective_max_tokens("claude-opus-4-8", 4096, None) == 8192
        k = _build("claude-opus-4-8", thinking_budget=None)
        assert effective_max_tokens("claude-opus-4-8", 4096, None) == k["max_tokens"]

    def test_matches_thinking_bump(self):
        assert effective_max_tokens("claude-opus-4-8", 4096, 8000) == 9024
        assert effective_max_tokens("claude-sonnet-4-6", 4096, 8000) == 9024

    def test_non_adaptive_model_unbumped(self):
        assert effective_max_tokens("claude-sonnet-4-6", 4096, None) == 4096

    def test_accepts_provider_prefixed_spec(self):
        # llm.py passes "provider:model" price specs; the helper must see
        # through the prefix or the estimate silently loses the bump.
        assert effective_max_tokens("anthropic:claude-opus-4-8", 4096, None) == \
            effective_max_tokens("claude-opus-4-8", 4096, None)


class TestEstimateAccountsForBump:
    def test_estimate_prices_bumped_output(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", raising=False)
        from maverick.llm import _estimate_call_cost

        base = _estimate_call_cost(
            "anthropic:claude-sonnet-4-6", "s", [], None, 4096)
        bumped = _estimate_call_cost(
            "anthropic:claude-opus-4-8", "s", [], None, 4096,
            thinking_budget=None)
        # Same inputs; the 4.8 estimate must be priced at the 8192 ceiling
        # (and at Opus rates), i.e. strictly above a naive 4096-output price.
        naive_48 = _estimate_call_cost(
            "anthropic:claude-sonnet-4-6", "s", [], None, 8192)
        assert bumped > base
        assert naive_48 > base  # sanity: output tokens actually priced


class TestThinkingBudgetKnob:
    def test_config_budget_overrides_default(self, monkeypatch):
        import maverick.agent as agent_mod

        monkeypatch.setattr(
            "maverick.config.load_config", lambda: {"thinking": {"budget": 5000}})
        a = agent_mod.Agent.__new__(agent_mod.Agent)
        a.role = "orchestrator"
        assert a._thinking_budget() == 5000

    def test_worker_stays_none(self, monkeypatch):
        import maverick.agent as agent_mod

        monkeypatch.setattr(
            "maverick.config.load_config", lambda: {"thinking": {"budget": 5000}})
        a = agent_mod.Agent.__new__(agent_mod.Agent)
        a.role = "coder"
        assert a._thinking_budget() is None

    def test_default_base_unchanged(self, monkeypatch):
        import maverick.agent as agent_mod

        monkeypatch.setattr("maverick.config.load_config", dict)
        a = agent_mod.Agent.__new__(agent_mod.Agent)
        a.role = "revisor"
        assert a._thinking_budget() == 8000
