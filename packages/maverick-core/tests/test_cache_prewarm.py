"""Prompt-cache pre-warming: max_tokens=0 prefill writes the system+tools cache."""
from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_provider_prewarm_sends_max_tokens_zero(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    from maverick.providers.anthropic_provider import AnthropicClient
    p = AnthropicClient()

    sent: list[dict] = []

    class _Msgs:
        def create(self, **kw):
            sent.append(kw)
            return object()

    monkeypatch.setattr(p.client, "messages", _Msgs())
    ok = p.prewarm("a large system prompt " * 2000, tools=[{"name": "t", "description": "d",
                   "input_schema": {"type": "object"}}], model="claude-opus-4-8")
    assert ok is True
    req = sent[0]
    assert req["max_tokens"] == 0
    assert req["model"] == "claude-opus-4-8"
    # System carries a cache breakpoint; the placeholder message is not cached.
    assert req["system"][0]["cache_control"]["type"] == "ephemeral"
    assert req["messages"] == [{"role": "user", "content": "warmup"}]
    # max_tokens=0 forbids thinking/output_config/tool_choice -> none present.
    assert "thinking" not in req and "output_config" not in req and "tool_choice" not in req


def test_provider_prewarm_records_budget_usage(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    from maverick.budget import Budget
    from maverick.providers.anthropic_provider import AnthropicClient

    p = AnthropicClient()

    class _Msgs:
        def create(self, **kw):
            return SimpleNamespace(
                content=[],
                stop_reason="end_turn",
                usage=SimpleNamespace(
                    input_tokens=10,
                    output_tokens=0,
                    cache_read_input_tokens=20,
                    cache_creation_input_tokens=1000,
                ),
            )

    monkeypatch.setattr(p.client, "messages", _Msgs())
    budget = Budget(max_dollars=100.0)

    assert p.prewarm("sys " * 5000, None, "claude-opus-4-8", budget=budget) is True
    assert budget.input_tokens == 10
    assert budget.cache_read_tokens == 20
    assert budget.cache_write_tokens == 1000
    assert budget.dollars == pytest.approx(0.01006)


def test_provider_prewarm_failsoft(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    from maverick.providers.anthropic_provider import AnthropicClient
    p = AnthropicClient()

    class _Boom:
        def create(self, **kw):
            raise RuntimeError("api down")

    monkeypatch.setattr(p.client, "messages", _Boom())
    assert p.prewarm("sys", None, "claude-opus-4-8") is False  # never raises


def test_llm_prewarm_dispatches_to_anthropic_only(monkeypatch):
    from maverick.llm import LLM
    llm = LLM(model="claude-opus-4-8")
    called = {}

    class _Fake:
        def prewarm(self, system, tools, model):
            called["args"] = (system, tools, model)
            return True

    monkeypatch.setattr(llm, "_get_client", lambda provider: _Fake())
    monkeypatch.setattr("maverick.enterprise.assert_provider_allowed", lambda p: None)
    assert llm.prewarm("sys", [{"name": "x"}]) is True
    assert called["args"][2] == "claude-opus-4-8"

    # Non-anthropic model -> no-op (no warm hook).
    llm2 = LLM(model="openai:gpt-4o")
    assert llm2.prewarm("sys") is False


def test_prewarm_disabled_when_caching_off(monkeypatch):
    from maverick.llm import LLM
    monkeypatch.setenv("MAVERICK_CACHE_MESSAGES", "0")
    llm = LLM(model="claude-opus-4-8")
    assert llm.prewarm("sys") is False


def test_cache_prewarm_enabled_flag(monkeypatch):
    import maverick.llm as llm_mod
    monkeypatch.delenv("MAVERICK_CACHE_PREWARM", raising=False)
    monkeypatch.setattr(llm_mod, "load_config", dict, raising=False)
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)
    assert llm_mod.cache_prewarm_enabled() is False
    monkeypatch.setenv("MAVERICK_CACHE_PREWARM", "1")
    assert llm_mod.cache_prewarm_enabled() is True


def test_llm_prewarm_reserves_budget_before_provider_call(monkeypatch):
    from maverick.budget import Budget
    from maverick.llm import LLM

    llm = LLM(model="claude-opus-4-8")

    class _Fake:
        def prewarm(self, system, tools, model, *, budget=None):
            raise AssertionError("provider prewarm must not run after reserve failure")

    monkeypatch.setattr(llm, "_get_client", lambda provider: _Fake())
    monkeypatch.setattr("maverick.enterprise.assert_provider_allowed", lambda p: None)

    budget = Budget(max_dollars=0.0)
    assert llm.prewarm("billable system prompt", budget=budget) is False
    assert budget.dollars == 0.0
