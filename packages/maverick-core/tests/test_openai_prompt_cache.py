"""OpenAI write-side prompt-cache ordering tests.

No API calls. The openai SDK is mocked so OpenAIClient can be constructed
without the real client, then ``_build_kwargs`` is exercised directly.

OpenAI's automatic prompt cache hits on the longest common prefix of a
request (>= ~1024 tokens): system + tools + leading messages must be
byte-identical across calls. These tests lock in the cache-friendly
ordering for gpt-4.1 / o-series with a long stable prefix.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest
from maverick.providers.openai_provider import OpenAIClient


class _FakeClient:
    def __init__(self, api_key=None, base_url=None, timeout=None, max_retries=None):
        pass


class _FakeModule:
    OpenAI = _FakeClient
    AsyncOpenAI = _FakeClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", _FakeModule())
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    return OpenAIClient()


# A system prompt well over the ~1024-token (4 chars/token) min so the
# auto-cache reordering actually engages.
_LONG_SYSTEM = "You are a careful, long-horizon agent. " * 200

_UNSORTED_TOOLS = [
    {"name": "zebra", "description": "z", "input_schema": {"type": "object"}},
    {"name": "alpha", "description": "a", "input_schema": {"type": "object"}},
    {"name": "mike", "description": "m", "input_schema": {"type": "object"}},
]


def _tool_names(kwargs):
    return [t["function"]["name"] for t in kwargs["tools"]]


class TestCacheFriendlyOrdering:
    def test_system_leads_and_user_trails(self, client):
        kwargs = client._build_kwargs(
            _LONG_SYSTEM,
            [{"role": "user", "content": "the volatile question"}],
            _UNSORTED_TOOLS,
            max_tokens=256,
            model="gpt-4.1",
        )
        msgs = kwargs["messages"]
        # Stable prefix leads (system first), volatile user turn trails.
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == _LONG_SYSTEM
        assert msgs[-1]["role"] == "user"
        assert msgs[-1]["content"] == "the volatile question"

    def test_tools_sorted_for_stable_prefix(self, client):
        kwargs = client._build_kwargs(
            _LONG_SYSTEM, [{"role": "user", "content": "q"}],
            _UNSORTED_TOOLS, max_tokens=256, model="gpt-4.1",
        )
        assert _tool_names(kwargs) == ["alpha", "mike", "zebra"]

    def test_ordering_stable_across_two_calls(self, client):
        # Differently-ordered tool inputs must produce the same prefix so
        # the second call hits OpenAI's auto-cache instead of busting it.
        first = client._build_kwargs(
            _LONG_SYSTEM, [{"role": "user", "content": "first"}],
            _UNSORTED_TOOLS, max_tokens=256, model="o3",
        )
        reordered = list(reversed(_UNSORTED_TOOLS))
        second = client._build_kwargs(
            _LONG_SYSTEM, [{"role": "user", "content": "second"}],
            reordered, max_tokens=256, model="o3",
        )
        assert _tool_names(first) == _tool_names(second)
        assert first["messages"][0] == second["messages"][0]

    def test_small_prefix_not_reordered(self, client):
        # Below the ~1024-token min the cache can't engage, so we leave the
        # caller's tool order untouched (no behaviour change on small prompts).
        kwargs = client._build_kwargs(
            "short system", [{"role": "user", "content": "q"}],
            _UNSORTED_TOOLS, max_tokens=256, model="gpt-4.1",
        )
        assert _tool_names(kwargs) == ["zebra", "alpha", "mike"]

    def test_non_cache_model_not_reordered(self, client):
        # gpt-4o has no automatic prompt cache; leave order as-is even with
        # a long prefix.
        kwargs = client._build_kwargs(
            _LONG_SYSTEM, [{"role": "user", "content": "q"}],
            _UNSORTED_TOOLS, max_tokens=256, model="gpt-4o",
        )
        assert _tool_names(kwargs) == ["zebra", "alpha", "mike"]

    def test_input_list_not_mutated(self, client):
        original = list(_UNSORTED_TOOLS)
        client._build_kwargs(
            _LONG_SYSTEM, [{"role": "user", "content": "q"}],
            _UNSORTED_TOOLS, max_tokens=256, model="gpt-4.1",
        )
        # sorted() returns a new list; the caller's list is unchanged.
        assert original == _UNSORTED_TOOLS


class TestReasoningEffortMapping:
    """thinking_budget must not be silently dropped for OpenAI: it maps
    to reasoning_effort for o-series/gpt-5, and is skipped for non-reasoning
    models (gpt-4o/4.1 want max_completion_tokens but reject reasoning_effort)."""

    def test_budget_maps_to_effort_buckets(self):
        f = OpenAIClient._reasoning_effort_for
        assert f(None) is None
        assert f(0) is None
        assert f(2000) == "low"
        assert f(8000) == "medium"
        assert f(30000) == "high"

    def test_reasoning_model_gets_reasoning_effort(self, client):
        kwargs = client._build_kwargs(
            "sys", [{"role": "user", "content": "hi"}], None,
            max_tokens=256, model="o3-mini", thinking_budget=30000,
        )
        assert kwargs["reasoning_effort"] == "high"
        # o-series also wants max_completion_tokens, not max_tokens.
        assert "max_completion_tokens" in kwargs
        assert "max_tokens" not in kwargs

    def test_gpt5_gets_reasoning_effort(self, client):
        kwargs = client._build_kwargs(
            "sys", [{"role": "user", "content": "hi"}], None,
            max_tokens=256, model="gpt-5", thinking_budget=2000,
        )
        assert kwargs["reasoning_effort"] == "low"

    def test_non_reasoning_model_skips_reasoning_effort(self, client):
        # gpt-4o is in _wants_max_completion but is NOT a reasoning model;
        # sending reasoning_effort would 400.
        for model in ("gpt-4o", "gpt-4.1"):
            kwargs = client._build_kwargs(
                "sys", [{"role": "user", "content": "hi"}], None,
                max_tokens=256, model=model, thinking_budget=30000,
            )
            assert "reasoning_effort" not in kwargs

    def test_no_budget_no_reasoning_effort(self, client):
        kwargs = client._build_kwargs(
            "sys", [{"role": "user", "content": "hi"}], None,
            max_tokens=256, model="o3-mini", thinking_budget=None,
        )
        assert "reasoning_effort" not in kwargs


class TestMaxCompletionTokensOnTheWire:
    def test_gpt_6_sends_max_completion_tokens(self, client):
        """Production 400 on gpt-6.1-sol: "'max_tokens' is not supported with
        this model. Use 'max_completion_tokens' instead." """
        for model in ("gpt-6.1-sol", "gpt-6-luna", "gpt-6-astra"):
            kwargs = client._build_kwargs(
                "sys", [{"role": "user", "content": "q"}], None,
                max_tokens=256, model=model,
            )
            assert kwargs.get("max_completion_tokens") == 256, model
            assert "max_tokens" not in kwargs, model

    def test_older_models_keep_max_tokens(self, client):
        kwargs = client._build_kwargs(
            "sys", [{"role": "user", "content": "q"}], None,
            max_tokens=256, model="gpt-4-turbo",
        )
        assert kwargs.get("max_tokens") == 256
        assert "max_completion_tokens" not in kwargs


# ---------- openai_provider prompt-caching extraction ----------

def test_openai_provider_records_cache_read_tokens():
    """When usage.prompt_tokens_details.cached_tokens is present, it
    flows into budget as cache_read_tok and billable input = full - cached.
    """
    try:
        from openai import OpenAI  # noqa: F401
    except ImportError:
        pytest.skip("openai SDK not installed")
    from maverick.budget import Budget
    from maverick.providers.openai_provider import OpenAIClient

    # Build a fake response shape matching the SDK's pydantic model.
    fake_choice = MagicMock()
    fake_choice.message.content = "hi"
    fake_choice.message.tool_calls = None
    fake_choice.finish_reason = "stop"

    fake_usage = MagicMock()
    fake_usage.prompt_tokens = 1000
    fake_usage.completion_tokens = 50
    # OpenAI-style cached tokens.
    fake_usage.prompt_tokens_details.cached_tokens = 400
    # Make sure the DeepSeek-shaped attr isn't preferred when OpenAI's is set.
    fake_usage.prompt_cache_hit_tokens = 999

    fake_resp = MagicMock()
    fake_resp.choices = [fake_choice]
    fake_resp.usage = fake_usage

    budget = Budget(max_dollars=10.0)
    OpenAIClient._from_response(fake_resp, budget, model="gpt-5.4")

    # full=1000, cached=400 -> billable=600 to input_tokens; cached -> cache_read_tokens.
    assert budget.input_tokens == 600
    assert budget.cache_read_tokens == 400
    assert budget.output_tokens == 50


def test_openai_provider_records_deepseek_cache_hit_tokens():
    """DeepSeek puts cached count under prompt_cache_hit_tokens."""
    try:
        from openai import OpenAI  # noqa: F401
    except ImportError:
        pytest.skip("openai SDK not installed")
    from maverick.budget import Budget
    from maverick.providers.openai_provider import OpenAIClient

    fake_choice = MagicMock()
    fake_choice.message.content = "hi"
    fake_choice.message.tool_calls = None
    fake_choice.finish_reason = "stop"

    fake_usage = MagicMock()
    fake_usage.prompt_tokens = 2000
    fake_usage.completion_tokens = 100
    # DeepSeek shape: OpenAI-style details absent, fall through to *_hit_tokens.
    fake_usage.prompt_tokens_details = None
    fake_usage.prompt_cache_hit_tokens = 800

    fake_resp = MagicMock()
    fake_resp.choices = [fake_choice]
    fake_resp.usage = fake_usage

    budget = Budget(max_dollars=10.0)
    OpenAIClient._from_response(
        fake_resp,
        budget,
        model="deepseek-v4-flash",
    )

    assert budget.input_tokens == 1200
    assert budget.cache_read_tokens == 800
    assert budget.output_tokens == 100


def test_openai_provider_no_cache_data_records_full_input():
    """When no cache fields, full prompt_tokens count as billable."""
    try:
        from openai import OpenAI  # noqa: F401
    except ImportError:
        pytest.skip("openai SDK not installed")
    from maverick.budget import Budget
    from maverick.providers.openai_provider import OpenAIClient

    fake_choice = MagicMock()
    fake_choice.message.content = "hi"
    fake_choice.message.tool_calls = None
    fake_choice.finish_reason = "stop"

    fake_usage = MagicMock()
    fake_usage.prompt_tokens = 500
    fake_usage.completion_tokens = 50
    fake_usage.prompt_tokens_details = None
    # Explicitly delete the DeepSeek attr so getattr returns the default.
    del fake_usage.prompt_cache_hit_tokens

    fake_resp = MagicMock()
    fake_resp.choices = [fake_choice]
    fake_resp.usage = fake_usage

    budget = Budget(max_dollars=10.0)
    OpenAIClient._from_response(fake_resp, budget, model="gpt-5.4")

    assert budget.input_tokens == 500
    assert budget.cache_read_tokens == 0
    assert budget.output_tokens == 50
