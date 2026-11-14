"""Cache identity, expiry and provider request/accounting edge cases."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


def test_learning_owner_case_is_exact_while_task_case_is_normalized():
    from maverick.cache.learning import task_key

    assert task_key("owner:Alice\nSummarize THIS.") != task_key("owner:alice\nSummarize THIS.")
    assert task_key("owner:Alice\nSummarize THIS.") == task_key("owner:Alice\n summarize this ")


@pytest.mark.parametrize("name", ["consent_check", "retention_check", "breach_notification", "coordinated_disclosure"])
def test_temporal_governance_tools_are_never_cached(name):
    from maverick.cache.tool import cacheable

    assert not cacheable(SimpleNamespace(name=name, parallel_safe=True))
    assert cacheable(SimpleNamespace(name="rbac_check", parallel_safe=True))


def test_redis_hit_does_not_restart_expiring_entry_age(monkeypatch):
    from maverick.cache import tool as cache

    cache.reset()
    clock = [100.0]
    monkeypatch.setattr(cache, "enabled", lambda: True)
    monkeypatch.setattr(cache, "_sync_epoch", lambda: "generation")
    monkeypatch.setattr(cache, "_warmed", True)
    monkeypatch.setattr(cache, "_ttl_s", lambda: 10)
    monkeypatch.setattr(cache.time, "monotonic", lambda: clock[0])
    backend = SimpleNamespace(get=lambda *args, **kwargs: (True, "fresh") if clock[0] < 101 else (False, None))
    monkeypatch.setattr(cache, "_shared_backend", lambda: backend)
    tool = SimpleNamespace(name="read_file", parallel_safe=True)
    assert cache.get_cached(tool, {}) == (True, "fresh")
    clock[0] = 102
    assert cache.get_cached(tool, {}) == (False, None)
    cache.reset()


@pytest.mark.parametrize("samples,expected", [([(1, 1, 1), (2, 1, 0)], (0, .5)),
                                                ([(1, 1, 1), (1, 2, 0)], (.5, 0))])
def test_nonnegative_cost_fit_refits_unclamped_coefficient(samples, expected):
    from maverick.cost.curve_fitter import fit_curve

    fitted = fit_curve(samples)
    assert (fitted.a, fitted.b) == expected


def test_azure_completion_override_uses_client_environment(monkeypatch):
    import openai
    from maverick.providers.azure_openai_provider import AzureOpenAIClient

    monkeypatch.setattr(openai, "AzureOpenAI", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(openai, "AsyncAzureOpenAI", lambda **kwargs: SimpleNamespace())
    monkeypatch.setenv("AZURE_OPENAI_USE_MAX_COMPLETION", "0")
    env = {"AZURE_OPENAI_ENDPOINT": "https://azure.example", "AZURE_OPENAI_DEPLOYMENT": "deployment",
           "AZURE_OPENAI_API_KEY": "synthetic", "AZURE_OPENAI_USE_MAX_COMPLETION": "1"}  # pragma: allowlist secret -- synthetic client fixture
    client = AzureOpenAIClient(environment=env)
    assert client._wants_max_completion("deployment")
    env["AZURE_OPENAI_USE_MAX_COMPLETION"] = "0"
    assert client._wants_max_completion("deployment")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_aborted_anthropic_stream_retains_observed_usage(monkeypatch, asynchronous):
    from maverick.budget import Budget
    from maverick.providers.anthropic_provider import AnthropicClient

    usage = SimpleNamespace(input_tokens=100, output_tokens=4, cache_read_input_tokens=20,
                            cache_creation_input_tokens=10)

    class Stream:
        current_message_snapshot = SimpleNamespace(usage=usage)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        @property
        def text_stream(self):
            async def texts():
                yield "partial"
            return texts() if asynchronous else iter(["partial"])

    client = AnthropicClient.__new__(AnthropicClient)
    endpoint = SimpleNamespace(stream=lambda **kwargs: Stream())
    client.client = client.aclient = SimpleNamespace(messages=endpoint)
    monkeypatch.setattr(client, "_build_request", lambda *args, **kwargs: {"model": "claude-sonnet-4-6"})
    budget = Budget()

    def abort(_text):
        raise RuntimeError("display disconnected")

    with pytest.raises(RuntimeError, match="display disconnected"):
        if asynchronous:
            asyncio.run(client.complete_async("", [], budget=budget, on_delta=abort))
        else:
            client.complete("", [], budget=budget, on_delta=abort)
    assert (budget.input_tokens, budget.output_tokens, budget.cache_read_tokens, budget.cache_write_tokens) == (100, 4, 20, 10)
    assert budget.dollars > 0
