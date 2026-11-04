"""[providers.<name>] default_headers — data-residency / ZDR control.

Operator-set headers are attached to every request so a compliance gateway can
enforce region pinning / zero-data-retention. Threaded into the two primary
cloud clients (anthropic, openai) via the provider factory + LLM._get_client.
"""
from __future__ import annotations


def test_anthropic_client_threads_default_headers(monkeypatch):
    from maverick.providers import anthropic_provider as ap

    captured: dict = {}

    class _FakeAnthropic:
        def __init__(self, **kw):
            captured.update(kw)

    monkeypatch.setattr(ap.anthropic, "Anthropic", _FakeAnthropic)
    monkeypatch.setattr(ap.anthropic, "AsyncAnthropic", _FakeAnthropic)
    ap.AnthropicClient(api_key="k", default_headers={"anthropic-region": "eu"})
    assert captured.get("default_headers") == {"anthropic-region": "eu"}


def test_anthropic_client_no_headers_by_default(monkeypatch):
    from maverick.providers import anthropic_provider as ap

    captured: dict = {}
    monkeypatch.setattr(ap.anthropic, "Anthropic",
                        lambda **kw: captured.update(kw))
    monkeypatch.setattr(ap.anthropic, "AsyncAnthropic", lambda **kw: None)
    ap.AnthropicClient(api_key="k")
    assert "default_headers" not in captured


def test_llm_reads_default_headers_from_config(monkeypatch):
    from maverick.llm import LLM

    seen: dict = {}

    def fake_get_provider_client(provider, **kw):
        seen["provider"] = provider
        seen["default_headers"] = kw.get("default_headers")
        return object()

    monkeypatch.setattr(
        "maverick.config.get_provider_config",
        lambda p: {"default_headers": {"x-no-retention": "1"}} if p == "anthropic" else {},
    )
    monkeypatch.setattr("maverick.providers.get_provider_client", fake_get_provider_client)
    # Ensure the anthropic branch builds an API client (key present).
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    client = LLM(model="claude-opus-4-8")._get_client("anthropic")
    assert client is not None
    assert seen["default_headers"] == {"x-no-retention": "1"}


def test_llm_rejects_non_dict_default_headers_before_factory(monkeypatch):
    import pytest
    from maverick.llm import LLM

    seen: dict = {}
    monkeypatch.setattr(
        "maverick.config.get_provider_config",
        lambda p: {"default_headers": "not-a-dict"} if p == "anthropic" else {},
    )
    monkeypatch.setattr(
        "maverick.providers.get_provider_client",
        lambda provider, **kw: seen.update(kw) or object(),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    with pytest.raises(ValueError, match="default_headers must be a table"):
        LLM(model="claude-opus-4-8")._get_client("anthropic")
    assert seen == {}
