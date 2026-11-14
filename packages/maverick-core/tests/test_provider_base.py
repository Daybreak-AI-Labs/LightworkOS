"""Tests for the shared provider base (maverick.providers.base)."""
from __future__ import annotations

# --- provider SDK clients get a bounded timeout ---

def test_llm_http_timeout_is_bounded():
    from maverick.providers.base import llm_http_timeout
    t = llm_http_timeout()
    if t is not None:  # httpx present
        import httpx
        assert isinstance(t, httpx.Timeout)


def test_non_streamed_generation_gets_a_read_timeout_sized_to_max_tokens(monkeypatch):
    # A non-streamed call sends nothing until it finishes, so a fixed 120 s
    # read timeout aborted (and retried, unrecorded) any longer generation.
    import pytest
    from maverick.providers.anthropic_provider import AnthropicClient

    monkeypatch.delenv("MAVERICK_LLM_READ_TIMEOUT", raising=False)
    sent: list[dict] = []

    class _Stop(Exception):
        pass

    def _create(**kw):
        sent.append(kw)
        raise _Stop

    client = AnthropicClient(api_key="sk-test")  # pragma: allowlist secret
    monkeypatch.setattr(client.client.messages, "create", _create)
    for max_tokens in (32_000, 1_024):
        with pytest.raises(_Stop):
            client.complete(system="s", messages=[{"role": "user", "content": "hi"}],
                            max_tokens=max_tokens, model="claude-sonnet-4-5")
    assert sent[0]["timeout"].read >= 32_000 * 3600 / 128_000
    assert "timeout" not in sent[1]  # the configured 120 s already covers it
    from maverick.providers.base import MAX_GENERATION_READ_TIMEOUT, generation_timeout
    assert generation_timeout(__import__("anthropic"), 1_000_000)["timeout"].read == MAX_GENERATION_READ_TIMEOUT
