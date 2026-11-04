from __future__ import annotations

from typing import Any

import anthropic
from maverick.providers import anthropic_provider


class _CaptureClient:
    calls: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


def test_anthropic_client_uses_the_sdk_native_timeout(monkeypatch) -> None:
    _CaptureClient.calls.clear()
    monkeypatch.setenv("MAVERICK_LLM_CONNECT_TIMEOUT", "7")
    monkeypatch.setenv("MAVERICK_LLM_READ_TIMEOUT", "31")
    monkeypatch.setattr(anthropic_provider.anthropic, "Anthropic", _CaptureClient)
    monkeypatch.setattr(anthropic_provider.anthropic, "AsyncAnthropic", _CaptureClient)

    anthropic_provider.AnthropicClient(api_key="test-key")  # pragma: allowlist secret

    assert len(_CaptureClient.calls) == 2
    for kwargs in _CaptureClient.calls:
        assert kwargs["max_retries"] == 0
        timeout = kwargs["timeout"]
        assert isinstance(timeout, anthropic.Timeout)
        assert timeout.connect == 7.0
        assert timeout.read == 31.0
        assert timeout.write == 31.0
        assert timeout.pool == 31.0
