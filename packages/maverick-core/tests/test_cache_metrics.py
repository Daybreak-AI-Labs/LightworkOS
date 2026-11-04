"""Prompt-cache effectiveness metric: _parse_response emits cache token buckets."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest


@pytest.fixture
def _client(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    from maverick.providers.anthropic_provider import AnthropicClient
    return AnthropicClient()


def _resp(*, input_tokens, output_tokens, cache_read, cache_creation):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text="hi")],
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=input_tokens, output_tokens=output_tokens,
            cache_read_input_tokens=cache_read,
            cache_creation_input_tokens=cache_creation,
        ),
    )


def test_parse_response_records_token_and_cache_metrics(_client, monkeypatch):
    calls: list[tuple[str, float, dict]] = []

    import maverick.observability as obs
    monkeypatch.setattr(obs, "record_metric",
                        lambda name, value=1.0, *, labels=None: calls.append((name, value, labels or {})))

    _client._parse_response(
        _resp(input_tokens=100, output_tokens=40, cache_read=900, cache_creation=0),
        budget=None, model="claude-opus-4-8",
    )
    by = {(n, lbl.get("direction") or lbl.get("kind")): v for n, v, lbl in calls}
    assert by[("llm_tokens", "input")] == 100
    assert by[("llm_tokens", "output")] == 40
    assert by[("llm_cache_tokens", "read")] == 900
    assert by[("llm_cache_tokens", "uncached")] == 100
    # No creation this turn -> not recorded.
    assert ("llm_cache_tokens", "creation") not in by
    # Hit rate the operator would compute: 900 / (900 + 100) = 90%.
    assert by[("llm_cache_tokens", "read")] / (
        by[("llm_cache_tokens", "read")] + by[("llm_cache_tokens", "uncached")]
    ) == pytest.approx(0.9)


def test_metrics_are_failsoft(_client, monkeypatch):
    import maverick.observability as obs

    def _boom(*a, **k):
        raise RuntimeError("metrics backend down")

    monkeypatch.setattr(obs, "record_metric", _boom)
    # A metrics error must not break response parsing.
    out = _client._parse_response(
        _resp(input_tokens=10, output_tokens=5, cache_read=0, cache_creation=10),
        budget=None, model="claude-opus-4-8",
    )
    assert out.text == "hi"


def test_cache_metric_registered():
    # The counter is wired into the exporter's metric registry definition.
    import maverick.observability as obs
    src = open(obs.__file__, encoding="utf-8").read() if os.path.exists(obs.__file__) else ""
    assert "maverick_llm_cache_tokens_total" in src
