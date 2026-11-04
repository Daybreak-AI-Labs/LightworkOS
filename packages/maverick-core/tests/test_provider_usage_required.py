"""Provider hardening regressions.

- A missing ``usage`` block aborts the turn for PAID providers (fail-closed) but
  NOT for self-hosted ollama/vllm/tgi (USAGE_REQUIRED=False): those price at $0,
  and many local OpenAI-compatible servers omit usage on non-streaming calls.
- Unparseable tool-call arguments are surfaced (warning), not silently swallowed.
"""
from __future__ import annotations

import logging
import os
from types import SimpleNamespace

import pytest
from maverick.budget import Budget, BudgetExceeded, UsageAccountingError, _coerce_count
from maverick.providers.ollama_provider import OllamaClient
from maverick.providers.openai_provider import OpenAIClient, _strict_usage_count
from maverick.providers.openrouter_provider import OpenRouterClient


class _Msg:
    def __init__(self, content="hi", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.reasoning_content = None


class _Choice:
    def __init__(self, msg, finish_reason="stop"):
        self.message = msg
        self.finish_reason = finish_reason


class _Resp:
    """An OpenAI-compatible response with NO usage block."""
    def __init__(self, msg, usage=None):
        self.choices = [_Choice(msg)]
        self.usage = usage


def test_paid_provider_missing_usage_aborts():
    # USAGE_REQUIRED is True on the base/paid client -> fail closed.
    budget = Budget(max_dollars=10.0)
    with pytest.raises(UsageAccountingError, match="missing token usage"):
        OpenAIClient._from_response(_Resp(_Msg()), budget, model="gpt-4o",
                                    usage_required=True)


@pytest.mark.parametrize("invalid", [0.5, -0.5, True, False, "", [], {}])
@pytest.mark.parametrize("field", ["prompt_tokens", "completion_tokens"])
def test_paid_provider_rejects_noninteger_usage(field, invalid):
    usage = {"prompt_tokens": 10, "completion_tokens": 5}
    usage[field] = invalid
    budget = Budget(max_dollars=10.0)
    with pytest.raises(UsageAccountingError, match="invalid OpenAI usage"):
        OpenAIClient._from_response(
            _Resp(_Msg(), SimpleNamespace(**usage)), budget, model="gpt-4o",
        )
    assert budget.input_tokens == 0
    assert budget.output_tokens == 0


@pytest.mark.parametrize("value", [5, 5.0, "5"])
def test_usage_accepts_valid_integral_counts(value):
    assert _strict_usage_count(value, "test") == 5


@pytest.mark.parametrize("missing", ["prompt_tokens", "completion_tokens"])
def test_paid_provider_rejects_missing_individual_usage_count(missing):
    usage = {"prompt_tokens": 10, "completion_tokens": 5}
    del usage[missing]
    with pytest.raises(UsageAccountingError, match="missing token count"):
        OpenAIClient._from_response(
            _Resp(_Msg(), SimpleNamespace(**usage)), Budget(max_dollars=10.0), model="gpt-4o",
        )


def test_self_hosted_missing_usage_does_not_abort():
    # ollama/vllm/tgi set USAGE_REQUIRED=False; a usage-less response must NOT
    # raise -- it records a $0 zero-token call and returns the text.
    assert OllamaClient.USAGE_REQUIRED is False
    budget = Budget(max_dollars=10.0)
    r = OpenAIClient._from_response(_Resp(_Msg("local answer")), budget,
                                    model="llama3.3:70b",
                                    price_model_prefix="ollama:",
                                    usage_required=False)
    assert r.text == "local answer"
    # $0 self-hosted: nothing was billed.
    assert budget.dollars == 0.0


def test_openrouter_free_model_response_records_the_provider_qualified_price(monkeypatch):
    from maverick import model_discovery

    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    monkeypatch.setattr(model_discovery, "free_models",
                        lambda provider: ["vendor/free"] if provider == "openrouter" else [])
    budget = Budget(max_dollars=1.0)
    response = _Resp(_Msg("answer"), SimpleNamespace(prompt_tokens=10, completion_tokens=5))

    result = OpenRouterClient._from_response(
        response, budget, model="vendor/free",
        price_model_prefix=OpenRouterClient.PRICE_MODEL_PREFIX,
    )

    assert result.text == "answer"
    assert budget.dollars == 0.0


class _BadArgsToolCall:
    class function:
        name = "do_thing"
        arguments = "{not valid json"
    id = "call_1"


def test_unparseable_tool_args_warns_and_uses_empty(caplog):
    msg = _Msg(tool_calls=[_BadArgsToolCall()])
    with caplog.at_level(logging.WARNING, logger="maverick.providers.openai_provider"):
        r = OpenAIClient._from_response(_Resp(msg), None)
    assert r.tool_calls and r.tool_calls[0].input == {}
    assert any("unparseable arguments" in rec.message for rec in caplog.records)


class _SecretBadArgsToolCall:
    class function:
        name = "exfiltrate"
        arguments = '{"api_key":"sk-ABCDEFGHIJKLMNOPQRSTUV1234567890", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"'
    id = "call_secret"


def test_unparseable_tool_args_warning_scrubs_raw_arguments(caplog):
    msg = _Msg(tool_calls=[_SecretBadArgsToolCall()])
    with caplog.at_level(logging.WARNING, logger="maverick.providers.openai_provider"):
        r = OpenAIClient._from_response(_Resp(msg), None)
    assert r.tool_calls and r.tool_calls[0].input == {}
    messages = "\n".join(rec.message for rec in caplog.records)
    assert "unparseable arguments" in messages
    assert "sk-ABCDEFGHIJKLMNOPQRSTUV1234567890" not in messages
    assert "abcdefghijklmnopqrstuvwxyz123456" not in messages
    assert "[REDACTED:openai_key]" in messages
    assert "[REDACTED:bearer]" in messages


def _openai_response_with_usage(**usage_fields):
    choice = SimpleNamespace(
        message=SimpleNamespace(content="hi", tool_calls=None),
        finish_reason="stop",
    )
    usage = SimpleNamespace(**usage_fields)
    return SimpleNamespace(choices=[choice], usage=usage)


def _client():
    from maverick.providers.anthropic_provider import AnthropicClient
    return AnthropicClient.__new__(AnthropicClient)


def _kwargs(model: str, *, thinking_budget, temp: str):
    os.environ["MAVERICK_TEMPERATURE"] = temp
    try:
        return _client()._build_request(
            system="s", messages=[{"role": "user", "content": "hi"}],
            tools=None, max_tokens=1024, thinking_budget=thinking_budget, model=model,
        )
    finally:
        os.environ.pop("MAVERICK_TEMPERATURE", None)


def _kwargs_ctx(model: str, *, thinking_budget, temp):
    from maverick.providers.base import (
        reset_sampling_temperature,
        set_sampling_temperature,
    )
    tok = set_sampling_temperature(temp)
    try:
        return _client()._build_request(
            system="s", messages=[{"role": "user", "content": "hi"}],
            tools=None, max_tokens=1024, thinking_budget=thinking_budget, model=model,
        )
    finally:
        reset_sampling_temperature(tok)


def test_coerce_count_handles_none_and_valid_counts() -> None:
    assert _coerce_count(None) == 0
    assert _coerce_count(0) == 0
    assert _coerce_count(3.9) == 3         # finite float truncates
    assert _coerce_count(7) == 7


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), "not a number", -5])
def test_coerce_count_fails_closed_on_invalid_counts(bad) -> None:
    with pytest.raises(UsageAccountingError, match="invalid token usage count"):
        _coerce_count(bad)


def test_usage_accounting_error_is_not_a_budget_cap_breach() -> None:
    # Malformed provider usage is a gateway fault. It must stop the run
    # but never masquerade as "budget exceeded" (raising the cap can't fix it)
    # and provider failover must not mask it by trying another model.
    from maverick.provider_failover import should_retry_llm_error

    assert not issubclass(UsageAccountingError, BudgetExceeded)
    assert should_retry_llm_error(UsageAccountingError("invalid usage")) is False


def test_record_tokens_survives_none_usage_counts() -> None:
    b = Budget(max_dollars=1.0)
    # None remains a tolerated missing count, and must not corrupt totals.
    b.record_tokens(
        None, None,
        model="claude-haiku-4-5",
        cache_read_tok=None, cache_write_tok=None,
    )
    assert b.dollars == 0.0
    assert b.input_tokens == 0 and b.output_tokens == 0
    # A normal call after a missing-count one still accounts correctly.
    b.record_tokens(1_000_000, 0, model="claude-haiku-4-5")
    assert b.dollars > 0.0


@pytest.mark.parametrize("kwargs", [
    {"in_tok": float("nan"), "out_tok": 0},
    {"in_tok": 0, "out_tok": float("inf")},
    {"in_tok": 0, "out_tok": 0, "cache_read_tok": "bad-cache"},
    {"in_tok": 0, "out_tok": 0, "cache_write_tok": -1},
])
def test_record_tokens_fails_closed_on_invalid_usage_counts(kwargs) -> None:
    b = Budget(max_dollars=1.0)

    with pytest.raises(UsageAccountingError, match="invalid token usage count"):
        b.record_tokens(model="claude-haiku-4-5", **kwargs)

    assert b.dollars == 0.0
    assert b.input_tokens == 0 and b.output_tokens == 0


def test_openai_provider_fails_closed_on_malformed_usage() -> None:
    from maverick.providers.openai_provider import OpenAIClient

    b = Budget(max_dollars=1.0)
    resp = _openai_response_with_usage(
        prompt_tokens=float("nan"),
        completion_tokens=float("inf"),
        prompt_tokens_details=SimpleNamespace(cached_tokens="bad-cache"),
    )

    with pytest.raises(UsageAccountingError, match="invalid OpenAI usage"):
        OpenAIClient._from_response(resp, b, model="gpt-5.4")

    assert b.input_tokens == 0
    assert b.output_tokens == 0
    assert b.cache_read_tokens == 0
    assert b.dollars == 0.0


def test_openai_provider_fails_closed_when_usage_missing() -> None:
    from maverick.providers.openai_provider import OpenAIClient

    b = Budget(max_dollars=1.0)
    resp = SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content="hi", tool_calls=None),
            finish_reason="stop",
        )],
        usage=None,
    )

    with pytest.raises(UsageAccountingError, match="missing token usage"):
        OpenAIClient._from_response(resp, b, model="gpt-5.4")

    assert b.dollars == 0.0


def test_temperature_dropped_when_thinking_active_opus_default() -> None:
    # Opus 4.8 with no explicit budget auto-injects adaptive thinking; sending
    # temperature alongside it is a 400.
    k = _kwargs("claude-opus-4-8", thinking_budget=None, temp="0.9")
    assert k.get("thinking") == {"type": "adaptive"}
    assert "temperature" not in k


def test_temperature_applied_without_thinking() -> None:
    # A non-thinking model still honors MAVERICK_TEMPERATURE (best-of-N diversity).
    k = _kwargs("claude-haiku-4-5", thinking_budget=None, temp="0.9")
    assert "thinking" not in k
    assert k.get("temperature") == 0.9


def test_temperature_from_contextvar_applied_without_thinking() -> None:
    # best-of-N now sets the per-attempt temperature via a ContextVar (race-free
    # across concurrent goals), not os.environ.
    k = _kwargs_ctx("claude-haiku-4-5", thinking_budget=None, temp=0.85)
    assert "thinking" not in k
    assert k.get("temperature") == 0.85


def test_contextvar_temperature_takes_precedence_over_env(monkeypatch) -> None:
    monkeypatch.setenv("MAVERICK_TEMPERATURE", "0.1")
    from maverick.providers.base import (
        reset_sampling_temperature,
        set_sampling_temperature,
    )
    tok = set_sampling_temperature(0.85)
    try:
        k = _client()._build_request(
            system="s", messages=[{"role": "user", "content": "hi"}],
            tools=None, max_tokens=1024, thinking_budget=None, model="claude-haiku-4-5",
        )
    finally:
        reset_sampling_temperature(tok)
    assert k.get("temperature") == 0.85   # contextvar wins over the env fallback


def test_contextvar_temperature_dropped_when_thinking_active() -> None:
    k = _kwargs_ctx("claude-opus-4-8", thinking_budget=None, temp=0.9)
    assert k.get("thinking") == {"type": "adaptive"}
    assert "temperature" not in k
