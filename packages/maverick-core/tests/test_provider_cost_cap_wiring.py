"""The deployment-wide provider spend cap ([budget.provider_caps]) must be
ENFORCED on the LLM dispatch path -- it was a configured-but-inert control."""
from __future__ import annotations

import pytest
from maverick.llm import LLM, MODEL_SONNET, LLMResponse


def _resp(text: str) -> LLMResponse:
    return LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason="end_turn")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_call_blocked_when_provider_over_cap(monkeypatch):
    from maverick import provider_cost_cap as pcc
    from maverick.provider_cost_cap import ProviderCapExceeded
    monkeypatch.setattr(pcc, "caps_from_config", lambda: {"anthropic": 1.0})
    pcc.record("anthropic", 2.0)  # seed the period ledger OVER the $1 cap

    dispatched = []

    class FakeClient:
        def complete(self, **kw):
            dispatched.append(1)
            return _resp("ok")

    monkeypatch.setattr(LLM, "_get_client", lambda self, p: FakeClient())
    with pytest.raises(ProviderCapExceeded):
        LLM(model=f"anthropic:{MODEL_SONNET}").complete(
            "sys", [{"role": "user", "content": "hi"}])
    assert dispatched == []  # blocked BEFORE the provider was called


def test_spend_recorded_to_the_cap_ledger_after_a_call(monkeypatch):
    from maverick import provider_cost_cap as pcc
    recorded = []
    monkeypatch.setattr(pcc, "caps_from_config", dict)  # no cap -> never blocks
    monkeypatch.setattr(
        pcc, "record",
        lambda provider, dollars, **k: recorded.append((provider, dollars)))

    class FakeClient:
        def complete(self, **kw):
            return _resp("ok")

    monkeypatch.setattr(LLM, "_get_client", lambda self, p: FakeClient())
    LLM(model=f"anthropic:{MODEL_SONNET}").complete(
        "sys", [{"role": "user", "content": "hi"}])
    assert recorded and recorded[0][0] == "anthropic"  # spend fed to the cap ledger


def test_no_cap_configured_is_a_noop(monkeypatch):
    # Default install (no provider_caps) must be unaffected: a call goes through.
    from maverick import provider_cost_cap as pcc
    monkeypatch.setattr(pcc, "caps_from_config", dict)

    class FakeClient:
        def complete(self, **kw):
            return _resp("through")

    monkeypatch.setattr(LLM, "_get_client", lambda self, p: FakeClient())
    out = LLM(model=f"anthropic:{MODEL_SONNET}").complete(
        "sys", [{"role": "user", "content": "hi"}])
    assert out.text == "through"
