"""Outbound prompt redaction (data-minimization before egress).

Opt-in / default-off: the kernel sends the prompt verbatim unless
[privacy] redact_egress / MAVERICK_REDACT_EGRESS is on. When on, PII/secrets are
stripped from the outbound copy at the LLM chokepoint -- but only for cloud
providers (local/self-hosted data never leaves the box).
"""
from __future__ import annotations

import pytest
from maverick.llm import LLM, LLMResponse

OPUS = "claude-opus-4-8"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_REDACT_EGRESS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_disabled_by_default():
    from maverick.privacy_egress import redact_egress_enabled
    assert redact_egress_enabled() is False


def test_env_enables(monkeypatch):
    from maverick.privacy_egress import redact_egress_enabled
    monkeypatch.setenv("MAVERICK_REDACT_EGRESS", "1")
    assert redact_egress_enabled() is True


def test_redact_prompt_handles_str_and_block_content():
    from maverick.privacy_egress import redact_prompt
    system, messages = redact_prompt(
        "reach me at jane@example.com",
        [
            {"role": "user", "content": "my ssn is 123-45-6789"},
            {"role": "user", "content": [{"type": "text", "text": "call 555-123-4567"}]},
        ],
    )
    assert "jane@example.com" not in system and "[REDACTED" in system
    assert "123-45-6789" not in messages[0]["content"]
    assert "555-123-4567" not in messages[1]["content"][0]["text"]


def test_redact_prompt_covers_tool_result_and_tool_use_channels():
    # Regression: the highest-volume egress channel is tool output. tool_result
    # carries its payload in `content` (str OR nested block list) and tool_use in
    # `input` -- neither is a `text` field, so the old redactor skipped them and
    # cat .env / db-query PII reached the provider verbatim.
    from maverick.privacy_egress import redact_prompt
    _, messages = redact_prompt(
        "s",
        [
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "a",
                 "content": "customer ssn 123-45-6789 email bob@corp.com"},
                {"type": "tool_result", "tool_use_id": "b",
                 "content": [{"type": "text", "text": "card 4111 1111 1111 1111"}]},
            ]},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "c", "name": "lookup",
                 "input": {"q": "ssn 123-45-6789", "nested": {"email": "eve@corp.com"}}},
            ]},
        ],
    )
    tr0 = messages[0]["content"][0]["content"]
    assert "123-45-6789" not in tr0 and "bob@corp.com" not in tr0
    assert "4111 1111 1111 1111" not in messages[0]["content"][1]["content"][0]["text"]
    tu_in = messages[1]["content"][0]["input"]
    assert "123-45-6789" not in tu_in["q"]
    assert "eve@corp.com" not in tu_in["nested"]["email"]


def test_redact_prompt_does_not_mutate_caller_messages():
    from maverick.privacy_egress import redact_prompt
    original = [{"role": "user", "content": "ssn 123-45-6789"}]
    _, redacted = redact_prompt("s", original)
    assert original[0]["content"] == "ssn 123-45-6789"  # untouched
    assert "123-45-6789" not in redacted[0]["content"]


def test_local_provider_is_not_redacted(monkeypatch):
    from maverick.privacy_egress import maybe_redact_egress
    monkeypatch.setenv("MAVERICK_REDACT_EGRESS", "1")
    s, _ = maybe_redact_egress("ollama", "email a@b.com", [])
    assert s == "email a@b.com"  # data stays on-box; no redaction


class _FakeClient:
    def __init__(self):
        self.seen = {}

    def complete(self, **kwargs):
        self.seen = kwargs
        return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")


def test_chokepoint_redacts_when_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_REDACT_EGRESS", "1")
    client = _FakeClient()
    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: client)

    LLM(model=OPUS).complete(
        "contact bob@example.com", [{"role": "user", "content": "ssn 123-45-6789"}],
    )
    assert "bob@example.com" not in client.seen["system"]
    assert "123-45-6789" not in client.seen["messages"][0]["content"]


def test_chokepoint_passthrough_when_disabled(monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: client)

    LLM(model=OPUS).complete(
        "contact bob@example.com", [{"role": "user", "content": "hi"}],
    )
    assert client.seen["system"] == "contact bob@example.com"  # unchanged
