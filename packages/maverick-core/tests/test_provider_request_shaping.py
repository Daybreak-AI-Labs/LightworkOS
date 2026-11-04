"""Provider request shaping.

- Anthropic: the messages cache breakpoint must strip cache_control carried in
  from prior turns, so system + tools + messages never exceeds Anthropic's hard
  4-breakpoint limit on long trajectories.
- Azure: max_completion_tokens vs max_tokens can be forced via
  AZURE_OPENAI_USE_MAX_COMPLETION, since the deployment name defeats the base
  model-id prefix-match.
"""
from __future__ import annotations


def _count_cache_marks(messages):
    n = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, list):
            n += sum(1 for b in c if isinstance(b, dict) and "cache_control" in b)
    return n


def test_breakpoint_strips_prior_marks_and_keeps_one():
    from maverick.providers.anthropic_provider import _add_messages_cache_breakpoint
    # History already carrying two stale breakpoints from earlier turns.
    messages = [
        {"role": "user", "content": [
            {"type": "text", "text": "old",
             "cache_control": {"type": "ephemeral"}}]},
        {"role": "assistant", "content": [
            {"type": "text", "text": "reply",
             "cache_control": {"type": "ephemeral"}}]},
        {"role": "user", "content": [{"type": "text", "text": "now"}]},
    ]
    out = _add_messages_cache_breakpoint(messages)
    # Exactly one breakpoint survives (the freshly-added one); the stale marks
    # are gone, so system + tools + messages <= 3 <= 4.
    assert _count_cache_marks(out) == 1


def test_breakpoint_noop_on_tiny_history_unchanged():
    from maverick.providers.anthropic_provider import _add_messages_cache_breakpoint
    messages = [{"role": "user", "content": "hi"}]
    assert _add_messages_cache_breakpoint(messages) == messages


def test_azure_use_max_completion_env_forces_true(monkeypatch):
    from maverick.providers.azure_openai_provider import AzureOpenAIClient
    monkeypatch.setenv("AZURE_OPENAI_USE_MAX_COMPLETION", "1")
    # A free-form deployment name that the base prefix-match would miss.
    assert AzureOpenAIClient._wants_max_completion("my-o3-deploy") is True


def test_azure_use_max_completion_env_forces_false(monkeypatch):
    from maverick.providers.azure_openai_provider import AzureOpenAIClient
    monkeypatch.setenv("AZURE_OPENAI_USE_MAX_COMPLETION", "0")
    # Even a name the base would flag is forced off when explicitly disabled.
    assert AzureOpenAIClient._wants_max_completion("gpt-5-turbo") is False


def test_azure_unset_falls_back_to_base_heuristic(monkeypatch):
    from maverick.providers.azure_openai_provider import AzureOpenAIClient
    from maverick.providers.openai_provider import OpenAIClient
    monkeypatch.delenv("AZURE_OPENAI_USE_MAX_COMPLETION", raising=False)
    for name in ("gpt-5", "o3-mini", "gpt-4o", "gpt-4-turbo"):
        assert (
            AzureOpenAIClient._wants_max_completion(name)
            == OpenAIClient._wants_max_completion(name)
        )
