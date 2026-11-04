"""OpenAI-compatible providers must strip the API key.

Regression: a trailing newline (`echo $KEY > file`) or stray whitespace
otherwise 401s every call. OpenAIClient strips the resolved key, which
covers openrouter / deepseek / ollama / moonshot / xai / tgi / vllm --
they all pass their key through OpenAIClient.
"""
import sys
import types

import pytest


class _FakeOpenAIClient:
    def __init__(self, **kwargs):
        self.api_key = kwargs.get("api_key")
        self.base_url = kwargs.get("base_url")


def _install_fake_openai(monkeypatch):
    fake = types.ModuleType("openai")
    fake.OpenAI = _FakeOpenAIClient
    fake.AsyncOpenAI = _FakeOpenAIClient
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_openai_client_strips_key(monkeypatch):
    _install_fake_openai(monkeypatch)
    from maverick.providers.openai_provider import OpenAIClient
    client = OpenAIClient(api_key="sk-test-123\n  ")
    assert client._sync.api_key == "sk-test-123"
    assert client._async.api_key == "sk-test-123"


def test_openai_client_all_whitespace_key_becomes_none(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from maverick.providers.openai_provider import OpenAIClient
    # A whitespace-only key must not masquerade as a real one.
    client = OpenAIClient(api_key="   \n")
    assert client._sync.api_key in (None, "")


def test_openai_client_refuses_sdk_env_fallback_when_disabled(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-env-secret")
    from maverick.providers.openai_provider import OpenAIClient

    with pytest.raises(RuntimeError, match="requires a non-empty API key"):
        OpenAIClient(
            api_key="   \n",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            allow_openai_env_fallback=False,
        )


@pytest.mark.parametrize("env_var", ["GEMINI_API_KEY", "GOOGLE_API_KEY"])
def test_gemini_client_rejects_whitespace_key_instead_of_openai_fallback(monkeypatch, env_var):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-env-secret")
    monkeypatch.setenv(env_var, "   \n")
    other_env = "GOOGLE_API_KEY" if env_var == "GEMINI_API_KEY" else "GEMINI_API_KEY"
    monkeypatch.delenv(other_env, raising=False)
    from maverick.providers.gemini_provider import GeminiClient

    with pytest.raises(RuntimeError, match="requires a non-empty API key"):
        GeminiClient()
