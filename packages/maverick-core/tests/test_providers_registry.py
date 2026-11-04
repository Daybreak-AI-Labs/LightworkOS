"""Registry resolves all 8 BYOK providers + their common aliases.

This test doesn't make any network calls — it just verifies that every
provider name is wired up and importable. Each provider's actual API
behavior (auth, model dispatch) is covered by the provider-specific
tests that hit a mocked SDK client.
"""
from __future__ import annotations

import importlib.util
import sys
import types

import pytest
from maverick.providers import KNOWN_PROVIDERS, get_provider_client

# All non-anthropic providers route through the OpenAI SDK (directly, or
# via openai-compatible base_url). If the optional `openai` extra isn't
# installed, those construction tests should skip rather than fail —
# we're testing wiring, not the SDK itself.
_HAS_OPENAI_SDK = importlib.util.find_spec("openai") is not None
_needs_openai = pytest.mark.skipif(
    not _HAS_OPENAI_SDK,
    reason="openai SDK not installed (pip install 'maverick-agent[openai]')",
)


CANONICAL_NAMES = (
    "anthropic", "openai", "moonshot", "xai", "gemini",
    "deepseek", "openrouter", "ollama",
)


ALIASES = {
    "claude":    "anthropic",
    "chatgpt":   "openai",
    "gpt":       "openai",
    "kimi":      "moonshot",
    "grok":      "xai",
    "google":    "gemini",
    "local":     "ollama",
}


class TestProviderRegistry:
    def test_known_providers_complete(self):
        for name in CANONICAL_NAMES:
            assert name in KNOWN_PROVIDERS, f"{name} not in KNOWN_PROVIDERS"

    @pytest.mark.parametrize("name", CANONICAL_NAMES)
    def test_canonical_name_instantiates(self, name, monkeypatch):
        # Anthropic is the only provider not gated on the openai SDK.
        if name != "anthropic" and not _HAS_OPENAI_SDK:
            pytest.skip("openai SDK not installed")
        # Stub env vars so providers can construct without network keys.
        for env in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MOONSHOT_API_KEY",
            "XAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY",
            "OPENROUTER_API_KEY", "GOOGLE_API_KEY",
        ):
            monkeypatch.setenv(env, "sk-test-placeholder")
        client = get_provider_client(name)
        assert client is not None, f"{name} returned None"

    @pytest.mark.parametrize("alias,canonical", list(ALIASES.items()))
    def test_alias_resolves_to_canonical(self, alias, canonical, monkeypatch):
        """Users typing 'kimi' / 'grok' / 'claude' get the right provider."""
        if canonical != "anthropic" and not _HAS_OPENAI_SDK:
            pytest.skip("openai SDK not installed")
        for env in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MOONSHOT_API_KEY",
            "XAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY",
            "OPENROUTER_API_KEY", "GOOGLE_API_KEY",
        ):
            monkeypatch.setenv(env, "sk-test-placeholder")
        client_alias = get_provider_client(alias)
        client_canon = get_provider_client(canonical)
        assert type(client_alias) is type(client_canon), (
            f"{alias!r} should resolve to {canonical!r} client class"
        )

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError) as exc:
            get_provider_client("not-a-real-provider")
        assert "Available" in str(exc.value)

    @_needs_openai
    def test_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        a = get_provider_client("OpenAI")
        b = get_provider_client("OPENAI")
        c = get_provider_client("openai")
        assert type(a) is type(b) is type(c)


@_needs_openai
class TestNewProviderEndpoints:
    """The three new BYOK providers default to the right base_url."""

    def test_moonshot_default_url(self, monkeypatch):
        monkeypatch.setenv("MOONSHOT_API_KEY", "sk-test")
        monkeypatch.delenv("MOONSHOT_BASE_URL", raising=False)
        from maverick.providers.moonshot_provider import MoonshotClient
        client = MoonshotClient()
        # The OpenAI SDK stores base_url on the underlying client.
        assert "moonshot" in str(client._sync.base_url).lower()

    def test_deepseek_default_url(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
        monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)
        from maverick.providers.deepseek_provider import DeepSeekClient
        client = DeepSeekClient()
        assert "deepseek" in str(client._sync.base_url).lower()

    def test_xai_default_url(self, monkeypatch):
        monkeypatch.setenv("XAI_API_KEY", "sk-test")
        monkeypatch.delenv("XAI_BASE_URL", raising=False)
        from maverick.providers.xai_provider import XaiClient
        client = XaiClient()
        assert "x.ai" in str(client._sync.base_url).lower()

    def test_xai_grok_api_key_alias(self, monkeypatch):
        """User may set GROK_API_KEY (the brand name they know) instead
        of XAI_API_KEY. Both should work."""
        monkeypatch.delenv("XAI_API_KEY", raising=False)
        monkeypatch.setenv("GROK_API_KEY", "sk-grok-test")
        from maverick.providers.xai_provider import XaiClient
        client = XaiClient()
        # Key found via the alias → client constructs without error.
        assert client is not None

    def test_env_var_overrides_default_url(self, monkeypatch):
        """For users behind corp proxies or China-region Moonshot users."""
        monkeypatch.setenv("MOONSHOT_API_KEY", "sk-test")
        monkeypatch.setenv("MOONSHOT_BASE_URL", "https://api.moonshot.cn/v1")
        from maverick.providers.moonshot_provider import MoonshotClient
        client = MoonshotClient()
        assert "moonshot.cn" in str(client._sync.base_url)


class _FakeOpenAIClient:
    def __init__(self, api_key=None, base_url=None, timeout=None, max_retries=None):
        self.api_key = api_key
        self.base_url = base_url


def _install_fake_openai(monkeypatch):
    fake = types.ModuleType("openai")
    fake.OpenAI = _FakeOpenAIClient
    fake.AsyncOpenAI = _FakeOpenAIClient
    monkeypatch.setitem(sys.modules, "openai", fake)


class TestThirdPartyProvidersDoNotFallbackToOpenAIKey:
    # When a third-party (OpenAI-compatible) provider has no key of its own,
    # we must NOT hand the OpenAI SDK api_key=None, because the SDK would then
    # read OPENAI_API_KEY from the environment and send it to the provider's
    # base_url. These providers set allow_openai_env_fallback=False, so the
    # client now fails closed with RuntimeError instead of constructing a
    # client that silently leaks the OpenAI key.
    def test_moonshot_does_not_use_openai_env_key(self, monkeypatch):
        _install_fake_openai(monkeypatch)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-should-not-leak")
        monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
        from maverick.providers.moonshot_provider import MoonshotClient
        with pytest.raises(RuntimeError, match="requires a non-empty API key"):
            MoonshotClient()

    def test_deepseek_does_not_use_openai_env_key(self, monkeypatch):
        _install_fake_openai(monkeypatch)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-should-not-leak")
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        from maverick.providers.deepseek_provider import DeepSeekClient
        with pytest.raises(RuntimeError, match="requires a non-empty API key"):
            DeepSeekClient()

    def test_xai_does_not_use_openai_env_key(self, monkeypatch):
        _install_fake_openai(monkeypatch)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-should-not-leak")
        monkeypatch.delenv("XAI_API_KEY", raising=False)
        monkeypatch.delenv("GROK_API_KEY", raising=False)
        from maverick.providers.xai_provider import XaiClient
        with pytest.raises(RuntimeError, match="requires a non-empty API key"):
            XaiClient()


def _clear_azure_auth(monkeypatch):
    for name in (
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_AD_TOKEN",
        "AZURE_OPENAI_AUTH",
        "AZURE_OPENAI_TOKEN_SCOPE",
    ):
        monkeypatch.delenv(name, raising=False)


# ---------- Providers ----------

def test_providers_registered():
    from maverick.providers import KNOWN_PROVIDERS
    assert "azure" in KNOWN_PROVIDERS
    assert "bedrock" in KNOWN_PROVIDERS


def test_azure_identity_dependency_is_preflighted(monkeypatch):
    import importlib.util

    from maverick import providers

    _clear_azure_auth(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "entra_id")

    def _find_spec(name):
        return None if name == "azure.identity" else object()

    monkeypatch.setattr(importlib.util, "find_spec", _find_spec)
    messages = providers.missing_sdks(["azure:gpt5"])

    assert any("maverick-core[azure]" in message for message in messages)


def test_static_azure_ad_token_does_not_require_identity_sdk(monkeypatch):
    import importlib.util

    from maverick import providers

    _clear_azure_auth(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", "static-token")

    def _find_spec(name):
        return None if name == "azure.identity" else object()

    monkeypatch.setattr(importlib.util, "find_spec", _find_spec)
    assert providers.missing_sdks(["azure:gpt5"]) == []
