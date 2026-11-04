"""Tests for the Azure OpenAI provider."""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib


def _openai_available() -> bool:
    try:
        import openai  # noqa: F401
        return True
    except ImportError:
        return False


_needs_openai = pytest.mark.skipif(
    not _openai_available(), reason="openai extra not installed")


def _clear_azure_auth(monkeypatch):
    for name in (
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_AD_TOKEN",
        "AZURE_OPENAI_AUTH",
        "AZURE_OPENAI_TOKEN_SCOPE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_azure_extra_installs_bounded_identity_dependency():
    metadata = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    requirements = [
        Requirement(item)
        for item in metadata["project"]["optional-dependencies"]["azure"]
    ]
    by_name = {requirement.name: requirement for requirement in requirements}

    assert "openai" in by_name
    assert Version("1.25.3") in by_name["azure-identity"].specifier
    assert Version("2.0.0") not in by_name["azure-identity"].specifier


@_needs_openai
def test_azure_requires_config(monkeypatch):
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_DEPLOYMENT", raising=False)
    from maverick.providers.azure_openai_provider import AzureOpenAIClient
    try:
        AzureOpenAIClient()
    except RuntimeError as e:
        assert "AZURE_OPENAI_ENDPOINT" in str(e)
        return
    raise AssertionError("expected RuntimeError")


@_needs_openai
def test_azure_uses_dedicated_client(monkeypatch):
    """The provider must build the SDK's AzureOpenAI client (which sends
    the api-key header + api-version query), NOT a plain OpenAI client
    with the api-version baked into base_url (the SDK drops it)."""
    from openai import AzureOpenAI
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://res.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt5")
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-10-21")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "k")
    monkeypatch.delenv("AZURE_OPENAI_AD_TOKEN", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_AUTH", raising=False)
    from maverick.providers.azure_openai_provider import AzureOpenAIClient
    c = AzureOpenAIClient()
    assert isinstance(c._sync, AzureOpenAI)
    assert c.deployment == "gpt5"
    assert c.api_version == "2024-10-21"
    assert c.endpoint == "https://res.openai.azure.com"
    assert c.DEFAULT_MODEL == "gpt5"
    assert c.auth_mode == "api_key"


def test_azure_auth_never_substitutes_fake_key(monkeypatch):
    from maverick.providers.azure_openai_provider import _azure_auth

    _clear_azure_auth(monkeypatch)
    with pytest.raises(RuntimeError, match="requires authentication"):
        _azure_auth(None, None)


def test_azure_auth_rejects_ambiguous_credentials(monkeypatch):
    from maverick.providers.azure_openai_provider import _azure_auth

    _clear_azure_auth(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "real-key")
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", "real-token")
    with pytest.raises(RuntimeError, match="exactly one"):
        _azure_auth(None, None)


def test_azure_auth_supports_static_entra_token(monkeypatch):
    from maverick.providers.azure_openai_provider import _azure_auth

    _clear_azure_auth(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", " entra-token ")
    kwargs, owner, mode = _azure_auth(None, None)
    assert kwargs == {"azure_ad_token": "entra-token"}
    assert owner is None
    assert mode == "entra_id"


def test_azure_entra_token_is_not_forwarded_as_an_api_key(monkeypatch):
    import maverick.llm as llm

    _clear_azure_auth(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", "entra-token")
    monkeypatch.setattr(llm, "_configured_provider_api_key", lambda _provider: None)

    assert llm._provider_api_key("azure", None) is None


def test_azure_auth_uses_documented_default_credential_path(monkeypatch):
    from maverick.providers.azure_openai_provider import AzureOpenAIClient

    _clear_azure_auth(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://res.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt5")
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "entra_id")
    monkeypatch.setenv("AZURE_OPENAI_TOKEN_SCOPE", "scope://custom/.default")

    calls = []

    class _FakeAzureClient:
        def __init__(self, **kwargs):
            calls.append(kwargs)

    fake_openai = types.ModuleType("openai")
    fake_openai.AzureOpenAI = _FakeAzureClient
    fake_openai.AsyncAzureOpenAI = _FakeAzureClient
    monkeypatch.setitem(sys.modules, "openai", fake_openai)

    credential = object()
    scopes = []

    def provider():
        return "entra-token"

    class _DefaultAzureCredential:
        def __new__(cls):
            return credential

    def _get_bearer_token_provider(owner, scope):
        scopes.append((owner, scope))
        return provider

    azure = types.ModuleType("azure")
    azure.__path__ = []
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = _DefaultAzureCredential
    identity.get_bearer_token_provider = _get_bearer_token_provider
    monkeypatch.setitem(sys.modules, "azure", azure)
    monkeypatch.setitem(sys.modules, "azure.identity", identity)

    client = AzureOpenAIClient()

    assert scopes == [(credential, "scope://custom/.default")]
    assert len(calls) == 2
    assert all(call["azure_ad_token_provider"] is provider for call in calls)
    assert all("api_key" not in call for call in calls)
    assert client.auth_mode == "entra_id"
    assert client._azure_credential is credential
