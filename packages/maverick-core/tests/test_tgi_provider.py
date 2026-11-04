"""Tests for the Hugging Face TGI provider."""
from __future__ import annotations

import sys
import types

# ---------- TGI provider ----------

class _FakeOpenAIClient:
    def __init__(self, api_key=None, base_url=None, timeout=None, max_retries=None):
        self.api_key = api_key
        self.base_url = base_url


def _install_fake_openai(monkeypatch):
    fake = types.ModuleType("openai")
    fake.OpenAI = _FakeOpenAIClient
    fake.AsyncOpenAI = _FakeOpenAIClient
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_tgi_provider_default_url(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.delenv("TGI_BASE_URL", raising=False)
    monkeypatch.delenv("TGI_API_KEY", raising=False)
    from maverick.providers.tgi_provider import TGIClient
    client = TGIClient()
    assert "8080" in client._sync.base_url
    assert client._sync.base_url.endswith("/v1")


def test_tgi_provider_env_overrides(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("TGI_BASE_URL", "http://my-tgi.example.com:9999")
    monkeypatch.setenv("TGI_API_KEY", "secret-token")
    from maverick.providers.tgi_provider import TGIClient
    client = TGIClient()
    # /v1 suffix appended automatically when missing.
    assert client._sync.base_url == "http://my-tgi.example.com:9999/v1"
    assert client._sync.api_key == "secret-token"


def test_tgi_provider_v1_suffix_idempotent(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("TGI_BASE_URL", "http://my-tgi.example.com/v1")
    from maverick.providers.tgi_provider import TGIClient
    client = TGIClient()
    # Already had /v1; don't double-suffix.
    assert client._sync.base_url == "http://my-tgi.example.com/v1"


def test_tgi_provider_in_registry():
    from maverick.providers import KNOWN_PROVIDERS, _canonical
    assert "tgi" in KNOWN_PROVIDERS
    assert _canonical("hf-tgi") == "tgi"
    assert _canonical("huggingface-tgi") == "tgi"


def test_tgi_provider_dispatches(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.delenv("TGI_BASE_URL", raising=False)
    from maverick.providers import get_provider_client
    from maverick.providers.tgi_provider import TGIClient
    client = get_provider_client("tgi")
    assert isinstance(client, TGIClient)
    # Alias also dispatches.
    client2 = get_provider_client("hf-tgi")
    assert isinstance(client2, TGIClient)
