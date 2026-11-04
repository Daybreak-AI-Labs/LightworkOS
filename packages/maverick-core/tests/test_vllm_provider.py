"""Tests for the vLLM provider."""
from __future__ import annotations

import pytest


def _openai_available() -> bool:
    try:
        import openai  # noqa: F401
        return True
    except ImportError:
        return False


_needs_openai = pytest.mark.skipif(
    not _openai_available(),
    reason="openai SDK extra not installed in this env",
)


# ---------- vLLM provider ----------

@_needs_openai
def test_vllm_provider_default_url(monkeypatch):
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)
    monkeypatch.delenv("VLLM_API_KEY", raising=False)
    from maverick.providers.vllm_provider import VLLMClient
    c = VLLMClient()
    assert c.DEFAULT_MODEL == "vllm"
    assert c.base_url.endswith("/v1")


@_needs_openai
def test_vllm_provider_env_url(monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", "http://gpu-box:8000")
    monkeypatch.setenv("VLLM_API_KEY", "sekret")
    from maverick.providers.vllm_provider import VLLMClient
    c = VLLMClient()
    assert c.base_url == "http://gpu-box:8000/v1"


def test_vllm_registered_in_provider_registry():
    """Registry membership check works without instantiating."""
    from maverick.providers import KNOWN_PROVIDERS
    assert "vllm" in KNOWN_PROVIDERS


@_needs_openai
def test_vllm_provider_instantiates():
    from maverick.providers import get_provider_client
    c = get_provider_client("vllm")
    assert c.__class__.__name__ == "VLLMClient"
