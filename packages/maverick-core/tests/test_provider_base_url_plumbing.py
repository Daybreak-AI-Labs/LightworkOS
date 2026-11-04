"""Self-hosted provider config must work end-to-end from config.toml alone.

Found by running the platform as a user: the preflight (`maverick start`)
accepts ``[providers.vllm] base_url`` as "a configured provider", but the
LLM facade never plumbed that base_url into the client -- only ``api_key``
crossed ``get_provider_client`` -- so the client fell back to its env var /
localhost default and the run died with "Couldn't reach the LLM provider".
Conversely, env-only setups (``VLLM_BASE_URL``, the documented mechanism in
the provider docstrings) failed the preflight. Ollama was worst: its client
reads no env at all, so the config key was the ONLY surface -- and it was
dead.

Pins:
  - ``get_provider_client`` forwards ``base_url`` to the local clients
  - the LLM facade reads ``[providers.<name>] base_url`` and forwards it
  - ``maverick.config.any_provider_configured()`` is the ONE predicate:
    key envs, base-url envs, or config providers all count
"""
from __future__ import annotations

import pytest
from maverick.config import any_provider_configured

_KEY_VARS = (
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
    "OPENROUTER_API_KEY", "MOONSHOT_API_KEY", "DEEPSEEK_API_KEY",
    "XAI_API_KEY",
)
_URL_VARS = ("VLLM_BASE_URL", "TGI_BASE_URL", "OPENAI_COMPATIBLE_BASE_URL")


@pytest.fixture
def clean_provider_env(monkeypatch, tmp_path):
    for v in _KEY_VARS + _URL_VARS:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    return tmp_path / "config.toml"


class _Recorder:
    last_kwargs: dict | None = None

    def __init__(self, api_key=None, base_url=None):
        type(self).last_kwargs = {"api_key": api_key, "base_url": base_url}


def test_dispatch_forwards_base_url_to_vllm(monkeypatch):
    import maverick.providers.vllm_provider as vp
    from maverick.providers import get_provider_client

    monkeypatch.setattr(vp, "VLLMClient", _Recorder)
    get_provider_client("vllm", api_key=None, base_url="http://h:1/v1")
    assert _Recorder.last_kwargs == {"api_key": None, "base_url": "http://h:1/v1"}


def test_dispatch_forwards_base_url_to_ollama(monkeypatch):
    import maverick.providers.ollama_provider as op
    from maverick.providers import get_provider_client

    monkeypatch.setattr(op, "OllamaClient", _Recorder)
    get_provider_client("ollama", base_url="http://h:2/v1")
    assert _Recorder.last_kwargs["base_url"] == "http://h:2/v1"


@pytest.mark.parametrize("address", ["http://localhost:11434", "http://localhost:11434/v1/"])
def test_ollama_root_and_api_addresses_point_chat_at_the_same_endpoint(address):
    pytest.importorskip("openai")
    from maverick.providers.ollama_provider import OllamaClient

    client = OllamaClient(base_url=address)
    try:
        assert client.base_url == "http://localhost:11434/v1"
        assert str(client._sync.base_url) == "http://localhost:11434/v1/"
    finally:
        client._sync.close()


@pytest.mark.parametrize("provider, module, cls", [
    ("deepseek", "deepseek_provider", "DeepSeekClient"),
    ("gemini", "gemini_provider", "GeminiClient"),
    ("moonshot", "moonshot_provider", "MoonshotClient"),
    ("xai", "xai_provider", "XaiClient"),
    ("openrouter", "openrouter_provider", "OpenRouterClient"),
])
def test_dispatch_forwards_base_url_to_cloud_vendors(monkeypatch, provider, module, cls):
    """A configured ``[providers.<name>] base_url`` was silently dropped for
    the OpenAI-translated cloud vendors: the registry constructed them with
    ``api_key`` only, so a gateway / regional endpoint (e.g. moonshot's China
    endpoint, a compliance proxy for deepseek/xai) was ignored and every
    request went to the vendor default."""
    import importlib

    from maverick.providers import get_provider_client

    mod = importlib.import_module(f"maverick.providers.{module}")
    monkeypatch.setattr(mod, cls, _Recorder)
    get_provider_client(provider, api_key="k", base_url="https://gw.corp/v1")
    assert _Recorder.last_kwargs == {"api_key": "k", "base_url": "https://gw.corp/v1"}


def test_llm_facade_passes_config_base_url(clean_provider_env, monkeypatch):
    clean_provider_env.write_text(
        '[providers.vllm]\nbase_url = "http://cfg-host:9/v1"\n', encoding="utf-8"
    )
    import maverick.llm as llm_mod
    captured = {}

    def fake_get_provider_client(name, api_key=None, base_url=None, default_headers=None, environment=None):
        captured["call"] = (name, api_key, base_url)
        return object()

    import maverick.providers as providers_mod
    monkeypatch.setattr(providers_mod, "get_provider_client", fake_get_provider_client)
    llm_mod.LLM(model="vllm:stub")._get_client("vllm")
    assert captured["call"] == ("vllm", None, "http://cfg-host:9/v1")


def test_predicate_false_when_nothing_configured(clean_provider_env):
    assert any_provider_configured() is False


def test_predicate_true_on_key_env(clean_provider_env, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    assert any_provider_configured() is True


def test_predicate_true_on_base_url_env(clean_provider_env, monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", "http://127.0.0.1:9911")
    assert any_provider_configured() is True


def test_predicate_true_on_config_base_url(clean_provider_env):
    clean_provider_env.write_text(
        '[providers.ollama]\nbase_url = "http://127.0.0.1:11434"\n', encoding="utf-8"
    )
    assert any_provider_configured() is True


def test_predicate_ignores_empty_interpolated_key(clean_provider_env, monkeypatch):
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    clean_provider_env.write_text(
        '[providers.anthropic]\napi_key = "${NOT_SET_ANYWHERE}"\n', encoding="utf-8"
    )
    assert any_provider_configured() is False


def test_channel_server_accepts_selected_keyless_local_provider(
    clean_provider_env, monkeypatch,
):
    """`maverick serve` had its own hard-coded ANTHROPIC_API_KEY-only gate
    (server.py build_from_config), refusing config-only self-hosted setups
    that `start` and the dashboard accept."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "vllm:stub")
    clean_provider_env.write_text(
        '[providers.vllm]\nbase_url = "http://127.0.0.1:9911/v1"\n'
        "[channels.cli]\nenabled = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(clean_provider_env.parent))
    monkeypatch.setenv("USERPROFILE", str(clean_provider_env.parent))

    import pytest as _pytest
    from maverick.server import build_from_config
    # Passing the provider gate is proven by reaching the NEXT error in the
    # build (no channels wired in this bare config) -- the gate itself must
    # not fire for a config-only self-hosted provider.
    with _pytest.raises(RuntimeError, match="[Nn]o channels enabled"):
        build_from_config()


def test_channel_server_still_refuses_unconfigured(clean_provider_env, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import pytest as _pytest
    from maverick.server import build_from_config
    with _pytest.raises(RuntimeError, match="[Nn]o LLM provider"):
        build_from_config()
