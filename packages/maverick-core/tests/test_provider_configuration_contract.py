"""Admission and installed adapter construction only; no provider calls."""
from __future__ import annotations

import importlib
from dataclasses import FrozenInstanceError

import pytest
from maverick.llm import LLM
from maverick.providers import KNOWN_PROVIDERS, get_provider_client
from maverick.providers.configuration import CAPABILITIES, canonical_headers

ADAPTERS = {
    "anthropic": ("anthropic_provider", "AnthropicClient"),
    "openai": ("openai_provider", "OpenAIClient"),
    "azure": ("azure_openai_provider", "AzureOpenAIClient"),
    "bedrock": ("bedrock_provider", "BedrockClient"),
    "vertex": ("vertex_provider", "VertexClient"),
    "openrouter": ("openrouter_provider", "OpenRouterClient"),
    "ollama": ("ollama_provider", "OllamaClient"),
    "gemini": ("gemini_provider", "GeminiClient"),
    "moonshot": ("moonshot_provider", "MoonshotClient"),
    "deepseek": ("deepseek_provider", "DeepSeekClient"),
    "xai": ("xai_provider", "XaiClient"),
    "tgi": ("tgi_provider", "TGIClient"),
    "vllm": ("vllm_provider", "VLLMClient"),
    "openai_compatible": ("openai_compatible_provider", "OpenAICompatibleClient"),
    "codex_cli": ("codex_cli_provider", "CodexCLIClient"),
}


def recorder(monkeypatch, provider):
    calls = []
    module, cls = ADAPTERS[provider]
    monkeypatch.setattr(importlib.import_module(f"maverick.providers.{module}"), cls,
                        lambda **kw: calls.append(kw) or object())
    return calls


def test_capability_inventory_covers_every_provider():
    assert set(CAPABILITIES) == set(KNOWN_PROVIDERS) == set(ADAPTERS)


@pytest.mark.parametrize("provider", KNOWN_PROVIDERS)
def test_supported_factory_options_reach_exact_adapter(monkeypatch, provider):
    calls = recorder(monkeypatch, provider)
    kwargs = {"environment": {"FIXTURE": "admitted"}}
    # Only fields the adapter admits are passed (vertex has no api_key: Google ADC only).
    if "api_key" in CAPABILITIES[provider].fields:
        kwargs["api_key"] = "fixture-key"  # pragma: allowlist secret - synthetic provider recorder fixture
    if "base_url" in CAPABILITIES[provider].fields:
        kwargs["base_url"] = "https://fixture.invalid/v1"
    if "default_headers" in CAPABILITIES[provider].fields:
        kwargs["default_headers"] = {"X-Residency": "fixture"}
    if provider == "codex_cli":
        kwargs["provider_options"] = {"binary": "fixture", "sandbox_mode": "read-only", "timeout_seconds": 30, "cwd": "fixture"}
    get_provider_client(provider, **kwargs)
    assert len(calls) == 1
    for name, value in kwargs.items():
        assert calls[0][name] == value


@pytest.mark.parametrize("provider", [p for p in KNOWN_PROVIDERS if "default_headers" not in CAPABILITIES[p].fields])
def test_unsupported_headers_fail_before_adapter_and_do_not_disclose_values(monkeypatch, provider):
    calls = recorder(monkeypatch, provider)
    with pytest.raises(ValueError, match=rf"providers\.{provider}\.default_headers") as error:
        get_provider_client(provider, default_headers={"X-Residency": "confidential-value"})
    assert calls == [] and "confidential-value" not in str(error.value)


@pytest.mark.parametrize("provider,field,value", [
    ("codex_cli", "base_url", "https://fixture.invalid"),
    ("openai", "auth_mode", "iam"),
    ("azure", "endpoint", "mantle"),
    ("bedrock", "binary", "fixture"),
    ("anthropic", "timeout_seconds", 13),
    ("openrouter", "unrecognized_setting", "fixture"),
])
def test_unknown_or_unsupported_config_refused_before_client_cache(monkeypatch, provider, field, value):
    calls = recorder(monkeypatch, provider)
    monkeypatch.setattr("maverick.config.get_provider_config", lambda _: {field: value})
    dispatcher = LLM()
    with pytest.raises(ValueError, match=rf"providers\.{provider}\.{field}"):
        dispatcher._get_client(provider)
    assert not calls and not dispatcher._client_cache


@pytest.mark.parametrize("headers", ["invalid", {"X": "one", "x": "two"}, {"X\nSecret": "value"}, {"X": "one\r\ntwo"}, {"X": []}])  # pragma: allowlist secret - synthetic rejected header fixture
def test_invalid_headers_cannot_be_ignored(headers):
    with pytest.raises(ValueError, match="default_headers"):
        canonical_headers(headers)


@pytest.mark.parametrize("provider,option,value,expected", [
    ("azure", "auth_mode", "entra_id", ("AZURE_OPENAI_AUTH", "entra_id")),
    ("bedrock", "auth_mode", "api_key", ("BEDROCK_AUTH_MODE", "api_key")),
    ("bedrock", "endpoint", "legacy", ("BEDROCK_ENDPOINT", "legacy")),
])
def test_adapter_specific_effective_options_reach_environment(monkeypatch, provider, option, value, expected):
    calls = recorder(monkeypatch, provider)
    monkeypatch.setattr("maverick.config.get_provider_config", lambda _: {option: value})
    LLM()._get_client(provider)
    assert calls[0]["environment"][expected[0]] == expected[1]


def test_codex_options_and_environment_rotate_cache_without_mutating_admitted_values(monkeypatch):
    calls = recorder(monkeypatch, "codex_cli")
    state = {"api_key": "fixture-secret", "binary": "fixture", "sandbox_mode": "read-only", "timeout_seconds": "30", "cwd": "fixture-a"}  # pragma: allowlist secret - synthetic cache admission fixture
    monkeypatch.setattr("maverick.config.get_provider_config", lambda _: dict(state))
    monkeypatch.setenv("CODEX_HOME", "fixture-home-a")
    dispatcher = LLM()
    admitted = dispatcher._provider_client_config("codex_cli")
    assert "fixture-secret" not in repr(admitted)
    with pytest.raises(FrozenInstanceError):
        admitted.api_key = "changed"  # pragma: allowlist secret - synthetic rejected mutation fixture
    first = dispatcher._get_client("codex_cli")
    state["timeout_seconds"] = 30.0
    assert dispatcher._get_client("codex_cli") is first
    state["cwd"] = "fixture-b"
    second = dispatcher._get_client("codex_cli")
    assert second is not first
    monkeypatch.setenv("CODEX_HOME", "fixture-home-b")
    assert dispatcher._get_client("codex_cli") is not second
    assert len(calls) == 3 and len(dispatcher._client_cache) == 1
    assert admitted.options_dict()["cwd"] == "fixture-a"
    assert calls[0]["environment"]["CODEX_HOME"] == "fixture-home-a"


@pytest.mark.parametrize("provider", ["openai", "openrouter", "gemini", "moonshot", "deepseek", "xai", "openai_compatible"])
def test_absent_admitted_key_never_uses_a_later_environment_key(monkeypatch, provider):
    import openai
    from maverick.config import PROVIDER_KEY_ENV_MAP

    calls = []
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: calls.append(kw))
    monkeypatch.setattr(openai, "AsyncOpenAI", lambda **kw: calls.append(kw))
    for name in PROVIDER_KEY_ENV_MAP[provider]:
        monkeypatch.setenv(name, "later-secret")
    with pytest.raises(RuntimeError, match="API key"):
        get_provider_client(provider, base_url="https://fixture.invalid/v1", environment={})
    assert not calls


def test_anthropic_absent_admitted_credentials_never_uses_live_secret(monkeypatch):
    import anthropic
    calls = []
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: calls.append(kw))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "later-secret")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "later-token")
    with pytest.raises(RuntimeError, match="admitted provider configuration"):
        get_provider_client("anthropic", environment={})
    assert not calls


def test_admitted_openai_endpoint_headers_timeout_and_sync_async_match(monkeypatch):
    import openai
    calls = []
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: calls.append(kw))
    monkeypatch.setattr(openai, "AsyncOpenAI", lambda **kw: calls.append(kw))
    monkeypatch.setenv("OPENAI_BASE_URL", "https://later.invalid")
    monkeypatch.setenv("MAVERICK_LLM_READ_TIMEOUT", "999")
    get_provider_client("openai", api_key="admitted", default_headers={"X-Residency": "fixture"},  # pragma: allowlist secret - synthetic mocked SDK fixture
                        environment={"MAVERICK_LLM_READ_TIMEOUT": "17"})
    assert len(calls) == 2
    assert all(call["base_url"] == "https://api.openai.com/v1" for call in calls)
    assert all(call["default_headers"] == {"X-Residency": "fixture"} for call in calls)
    assert all(call["timeout"].read == 17 and call["max_retries"] == 0 for call in calls)


def test_configuration_change_and_key_rotation_reuse_only_equivalent_client(monkeypatch):
    calls = recorder(monkeypatch, "openai")
    state = {"api_key": "fixture-a", "default_headers": {"X-Residency": "a"}}  # pragma: allowlist secret - synthetic key rotation fixture
    monkeypatch.setattr("maverick.config.get_provider_config", lambda _: dict(state))
    dispatcher = LLM()
    first = dispatcher._get_client("openai")
    assert dispatcher._get_client("openai") is first
    state["api_key"] = "fixture-b"  # pragma: allowlist secret - synthetic key rotation fixture
    second = dispatcher._get_client("openai")
    assert second is not first
    state["base_url"] = "https://next.invalid/v1"
    assert dispatcher._get_client("openai") is not second
    assert len(calls) == 3 and len(dispatcher._client_cache) == 1


@pytest.mark.parametrize("endpoint", ["mantle", "legacy"])
def test_installed_bedrock_sdk_cannot_silently_override_iam_with_ambient_bearer(monkeypatch, endpoint):
    """Real SDK constructors; dependency presence stubbed, no IAM resolution."""
    import anthropic
    from maverick.providers import bedrock_provider as bedrock

    original_find = bedrock.importlib.util.find_spec
    monkeypatch.setattr(bedrock.importlib.util, "find_spec", lambda name: object() if name in ("boto3", "botocore") else original_find(name))
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "later-live-token")
    monkeypatch.setenv("ANTHROPIC_AWS_API_KEY", "later-live-token")
    sync_cls = anthropic.AnthropicBedrockMantle if endpoint == "mantle" else anthropic.AnthropicBedrock
    original_close = sync_cls.close
    closed = []

    def close(client):
        closed.append(client)
        return original_close(client)

    monkeypatch.setattr(sync_cls, "close", close)
    with pytest.raises(RuntimeError, match="IAM configuration conflicts") as error:
        bedrock.BedrockClient(environment={"AWS_REGION": "fixture-region", "BEDROCK_AUTH_MODE": "iam", "BEDROCK_ENDPOINT": endpoint})
    assert len(closed) == 1 and "later-live-token" not in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["mantle", "legacy"])
async def test_installed_bedrock_sdk_honors_admitted_bearer_endpoint_and_async_parity(monkeypatch, endpoint):
    from maverick.providers.bedrock_provider import BedrockClient
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "later-live-token")
    monkeypatch.setenv("ANTHROPIC_BEDROCK_MANTLE_BASE_URL", "https://later.invalid")
    monkeypatch.setenv("ANTHROPIC_BEDROCK_BASE_URL", "https://later.invalid")
    client = BedrockClient(api_key="admitted-key", environment={  # pragma: allowlist secret - synthetic SDK configuration fixture
        "AWS_REGION": "fixture-region", "BEDROCK_AUTH_MODE": "api_key", "BEDROCK_ENDPOINT": endpoint,
    })
    try:
        assert all(sdk.api_key == "admitted-key" for sdk in (client.client, client.aclient))  # pragma: allowlist secret - repeated synthetic fixture
        assert client.client.base_url == client.aclient.base_url
        assert "fixture-region" in str(client.client.base_url) and "later.invalid" not in str(client.client.base_url)
    finally:
        client.client.close()
        await client.aclient.close()


@pytest.mark.asyncio
async def test_installed_openai_sdk_does_not_add_empty_or_later_metadata_headers(monkeypatch):
    from maverick.providers.openai_provider import OpenAIClient
    monkeypatch.setenv("OPENAI_ORG_ID", "later-organization")
    monkeypatch.setenv("OPENAI_PROJECT_ID", "later-project")
    client = OpenAIClient(api_key="fixture", environment={})  # pragma: allowlist secret - repeated synthetic fixture
    try:
        for sdk in (client._sync, client._async):
            assert sdk.organization is None and sdk.project is None
            assert not isinstance(sdk.default_headers["OpenAI-Organization"], str)
            assert not isinstance(sdk.default_headers["OpenAI-Project"], str)
    finally:
        client._sync.close()
        await client._async.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["mantle", "legacy"])
async def test_installed_bedrock_iam_construction_preserves_selected_signing_mode(monkeypatch, endpoint):
    """Constructor contract only; boto presence stubbed, no credential/signing call."""
    from maverick.providers import bedrock_provider as bedrock
    original_find = bedrock.importlib.util.find_spec
    monkeypatch.setattr(bedrock.importlib.util, "find_spec", lambda name: object() if name in ("boto3", "botocore") else original_find(name))
    for name in ("AWS_BEARER_TOKEN_BEDROCK", "ANTHROPIC_AWS_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    client = bedrock.BedrockClient(environment={
        "AWS_REGION": "fixture-region", "BEDROCK_AUTH_MODE": "iam", "BEDROCK_ENDPOINT": endpoint,
    })
    try:
        for sdk in (client.client, client.aclient):
            assert sdk.api_key is None
            if endpoint == "mantle":
                assert sdk._use_sigv4 is True
    finally:
        client.client.close()
        await client.aclient.close()


def test_codex_constructor_consumes_snapshot_without_config_or_launch_environment_reread(monkeypatch):
    import sys
    from pathlib import Path

    from maverick.providers.codex_cli_provider import CodexCLIClient

    monkeypatch.setattr("maverick.providers.codex_cli_provider._snapshot_binary", lambda name, environment: sys.executable)
    monkeypatch.setattr(CodexCLIClient, "_provider_config", staticmethod(lambda: pytest.fail("must not reread config")))
    environment = {"CODEX_HOME": "fixture-original", "PATH": "fixture-path", "COMSPEC": "fixture-shell"}
    options = {"binary": "fixture", "sandbox_mode": "read-only", "timeout_seconds": 17, "cwd": "fixture-cwd"}
    client = CodexCLIClient(api_key="fixture", environment=environment, provider_options=options)  # pragma: allowlist secret - repeated synthetic fixture
    environment["CODEX_HOME"] = "mutated-caller"
    options["sandbox_mode"] = "danger-full-access"
    monkeypatch.setenv("CODEX_HOME", "later-home")
    assert client._subprocess_env()["CODEX_HOME"] == str(Path("fixture-original").absolute())
    assert client.sandbox_mode == "read-only" and client.timeout_seconds == 17
    assert client.cwd == "fixture-cwd"


def test_azure_missing_snapshot_version_uses_existing_default_not_empty_query(monkeypatch):
    import openai
    from maverick.providers.azure_openai_provider import AzureOpenAIClient
    calls = []
    monkeypatch.setattr(openai, "AzureOpenAI", lambda **kw: calls.append(kw))
    monkeypatch.setattr(openai, "AsyncAzureOpenAI", lambda **kw: calls.append(kw))
    client = AzureOpenAIClient(api_key="fixture", base_url="https://fixture.invalid", environment={  # pragma: allowlist secret - synthetic mocked Azure fixture
        "AZURE_OPENAI_DEPLOYMENT": "fixture-deployment", "AZURE_OPENAI_API_VERSION": "",
    })
    assert client.api_version == "2024-10-21"
    assert all(call["api_version"] == "2024-10-21" for call in calls)


def test_workspace_endpoint_never_receives_the_deployment_key(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    (tmp_path / "config.toml").write_text(
        '[providers.anthropic]\napi_key = "deployment-fixture"\n')  # pragma: allowlist secret
    tenant = tmp_path / "tenants" / "acme" / "config.toml"
    tenant.parent.mkdir(parents=True)
    tenant.write_text('[providers.anthropic]\nbase_url = "https://collector.example/v1"\n')
    config.reset_config_cache()
    try:
        with pytest.raises(ValueError, match="own api_key"):
            LLM()._provider_client_config("anthropic")
        tenant.write_text('[providers.anthropic]\nbase_url = "https://gw.example/v1"\n'
                          'api_key = "workspace-fixture"\n')  # pragma: allowlist secret
        assert LLM()._provider_client_config("anthropic") is not None
    finally:
        config.reset_config_cache()


@pytest.mark.parametrize("provider,env,refused", [
    ("vertex", {}, True),                                      # Google ADC: ambient identity
    ("azure", {"AZURE_OPENAI_AD_TOKEN": "ad-fixture"}, True),  # pragma: allowlist secret
    ("azure", {"AZURE_OPENAI_AUTH": "entra_id"}, True),      # managed identity, no key or token
    ("ollama", {}, False),                                     # keyless local endpoint
])
def test_workspace_endpoint_refused_for_every_deployment_credential_kind(
    tmp_path, monkeypatch, provider, env, refused,
):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    for name in ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_AD_TOKEN", "AZURE_OPENAI_AUTH", "OLLAMA_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    (tmp_path / "config.toml").write_text("")
    tenant = tmp_path / "tenants" / "acme" / "config.toml"
    tenant.parent.mkdir(parents=True)
    tenant.write_text(f'[providers.{provider}]\nbase_url = "https://collector.example/v1"\n')
    config.reset_config_cache()
    try:
        if refused:
            with pytest.raises(ValueError, match="own api_key"):
                LLM()._provider_client_config(provider)
        else:
            assert LLM()._provider_client_config(provider) is not None
    finally:
        config.reset_config_cache()
