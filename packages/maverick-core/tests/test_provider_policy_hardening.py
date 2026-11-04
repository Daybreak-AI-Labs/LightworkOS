"""Provider snapshot/cache isolation and model allow-list dispatch gates."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
from click.testing import CliRunner


def _allow_only(monkeypatch, *models: str) -> None:
    from maverick import runtime_overrides

    monkeypatch.setattr(runtime_overrides, "allowed_models", lambda: set(models))


def _quiet_dispatch(monkeypatch) -> None:
    from maverick import enterprise, llm, privacy_egress

    monkeypatch.setattr(enterprise, "assert_provider_allowed", lambda _provider: None)
    monkeypatch.setattr(
        privacy_egress,
        "maybe_redact_egress",
        lambda _provider, system, messages: (system, messages),
    )
    for name in (
        "_enforce_circuit",
        "_enforce_provider_cap",
        "_feed_circuit",
        "_record_provider_call",
        "_record_provider_spend",
        "_run_preflight",
    ):
        monkeypatch.setattr(llm, name, lambda *args, **kwargs: None)
    # These synthetic clients have no paid usage. Keep the numeric projection
    # contract intact while this fixture isolates model selection/failover.
    monkeypatch.setattr(llm, "_estimate_call_cost", lambda *args, **kwargs: 0.0)
    monkeypatch.setattr(llm, "_lookup_price_quote", lambda _spec: None)


def test_provider_snapshot_rotation_never_mixes_generations(monkeypatch):
    """A rotation released at the config-read barrier is admitted atomically."""
    from maverick import config
    from maverick.llm import LLM

    barrier = __import__("threading").Barrier(2)
    state = {
        "generation": "old",
        "calls": 0,
    }
    monkeypatch.setenv("OPENAI_API_KEY", "env-old-key")

    def provider_config(_provider):
        state["calls"] += 1
        generation = state["generation"]
        snapshot = {
            "api_key": f"{generation}-key",
            "base_url": f"https://{generation}.example/v1",
        }
        if state["calls"] == 1:
            barrier.wait(timeout=5)
            barrier.wait(timeout=5)
        return snapshot

    monkeypatch.setattr(config, "get_provider_config", provider_config)
    llm = LLM(model="openai:test")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(llm._provider_client_config, "openai")
        barrier.wait(timeout=5)
        state["generation"] = "new"
        monkeypatch.setenv("OPENAI_API_KEY", "env-new-key")
        barrier.wait(timeout=5)
        admitted = future.result(timeout=5)

    assert admitted.api_key == "new-key"  # pragma: allowlist secret
    assert admitted.base_url == "https://new.example/v1"
    assert state["calls"] >= 2


def test_provider_snapshot_fails_closed_during_continuous_rotation(monkeypatch):
    from maverick import config
    from maverick import llm as llm_module

    calls = {"count": 0}
    monkeypatch.setenv("OPENAI_API_KEY", "generation-0")

    def provider_config(_provider):
        calls["count"] += 1
        monkeypatch.setenv(
            "OPENAI_API_KEY", f"generation-{calls['count']}"
        )
        return {
            "api_key": f"config-{calls['count']}",
            "base_url": f"https://generation-{calls['count']}.example/v1",
        }

    monkeypatch.setattr(config, "get_provider_config", provider_config)

    with pytest.raises(RuntimeError, match="changed during.*client admission"):
        llm_module._provider_config_snapshot("openai")
    assert calls["count"] == llm_module._PROVIDER_SNAPSHOT_RETRIES


def test_header_rotation_rekeys_and_evicts_stale_client(monkeypatch):
    from maverick import config, providers
    from maverick.llm import LLM

    state = {"headers": {"X-Data-Residency": "eu"}}
    monkeypatch.setattr(
        config,
        "get_provider_config",
        lambda _provider: {
            "api_key": "test-key",  # pragma: allowlist secret
            "base_url": "https://gateway.example/v1",
            "default_headers": dict(state["headers"]),
        },
    )
    created = []

    class Client:
        def __init__(self, headers):
            self.headers = headers

    def factory(_provider, *, api_key=None, base_url=None, default_headers=None, environment=None):
        del api_key, base_url
        client = Client(default_headers)
        created.append(client)
        return client

    monkeypatch.setattr(providers, "get_provider_client", factory)
    llm = LLM(model="openai:test")
    first = llm._get_client("openai")

    # Header names are case-insensitive: casing-only edits reuse the client.
    state["headers"] = {"x-data-residency": "eu"}
    assert llm._get_client("openai") is first

    state["headers"] = {"X-Data-Residency": "us"}
    second = llm._get_client("openai")
    assert second is not first
    assert second.headers == {"X-Data-Residency": "us"}
    assert len(created) == 2
    assert len(llm._client_cache) == 1


def test_azure_auth_mode_rotation_uses_one_snapshot_and_rekeys(monkeypatch):
    from maverick import config, providers
    from maverick.llm import LLM

    monkeypatch.setattr(
        config,
        "get_provider_config",
        lambda _provider: {"base_url": "https://azure.example"},
    )
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "api-key")
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "api_key")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "deployment")
    monkeypatch.delenv("AZURE_OPENAI_AD_TOKEN", raising=False)
    calls = []

    def factory(
        _provider,
        *,
        api_key=None,
        base_url=None,
        default_headers=None,
        environment=None,
    ):
        calls.append(
            {
                "api_key": api_key,
                "base_url": base_url,
                "headers": default_headers,
                "environment": dict(environment or {}),
            }
        )
        return object()

    monkeypatch.setattr(providers, "get_provider_client", factory)
    dispatcher = LLM(model="azure:deployment")
    first = dispatcher._get_client("azure")

    monkeypatch.delenv("AZURE_OPENAI_API_KEY")
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "entra_id")
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", "entra-token")
    second = dispatcher._get_client("azure")

    assert second is not first
    assert calls[0]["api_key"] == "api-key"  # pragma: allowlist secret
    assert calls[0]["environment"]["AZURE_OPENAI_AUTH"] == "api_key"
    assert calls[0]["environment"]["AZURE_OPENAI_AD_TOKEN"] == ""
    assert calls[1]["api_key"] is None
    assert calls[1]["environment"]["AZURE_OPENAI_AUTH"] == "entra_id"
    assert calls[1]["environment"]["AZURE_OPENAI_AD_TOKEN"] == "entra-token"
    assert len(dispatcher._client_cache) == 1


def test_azure_client_consumes_admitted_environment_not_live_rotation(
    monkeypatch,
):
    import sys
    import types

    from maverick.providers.azure_openai_provider import AzureOpenAIClient

    calls = []

    class FakeAzure:
        def __init__(self, **kwargs):
            calls.append(kwargs)

    fake_openai = types.ModuleType("openai")
    fake_openai.AzureOpenAI = FakeAzure
    fake_openai.AsyncAzureOpenAI = FakeAzure
    monkeypatch.setitem(sys.modules, "openai", fake_openai)

    admitted = {
        "AZURE_OPENAI_AD_TOKEN": "",
        "AZURE_OPENAI_API_VERSION": "old-version",
        "AZURE_OPENAI_AUTH": "api_key",
        "AZURE_OPENAI_DEPLOYMENT": "old-deployment",
        "AZURE_OPENAI_TOKEN_SCOPE": "",
    }
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "entra_id")
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", "new-live-token")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "new-live-deployment")

    client = AzureOpenAIClient(
        api_key="old-key",  # pragma: allowlist secret
        base_url="https://old.example",
        environment=admitted,
    )

    assert client.auth_mode == "api_key"
    assert client.deployment == "old-deployment"
    assert client.api_version == "old-version"
    assert len(calls) == 2
    assert all(call["api_key"] == "old-key" for call in calls)  # pragma: allowlist secret
    assert all("azure_ad_token" not in call for call in calls)


def test_provider_client_cache_is_bounded_lru(monkeypatch):
    from maverick import config, paths, providers
    from maverick import llm as llm_module
    from maverick.llm import LLM

    tenant = {"id": "tenant-0"}
    monkeypatch.setattr(paths, "current_tenant_id", lambda: tenant["id"])
    monkeypatch.setattr(
        config,
        "get_provider_config",
        lambda _provider: {"api_key": "test-key"},  # pragma: allowlist secret
    )
    monkeypatch.setattr(
        providers,
        "get_provider_client",
        lambda _provider, **_kwargs: object(),
    )
    monkeypatch.setattr(llm_module, "_CLIENT_CACHE_MAX", 2)

    dispatcher = LLM(model="openai:test")
    for index in range(3):
        tenant["id"] = f"tenant-{index}"
        dispatcher._get_client("openai")

    assert len(dispatcher._client_cache) == 2
    assert all(key[1] != "tenant-0" for key in dispatcher._client_cache)


def test_direct_constructor_primary_is_rejected_before_client_work(monkeypatch):
    from maverick.llm import LLM, ModelNotAllowedError

    _allow_only(monkeypatch, "anthropic:allowed")
    dispatcher = LLM(model="openai:blocked")
    monkeypatch.setattr(
        dispatcher,
        "_get_client",
        lambda _provider: pytest.fail("provider client must not be constructed"),
    )
    with pytest.raises(ModelNotAllowedError, match="openai:blocked"):
        dispatcher.complete("system", [], _no_failover=True)


def test_unreadable_operator_policy_is_not_treated_as_unrestricted(monkeypatch):
    from maverick import runtime_overrides
    from maverick.llm import LLM

    error = runtime_overrides.RuntimeOverridesSecurityError("policy unreadable")
    monkeypatch.setattr(
        runtime_overrides,
        "allowed_models",
        lambda: (_ for _ in ()).throw(error),
    )
    dispatcher = LLM(model="openai:would-otherwise-run")
    monkeypatch.setattr(
        dispatcher,
        "_get_client",
        lambda _provider: pytest.fail("provider client must not be constructed"),
    )

    with pytest.raises(
        runtime_overrides.RuntimeOverridesSecurityError,
        match="policy unreadable",
    ):
        dispatcher.complete("system", [], _no_failover=True)


def test_per_call_override_is_rejected_sync_and_async(monkeypatch):
    from maverick.llm import LLM, ModelNotAllowedError

    _allow_only(monkeypatch, "anthropic:allowed")
    dispatcher = LLM(model="anthropic:allowed")
    monkeypatch.setattr(
        dispatcher,
        "_get_client",
        lambda _provider: pytest.fail("provider client must not be constructed"),
    )

    with pytest.raises(ModelNotAllowedError, match="openai:blocked"):
        dispatcher.complete("system", [], model="gpt:blocked", _no_failover=True)
    with pytest.raises(ModelNotAllowedError, match="openai:blocked"):
        asyncio.run(
            dispatcher.complete_async(
                "system", [], model="chatgpt:blocked", _no_failover=True
            )
        )


def test_alias_and_bare_specs_are_canonicalized_at_dispatch(monkeypatch):
    from maverick.llm import LLM, LLMResponse

    _allow_only(monkeypatch, "anthropic:allowed")
    _quiet_dispatch(monkeypatch)
    seen = []

    class Client:
        def complete(self, **kwargs):
            seen.append(kwargs["model"])
            return LLMResponse(
                text="ok", thinking=None, tool_calls=[], stop_reason="end_turn"
            )

        async def complete_async(self, **kwargs):
            seen.append(kwargs["model"])
            return LLMResponse(
                text="ok", thinking=None, tool_calls=[], stop_reason="end_turn"
            )

    dispatcher = LLM(model="claude:allowed")
    monkeypatch.setattr(dispatcher, "_get_client", lambda _provider: Client())
    assert dispatcher.complete("system", [], _no_failover=True).text == "ok"
    assert asyncio.run(
        dispatcher.complete_async(
            "system", [], model="allowed", _no_failover=True
        )
    ).text == "ok"
    assert seen == ["allowed", "allowed"]


def test_failover_never_attempts_disallowed_configured_model(monkeypatch):
    from maverick import failover_policy, provider_failover
    from maverick.llm import LLM, LLMResponse

    _allow_only(
        monkeypatch,
        "anthropic:primary",
        "openai:allowed-fallback",
    )
    _quiet_dispatch(monkeypatch)
    monkeypatch.setattr(
        provider_failover,
        "fallback_models",
        lambda _primary: ["gemini:blocked", "gpt:allowed-fallback"],
    )
    monkeypatch.setattr(failover_policy, "order_chain", lambda models: list(models))
    attempted = []

    class Client:
        def __init__(self, provider):
            self.provider = provider

        def complete(self, **kwargs):
            attempted.append(f"{self.provider}:{kwargs['model']}")
            if self.provider == "anthropic":
                raise RuntimeError("primary unavailable")
            return LLMResponse(
                text="fallback",
                thinking=None,
                tool_calls=[],
                stop_reason="end_turn",
            )

    dispatcher = LLM(model="claude:primary")
    monkeypatch.setattr(
        dispatcher, "_get_client", lambda provider: Client(provider)
    )

    response = dispatcher.complete("system", [])
    assert response.text == "fallback"
    assert attempted == [
        "anthropic:primary",
        "openai:allowed-fallback",
    ]


def test_failover_finds_chain_declared_under_canonical_primary(monkeypatch):
    from maverick import failover_policy, provider_failover
    from maverick.llm import LLM, LLMResponse

    _allow_only(
        monkeypatch,
        "anthropic:primary",
        "openai:allowed-fallback",
    )
    _quiet_dispatch(monkeypatch)
    lookups = []

    def fallback_models(primary):
        lookups.append(primary)
        if primary == "anthropic:primary":
            return ["openai:allowed-fallback"]
        return []

    monkeypatch.setattr(provider_failover, "fallback_models", fallback_models)
    monkeypatch.setattr(failover_policy, "order_chain", lambda models: list(models))

    class Client:
        def __init__(self, provider):
            self.provider = provider

        def complete(self, **kwargs):
            if self.provider == "anthropic":
                raise RuntimeError("primary unavailable")
            return LLMResponse(
                text="fallback",
                thinking=None,
                tool_calls=[],
                stop_reason="end_turn",
            )

    dispatcher = LLM(model="claude:primary")
    monkeypatch.setattr(
        dispatcher, "_get_client", lambda provider: Client(provider)
    )

    assert dispatcher.complete("system", []).text == "fallback"
    assert lookups == ["claude:primary", "anthropic:primary"]


def test_async_failover_never_attempts_disallowed_configured_model(monkeypatch):
    from maverick import failover_policy, provider_failover
    from maverick.llm import LLM, LLMResponse

    _allow_only(
        monkeypatch,
        "anthropic:primary",
        "openai:allowed-fallback",
    )
    _quiet_dispatch(monkeypatch)
    monkeypatch.setattr(
        provider_failover,
        "fallback_models",
        lambda _primary: ["google:blocked", "chatgpt:allowed-fallback"],
    )
    monkeypatch.setattr(failover_policy, "order_chain", lambda models: list(models))
    attempted = []

    class Client:
        def __init__(self, provider):
            self.provider = provider

        async def complete_async(self, **kwargs):
            attempted.append(f"{self.provider}:{kwargs['model']}")
            if self.provider == "anthropic":
                raise RuntimeError("primary unavailable")
            return LLMResponse(
                text="fallback",
                thinking=None,
                tool_calls=[],
                stop_reason="end_turn",
            )

    dispatcher = LLM(model="claude:primary")
    monkeypatch.setattr(
        dispatcher, "_get_client", lambda provider: Client(provider)
    )

    response = asyncio.run(dispatcher.complete_async("system", []))
    assert response.text == "fallback"
    assert attempted == [
        "anthropic:primary",
        "openai:allowed-fallback",
    ]


def test_cli_rejects_disallowed_explicit_model(monkeypatch):
    from maverick.cli import main

    _allow_only(monkeypatch, "anthropic:allowed")
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    result = CliRunner().invoke(
        main, ["--model", "gpt:blocked", "version"]
    )

    assert result.exit_code == 2
    assert "openai:blocked" in result.output
    assert "not allowed" in result.output
    assert "MAVERICK_MODEL_OVERRIDE" not in __import__("os").environ


def test_self_improvement_explicit_model_policy_error_is_not_downgraded(
    monkeypatch,
):
    from maverick import self_improvement_runner
    from maverick.llm import ModelNotAllowedError

    _allow_only(monkeypatch, "anthropic:allowed")
    with pytest.raises(ModelNotAllowedError, match="openai:blocked"):
        self_improvement_runner.run_self_harness_cycle(
            model_id="openai:blocked"
        )


def test_self_harness_llm_runner_does_not_swallow_model_policy(monkeypatch):
    from maverick import self_harness_eval
    from maverick.llm import LLM, ModelNotAllowedError

    _allow_only(monkeypatch, "anthropic:allowed")
    run = self_harness_eval.llm_runner(
        LLM(model="anthropic:allowed"),
        model="openai:blocked",
    )

    with pytest.raises(ModelNotAllowedError, match="openai:blocked"):
        run("", "evaluate this case")
