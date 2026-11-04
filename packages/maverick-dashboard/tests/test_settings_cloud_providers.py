"""Azure and Bedrock can be connected by a workspace owner in Settings."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "maverick"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    for name in ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_AD_TOKEN", "AZURE_OPENAI_ENDPOINT",
                 "AZURE_OPENAI_DEPLOYMENT", "AZURE_OPENAI_AUTH", "BEDROCK_API_KEY",
                 "AWS_BEARER_TOKEN_BEDROCK", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    dashboard._world_cache.clear()
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_azure_key_setup_is_complete_sealed_and_visible(workspace):
    from maverick import config

    page = workspace.get("/settings")
    assert page.status_code == 200
    assert 'id="provider-azure"' in page.text
    assert "Azure model deployment" in page.text
    response = workspace.post("/settings/providers", data={
        "provider": "azure", "base_url": "https://sample.openai.azure.com",
        "deployment": "production", "auth_mode": "api_key",
        "api_key": "azure-secret-1234",  # pragma: allowlist secret
    }, follow_redirects=False)
    assert response.status_code == 303
    assert config.get_provider_config("azure") == {
        "api_key": "azure-secret-1234",  # pragma: allowlist secret
        "base_url": "https://sample.openai.azure.com",
        "auth_mode": "api_key", "deployment": "production",
    }
    assert "azure-secret-1234" not in config.dashboard_overrides_path().read_text(encoding="utf-8")  # pragma: allowlist secret
    page = workspace.get("/settings").text
    assert "azure-secret-1234" not in page  # pragma: allowlist secret
    assert "production" in page
    assert 'value="azure:production"' in page


def test_azure_server_identity_can_be_saved_without_key_and_tested(workspace, monkeypatch):
    from maverick import config
    from maverick_dashboard import integration_readiness

    response = workspace.post("/settings/providers", data={
        "provider": "azure", "base_url": "https://sample.openai.azure.com",
        "deployment": "production", "auth_mode": "entra_id",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert config.get_provider_config("azure")["auth_mode"] == "entra_id"
    assert "api_key" not in config.get_provider_config("azure")
    monkeypatch.setattr(integration_readiness, "probe_provider", lambda name, cfg: {
        "verified": None, "detail": "no live result", "evidence": {"kind": "unsupported"},
    })
    tested = workspace.post("/settings/providers/test", data={"provider": "azure"},
                            follow_redirects=False)
    assert tested.status_code == 303
    azure = next(row for row in workspace.get("/api/v1/providers").json()["providers"]
                 if row["name"] == "azure")
    assert azure["configured"] is True
    assert azure["status"] != "connected"


def test_bedrock_iam_setup_and_removal(workspace):
    from maverick import config
    from maverick.llm import LLM

    response = workspace.post("/settings/providers", data={
        "provider": "bedrock", "region": "us-east-1", "endpoint": "mantle",
        "auth_mode": "iam", "model_id": "anthropic.claude-sonnet-5",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert config.get_provider_config("bedrock") == {
        "auth_mode": "iam", "endpoint": "mantle", "region": "us-east-1",
        "model_id": "anthropic.claude-sonnet-5",
    }
    route = LLM()._provider_client_config("bedrock")
    assert route.environment_dict()["AWS_REGION"] == "us-east-1"
    assert route.environment_dict()["BEDROCK_MODEL_ID"] == "anthropic.claude-sonnet-5"
    assert 'value="bedrock:anthropic.claude-sonnet-5"' in workspace.get("/settings").text
    bedrock = next(row for row in workspace.get("/api/v1/providers").json()["providers"]
                   if row["name"] == "bedrock")
    assert bedrock["configured"] is True
    assert bedrock["status"] != "connected"
    removed = workspace.post("/settings/providers/clear", data={"provider": "bedrock"},
                             follow_redirects=False)
    assert removed.status_code == 303
    assert config.get_provider_config("bedrock") == {}


def test_incomplete_azure_setup_rolls_back(workspace):
    from maverick import config

    response = workspace.post("/settings/providers", data={
        "provider": "azure", "base_url": "https://sample.openai.azure.com",
        "auth_mode": "api_key", "api_key": "azure-secret-1234",  # pragma: allowlist secret
    }, follow_redirects=False)
    assert response.status_code == 409
    assert config.get_provider_config("azure") == {}


def test_live_cloud_probe_records_only_status(monkeypatch):
    from maverick.llm import LLM
    from maverick_dashboard.integration_readiness import probe_provider

    calls = []

    class Endpoint:
        def create(self, **values):
            calls.append(values)
            return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=10, completion_tokens=1))

    class Completions:
        completions = Endpoint()

        def with_options(self, **options):
            assert options == {"timeout": 8.0, "max_retries": 0}
            return self

        chat = None

    class FakeAzure:
        deployment = "production"
        _sync = Completions()

        def _build_kwargs(self, *_args):
            return {"model": "production", "max_tokens": 16}

    FakeAzure._sync.chat = FakeAzure._sync
    route = type("Route", (), {
        "api_key": "secret", "base_url": "https://sample.openai.azure.com",  # pragma: allowlist secret
        "headers_dict": lambda self: None, "environment_dict": lambda self: {},
    })()
    monkeypatch.setattr(LLM, "_provider_client_config", lambda self, name: route)
    monkeypatch.setattr("maverick.providers.get_provider_client", lambda *args, **kwargs: FakeAzure())
    monkeypatch.setattr("maverick.llm.model_for_role", lambda role: "anthropic:sample")
    monkeypatch.setattr("maverick.llm._enforce_provider_cap", lambda name, cost: None)
    monkeypatch.setattr("maverick.budget._lookup_price_quote", lambda spec:
                        SimpleNamespace(input_per_mtok=1.0, output_per_mtok=1.0))

    class Meter:
        def __init__(self, **limits):
            assert limits["max_dollars"] == 0.05

        def check(self):
            pass

        def reserve(self, estimate):
            assert 0 < estimate < 0.05
            return estimate

        def record_tokens(self, inp, out, *, model):
            assert (inp, out, model) == (10, 1, "azure:production")

        def release(self, amount):
            assert amount > 0

    monkeypatch.setattr("maverick.budget.Budget", Meter)
    result = probe_provider("azure", {})
    assert result["verified"] is True
    assert result["evidence"] == {"kind": "live_model_probe", "external_live_verified": True}
    assert calls == [{"model": "production", "max_tokens": 16}]


def test_reached_provider_cap_is_not_recorded_as_a_failed_connection_test(monkeypatch):
    """The cap check is local: nothing was sent, so the receipt must not say the
    provider failed."""
    from maverick.llm import LLM
    from maverick.provider_cost_cap import ProviderCapExceeded
    from maverick_dashboard import integration_readiness
    from maverick_dashboard.integration_readiness import probe_provider

    class FakeAzure:
        deployment = "production"

    route = SimpleNamespace(api_key="secret", base_url="https://sample.openai.azure.com",  # pragma: allowlist secret
                            headers_dict=lambda: None, environment_dict=dict)

    def capped(name, cost):
        raise ProviderCapExceeded(name, 10.0, 10.0, "2026-10")

    monkeypatch.setattr(LLM, "_provider_client_config", lambda self, name: route)
    monkeypatch.setattr("maverick.providers.get_provider_client", lambda *args, **kwargs: FakeAzure())
    monkeypatch.setattr("maverick.llm.model_for_role", lambda role: "anthropic:sample")
    monkeypatch.setattr("maverick.llm._enforce_provider_cap", capped)
    monkeypatch.setattr("maverick.budget._lookup_price_quote", lambda spec:
                        SimpleNamespace(input_per_mtok=1.0, output_per_mtok=1.0))
    result = probe_provider("azure", {})
    assert result["verified"] is None
    assert result["evidence"] == {"kind": "budget_limit", "external_live_verified": False}
    assert "ProviderCapExceeded" not in result["detail"]
    receipt = integration_readiness.record("provider", "azure", {}, verified=result["verified"],
                                           detail=result["detail"], evidence=result["evidence"])
    assert receipt["status"] == "unknown"


def test_bedrock_probe_uses_saved_model_and_refuses_a_mismatched_default(monkeypatch):
    from maverick.llm import LLM
    from maverick_dashboard.integration_readiness import probe_provider

    calls = []

    class BedrockWire:
        messages = None

        def with_options(self, **options):
            assert options == {"timeout": 8.0, "max_retries": 0}
            return self

        def create(self, **values):
            calls.append(values)
            return SimpleNamespace(usage=SimpleNamespace(input_tokens=9, output_tokens=1))

    class FakeBedrock:
        DEFAULT_MODEL = "customer-model"
        client = BedrockWire()

    FakeBedrock.client.messages = FakeBedrock.client
    route = SimpleNamespace(
        api_key=None, base_url=None,
        headers_dict=lambda: None, environment_dict=dict,
    )
    monkeypatch.setattr(LLM, "_provider_client_config", lambda self, name: route)
    monkeypatch.setattr("maverick.providers.get_provider_client", lambda *args, **kwargs: FakeBedrock())
    monkeypatch.setattr("maverick.llm.model_for_role", lambda role: "bedrock:other-model")
    refused = probe_provider("bedrock", {})
    assert refused["verified"] is None and refused["evidence"]["kind"] == "model_mismatch"
    assert not calls

    monkeypatch.setattr("maverick.llm.model_for_role", lambda role: "bedrock:customer-model")
    monkeypatch.setattr("maverick.llm._enforce_provider_cap", lambda name, cost: None)
    monkeypatch.setattr("maverick.budget._lookup_price_quote", lambda spec:
                        SimpleNamespace(input_per_mtok=1.0, output_per_mtok=1.0))

    class Meter:
        def __init__(self, **_limits):
            pass

        def check(self):
            pass

        def reserve(self, estimate):
            return estimate

        def record_tokens(self, inp, out, *, model):
            assert (inp, out, model) == (9, 1, "bedrock:customer-model")

        def release(self, _amount):
            pass

    monkeypatch.setattr("maverick.budget.Budget", Meter)
    passed = probe_provider("bedrock", {})
    assert passed["verified"] is True
    assert calls == [{
        "model": "customer-model", "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply OK."}],
    }]
