"""Claude on Google Cloud Vertex AI can be connected by a workspace owner in Settings.

Vertex signs in with the server's Google credentials, so the guided form asks
for a project, a region and a model ID and never offers a key.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

_VERTEX_ENV = ("ANTHROPIC_VERTEX_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "CLOUD_ML_REGION",
               "VERTEX_MODEL_ID", "ANTHROPIC_VERTEX_BASE_URL")
_HAIKU = "claude-haiku-4-5@20251001"


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "maverick"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    for name in _VERTEX_ENV:
        monkeypatch.delenv(name, raising=False)
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    dashboard._world_cache.clear()
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_vertex_setup_is_saved_without_a_key_and_reaches_the_client(workspace):
    from maverick import config
    from maverick.llm import LLM

    response = workspace.post("/settings/providers", data={
        "provider": "vertex", "project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU,
    }, follow_redirects=False)
    assert response.status_code == 303
    assert config.get_provider_config("vertex") == {
        "project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU,
    }
    route = LLM()._provider_client_config("vertex")
    assert route.api_key is None
    assert route.environment_dict()["ANTHROPIC_VERTEX_PROJECT_ID"] == "acme-ai"
    assert route.environment_dict()["CLOUD_ML_REGION"] == "us-east5"
    assert route.environment_dict()["VERTEX_MODEL_ID"] == _HAIKU
    page = workspace.get("/settings").text
    assert 'name="project_id" value="acme-ai"' in page
    assert 'id="provider-key-vertex"' not in page  # no key field: Google sign-in only
    vertex = next(row for row in workspace.get("/api/v1/providers").json()["providers"]
                  if row["name"] == "vertex")
    assert vertex["configured"] is True
    assert vertex["status"] != "connected"


def test_vertex_refuses_a_key_and_values_that_could_reshape_the_request(workspace):
    from maverick import config

    saved = {"project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU}
    # The same form saves valid values first, so each refusal below is the
    # Vertex-specific check for that field, not an unknown-provider error.
    assert workspace.post("/settings/providers", data={"provider": "vertex", **saved},
                          follow_redirects=False).status_code == 303
    assert workspace.post("/settings/providers", data={
        "provider": "vertex", "api_key": "not-a-vertex-credential",  # pragma: allowlist secret
        **saved,
    }, follow_redirects=False).status_code == 400
    for field, value in (("project_id", "acme/../other"), ("region", "US-EAST5"),
                         ("model_id", "claude/../other:rawPredict")):
        values = {"provider": "vertex", **saved, field: value}
        assert workspace.post("/settings/providers", data=values,
                              follow_redirects=False).status_code == 400, field
    assert config.get_provider_config("vertex") == saved


def test_vertex_setup_can_be_removed(workspace):
    from maverick import config

    workspace.post("/settings/providers", data={
        "provider": "vertex", "project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU,
    }, follow_redirects=False)
    removed = workspace.post("/settings/providers/clear", data={"provider": "vertex"},
                             follow_redirects=False)
    assert removed.status_code == 303
    assert config.get_provider_config("vertex") == {}


def test_vertex_readiness_needs_a_project_region_and_model():
    from maverick_dashboard.provider_readiness import _configured

    complete = {"project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU}
    assert _configured("vertex", {}, complete) == (True, "Google sign-in")
    assert _configured("vertex", {}, {k: v for k, v in complete.items() if k != "model_id"}) == (False, "")
    assert _configured("vertex", {}, {}) == (False, "")


def test_vertex_picker_offers_the_model_the_operator_saved(monkeypatch):
    from maverick_dashboard import model_pickers

    monkeypatch.delenv("VERTEX_MODEL_ID", raising=False)
    monkeypatch.setattr("maverick.config.get_provider_config",
                        lambda name: {"model_id": _HAIKU} if name == "vertex" else {})
    assert model_pickers._configured_cloud_model("vertex") == f"{_HAIKU}"


def test_vertex_probe_refuses_to_guess_a_model(monkeypatch):
    from maverick.llm import LLM
    from maverick_dashboard.integration_readiness import probe_provider

    class NoModelClient:
        DEFAULT_MODEL = ""

    route = SimpleNamespace(api_key=None, base_url=None,
                            headers_dict=lambda: None, environment_dict=dict)
    monkeypatch.setattr(LLM, "_provider_client_config", lambda self, name: route)
    monkeypatch.setattr("maverick.providers.get_provider_client",
                        lambda *args, **kwargs: NoModelClient())
    result = probe_provider("vertex", {})
    assert result["verified"] is None
    assert result["evidence"]["kind"] == "setup_incomplete"


def test_vertex_probe_sends_nothing_for_a_model_id_outside_the_vertex_form(monkeypatch):
    from maverick.llm import LLM
    from maverick_dashboard.integration_readiness import probe_provider

    sent = []

    class Messages:
        def create(self, **values):
            sent.append(values)
            raise AssertionError("no request may carry a model id outside the Vertex form")

    class Wire:
        messages = Messages()

        def with_options(self, **options):
            return self

    class HostileClient:
        DEFAULT_MODEL = "claude-haiku-4-5/../../other@1"
        client = Wire()

    route = SimpleNamespace(api_key=None, base_url=None,
                            headers_dict=lambda: None, environment_dict=dict)
    monkeypatch.setattr(LLM, "_provider_client_config", lambda self, name: route)
    monkeypatch.setattr("maverick.providers.get_provider_client", lambda *args, **kwargs: HostileClient())
    monkeypatch.setattr("maverick.llm.model_for_role", lambda role: "anthropic:sample")
    monkeypatch.setattr("maverick.llm._enforce_provider_cap", lambda name, cost: None)
    monkeypatch.setattr("maverick.budget._lookup_price_quote", lambda spec:
                        SimpleNamespace(input_per_mtok=1.0, output_per_mtok=1.0))
    result = probe_provider("vertex", {})
    assert result["verified"] is None
    assert result["evidence"]["kind"] == "setup_incomplete"
    assert sent == []


def test_vertex_model_id_must_be_the_name_at_version_form(workspace):
    from maverick import config

    for model_id in ("claude-haiku-4-5", "claude-haiku-4-5@2025/10"):
        response = workspace.post("/settings/providers", data={
            "provider": "vertex", "project_id": "acme-ai", "region": "us-east5", "model_id": model_id,
        }, follow_redirects=False)
        assert response.status_code == 400, model_id
    assert config.get_provider_config("vertex") == {}


def test_vertex_refuses_a_server_address_from_settings_and_keeps_its_setup(workspace):
    """The Google sign-in token goes to the endpoint, so Settings must never choose it."""
    from maverick import config
    from maverick.llm import LLM

    saved = {"project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU}
    assert workspace.post("/settings/providers", data={"provider": "vertex", **saved},
                          follow_redirects=False).status_code == 303
    response = workspace.post("/settings/providers", data={
        "provider": "vertex", "base_url": "https://attacker.invalid/v1", **saved,
    }, follow_redirects=False)
    assert response.status_code == 400
    assert config.get_provider_config("vertex") == saved
    assert LLM()._provider_client_config("vertex").base_url is None


def test_rotation_refuses_a_server_address_even_past_the_form_check(workspace, monkeypatch):
    """Skip the form-level check so the rotation's own guard is what refuses the address.

    The setup is complete, so the refusal cannot come from the incomplete-setup rollback.
    """
    from maverick import config
    from maverick_dashboard import settings_store

    details = {"project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU}
    monkeypatch.setattr(settings_store, "_checked_provider_setup",
                        lambda name, key, base, values: (settings_store._provider_setup_details(name, values), False))
    with pytest.raises(settings_store.ProviderRotationConflict, match="server address"):
        settings_store.rotate_provider("vertex", base_url="https://attacker.invalid/v1", details=details)
    assert config.get_provider_config("vertex") == {}


@pytest.mark.parametrize("provider", ["openai", "bedrock"])
def test_providers_without_a_server_address_field_refuse_one(workspace, provider):
    from maverick import config

    response = workspace.post("/settings/providers", data={
        "provider": provider, "base_url": "https://attacker.invalid/v1",
    }, follow_redirects=False)
    assert response.status_code == 400
    assert config.get_provider_config(provider) == {}


def test_vertex_receipt_goes_stale_when_the_routed_region_changes(workspace, monkeypatch):
    """A passed connection test is for the route it ran on. Here the region comes from the environment."""
    from maverick import config
    from maverick_dashboard import integration_readiness as readiness

    monkeypatch.setenv("CLOUD_ML_REGION", "us-east5")
    saved = {"project_id": "acme-ai", "model_id": _HAIKU}
    assert workspace.post("/settings/providers", data={"provider": "vertex", **saved},
                          follow_redirects=False).status_code == 303
    material = config.get_provider_config("vertex")
    readiness.record("provider", "vertex", readiness._cloud_receipt_material("vertex", material),
                     verified=True, detail="provider accepted the bounded model request")
    assert readiness.get("provider", "vertex",
                         readiness._cloud_receipt_material("vertex", material))["status"] == "verified"

    monkeypatch.setenv("CLOUD_ML_REGION", "europe-west4")
    assert readiness.get("provider", "vertex",
                         readiness._cloud_receipt_material("vertex", material))["status"] != "verified"


def test_vertex_picker_offers_the_saved_model_the_route_calls(monkeypatch):
    """The Vertex client takes the saved model over VERTEX_MODEL_ID, so the picker must too."""
    from maverick_dashboard import model_pickers

    monkeypatch.setenv("VERTEX_MODEL_ID", "claude-sonnet-4-5@20250929")
    monkeypatch.setattr("maverick.config.get_provider_config",
                        lambda name: {"model_id": _HAIKU} if name == "vertex" else {})
    assert model_pickers._configured_cloud_model("vertex") == _HAIKU
