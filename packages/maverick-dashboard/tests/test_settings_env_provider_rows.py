"""Settings lists every provider that takes a key and a server address,
so an OpenAI-compatible (or TGI) server configured on the computer running
Lightwork is shown as set up instead of "0 providers connected / No key"."""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_ENV_URL = "https://llm.example.test/v1"
_ENV_KEY = "env-only-credential-1234"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path: Path):
    home = tmp_path / "maverick-home"
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    for name in (
        "MAVERICK_AUTH_REQUIRED",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_ENTERPRISE",
        "MAVERICK_TENANT",
        "MAVERICK_MODEL_OVERRIDE",
    ):
        monkeypatch.delenv(name, raising=False)

    import maverick.runtime_overrides as runtime_overrides
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import integration_readiness

    for name in config.PROVIDER_KEY_ENV_VARS + config.PROVIDER_BASE_URL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in ("GOOGLE_API_KEY", "GROK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    integration_readiness._clear_for_testing()
    monkeypatch.setattr(world_model, "DEFAULT_DB", home / "world.db")
    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", home / "runtime-overrides.toml")
    dashboard_app._world_cache.clear()
    yield
    integration_readiness._clear_for_testing()
    config.reset_config_cache()


def _env_openai_compatible(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", _ENV_URL)
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", _ENV_KEY)
    from maverick import config

    config.reset_config_cache()


def _rows() -> dict[str, dict]:
    from maverick_dashboard import settings_store

    return {row["name"]: row for row in settings_store.state()["providers"]}


def test_environment_openai_compatible_server_is_listed_as_set_up(monkeypatch):
    _env_openai_compatible(monkeypatch)
    row = _rows()["openai_compatible"]
    assert row["configured"] is True
    assert row["base_url"] == _ENV_URL
    assert row["base_url_field"] is True
    assert row["via"] and "environment:" in row["via"]
    assert row["api_key_source"].startswith("environment:")
    # Nothing here reveals the credential itself.
    assert _ENV_KEY not in repr(row)


def test_vllm_row_is_not_confused_with_the_openai_compatible_server(monkeypatch):
    _env_openai_compatible(monkeypatch)
    rows = _rows()
    assert rows["vllm"]["configured"] is False
    assert "OpenAI-compatible" not in rows["vllm"]["label"]
    assert "OPENAI_COMPATIBLE" not in rows["vllm"]["env_hint"]


def test_tgi_server_from_the_environment_is_listed_as_set_up(monkeypatch):
    monkeypatch.setenv("TGI_BASE_URL", "https://tgi.example.test")
    from maverick import config

    config.reset_config_cache()
    row = _rows()["tgi"]
    assert row["configured"] is True
    assert row["base_url"] == "https://tgi.example.test"


def test_settings_page_no_longer_says_nothing_is_connected(monkeypatch):
    _env_openai_compatible(monkeypatch)
    # The routed model, exactly as in the audit's lab: tasks already run on it.
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai_compatible:fake-model")
    client = TestClient(
        __import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )
    response = client.get("/settings")
    assert response.status_code == 200
    page = response.text
    assert 'id="provider-openai_compatible"' in page
    assert "OpenAI-compatible server" in page
    assert "Add a provider key" not in page
    # Models tab: one provider is set up, not "0 providers".
    assert re.search(
        r'<span class="num">1</span><span class="muted">provider set up</span>', page
    )
    # The address in use is named, and the credential is described without
    # naming a variable or revealing it.
    # The row ends where the next provider row starts (rows carry their own
    # id="provider-name-…" label inside).
    row = page.split('id="provider-openai_compatible"', 1)[1].split('<div class="provider-row"', 1)[0]
    assert _ENV_URL in row
    assert _ENV_KEY not in page
    assert "OPENAI_COMPATIBLE" not in row
    assert "set on the computer running Lightwork" in row


def test_a_key_saved_here_replaces_the_environment_key_and_clearing_returns(monkeypatch):
    _env_openai_compatible(monkeypatch)
    from maverick import config
    from maverick_dashboard import settings_store

    new_key = "dashboard-rotated-5678"  # pragma: allowlist secret
    settings_store.rotate_provider("openai_compatible", api_key=new_key)
    config.reset_config_cache()
    assert config.get_provider_config("openai_compatible")["api_key"] == new_key
    row = _rows()["openai_compatible"]
    assert row["dashboard_set"] is True
    assert row["key_hint"] == "••••5678"

    settings_store.clear_provider("openai_compatible")
    config.reset_config_cache()
    row = _rows()["openai_compatible"]
    assert row["dashboard_set"] is False
    assert row["configured"] is True  # the server's own key is back in use
    assert row["api_key_source"].startswith("environment:")


def test_provider_form_key_rotation_preserves_the_server_address_source(monkeypatch):
    _env_openai_compatible(monkeypatch)
    from maverick import config
    from maverick.llm import LLM
    from maverick_dashboard import admin_pages, settings_store

    # Discovery is a separate network operation, not evidence of a saved key.
    monkeypatch.setattr(admin_pages, "_refresh_models_quietly", lambda _name: None)
    client = TestClient(
        __import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )
    page = client.get("/settings").text
    field = re.search(r'<input[^>]*id="provider-url-openai_compatible"[^>]*>', page).group()
    assert 'value=""' in field
    assert "Leave blank to keep the address above" in page
    replacement = "dashboard-replacement-5678"  # pragma: allowlist secret
    response = client.post("/settings/providers", data={
        "provider": "openai_compatible", "api_key": replacement, "base_url": "",
    }, follow_redirects=False)
    assert response.status_code == 303, response.text
    saved = settings_store.load_overlay()["providers"]["openai_compatible"]
    assert "base_url" not in saved
    assert replacement not in config.dashboard_overrides_path().read_text(encoding="utf-8")
    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "https://moved.example.test/v1")
    config.reset_config_cache()
    route = LLM()._provider_client_config("openai_compatible")
    assert route.base_url == "https://moved.example.test/v1"
    assert route.api_key == replacement


def test_native_key_rotation_does_not_freeze_a_carried_forward_address(monkeypatch):
    _env_openai_compatible(monkeypatch)
    from maverick import config
    from maverick_dashboard import settings_store

    settings_store.rotate_provider(
        "openai_compatible", api_key="replacement-5678", base_url=_ENV_URL,  # pragma: allowlist secret -- test value
    )
    assert "base_url" not in settings_store.load_overlay()["providers"]["openai_compatible"]
    assert config.provider_configuration_state("openai_compatible")["base_url_source"].startswith("environment:")
    settings_store.rotate_provider("openai_compatible", base_url="https://chosen.example.test/v1")
    assert config.provider_configuration_state("openai_compatible")["base_url_source"] == "dashboard"
    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "https://moved.example.test/v1")
    config.reset_config_cache()
    assert config.provider_configuration_state("openai_compatible")["base_url"] == "https://chosen.example.test/v1"


def test_provider_address_sign_in_material_is_not_displayed_or_prefilled(monkeypatch):
    _env_openai_compatible(monkeypatch)
    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL",
                       "https://user:private-password@llm.example.test/v1?token=private-token#private-fragment")  # pragma: allowlist secret -- test value
    from maverick import config

    config.reset_config_cache()
    row = _rows()["openai_compatible"]
    assert row["base_url"] == _ENV_URL
    assert row["base_url_needs_repair"] is True
    client = TestClient(
        __import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )
    page = client.get("/settings").text
    assert "private-password" not in page and "private-token" not in page and "private-fragment" not in page
    assert "Enter a clean server address below" in page
    catalog = client.get("/api/v1/settings/catalog?group=integrations")
    assert catalog.status_code == 200
    assert not any(word in catalog.text for word in ("private-password", "private-token", "private-fragment"))
    address = next(row for group in catalog.json()["groups"] for row in group["settings"]
                   if row["id"] == "providers.openai_compatible.base_url")
    assert address["value"] == _ENV_URL


@pytest.mark.parametrize("address", [
    "https://user:private-password@llm.example.test/v1",  # pragma: allowlist secret -- test value
    "https://llm.example.test/v1?token=private-token",
    "http://localhost:bad-port/v1",
])
def test_provider_rejects_an_unusable_address_before_rotating_the_key(monkeypatch, address):
    _env_openai_compatible(monkeypatch)
    from maverick import config
    from maverick_dashboard import settings_store

    client = TestClient(
        __import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )
    response = client.post("/settings/providers", data={
        "provider": "openai_compatible", "api_key": "new-key-5678", "base_url": address,  # pragma: allowlist secret -- test value
    }, follow_redirects=False)
    assert response.status_code == 400, response.text
    assert "use the key field for access" in response.json()["detail"]
    assert not config.dashboard_overrides_path().exists()
    assert not settings_store.load_overlay().get("providers")


def test_self_hosted_setup_hints_match_the_service_and_keyless_model(monkeypatch):
    client = TestClient(
        __import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )
    page = client.get("/settings").text

    def block(name):
        return page.split(f'id="provider-{name}"', 1)[1].split('<div class="provider-row"', 1)[0]

    assert "No key yet" not in block("ollama")
    assert "Where do I get a key?" not in block("ollama")
    assert "Server access key (if required)" in block("ollama")
    assert 'placeholder="http://localhost:11434"' in block("ollama")
    assert 'placeholder="http://localhost:8000/v1"' in block("vllm")
    assert 'placeholder="http://localhost:8080/v1"' in block("tgi")


def test_all_settings_shows_effective_server_fallback_and_safe_replacement(monkeypatch):
    _env_openai_compatible(monkeypatch)
    from maverick import config

    client = TestClient(
        __import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )

    def current_rows():
        result = client.get("/api/v1/settings/catalog?group=integrations")
        assert result.status_code == 200
        return result.json(), {row["id"]: row for group in result.json()["groups"]
                               for row in group["settings"]}

    snapshot, rows = current_rows()
    address = rows["providers.openai_compatible.base_url"]
    key = rows["providers.openai_compatible.api_key"]
    assert address["value"] == _ENV_URL
    assert address["source"] == "deployment" and address["locked"] is False
    assert "save here to replace" in address["source_text"]
    assert key["is_set"] is True and key["value"] is None
    assert _ENV_KEY not in repr(snapshot)

    updated = client.post("/api/v1/settings/catalog", json={
        "expected_revision": snapshot["revision"],
        "changes": [{"id": "providers.openai_compatible.base_url",
                     "value": "https://new.example.test/v1"}],
        "confirm": True,
    })
    assert updated.status_code == 200
    assert config.get_provider_config("openai_compatible")["base_url"] == "https://new.example.test/v1"
    saved, rows = current_rows()
    assert rows["providers.openai_compatible.base_url"]["source"] == "here"
    assert rows["providers.openai_compatible.base_url"]["value"] == "https://new.example.test/v1"
    assert _ENV_KEY not in repr(rows)

    cleared = client.post("/api/v1/settings/catalog", json={
        "expected_revision": saved["revision"],
        "changes": [{"id": "providers.openai_compatible.base_url", "reset": True}],
        "confirm": True,
    })
    assert cleared.status_code == 200
    _, rows = current_rows()
    assert rows["providers.openai_compatible.base_url"]["value"] == _ENV_URL
    assert rows["providers.openai_compatible.base_url"]["source"] == "deployment"
    assert config.provider_configuration_state("openai_compatible")["base_url"] == _ENV_URL


def test_reset_installer_address_reveals_server_fallback(monkeypatch):
    _env_openai_compatible(monkeypatch)
    from maverick import config

    path = Path(os.environ["MAVERICK_CONFIG"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[providers.openai_compatible]\nbase_url = "https://installer.example.test/v1"\n', encoding="utf-8")
    config.reset_config_cache()
    client = TestClient(
        __import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )
    initial = client.get("/api/v1/settings/catalog?group=integrations").json()
    response = client.post("/api/v1/settings/catalog", json={
        "expected_revision": initial["revision"],
        "changes": [{"id": "providers.openai_compatible.base_url", "reset": True}],
        "confirm": True,
    })
    assert response.status_code == 200
    assert config.provider_configuration_state("openai_compatible")["base_url"] == _ENV_URL
    after = client.get("/api/v1/settings/catalog?group=integrations").json()
    row = next(row for group in after["groups"] for row in group["settings"]
               if row["id"] == "providers.openai_compatible.base_url")
    assert row["value"] == _ENV_URL and row["source"] == "deployment"
