"""The Data Use Governance page can be turned on by environment alone.

Hosted deployments keep the config file on ephemeral storage, so the module
needs the same env-first switch the flow engine has.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

DISABLED_COPY = 'data-module-gate="data_use_governance"'


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    from maverick import config, world_model
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DATA_USE_GOVERNANCE", raising=False)
    monkeypatch.setenv("MAVERICK_TENANT", "data-use-switch")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield tmp_path / "config.toml"
    config.reset_config_cache()


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_is_off_without_config_or_env():
    r = _client().get("/data-use")
    assert r.status_code == 200
    assert DISABLED_COPY in r.text


def test_env_switch_turns_the_page_on(monkeypatch):
    monkeypatch.setenv("MAVERICK_DATA_USE_GOVERNANCE", "1")
    r = _client().get("/data-use")
    assert r.status_code == 200
    assert DISABLED_COPY not in r.text


@pytest.mark.parametrize(
    ("environment", "file_enabled", "enabled"),
    [(None, False, False), (None, True, True), ("1", False, True), ("0", True, False)],
)
def test_page_and_api_use_the_same_effective_gate(
    monkeypatch, _isolate, environment, file_enabled, enabled,
):
    from maverick import config

    _isolate.write_text(
        "[data_use_governance]\nenable = " + str(file_enabled).lower() + "\n",
        encoding="utf-8",
    )
    if environment is not None:
        monkeypatch.setenv("MAVERICK_DATA_USE_GOVERNANCE", environment)
    config.reset_config_cache()
    client = _client()
    assert (DISABLED_COPY not in client.get("/data-use").text) is enabled
    status = client.get("/api/v1/data-use/status")
    assert status.status_code == (200 if enabled else 403), status.text
    if enabled:
        assert status.json()["compiler_enabled"] is False
        assert client.post("/api/v1/data-use/decisions/example/compile", json={}).status_code == 403


def test_invalid_configuration_cannot_be_enabled_by_environment(monkeypatch, _isolate):
    from maverick import config

    _isolate.write_text("[data_use_governance\nenable = true", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_DATA_USE_GOVERNANCE", "1")
    config.reset_config_cache()
    assert config.data_use_governance_enabled() is False
    client = _client()
    # The shared authentication boundary may reject the unreadable config
    # before either route is reached. It must never enable an operation.
    assert client.get("/data-use").status_code in (401, 403)
    assert client.get("/api/v1/data-use/status").status_code in (401, 403)
