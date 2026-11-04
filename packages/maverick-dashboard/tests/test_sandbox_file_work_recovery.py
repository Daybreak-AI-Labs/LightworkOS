"""First-run file work must be recoverable from Permissions after Docker starts."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    import maverick_dashboard.api as api
    from maverick import config, runtime_overrides
    from maverick_installer import wizard

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    monkeypatch.setattr(api, "_probe_container_daemon", lambda name: {
        "available": name == "docker", "detail": "Ready" if name == "docker" else "Not running",
    })
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "_docker_available", lambda: False)
    assert wizard.write_consumer_config(
        user_name="Taylor", keys={}, workdir=str(tmp_path / "work"),
        budget={"max_dollars": 2, "max_wall_seconds": 1800},
    ) == "local"
    config.reset_config_cache()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_first_run_recovery_is_explicit_and_keeps_other_blocks(client):
    from maverick import config

    status = client.get("/api/v1/sandbox/status").json()
    assert status["backend"] == "local"
    assert set(status["file_work"]["blocked_tools"]) == {
        "shell", "write_file", "apply_patch", "str_replace_editor", "ast_edit",
    }
    assert client.post("/api/v1/sandbox/file-work/enable", json={"confirm": True}).status_code == 409
    assert client.post("/api/v1/sandbox/backend", json={"backend": "docker"}).status_code == 200
    assert client.post("/api/v1/sandbox/file-work/enable", json={}).status_code == 400
    assert "write_file" in config.load_config()["security"]["denied_tools"]

    result = client.post("/api/v1/sandbox/file-work/enable", json={"confirm": True})
    assert result.status_code == 200, result.text
    assert result.json()["backend"] == "docker"
    assert result.json()["file_work"]["blocked_tools"] == []
    assert set(config.load_config()["security"]["denied_tools"]) == {
        "computer", "browser",
    }
    assert client.get("/api/v1/sandbox/status").json()["file_work"]["blocked_tools"] == []


def test_recovery_refuses_unavailable_daemon_without_mutating(client, monkeypatch):
    import maverick_dashboard.api as api
    from maverick import config

    assert client.post("/api/v1/sandbox/backend", json={"backend": "docker"}).status_code == 200
    monkeypatch.setattr(api, "_probe_container_daemon", lambda name: {
        "available": False, "detail": "Still starting",
    })
    result = client.post("/api/v1/sandbox/file-work/enable", json={"confirm": True})
    assert result.status_code == 409
    assert "write_file" in config.load_config()["security"]["denied_tools"]


def test_recovery_requires_global_admin(client, monkeypatch):
    import maverick_dashboard.auth as auth

    assert client.post("/api/v1/sandbox/backend", json={"backend": "docker"}).status_code == 200
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:operator")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "operator")
    assert client.post("/api/v1/sandbox/file-work/enable", json={"confirm": True}).status_code == 403


def test_higher_precedence_rule_cannot_be_overridden_by_recovery(client, monkeypatch, tmp_path):
    from maverick import config
    from maverick_dashboard import settings_store

    assert client.post("/api/v1/sandbox/backend", json={"backend": "docker"}).status_code == 200
    operator = tmp_path / "operator.toml"
    operator.write_text('[security]\ndenied_tools = ["write_file"]\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(operator))
    config.reset_config_cache()
    result = client.post("/api/v1/sandbox/file-work/enable", json={"confirm": True})
    assert result.status_code == 409
    assert "write_file" in result.json()["detail"] or "deployment" in result.json()["detail"]
    assert not (settings_store.load_overlay().get("security") or {}).get("denied_tools")


def test_missing_activity_record_prevents_recovery_write(client, monkeypatch):
    from maverick import audit, config

    assert client.post("/api/v1/sandbox/backend", json={"backend": "docker"}).status_code == 200
    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: False)
    result = client.post("/api/v1/sandbox/file-work/enable", json={"confirm": True})
    assert result.status_code == 503
    assert "write_file" in config.load_config()["security"]["denied_tools"]


def test_other_tool_rules_are_reported_after_first_run_blocks_are_cleared(client, tmp_path):
    from maverick import runtime_overrides

    assert client.post("/api/v1/sandbox/backend", json={"backend": "docker"}).status_code == 200
    runtime_overrides.OVERRIDES_PATH.write_text(
        '[security]\ndenied_tools = ["shell"]\n', encoding="utf-8",
    )
    status = client.get("/api/v1/sandbox/status")
    assert status.status_code == 200
    assert "shell" in status.json()["file_work"]["other_policy_blocks"]
    result = client.post("/api/v1/sandbox/file-work/enable", json={"confirm": True})
    assert result.status_code == 200
    assert result.json()["file_work"]["blocked_tools"] == []
    assert "shell" in result.json()["file_work"]["other_policy_blocks"]


def test_permissions_explains_second_step(client):
    page = client.get("/permissions").text
    assert 'id="file-work-card"' in page
    assert "/api/v1/sandbox/file-work/enable" in page
    assert "Allow file work in" in page
