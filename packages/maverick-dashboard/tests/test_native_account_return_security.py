"""Actual dashboard CSP/validation responses; no provider or native host launch."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick import connection_oauth, world_model
from maverick_dashboard.app import app


@pytest.mark.parametrize("base,path,enabled,allowed", [
    ("http://127.0.0.1:8765", "/connections", True, True),
    ("http://127.0.0.1:8765", "/connections", False, False),
    ("http://127.0.0.1:8765", "/settings", True, False),
    ("http://localhost:8765", "/connections", True, False),
    ("http://127.0.0.1:9999", "/connections", True, False),
    ("https://lightwork.example", "/connections", True, False),
])
def test_ipc_csp_is_limited_to_enabled_exact_local_connections(monkeypatch, tmp_path, base, path, enabled, allowed):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(connection_oauth, "desktop_return_enabled", lambda: enabled)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "synthetic-csp-test-token")
    with TestClient(app, base_url=base, headers={"Origin": base, "Authorization": "Bearer synthetic-csp-test-token"}) as client:
        response = client.get(path)
    assert response.status_code == 200, response.text[:100]
    policy = response.headers["Content-Security-Policy"]
    assert ("http://ipc.localhost" in policy) is allowed
    assert (" ipc:" in policy) is allowed
    assert "script-src 'self'" in policy


@pytest.mark.parametrize("field", ["return_profile", "desktop_return"])
def test_new_native_fields_keep_validation_errors_value_free(monkeypatch, tmp_path, field):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    body = {"confirm": True, "context": "a" * 64}
    if field == "return_profile":
        path = "/exchange"
        body.update(state="b" * 43, code="synthetic-code")
    else:
        path = "/application"
        body.update(provider="google", client_id="synthetic-client")
    body[field] = "synthetic-private-submitted-value"
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        response = client.request("PUT" if field == "desktop_return" else "POST", "/api/v1/connection-setup" + path, json=body)
    assert response.status_code == 422
    assert "synthetic-private-submitted-value" not in response.text
    assert response.json()["detail"][0]["loc"] == ["body", field]


def test_remote_native_capability_has_only_four_scoped_commands():
    root = Path(__file__).resolve().parents[3]
    capabilities = root / "apps/desktop/src-tauri/capabilities"
    remote = json.loads((capabilities / "account-return.json").read_text())
    assert remote["local"] is False and remote["windows"] == ["main"]
    assert remote["remote"] == {"urls": ["http://127.0.0.1:8765/connections"]}
    assert set(remote["permissions"]) == {"allow-prepare-oauth-return", "allow-launch-oauth-return", "allow-consume-oauth-return", "allow-cancel-oauth-return"}
    bundled = json.loads((capabilities / "default.json").read_text())
    assert "remote" not in bundled
    assert not set(remote["permissions"]) & set(bundled["permissions"])


def test_native_helper_is_served_by_real_asset_handler():
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        response = client.get("/static/lightwork-native-account-return.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "LightworkNativeAccountReturn" in response.text
