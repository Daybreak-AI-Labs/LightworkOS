"""Exception choices on /security/assurance when AI use rules are off or empty.

Live: GET /api/v1/security/assurance/pickers/policy-exceptions answered 503
"Current rules and safeguards could not be verified" because the turned-off
feature was reported as a verification failure.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ADMIN = "user:dana@corp.com"
PICKER = "/api/v1/security/assurance/pickers/policy-exceptions"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config
    from maverick_dashboard import auth, rbac

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_TENANT", "exceptions-test")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT_BY_USER"):
        monkeypatch.delenv(name, raising=False)
    allowed = lambda request, perm, **kw: perm in rbac.permissions_for("admin")  # noqa: E731
    monkeypatch.setattr(auth, "caller_principal", lambda request: ADMIN)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: ADMIN)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: "admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: "admin")
    monkeypatch.setattr(auth, "has_permission", allowed)
    monkeypatch.setattr(auth, "has_global_permission", allowed)
    config.reset_config_cache()
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), tmp_path / "config.toml"
    config.reset_config_cache()


def test_turned_off_rules_answer_as_turned_off_not_unverified(client):
    http, _config = client
    response = http.get(PICKER)
    assert response.status_code == 403
    assert response.headers["X-Lightwork-Reason"] == "feature-off"
    assert response.json()["detail"] == "AI use rules are turned off."


def test_turned_on_rules_with_nothing_recorded_are_empty_not_an_error(client):
    from maverick import config

    http, path = client
    path.write_text("[ai_policy_management]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    response = http.get(PICKER)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["policies"] == [] and body["exceptions"] == [] and body["controls"] == [] and body["assets"] == []
