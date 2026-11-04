"""Account sign-in connections without a named Lightwork sign-in.

A single-user (sign-in off) installation, or one that uses a shared dashboard
token, has no named person to own a renewable account sign-in. The Connections
page must say so plainly instead of reporting lost access, and nothing that
changes a connection may be allowed without that named owner.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app


@pytest.fixture(autouse=True)
def _local_home(tmp_path, monkeypatch):
    import os

    from maverick import config, world_model
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_TENANT", "local-workspace")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _client() -> TestClient:
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_account_sign_in_is_reported_unavailable_not_as_lost_access():
    response = _client().get("/api/v1/connection-setup")
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "private, no-store"
    body = response.json()
    assert body["account_sign_in_available"] is False
    assert "named lightwork sign-in" in body["message"].lower()
    assert "key" in body["message"].lower()
    # The test client is not the local machine, so the local-owner shortcut is not offered.
    assert body["can_set_up_sign_in"] is False
    assert "ask whoever manages lightwork sign-in" in body["message"].lower()


def test_fresh_local_install_is_offered_the_named_owner_set_up(monkeypatch):
    monkeypatch.setattr("maverick_dashboard.local_owner.available", lambda request: True)
    body = _client().get("/api/v1/connection-setup").json()
    assert body["account_sign_in_available"] is False
    assert body["can_set_up_sign_in"] is True
    assert "set up named sign-in now" in body["message"]
    # Nothing to review or confirm yet: no context, nothing to connect.
    assert "context" not in body
    assert "applications" not in body


def test_shared_dashboard_token_gets_the_same_plain_answer(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")  # pragma: allowlist secret
    response = TestClient(app, base_url="http://127.0.0.1").get(
        "/api/v1/connection-setup",
        headers={"Authorization": "Bearer dashboard-token"},  # pragma: allowlist secret
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["account_sign_in_available"] is False
    # The local-owner shortcut is not offered where sign-in is already a shared token.
    assert body["can_set_up_sign_in"] is False
    assert "ask whoever manages lightwork sign-in" in body["message"].lower()


_REVIEWED = {"confirm": True, "context": "a" * 64}


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/enable", _REVIEWED),
        ("post", "/authorize", {**_REVIEWED, "profile": "google-drive", "name": "team-drive"}),
        ("post", "/exchange", {**_REVIEWED, "state": "b" * 43, "code": "synthetic-code"}),
        ("put", "/application", {**_REVIEWED, "provider": "google", "client_id": "synthetic-client"}),
    ],
)
def test_changing_account_connections_still_needs_a_named_sign_in(method, path, body):
    response = getattr(_client(), method)("/api/v1/connection-setup" + path, json=body)
    assert response.status_code == 403, (path, response.status_code, response.text)
