"""A2A Agent Card integration tests for the production dashboard app."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture(autouse=True)
def _restore_dashboard_module():
    import maverick_dashboard.app as dashboard_app

    # Reloading replaces the module's app and template globals. Other test
    # modules keep references collected before this file runs.
    previous = vars(dashboard_app).copy()
    try:
        yield
    finally:
        vars(dashboard_app).clear()
        vars(dashboard_app).update(previous)


def _reload_dashboard_app(monkeypatch):
    monkeypatch.setenv("HOME", "/nonexistent-a2a-dashboard-test")
    import maverick_dashboard.app as dashboard_app

    return importlib.reload(dashboard_app)


@pytest.mark.parametrize("path", ["/.well-known/agent-card.json", "/.well-known/agent.json"])
def test_dashboard_serves_a2a_agent_card_when_enabled(monkeypatch, path):
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    # Discovery should remain reachable even when the dashboard control surface
    # is protected by a bearer token.
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
    dashboard_app = _reload_dashboard_app(monkeypatch)

    from fastapi.testclient import TestClient

    client = TestClient(dashboard_app.app, base_url="http://127.0.0.1")
    response = client.get(path)

    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Lightwork"
    assert body["protocolVersion"] == "0.3.0"


def test_dashboard_omits_a2a_agent_card_when_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_A2A_ENABLED", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    dashboard_app = _reload_dashboard_app(monkeypatch)

    from fastapi.testclient import TestClient

    client = TestClient(dashboard_app.app, base_url="http://127.0.0.1")

    assert client.get("/.well-known/agent-card.json").status_code == 404


def test_dashboard_a2a_endpoint_uses_only_its_own_bearer(monkeypatch):
    """Dashboard auth must not force credential reuse across trust domains."""
    import maverick.a2a_tasks as a2a_tasks

    monkeypatch.setattr(
        a2a_tasks, "_default_runner", lambda text, **kwargs: f"ran:{text}"
    )
    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_A2A_TOKEN", "a2a-secret")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-secret")
    dashboard_app = _reload_dashboard_app(monkeypatch)

    from fastapi.testclient import TestClient

    client = TestClient(dashboard_app.app, base_url="http://127.0.0.1")
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "dashboard-a2a-integration-1",
                "parts": [{"kind": "text", "text": "hello"}],
            }
        },
    }

    missing = client.post("/a2a/v1", json=rpc)
    assert missing.status_code == 401
    wrong_domain = client.post(
        "/a2a/v1",
        headers={"Authorization": "Bearer dashboard-secret"},
        json=rpc,
    )
    assert wrong_domain.status_code == 401
    accepted = client.post(
        "/a2a/v1",
        headers={"Authorization": "Bearer a2a-secret"},
        json=rpc,
    )
    assert accepted.status_code == 200
    assert accepted.json()["result"]["status"]["state"] == "completed"
