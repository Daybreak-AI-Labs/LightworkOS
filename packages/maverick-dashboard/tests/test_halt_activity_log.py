"""Engaging and releasing the emergency stop appears in the Activity log.

Live, an organization administrator engaged and released the emergency stop
from a workspace, then searched the workspace's Activity log for "halt" and
"emergency": nothing. The stop was recorded only in the deployment-wide
chain, as an unnamed "Administrator action" by "*".
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash
    from maverick_dashboard import auth

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "halt" / "HALT"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_TENANT", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:chris")
    config.reset_config_cache()
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **_: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick",
        claims={"sub": token, "email": token + "@example.com"}))
    from maverick_dashboard import step_up
    monkeypatch.setattr(step_up, "require_recent_mfa", lambda *a, **k: None)
    dash._world_cache.clear()
    from maverick.tenant import registry
    from maverick_dashboard import workspace_tenants

    registry.create_tenant("demo", display_name="Demo")
    workspace_tenants.set_selection("user:chris", "demo")
    yield TestClient(dash.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash._world_cache.clear()
    audit_writer._defaults.clear()


HEADERS = {"Authorization": "Bearer chris", "X-Lightwork-Expected-Tenant": "demo"}


@pytest.mark.parametrize("words", ["emergency", "halt"])
def test_engaging_and_releasing_the_emergency_stop_is_in_the_activity_log(client, words):
    assert client.post("/api/v1/halt", json={"reason": "QA check of the stop"}, headers=HEADERS).status_code == 204
    assert client.delete("/api/v1/halt", headers=HEADERS).status_code == 204
    page = client.get("/audit", params={"q": words}, headers=HEADERS)
    assert page.status_code == 200
    text = page.text
    assert "Emergency stop engaged" in text and "Emergency stop released" in text
    assert "chris" in text


def test_the_stop_rows_name_who_did_it(client):
    from maverick_dashboard.audit_actions_api import event_label, event_person

    assert client.post("/api/v1/halt", json={"reason": "QA"}, headers=HEADERS).status_code == 204
    assert client.delete("/api/v1/halt", headers=HEADERS).status_code == 204
    from maverick.audit import global_audit_log
    rows = [row for row in global_audit_log().tail(20) if row.get("kind") == "control_plane_action"]
    assert [event_label(row) for row in rows[-2:]] == ["Emergency stop engaged", "Emergency stop released"]
    assert {event_person(row) for row in rows[-2:]} == {"user:chris"}


def test_the_workspace_record_keeps_who_and_why(client, tmp_path):
    import json

    assert client.post("/api/v1/halt", json={"reason": "QA check of the stop"}, headers=HEADERS).status_code == 204
    assert client.delete("/api/v1/halt", headers=HEADERS).status_code == 204
    rows = [json.loads(line) for path in sorted((tmp_path / "home" / "tenants" / "demo" / "audit").glob("*.ndjson"))
            for line in path.read_text().splitlines() if line.strip()]
    stops = [row for row in rows if row.get("kind") == "halt"]
    assert [(row["status"], row["actor"]) for row in stops] == [("engaged", "user:chris"), ("released", "user:chris")]
    assert stops[0]["reason"] == "QA check of the stop" and stops[1]["reason"]
