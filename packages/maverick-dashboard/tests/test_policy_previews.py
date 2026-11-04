"""Previews of a policy change before it is saved.

Every policy type now shows, before anything is enforced, who and what it
would have affected: blocking tools (for everyone or for one agent or
specialist, on Permissions and in Agent Factory), a shorter keep period
(All settings), and a data use rule (preview, and again when it is switched
on). The approval threshold and spending limits already had theirs.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in list(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")) and name not in {"MAVERICK_HOME", "MAVERICK_ENCRYPT_AT_REST"}:
            monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    from maverick_dashboard.app import _world_cache, app
    _world_cache.clear()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_blocking_tools_previews_their_recorded_use(client):
    from maverick.audit import audit_event
    from maverick.world_model import close_world_if_owned, open_world

    world = open_world()
    try:
        goal = world.create_goal("Check suppliers", owner="user:ana")
    finally:
        close_world_if_owned(world)
    for _ in range(3):
        assert audit_event("tool_call", agent="vendor_review", goal_id=goal, name="web_fetch")
    assert audit_event("tool_call", agent="vendor_review", goal_id=goal, name="shell")
    body = client.get("/api/v1/policy-preview/tools", params={"tools": "web_fetch"}).json()
    assert (body["calls"], body["tasks"], body["agents"], body["people"]) == (3, 1, 1, 1)
    agent = client.get("/api/v1/policy-preview/tools", params={"tools": "web_fetch,shell", "agent": "finance_ap"}).json()
    assert agent["calls"] == 0 and agent["recorded"] is True
    assert client.get("/api/v1/policy-preview/tools", params={"tools": "../etc"}).status_code == 422


def test_a_keep_period_previews_the_next_clean_up(client):
    body = client.get("/api/v1/settings/catalog/preview/retention.messages_days", params={"value": "30"}).json()
    assert body["kind"] == "retention" and body["count"] == 0 and body["unit"] == "messages"
    refused = client.get("/api/v1/settings/catalog/preview/retention.messages_days", params={"value": "0"})
    assert refused.status_code == 422


def test_each_retention_setting_offers_the_preview():
    from maverick_dashboard import settings_catalog as catalog

    keys = {s.key for s in catalog.SETTINGS if s.section == "retention" and s.preview == "retention"}
    assert keys == {"audit_days", "episodes_days", "events_days", "messages_days", "usage_days"}


def test_the_pages_show_the_preview_before_the_change_bites():
    permissions = (PACKAGE / "templates/permissions.html").read_text(encoding="utf-8")
    assert "Block ' + label + '? ' + (foresee" in permissions  # one tool, previewed before Block
    assert "preview: function (items) { return blockPreview(" in permissions  # many tools
    agents = (PACKAGE / "templates/agents.html").read_text(encoding="utf-8")
    assert "'&agent=' + encodeURIComponent(name)" in agents  # a specialist's lost actions
    rules = (PACKAGE / "templates/data_use_governance.html").read_text(encoding="utf-8")
    assert 'id="dug-policy-preview"' in rules and "await rulePreviewText(latest.document)" in rules


def test_a_data_use_rule_previews_the_recorded_requests_it_would_cover(client, tmp_path, monkeypatch):
    import hashlib

    from maverick import config

    (tmp_path / "config.toml").write_text("[data_use_governance]\nenable = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    config.reset_config_cache()

    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    api = "/api/v1/data-use"
    assert client.put(f"{api}/assets/customers", json={"expected_revision": 0, "idempotency_key": "a1",
                      "asset_type": "table", "catalog_binding_sha256": digest("c")}).status_code == 200
    assert client.put(f"{api}/assets/customers/fields/email", json={"expected_revision": 0, "idempotency_key": "f1",
                      "data_type": "string", "nullable": False, "catalog_binding_sha256": digest("e")}).status_code == 200
    made = client.post(f"{api}/requests/use-email", json={
        "project_id": "analytics", "asset_id": "customers", "field_ids": ["email"], "action": "export",
        "purpose_codes": ["analytics"], "request_evidence_sha256": digest("x"), "idempotency_key": "r1"})
    assert made.status_code == 201, made.text
    rule = {"scope": {"asset_ids": ["customers"], "actions": ["export"]}, "conditions": {},
            "controls": [{"control_id": "c1", "effect": "deny"}]}
    body = client.post(f"{api}/policies/preview", json={"document": rule}).json()
    assert (body["considered"], body["requests"], body["projects"]) == (1, 1, 1)
    other = client.post(f"{api}/policies/preview", json={"document": {**rule, "scope": {"actions": ["train"]}}}).json()
    assert other["requests"] == 0
    bad = client.post(f"{api}/policies/preview", json={"document": {"controls": []}})
    assert bad.status_code == 422
