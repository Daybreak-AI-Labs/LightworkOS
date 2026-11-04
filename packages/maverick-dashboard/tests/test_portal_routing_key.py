"""Vendor link key rotation: global admin, grace period, audited, never shown.

The key behind every vendor portal address can be rotated from the
Third-Party Collaboration page. The previous key keeps opening existing
addresses until its grace period ends; the environment variable, when set,
wins and cannot be rotated here.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/third-party/portal-routing-key"
ENV = "MAVERICK_THIRD_PARTY_PORTAL_ROUTING_KEY"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in (ENV, "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    return rows


def _ring() -> dict:
    from maverick import config

    config.reset_config_cache()
    return config.load_global_config()["third_party_portal"]["routing_keyring"]


def _keys() -> tuple[bytes, ...]:
    from maverick_dashboard.third_party_collaboration_composition import (
        _configured_routing_key,
        _resolve_routing_key_material,
    )

    return _resolve_routing_key_material(_configured_routing_key)[1]


def _rotate(hours: int, **extra):
    return client.post(API + "/rotate", json={"confirm": True, "grace_hours": hours, **extra})


def test_rotation_keeps_old_links_working_for_the_grace_period(monkeypatch, audit_rows):
    from maverick import config
    from maverick_dashboard.third_party_collaboration_composition import (
        derive_third_party_collaboration_portal_ref,
    )

    assert client.get(API).json()["configured"] is False
    first = _rotate(24)
    assert first.status_code == 200, first.text
    old_key = _ring()["current"]
    old_ref = derive_third_party_collaboration_portal_ref("acme", old_key)
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert old_key not in stored and "MVKAR1:" in stored
    assert old_key not in first.text and old_key not in client.get(API).text

    second = _rotate(24)
    assert second.status_code == 200 and second.json()["previous_keys_open"] == 1
    new_key = _ring()["current"]
    assert new_key != old_key and new_key not in second.text
    keys = _keys()
    assert keys[0] == new_key.encode() and old_key.encode() in keys
    refs = {derive_third_party_collaboration_portal_ref("acme", key) for key in keys}
    assert old_ref in refs
    # After the grace period the old key no longer opens anything.
    later = time.time() + 25 * 3600
    monkeypatch.setattr(time, "time", lambda: later)
    assert _keys() == (new_key.encode(),)
    assert [(row["section"], row["key"], row["old"], row["new"]) for row in audit_rows] == [
        ("third_party_portal", "routing_key", "not set", "rotated"),
        ("third_party_portal", "routing_key", "set", "rotated")]
    assert all(old_key not in repr(row) and new_key not in repr(row) for row in audit_rows)


def test_no_grace_ends_old_links_now_and_at_most_two_old_keys_stay(audit_rows):
    for hours in (24, 24, 24, 24):
        assert _rotate(hours).status_code == 200
    assert len(_keys()) == 3  # the current key plus two previous ones
    assert _rotate(0).status_code == 200
    assert len(_keys()) == 3  # older grace periods still run their course
    ring = _ring()
    assert ring["current"].encode() == _keys()[0]


def test_only_installation_administrators_on_this_site_can_rotate(monkeypatch, audit_rows):
    from maverick_dashboard import auth, rbac

    assert TestClient(app, base_url="http://127.0.0.1").post(API + "/rotate", json={"confirm": True, "grace_hours": 1}).status_code == 403
    assert _rotate(1, extra="field").status_code == 422
    assert client.post(API + "/rotate", json={"confirm": False, "grace_hours": 1}).status_code == 422
    assert _rotate(5).status_code == 422
    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    assert client.get(API).status_code == 403
    assert _rotate(1).status_code == 403
    assert [row for row in audit_rows if row["kind"] != "access_grant_changed"] == []


def test_a_key_set_on_the_server_wins_and_cannot_be_rotated_here(monkeypatch, audit_rows):
    assert _rotate(1).status_code == 200
    server_key = "k" * 40
    monkeypatch.setenv(ENV, server_key)
    assert client.get(API).json()["managed_by_server"] is True
    assert _rotate(1).status_code == 409
    assert _keys() == (server_key.encode(),)
    assert len(audit_rows) == 1


def test_a_refused_audit_record_undoes_the_rotation(monkeypatch):
    import maverick.audit as audit

    assert _rotate(1).status_code == 200
    before = _ring()["current"]

    def refuse(kind, **payload):
        raise audit.AuditRefused("audit sink unavailable")

    monkeypatch.setattr(audit, "audit_event", refuse)
    assert _rotate(1).status_code == 503
    assert _ring()["current"] == before


def test_the_page_offers_the_link_key_panel(audit_rows):
    from maverick_dashboard import app as dash_app

    page = dash_app.templates.get_template("_portal_routing_key.html").render()
    assert 'id="portal-key"' in page and "/static/lightwork-portal-routing-key.js" in page
    assert client.get("/static/lightwork-portal-routing-key.js").status_code == 200
