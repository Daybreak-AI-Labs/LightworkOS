"""UI hardening (ids_and_labels): unique ids, input accessible names, search guard."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _setup_all(monkeypatch, tmp_path):
    """Full setup + the list of every HTML route (one goal exists)."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.setattr(
        "maverick.audit.writer.DEFAULT_AUDIT_DIR", tmp_path / "audit",
    )
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.audit.writer as aw
    aw._default = None
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    gid = world_model.WorldModel(db).create_goal("g", "d")
    paths = [
        "/", "/chat", "/goals", "/skills", "/store", "/facts", "/spend",
        "/providers", "/tools", "/permissions", "/channels", "/plugins",
        "/mcp", "/audit", "/cache", "/ekko",
        f"/chat/goal/{gid}", f"/goals/{gid}/plan", f"/goals/{gid}/trajectory",
    ]
    return _client(), paths


def test_no_duplicate_element_ids(monkeypatch, tmp_path):
    """Duplicate ids break label/anchor links and getElementById."""
    client, paths = _setup_all(monkeypatch, tmp_path)
    for p in paths:
        r = client.get(p)
        assert r.status_code == 200, f"{p} -> {r.status_code}"
        ids = re.findall(r'\bid="([^"]+)"', r.text)
        dups = sorted({i for i in ids if ids.count(i) > 1})
        assert not dups, f"{p}: duplicate ids {dups}"


def test_overview_goal_input_has_accessible_name(monkeypatch, tmp_path):
    # The first-run goal form only renders on an empty world (no goals).
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    r = _client().get("/overview")
    assert 'aria-label="Describe a task for Lightwork to do"' in r.text


def test_skill_source_input_has_accessible_name(monkeypatch, tmp_path):
    client, _ = _setup_all(monkeypatch, tmp_path)
    r = client.get("/skills")
    assert 'aria-label="Web address of the skill"' in r.text


def test_audit_search_button_disables_during_search(monkeypatch, tmp_path):
    client, _ = _setup_all(monkeypatch, tmp_path)
    r = client.get("/audit")
    assert "b.disabled = true" in r.text
