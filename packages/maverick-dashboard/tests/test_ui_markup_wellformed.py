"""UI hardening (markup_wellformed): markup well-formedness + base-layout polish.

Adds a render-time tag-balance guard across every HTML route (would have
caught the audit stray </div> and the channels missing </tbody>), plus
checks for the theme-switch param fix, halt-pill Space activation, and
the new head meta tags.
"""
from __future__ import annotations

import re

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_all_html_pages_are_well_formed(monkeypatch, tmp_path):
    """Every HTML route renders 200 with balanced block-level tags."""
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

    client = _client()
    paths = [
        "/", "/chat", "/goals", "/skills", "/store", "/facts", "/spend",
        "/providers", "/tools", "/permissions", "/channels", "/plugins",
        "/mcp", "/audit", "/cache", "/ekko",
        f"/chat/goal/{gid}", f"/goals/{gid}/plan", f"/goals/{gid}/trajectory",
    ]
    for p in paths:
        r = client.get(p)
        assert r.status_code == 200, f"{p} -> {r.status_code}"
        for tag in ("div", "tbody", "table", "ul"):
            opens = len(re.findall(rf"<{tag}\b", r.text))
            closes = len(re.findall(rf"</{tag}>", r.text))
            assert opens == closes, f"{p}: <{tag}> {opens} open / {closes} close"


def test_theme_switch_preserves_query_params(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/")
    assert 'data-ui-preference="theme"' in r.text
    script = _client().get("/static/lightwork-ui.js")
    assert script.status_code == 200
    assert "fetch('/api/v1/preferences/display'" in script.text
    assert "window.mvApplyDisplayPreference(key, value)" in script.text
    # The old clobbering assignment is gone.
    assert "window.location.search = '?theme='" not in r.text


def test_halt_pill_activates_on_space(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    ui = _client().get("/static/lightwork-ui.js").text
    assert "pill.addEventListener('keydown'" in ui


def test_head_declares_color_scheme_and_theme_color(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/")
    assert 'name="color-scheme"' in r.text
    assert 'name="theme-color"' in r.text
