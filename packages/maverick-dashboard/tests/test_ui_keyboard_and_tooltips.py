"""UI hardening (keyboard_and_tooltips): keyboard-scrollable regions + truncation tooltips."""
from __future__ import annotations

from fastapi.testclient import TestClient

from test_support.element_text import element_attributes, element_texts


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_goal_log_and_result_are_keyboard_scrollable(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick import world_model
    gid = world_model.WorldModel(tmp_path / "world.db").create_goal("g", "d")
    r = _client().get(f"/chat/goal/{gid}")
    assert r.status_code == 200
    assert ('id="events" role="log" aria-live="polite" '
            'aria-label="Goal progress" tabindex="0"') in r.text
    result, = element_attributes(r.text, "div", {"id": "result"})
    assert result["tabindex"] == "0"
    assert result["aria-labelledby"] == "answer-result-label"
    assert element_texts(r.text, "span", {"id": result["aria-labelledby"]}) == ["Goal result"]


def test_audit_results_region_is_focusable_and_named(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(
        "maverick.audit.writer.DEFAULT_AUDIT_DIR", tmp_path / "audit",
    )
    import maverick.audit.writer as aw
    aw._default = None
    r = _client().get("/audit")
    assert 'id="aud-q"' in r.text and 'name="q"' in r.text  # word search is a labelled field


def test_focus_ring_covers_focusable_regions(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    css = _client().get("/static/lightwork.css").text
    assert '[tabindex="0"]:focus-visible' in css


def test_long_goal_description_has_tooltip(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick import world_model
    long_desc = "x" * 200
    world_model.WorldModel(tmp_path / "world.db").create_goal("g", long_desc)
    r = _client().get("/goals")
    assert r.status_code == 200
    assert 'title="' + long_desc + '"' in r.text
