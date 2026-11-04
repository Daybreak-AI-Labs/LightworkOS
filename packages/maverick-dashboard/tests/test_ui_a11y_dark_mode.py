"""UI hardening (a11y_dark_mode): a11y + dark-mode sweep.

Covers table-header scope, color-scheme, the nav landmark label, the
skip-link focus target, and the skill-install double-submit guard.
"""
from __future__ import annotations

import pytest
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


# ---------- table headers carry scope ----------

def test_goals_renders_runs_accessibly(monkeypatch, tmp_path):
    # Goals now renders scannable run rows (not a table); the a11y guarantee is
    # that it carries no bare header cells and surfaces the run.
    _prep(monkeypatch, tmp_path)
    from maverick import world_model
    world_model.WorldModel(tmp_path / "world.db").create_goal("g", "d")
    r = _client().get("/goals")
    assert r.status_code == 200
    assert "g-row" in r.text and "g" in r.text
    assert "<th>" not in r.text  # no bare header cells


@pytest.mark.parametrize("path", ["/goals", "/facts", "/spend", "/tools", "/providers"])
def test_no_bare_table_headers(monkeypatch, tmp_path, path):
    """Regression guard: every rendered <th> is scoped (or there is none)."""
    _prep(monkeypatch, tmp_path)
    r = _client().get(path)
    assert r.status_code == 200
    assert "<th>" not in r.text


# ---------- base layout: dark-mode + landmarks ----------

def test_color_scheme_declared_for_native_controls(monkeypatch, tmp_path):
    """Native controls (scrollbars, selects, number spinners) match the theme."""
    _prep(monkeypatch, tmp_path)
    css = _client().get("/static/lightwork.css").text
    assert "color-scheme: dark;" in css
    assert "color-scheme: light;" in css


def test_nav_landmark_is_labelled(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    # This contract covers base.html; the root may route to the chat shell
    # or onboarding according to the selected model's readiness.
    r = _client().get("/overview")
    assert r.status_code == 200
    from test_support.element_text import element_texts
    from test_support.navigation import assert_navigation_link

    assert len(element_texts(r.text, "nav", {"aria-label": "Primary"})) == 1
    assert_navigation_link(r.text, "/overview", "Overview")


def test_skip_link_target_is_focusable(monkeypatch, tmp_path):
    """The skip link moves keyboard focus into <main>, not just the viewport."""
    _prep(monkeypatch, tmp_path)
    r = _client().get("/")
    assert '<main id="content" tabindex="-1">' in r.text


# ---------- skill install double-submit guard ----------

def test_skill_install_button_disables_on_submit(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/skills")
    assert "btn.disabled = true" in r.text
