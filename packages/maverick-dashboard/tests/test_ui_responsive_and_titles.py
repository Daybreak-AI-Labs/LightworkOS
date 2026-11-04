"""UI hardening (responsive_and_titles): responsive tables, page titles, goal rate limit."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _reset_rate_limit():
    from maverick_dashboard import app as dash_app
    with dash_app._goal_rl_lock:
        dash_app._goal_times.clear()
        # Also clear the process-wide window, not just the per-client one: it
        # accumulates across the whole suite (goals from earlier tests within the
        # 60s window), so without this a cap-boundary assertion here is at the
        # mercy of how many goals other tests happened to create just before.
        dash_app._goal_times_global.clear()


# ---------- responsive tables ----------

def test_panel_has_horizontal_overflow(monkeypatch, tmp_path):
    """Wide tables scroll within the panel instead of breaking layout on mobile."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    # /spend renders real .panel markup wrapping a wide table (Goals moved to a
    # rows layout with no table, so it no longer needs the overflow wrapper).
    r = _client().get("/spend")
    assert 'class="panel' in r.text
    # The base stylesheet gives panels overflow-x so tables don't overflow.
    css = _client().get("/static/lightwork.css").text
    assert ".panel" in css and "overflow-x: auto" in css


def test_mobile_topbar_cannot_widen_the_document(monkeypatch, tmp_path):
    """Phone chrome keeps every control reachable without clipping the page."""
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    css = _client().get("/static/lightwork.css").text
    assert "@media (max-width: 560px)" in css
    assert ".brand__name { display: none; }" in css
    assert "flex-wrap: nowrap;" in css
    # The pill never wraps to "Emerg / ency / stop" on a narrow screen: the
    # label is clipped with an ellipsis instead, and the banner repeats it.
    assert ".halt-pill { min-width: 0; padding-inline: 0.55rem; white-space: nowrap; }" in css
    assert ".halt-pill #halt-label { max-width: 6.5rem; overflow: hidden; text-overflow: ellipsis; }" in css
    assert "@media (max-width: 360px)" in css
    assert ".topbar__controls { flex-basis: 100%; }" in css
    assert "max-height: calc(100dvh - var(--shell-topbar-h) - var(--space-5))" in css


# ---------- page titles ----------

@pytest.mark.parametrize("path,fragment", [
    ("/goals", "Tasks · Lightwork"),
    ("/facts", "Facts · Lightwork"),
    ("/tools", "Tools · Lightwork"),
    ("/spend", "Spend · Lightwork"),
    ("/plugins", "Plugins · Lightwork"),
    ("/channels", "Channels · Lightwork"),
    ("/audit", "Activity log · Lightwork"),
    ("/mcp", "Tool servers · Lightwork"),
])
def test_page_titles_carry_app_name(monkeypatch, tmp_path, path, fragment):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    r = _client().get(path)
    assert f"<title>{fragment}</title>" in r.text


# ---------- goal-creation rate limit ----------

def test_chat_send_rate_limited(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "2")
    from maverick import runner
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda *a, **kw: None)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    _reset_rate_limit()

    client = _client()
    ok1 = client.post("/chat/send", data={"title": "a"},
                      headers={"Origin": "http://127.0.0.1"}, follow_redirects=False)
    ok2 = client.post("/chat/send", data={"title": "b"},
                      headers={"Origin": "http://127.0.0.1"}, follow_redirects=False)
    blocked = client.post("/chat/send", data={"title": "c"},
                          headers={"Origin": "http://127.0.0.1"}, follow_redirects=False)
    assert ok1.status_code == 303
    assert ok2.status_code == 303
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_api_goals_shares_the_same_cap(monkeypatch, tmp_path):
    """The cap is global across /chat/send + /api/v1/goals."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "1")
    from maverick import runner
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda *a, **kw: None)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    _reset_rate_limit()

    client = _client()
    # One goal via chat consumes the single slot...
    r1 = client.post("/chat/send", data={"title": "a"},
                     headers={"Origin": "http://127.0.0.1"}, follow_redirects=False)
    assert r1.status_code == 303
    # ...so the API route is now over the shared cap.
    r2 = client.post("/api/v1/goals", json={"title": "b"},
                     headers={"Origin": "http://127.0.0.1"})
    assert r2.status_code == 429


def test_chat_send_empty_title_rejected(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "30")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    _reset_rate_limit()
    r = _client().post("/chat/send", data={"title": "   "},
                       headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 400


def test_rate_limit_default_is_generous(monkeypatch):
    """Default cap is 30/min; a malformed env value falls back to 30."""
    from maverick_dashboard import app as dash_app
    monkeypatch.delenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", raising=False)
    assert dash_app._max_goals_per_min() == 30
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "not-a-number")
    assert dash_app._max_goals_per_min() == 30
