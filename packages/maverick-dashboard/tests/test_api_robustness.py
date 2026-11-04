"""Functional robustness: API input validation + polling stop-on-404.

The chat UI rejects empty goal titles / answers, but a direct API call
bypassed that. And the goal page's polling fallback retried a deleted
goal (404) forever instead of giving up.
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
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "30")
    from maverick import runner
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda *a, **kw: None)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    with dash_app._goal_rl_lock:
        dash_app._goal_times.clear()


@pytest.mark.parametrize("title", ["", "   "])
def test_api_create_goal_rejects_empty_title(monkeypatch, tmp_path, title):
    _prep(monkeypatch, tmp_path)
    r = _client().post(
        "/api/v1/goals", json={"title": title},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 400


def test_api_answer_rejects_empty_answer(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick import world_model
    gid = world_model.WorldModel(tmp_path / "world.db").create_goal("g", "d")
    r = _client().post(
        f"/api/v1/goals/{gid}/answer",
        json={"question_id": 1, "answer": "   "},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 400


def test_polling_fallback_stops_on_deleted_goal(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick import world_model
    gid = world_model.WorldModel(tmp_path / "world.db").create_goal("g", "d")
    r = _client().get(f"/chat/goal/{gid}")
    assert "[401, 403, 404].includes(resp.status)" in r.text
    assert "Task access is no longer available." in r.text
    assert "lightwork:task-access-lost" in r.text
