"""Dependent initializers run only after the shell provides shared UI helpers."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(("path", "helper_call"), [
    ("/deliverables", "window.mvWhen(ts)"),
    ("/perf", 'mvEl("td", null, c)'),
    ("/chat/goal/{goal_id}", "/static/lightwork-answer-panel.js"),
])
def test_page_initializers_follow_shared_helpers(monkeypatch, tmp_path, path, helper_call):
    from maverick import world_model
    from maverick_dashboard import app as dashboard

    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    dashboard._world_cache.clear()
    if "{goal_id}" in path:
        goal_id = world_model.WorldModel(db).create_goal("Review the result", "Test")
        path = path.format(goal_id=goal_id)
    client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    page = client.get(path)
    assert page.status_code == 200
    dependency = page.text.index('<script src="/static/lightwork-ui.js')
    dependent_call = page.text.index(helper_call)
    initializer = page.text.rfind("<script", 0, dependent_call)
    if helper_call.startswith("/static/"):
        # This external controller is deferred until parsing completes. The
        # synchronous shared helper loads in the shell before deferred scripts run.
        assert "defer" in page.text[initializer:page.text.index(">", initializer)]
        dependency_tag = page.text[dependency:page.text.index(">", dependency)]
        assert "defer" not in dependency_tag and "async" not in dependency_tag
    else:
        assert dependency < initializer < dependent_call


def test_answer_controller_asset_uses_shared_helpers():
    from maverick_dashboard.app import app
    response = TestClient(app, base_url="http://127.0.0.1").get("/static/lightwork-answer-panel.js")
    assert response.status_code == 200
    assert "window.mvWhen" in response.text
