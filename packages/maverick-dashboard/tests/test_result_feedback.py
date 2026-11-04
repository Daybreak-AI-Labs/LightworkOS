"""Finished results outside the task page are marked as AI-written and take
one-tap feedback through the task's own saved-answer feedback."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api, app, auth

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:customer")
    config.reset_config_cache()
    api._world_cache.clear()
    from maverick_dashboard import rbac
    rbac.set_role("user:customer", "admin")
    yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), api._world()
    config.reset_config_cache()
    api._world_cache.clear()


def _finished(world, title, owner):
    goal = world.create_goal(title, "", owner=owner)
    world.set_goal_status(goal, "done", result="The answer.")
    return goal


def _card(page, goal):
    match = re.search(rf'<div class="card dlv-finished">((?:(?!<div class="card dlv-finished">).)*?data-goal="{goal}".*?)</div>\s*</div>',
                      page, re.DOTALL)
    assert match, f"no card for task {goal}"
    return match.group(1)


def test_results_are_marked_and_only_the_owner_can_rate_them(client):
    from maverick_dashboard import rbac

    test_client, world = client
    mine = _finished(world, "My report", "user:customer")
    page = test_client.get("/deliverables").text
    assert "lightwork-result-feedback.js" in page
    own = _card(page, mine)
    assert "Written by an agent." in own and 'data-rating="up"' in own and 'data-rating="down"' in own
    # The card is no longer one big link, so its buttons are not inside an <a>.
    assert f'<a class="dlv-finished__open" href="/chat/goal/{mine}">' in page
    # Someone who may only view still sees the AI mark, without rating buttons.
    rbac.set_role("user:another-admin", "admin")
    rbac.set_role("user:customer", "viewer")
    viewed = _card(test_client.get("/deliverables").text, mine)
    assert "Written by an agent." in viewed and "data-rating" not in viewed


def test_the_feedback_script_is_served(client):
    test_client, _world = client
    response = test_client.get("/static/lightwork-result-feedback.js")
    assert response.status_code == 200 and "javascript" in response.headers["content-type"]


def test_one_tap_saves_through_the_tasks_own_feedback(client):
    test_client, world = client
    goal = _finished(world, "My report", "user:customer")
    current = test_client.get(f"/api/v1/goals/{goal}/answer-feedback").json()
    assert current["eligible"] is True
    body = {"rating": "up", "note": "", "reason": "", "revision": current["revision"],
            "expected_context": current["context"], "operation_id": "a" * 32}
    saved = test_client.post(f"/api/v1/goals/{goal}/answer-feedback", json=body)
    assert saved.status_code == 200, saved.text
    assert saved.json()["feedback"]["rating"] == "up"
    assert saved.json()["acknowledgement"].startswith("Thanks.")
    # The same operation again is the same receipt, not a second rating.
    again = test_client.post(f"/api/v1/goals/{goal}/answer-feedback", json=body).json()
    assert again["feedback"]["replayed"] is True
