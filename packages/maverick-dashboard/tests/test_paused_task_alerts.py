"""Five long tasks pause for input; each one alerts its owner.

A task the agent parks with a question is "blocked" with the question open.
Every such pause must reach the owner's bell and inbox as "needs-decision",
linking straight to the answer box, without carrying the task's text in the
summary. Other people never see them.
"""
from __future__ import annotations

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal


@pytest.fixture
def client_and_actor(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")   # in-app alerts are on by default
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    dashboard._world_cache.clear()
    actor = {"principal": "user:alice"}

    async def bind(request: Request):
        request.state.principal = VerifiedPrincipal(sub=(actor["principal"]).removeprefix("user:"), issuer="https://idp.test", audience="lightwork")
        return request.state.principal

    dashboard.app.dependency_overrides[auth.require_principal_in_request_context] = bind
    monkeypatch.setattr(auth, "role_for_principal", lambda _principal: "operator")
    try:
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            yield client, actor, dashboard._world()
    finally:
        dashboard.app.dependency_overrides.clear()
        dashboard._world_cache.clear()
        config.reset_config_cache()


TASKS = ["Research three vendors for the travel policy", "Draft the quarterly policy update",
         "Reconcile last month's invoices", "Prepare the onboarding checklist", "Summarise the security review"]


def test_every_pause_for_input_in_five_tasks_alerts_the_owner(client_and_actor):
    client, actor, world = client_and_actor
    assert client.get("/api/v1/notifications/personal/summary").json()["unseen"] == 0
    paused = []
    for title in TASKS:
        goal = world.create_goal(title, owner="user:alice")
        world.set_goal_status(goal, "running")
        world.set_goal_status(goal, "blocked")
        paused.append((goal, world.ask(f"Which date range should I use for: {title}?", goal_id=goal)))
    # A sixth task stops for another reason: it is not waiting for an answer.
    other = world.create_goal("Export the audit log", owner="user:alice")
    world.set_goal_status(other, "blocked")

    summary = client.get("/api/v1/notifications/personal/summary")
    assert summary.status_code == 200
    assert summary.json()["unseen"] >= len(TASKS)
    assert "Which date range" not in summary.text

    inbox = client.get("/api/v1/notifications/personal").json()["items"]
    asks = [row for row in inbox if row["category"] == "needs-decision"]
    assert sorted(row["goal_id"] for row in asks) == sorted(goal for goal, _question in paused)
    for row in asks:
        assert row["href"] == f"/chat/goal/{row['goal_id']}#question-panel"
        assert row["label"] == "Needs your answer"
    assert other not in {row["goal_id"] for row in asks}

    # The page people open from the bell is the same inbox (filled by its script).
    assert client.get("/notifications").status_code == 200
    assert sorted(row["title"] for row in asks) == sorted(TASKS)

    # Answering one pause clears its alert; the other four stay.
    goal, question = paused[0]
    world.answer(question, "The last 30 days", expected_owner="user:alice")
    inbox = client.get("/api/v1/notifications/personal").json()["items"]
    still = {row["goal_id"] for row in inbox if row["category"] == "needs-decision"}
    assert still == {goal for goal, _question in paused[1:]}

    # Nobody else is told about Alice's paused tasks.
    actor["principal"] = "user:bob"
    assert not [row for row in client.get("/api/v1/notifications/personal").json()["items"]
                if row["category"] == "needs-decision"]
