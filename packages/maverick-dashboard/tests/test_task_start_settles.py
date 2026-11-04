"""Starting a task lands on its page, never on a false "could not start".

A just-created task's row keeps changing while it is admitted and worked on
(status, timestamps). Opening the task page then must not answer 409
"result_changing": only the answer itself and the viewer's access decide
whether a page is stale. A real change while the page is built is retried
briefly; one that never settles is still withheld.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.world_model import WorldModel
from maverick_dashboard import answer_projection, api
from maverick_dashboard import app as dashboard


@pytest.fixture
def chat(monkeypatch, tmp_path):
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(dashboard, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request: None)
    monkeypatch.setattr(answer_projection, "SETTLE_PAUSE_SECONDS", 0)

    async def run(goal_id, **kwargs):
        return None

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()


def _send(client, title="Summarize vendor spend", key="k" * 24):
    response = client.post("/chat/send", data={"title": title, "submission_key": key}, follow_redirects=False)
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def _busy_row(monkeypatch, world, goal_id):
    """Every read of the task sees its row changed by the runner, as during admission."""
    original = world.get_goal
    states = iter(["pending", "active"] * 50)

    def get_goal(wanted):
        if wanted == goal_id:
            world.set_goal_status(goal_id, next(states))
        return original(wanted)

    monkeypatch.setattr(world, "get_goal", get_goal)


@pytest.mark.parametrize("path", ["/chat/goal/{id}", "/chat/goal/{id}/answer-panel"])
def test_a_task_whose_row_is_still_changing_opens_without_a_conflict(chat, monkeypatch, path):
    client, world = chat
    goal_id = _send(client)
    _busy_row(monkeypatch, world, goal_id)
    page = client.get(path.format(id=goal_id))
    assert page.status_code == 200, page.text
    assert "result_changing" not in page.text


def test_a_change_to_the_task_while_its_page_is_built_is_retried_not_shown_as_an_error(chat, monkeypatch):
    client, world = chat
    goal_id = _send(client)
    original = answer_projection._snapshot
    calls = []

    def snapshot(w, goal):
        calls.append(goal_id)
        if len(calls) == 1:  # one real edit lands while the first page is built
            w.add_artifact(goal_id, kind="text", title="Draft", content="Arrived mid-read")
        return original(w, goal)

    monkeypatch.setattr(answer_projection, "_snapshot", snapshot)
    page = client.get(f"/chat/goal/{goal_id}")
    assert page.status_code == 200, page.text
    assert len(calls) >= 2


def test_a_result_that_never_settles_is_still_withheld(chat, monkeypatch):
    client, world = chat
    goal_id = _send(client)
    original = answer_projection._snapshot

    def snapshot(w, goal):
        w.add_artifact(goal_id, kind="text", title="Draft", content="Always changing")
        return original(w, goal)

    monkeypatch.setattr(answer_projection, "_snapshot", snapshot)
    page = client.get(f"/chat/goal/{goal_id}/answer-panel", headers={"Accept": "application/json"})
    assert page.status_code == 409
    assert page.json()["detail"]["code"] == "result_changing"
    assert page.json()["detail"]["retryable"] is True


def test_a_finished_task_still_compares_its_whole_row():
    from maverick.world_model import Goal

    base = dict(id=1, parent_id=None, title="T", description=None, created_at=1.0, deadline=None, owner="user:a")
    running = [Goal(status=s, updated_at=u, result=None, **base) for s, u in (("pending", 2.0), ("active", 3.0))]
    assert len({answer_projection.version_for(g, None, None, []) for g in running}) == 1
    done = [Goal(status="done", updated_at=u, result="R", **base) for u in (2.0, 3.0)]
    assert len({answer_projection.version_for(g, None, None, []) for g in done}) == 2
    # Access is part of the version at every stage.
    moved = Goal(status="active", updated_at=3.0, result=None, **{**base, "owner": "user:b"})
    assert answer_projection.version_for(moved, None, None, []) != answer_projection.version_for(running[1], None, None, [])


def test_one_submit_makes_one_task_even_when_it_is_sent_twice(chat):
    client, world = chat
    first = _send(client, key="same-key-" + "x" * 16)
    second = _send(client, key="same-key-" + "x" * 16)
    assert first == second
    titles = [goal.title for goal in world.list_goals(limit=50)]
    assert titles.count("Summarize vendor spend") == 1


def test_the_sample_task_opens_its_page(chat, monkeypatch):
    from maverick_dashboard import first_outcome_api

    client, world = chat
    monkeypatch.setattr(first_outcome_api, "provider_ready", lambda: True)
    monkeypatch.setattr(first_outcome_api, "run_goal_in_background_async", lambda *a, **k: None)
    monkeypatch.setattr(first_outcome_api, "_world", lambda: world)
    started = client.post("/api/v1/first-outcome/run", json={"department": "finance"})
    assert started.status_code == 201, started.text
    goal_id = started.json()["goal_id"]
    _busy_row(monkeypatch, world, goal_id)
    page = client.get(started.json()["href"])
    assert page.status_code == 200, page.text


def test_a_browser_that_still_meets_a_busy_task_gets_a_page_that_refreshes_itself(chat, monkeypatch):
    client, world = chat
    goal_id = _send(client)
    original = answer_projection._snapshot

    def snapshot(w, goal):
        w.add_artifact(goal_id, kind="text", title="Draft", content="Always changing")
        return original(w, goal)

    monkeypatch.setattr(answer_projection, "_snapshot", snapshot)
    page = client.get(f"/chat/goal/{goal_id}", headers={"Accept": "text/html"})
    assert page.status_code == 409
    assert "Still getting this ready" in page.text
    assert "It refreshes by itself in a moment." in page.text
    assert "location.reload()" in page.text
    assert "Could not start" not in page.text
