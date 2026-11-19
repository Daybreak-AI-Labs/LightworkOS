"""A file a task saved is a working download on the task's page.

Seen live: asked for totals.csv, the agent wrote it and linked
``sandbox:/…/totals.csv``; the page showed "Download totals.csv" as plain
text and nothing could serve the file.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

BODY = "region,total\nNorth,100\nSouth,200\nEast,300\n"


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick.tools.fs import write_file
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gid = world.create_goal("Make totals.csv", "")
    write_file(SimpleNamespace(workdir=workspace), goal_id=gid, world=world).fn(
        {"path": "totals.csv", "content": BODY})
    world.set_goal_status(gid, "done", result=(
        f"The file is ready: [Download totals.csv](sandbox:{workspace.resolve()}/totals.csv)\n\n"
        "See also [the guide](https://example.com/guide)."))
    client = TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    yield client, world, gid, workspace
    world.close()


def test_the_page_lists_the_file_and_the_answer_links_to_it(env):
    client, _world, gid, _workspace = env
    page = client.get(f"/chat/goal/{gid}").text
    assert 'id="task-files"' in page and "Files from this task" in page
    assert f'href="/chat/goal/{gid}/task-files/1"' in page
    assert f"(/chat/goal/{gid}/task-files/1)" in page        # the answer's own link
    assert "(https://example.com/guide)" in page             # other links untouched
    assert "sandbox:" not in page.split('id="saved-answer-source"')[0]
    panel = client.get(f"/chat/goal/{gid}/answer-panel").text
    assert f'href="/chat/goal/{gid}/task-files/1"' in panel


def test_the_download_serves_the_saved_bytes_as_an_attachment(env):
    client, _world, gid, _workspace = env
    response = client.get(f"/chat/goal/{gid}/task-files/1")
    assert response.status_code == 200 and response.content == BODY.encode()
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"].startswith('attachment; filename="totals.csv"')
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert client.get(f"/chat/goal/{gid}/task-files/2").status_code == 409


def test_a_file_changed_since_is_refused_with_the_reason(env):
    client, _world, gid, workspace = env
    (workspace / "totals.csv").write_text("North,999\n")
    response = client.get(f"/chat/goal/{gid}/task-files/1", headers={"Accept": "text/html"})
    assert response.status_code == 409
    assert "changed after the task saved it" in response.text
    assert f'href="/chat/goal/{gid}"' in response.text
    assert "North,999" not in response.text


def test_another_persons_task_files_stay_private(env):
    client, world, _gid, workspace = env
    from maverick.tools.fs import write_file

    private = world.create_goal("Private plan", "", owner="user:someone-else")
    write_file(SimpleNamespace(workdir=workspace), goal_id=private, world=world).fn(
        {"path": "plan.txt", "content": "secret plan\n"})
    response = client.get(f"/chat/goal/{private}/task-files/1")
    assert response.status_code in (403, 404)
    assert b"secret plan" not in response.content


def test_files_wait_for_the_same_sign_off_as_the_answer(env, monkeypatch):
    client, _world, gid, _workspace = env
    from maverick_dashboard import deliverable_policy

    monkeypatch.setattr(deliverable_policy, "goal_gate", lambda _domain: object())
    page = client.get(f"/chat/goal/{gid}").text
    assert "A reviewer must approve this task" in page
    assert f'href="/chat/goal/{gid}/task-files/1"' not in page
    refused = client.get(f"/chat/goal/{gid}/task-files/1")
    assert refused.status_code == 409 and b"region" not in refused.content


def test_copilot_names_a_tasks_files(monkeypatch):
    from maverick_dashboard import api
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import copilot_live_state as live

    monkeypatch.setenv("MAVERICK_TENANT", "copilot-api-test")
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(dashboard_app, "check_goal_rate_limit", lambda *_a, **_k: None)
    goal = SimpleNamespace(id=34, owner="alice", title="Make totals.csv", status="done",
                           result="Done", updated_at=9, domain="")
    private = SimpleNamespace(id=35, owner="bob", title="Private", status="done",
                              result="", updated_at=9, domain="")
    saved = [SimpleNamespace(number=1, name="totals.csv", size=40)]

    class World:
        def get_goal(self, identifier):
            return {34: goal, 35: private}.get(identifier)

    monkeypatch.setattr(dashboard_app, "_world", lambda: World())
    monkeypatch.setattr("maverick.task_files.files_for", lambda _w, gid: saved if gid == 34 else [])
    monkeypatch.setattr(live.auth, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(live.auth, "assert_goal_access", lambda _request, row: None if row.owner == "alice"
                        else (_ for _ in ()).throw(HTTPException(404, "no such goal")))
    monkeypatch.setattr(api, "_copilot_model_route_status", lambda: pytest.fail("went to the model"))
    client = TestClient(dashboard_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    answer = client.post("/api/v1/copilot", json={"message": "What files did this task make?",
                                                  "page": "/chat/goal/34"}).json()
    assert answer["mode"] == "live"
    assert "totals.csv" in answer["reply"] and "Files from this task" in answer["reply"]
    assert answer["action_link"]["href"] == "/chat/goal/34#task-files"
    denied = client.post("/api/v1/copilot", json={"message": "Which files did task 35 create?",
                                                  "page": "/chat"}).json()
    assert "can't access that task" in denied["reply"]
