"""Run tree on the dashboard: the read-only counterfactual view and its JSON
endpoint — forked runs listed, branches nested, empty state honest, and the
same owner scoping every other goal surface uses."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, session_tree, world_model
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(session_tree, "registry_path",
                        lambda: tmp_path / "session_tree.json")
    # api.py and app.py keep separate per-path WorldModel caches; drop both so
    # the new DEFAULT_DB binds on this test's first request.
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod
    api_mod._world_cache.clear()
    app_mod._world_cache.clear()
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _forked_run(owner=""):
    """A parent run with a trail, plus one branch off its second event."""
    from maverick import session_tree
    from maverick.world_model import open_world
    world = open_world()
    gid = world.create_goal("ship the migration", "cutover", owner=owner)
    ids = [world.append_event(gid, "planner", "status", s)
           for s in ("planned", "called the API", "wrote the file")]
    child = session_tree.fork(gid, at_event=ids[1], label="blue/green instead",
                              forked_by=owner)
    return gid, child, ids


def test_page_renders_a_forked_run_and_its_branch():
    gid, child, ids = _forked_run()
    r = client.get("/run-tree")
    assert r.status_code == 200
    body = r.text
    assert "Branches" in body
    assert f"/goals/{gid}/trajectory" in body and f"/goals/{child}/trajectory" in body
    assert "blue/green instead" in body
    assert "branched from a step" in body
    # The nesting is real markup, not a flat list.
    assert "loop(" not in body and "<ul>" in body


def test_page_renders_the_empty_state_with_no_forks():
    r = client.get("/run-tree")
    assert r.status_code == 200
    assert "No tasks have branches yet" in r.text
    assert "0 tasks with branches" in r.text


def test_api_returns_the_tree_json():
    gid, child, ids = _forked_run()
    r = client.get(f"/api/v1/run-tree/{gid}")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True and body["root"] == gid
    assert body["lineage"] == {
        "goal_id": gid, "parent": None, "children": [child], "depth": 0,
        "root": gid, "label": "", "forked_at_event": None}
    tree = body["tree"]
    assert tree["goal_id"] == gid and len(tree["children"]) == 1
    branch = tree["children"][0]
    assert branch["goal_id"] == child and branch["label"] == "blue/green instead"
    assert branch["forked_at_event"] == ids[1] and branch["children"] == []


def test_api_answers_from_the_root_when_asked_about_a_branch():
    gid, child, _ = _forked_run()
    body = client.get(f"/api/v1/run-tree/{child}").json()
    assert body["goal_id"] == child and body["root"] == gid
    assert body["lineage"]["parent"] == gid and body["lineage"]["depth"] == 1
    assert body["tree"]["goal_id"] == gid   # the whole tree, both branches


def test_api_404s_an_unknown_run():
    assert client.get("/api/v1/run-tree/999999").status_code == 404


def test_owner_scoping_hides_another_principal_s_run(monkeypatch):
    # Same rule as every other goal surface: an authenticated non-admin sees
    # only runs they own, and a foreign run is a 404, not a 403. Hermetic OIDC
    # seam (as in test_authz_owner_scoping): `Bearer ada` -> principal user:ada.
    import maverick_dashboard.auth as auth
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import rbac

    rbac.set_role("user:ada", "operator")
    rbac.set_role("user:bob", "operator")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **_kw: (
        VerifiedPrincipal(sub=token, issuer="https://issuer.example",
                          audience="maverick", claims={"sub": token})))
    gid, child, _ = _forked_run(owner="user:ada")

    def _as(user):
        return {"Origin": "http://127.0.0.1", "Authorization": f"Bearer {user}"}

    assert client.get(f"/api/v1/run-tree/{gid}", headers=_as("bob")).status_code == 404
    assert "No tasks have branches yet" in client.get(
        "/run-tree", headers=_as("bob")).text
    # The owner still sees the whole tree.
    owned = client.get(f"/api/v1/run-tree/{gid}", headers=_as("ada"))
    assert owned.status_code == 200
    assert owned.json()["tree"]["children"][0]["goal_id"] == child
    assert f"/goals/{child}/trajectory" in client.get("/run-tree", headers=_as("ada")).text
    # Branching someone else's task is refused like reading it.
    assert client.post(f"/api/v1/run-tree/{gid}/fork", json={}, headers=_as("bob")).status_code == 404


def test_fork_endpoint_branches_a_task_from_a_chosen_step():
    from maverick.world_model import open_world

    world = open_world()
    gid = world.create_goal("draft the memo", "")
    ids = [world.append_event(gid, "planner", "status", s) for s in ("one", "two", "three")]
    r = client.post(f"/api/v1/run-tree/{gid}/fork", json={"at_event": ids[1], "label": "shorter"})
    assert r.status_code == 201
    child = r.json()["goal_id"]
    tree = client.get(f"/api/v1/run-tree/{gid}").json()["tree"]
    assert tree["children"][0]["goal_id"] == child
    assert tree["children"][0]["forked_at_event"] == ids[1]
    # A step that is not on the task is refused in plain terms, not a 500.
    assert client.post(f"/api/v1/run-tree/{gid}/fork", json={"at_event": 999999}).status_code == 409
    assert client.post("/api/v1/run-tree/999999/fork", json={}).status_code == 404


def test_fork_and_rewind_need_the_operate_permission(monkeypatch):
    from fastapi import HTTPException
    from maverick.world_model import open_world
    from maverick_dashboard import run_tree_actions_api

    gid = open_world().create_goal("keep me", "")

    def deny(_request, _permission):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(run_tree_actions_api, "require_permission", deny)
    assert client.post(f"/api/v1/run-tree/{gid}/fork", json={}).status_code == 403
    assert client.get(f"/api/v1/run-tree/{gid}/checkpoints").status_code == 403
    assert client.post(f"/api/v1/run-tree/{gid}/rewind", json={"to_step": 1}).status_code == 403


def test_rewind_lists_saved_steps_and_refuses_what_it_cannot_restore():
    from maverick.world_model import open_world

    world = open_world()
    gid = world.create_goal("never checkpointed", "")
    assert client.get(f"/api/v1/run-tree/{gid}/checkpoints").json() == {"goal_id": gid, "steps": []}
    assert client.post(f"/api/v1/run-tree/{gid}/rewind", json={"to_step": 1}).status_code == 409
    world.set_goal_status(gid, "active")
    running = client.post(f"/api/v1/run-tree/{gid}/rewind", json={"to_step": 1, "as_copy": False})
    assert running.status_code == 409


def test_branch_pages_read_plainly_and_offer_the_controls():
    from maverick.world_model import open_world

    from test_support.plain_language import developer_terms

    world = open_world()
    gid = world.create_goal("plan the offsite", "")
    world.append_event(gid, "planner", "status", "picked a venue")
    page = client.get("/run-tree").text
    assert developer_terms(page) == []
    assert 'id="rt-fork"' in page and 'id="rt-rewind"' in page and "plan the offsite" in page
    steps = client.get(f"/goals/{gid}/trajectory").text
    assert developer_terms(steps) == []
    assert "Branch from here" in steps and "Step-by-step history" in steps


@pytest.mark.parametrize("status", ["pending", "queued", "active", "running"])
def test_rewind_refuses_a_task_a_worker_may_start(monkeypatch, status):
    """A waiting task can be picked up by a worker at any moment: going back
    under it would race that run, so it is refused like a running one."""
    import maverick.checkpoint as checkpoint
    from maverick.world_model import open_world

    calls: list[int] = []

    def fake_rewind(world, goal_id, to_step, fork=False):  # pragma: no cover - must not run
        calls.append(goal_id)
        raise AssertionError("rewind must not run for a task a worker may start")

    monkeypatch.setattr(checkpoint, "rewind", fake_rewind)
    world = open_world()
    gid = world.create_goal("waiting to run", "")
    world.set_goal_status(gid, status)
    r = client.post(f"/api/v1/run-tree/{gid}/rewind", json={"to_step": 1, "as_copy": False})
    assert r.status_code == 409
    assert "waiting" in r.json()["detail"] or "running" in r.json()["detail"]
    assert calls == []
