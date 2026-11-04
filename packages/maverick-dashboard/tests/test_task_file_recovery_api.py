"""Real file restoration behind named task owner and reviewed context checks."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config
from maverick import task_file_recovery as recovery
from maverick.paths import tenant_scope
from maverick.sandbox.local import LocalBackend
from maverick.tools.fs import write_text_contained
from maverick.world_model import WorldModel
from maverick_dashboard import rbac
from maverick_dashboard import task_file_recovery_api as api


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "private"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    config.reset_config_cache()
    rbac.set_role("user:owner", "admin")
    rbac.set_role("user:foreign", "admin")
    from maverick_dashboard import app as dashboard
    world = WorldModel(tmp_path / "world.db")
    goal = world.create_goal("Synthetic task file recovery", owner="user:owner")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    application = FastAPI()
    @application.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "file-workspace")):
            return await call_next(request)
    application.include_router(api.router)
    folder = tmp_path / "task"
    folder.mkdir()
    (folder / "review.txt").write_text("original")
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield client, world, goal, LocalBackend(folder)
    config.reset_config_cache()


def test_enable_capture_real_files_and_explicit_reviewed_restore(fixture):
    client, world, goal, sandbox = fixture
    base = f"/api/v1/task-files/{goal}"
    state = client.get(base).json()
    assert state["capture_enabled"] is False and state["can_enable"] is True
    denied = client.post("/api/v1/task-files/enable", json={"context": state["context"], "confirm": False})
    assert denied.status_code == 409
    enabled = client.post("/api/v1/task-files/enable", json={"context": state["context"], "confirm": True})
    assert enabled.status_code == 200, enabled.text
    with tenant_scope(tenant="file-workspace"):
        with recovery.run_scope(world, goal, sandbox):
            recovery.begin_capture(world, goal)
            write_text_contained(sandbox, sandbox.workdir / "review.txt", "task revision")
        world.set_goal_status(goal, "done", result="Synthetic complete")
    page = client.get(f"/chat/goal/{goal}/files")
    assert page.status_code == 200 and "Review and restore task files" in page.text
    review = client.get(base + "/preview")
    assert review.status_code == 200, review.text
    assert review.headers["cache-control"] == "private, no-store"
    assert str(sandbox.workdir) not in review.text
    payload = {"context": review.json()["context"], "version": review.json()["version"], "request_id": "exact-review-1", "confirm": True}
    cross_site = client.post(base + "/restore", json=payload, headers={"Origin": "https://foreign.example"})
    assert cross_site.status_code == 403
    (sandbox.workdir / "review.txt").write_text("manual update")
    assert client.post(base + "/restore", json=payload).status_code == 409
    payload["version"] = client.get(base + "/preview").json()["version"]
    saved = client.post(base + "/restore", json=payload)
    assert saved.status_code == 200, saved.text
    assert (sandbox.workdir / "review.txt").read_text() == "original"
    assert client.post(base + "/restore", json=payload).json() == saved.json()


def test_foreign_admin_context_and_arbitrary_path_cannot_restore(fixture):
    client, _, goal, _ = fixture
    base = f"/api/v1/task-files/{goal}"
    state = client.get(base).json()
    assert client.get(base, headers={"X-Test-User": "foreign"}).status_code == 404
    assert client.get(base, headers={"X-Test-Tenant": "different", "X-Lightwork-File-Context": state["context"]}).status_code == 409
    response = client.post(base + "/restore", json={"context": state["context"], "confirm": True, "version": "a" * 64, "request_id": "review-1", "workdir": "C:/Windows"})
    assert response.status_code == 422


def test_non_ascii_file_context_header_is_refused_as_changed_not_a_server_error(fixture):
    client, _, goal, _ = fixture
    response = client.get(f"/api/v1/task-files/{goal}", headers={"X-Lightwork-File-Context": "contéxt".encode()})
    assert response.status_code == 409, response.text


def test_deployment_managed_capture_is_not_waived(fixture, monkeypatch):
    client, _, goal, _ = fixture
    monkeypatch.setenv("LIGHTWORK_WORKSPACE_JOURNAL", "0")
    state = client.get(f"/api/v1/task-files/{goal}").json()
    response = client.post("/api/v1/task-files/enable", json={"context": state["context"], "confirm": True})
    assert response.status_code == 409
    assert "manage file capture" in response.text


def test_file_protection_turns_off_for_future_runs_and_keeps_saved_copies(fixture, monkeypatch):
    import maverick.audit as audit

    client, world, goal, sandbox = fixture
    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    base = f"/api/v1/task-files/{goal}"
    state = client.get(base).json()
    assert client.post("/api/v1/task-files/enable", json={"context": state["context"], "confirm": True}).status_code == 200
    with tenant_scope(tenant="file-workspace"):
        with recovery.run_scope(world, goal, sandbox):
            recovery.begin_capture(world, goal)
            write_text_contained(sandbox, sandbox.workdir / "review.txt", "task revision")
        world.set_goal_status(goal, "done", result="Synthetic complete")
    assert client.post("/api/v1/task-files/disable", json={"context": state["context"], "confirm": False}).status_code == 409
    assert client.post("/api/v1/task-files/disable", json={"context": state["context"], "confirm": True},
                       headers={"X-Test-User": "foreign", "Origin": "https://foreign.example"}).status_code == 403
    response = client.post("/api/v1/task-files/disable", json={"context": state["context"], "confirm": True})
    assert response.status_code == 200, response.text
    assert response.json()["capture_enabled"] is False
    after = client.get(base).json()
    assert after["capture_enabled"] is False and after["has_history"] is True
    assert sorted((row["section"], row["key"]) for row in rows) == [("workspace", "journal"), ("workspace", "journal_strict")]
    assert client.get(base + "/preview").status_code == 200


def test_file_protection_off_is_refused_when_deployment_manages_capture(fixture, monkeypatch):
    client, world, goal, sandbox = fixture
    state = client.get(f"/api/v1/task-files/{goal}").json()
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL", "1")
    response = client.post("/api/v1/task-files/disable", json={"context": state["context"], "confirm": True})
    assert response.status_code == 409
