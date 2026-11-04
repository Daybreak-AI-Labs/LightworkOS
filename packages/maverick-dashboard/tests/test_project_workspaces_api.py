"""Project native HTTP and typed adapter contracts over real local stores."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import audit, config
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.world_model import WorldModel
from maverick_dashboard import app as dashboard
from maverick_dashboard import product_operations_projects as adapters
from maverick_dashboard import project_reviews_api, rbac
from maverick_dashboard import project_workspaces_api as api


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text('[features]\nproject_workspaces=true\nproject_reviews=true\n[dashboard]\ndefault_role="viewer"\n', encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *args, **kwargs: True)
    worlds = {tenant: WorldModel(tmp_path / (tenant + ".sqlite3")) for tenant in ("tenant-a", "tenant-b")}
    world = worlds["tenant-a"]
    project = world.create_project("Private project", owner="user:owner")
    goal = world.create_goal("Exact reviewed task", "", owner="user:owner", project_id=project)
    world.set_goal_status(goal, "done", result="Private source content")
    for principal in ("user:owner", "user:colleague"):
        rbac.set_tenant_role("tenant-a", principal, "operator", actor="user:owner")
    active = dict.fromkeys(("user:owner", "user:colleague"), True)
    monkeypatch.setattr(project_reviews_api.scim_groups, "active_for_principal", lambda principal: active.get(principal))
    monkeypatch.setattr(dashboard, "_world", lambda: worlds[current_tenant_id_strict()])
    application = FastAPI()
    @application.middleware("http")
    async def identity(request: Request, call_next):
        subject = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + subject, sub=subject)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)
    application.include_router(api.router)
    @application.post("/test-adapter")
    async def adapter(request: Request):
        body = await request.json()
        selection = {"kind": "project", "id": project}
        entry = next(row for row in adapters.entries() if row.id == body["entry"])
        args = entry.input_model.model_validate(body.get("args", {})).model_dump()
        preview = entry.prepare(request, selection, args)
        if body.get("execute"):
            result = entry.execute(request, selection, args, preview.native, body["operation_id"])
            replay = entry.recover(request, selection, args, preview.native, body["operation_id"])
            return {"status": result.status, "recovery": replay.status, "review": preview.changes}
        return {"review": preview.changes, "native": preview.native}
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield client, project, goal, active, world
    for value in worlds.values():
        value.close()
    config.reset_config_cache()


def context(client, project, **headers):
    response = client.get(api.BASE + f"/{project}", headers=headers)
    assert response.status_code == 200, response.text
    return {**headers, "X-Lightwork-Project-Context": response.json()["context"]}, response.json()


def save(client, project, headers, **body):
    payload = {"action": "details", "payload": {"outcome": "Explicit outcome", "criteria": ["Evidence reviewed"], "labels": ["Customer"], "default_view": "list"},
               "expected_revision": 0, "operation_id": "save-outcome-one", "confirmed": True}
    payload.update(body)
    return client.post(api.BASE + f"/{project}/change", headers=headers, json=payload)


def test_review_is_readonly_and_context_confirmation_cas_are_required(setup):
    client, project, _, _, _ = setup
    headers, before = context(client, project)
    body = {"action": "details", "payload": {"outcome": "Reviewed outcome", "criteria": [], "labels": [], "default_view": "board"}}
    response = client.post(api.BASE + f"/{project}/prepare", headers=headers, json=body)
    assert response.status_code == 200 and response.json()["revision"] == 0
    assert context(client, project)[1]["workspace"]["revision"] == before["workspace"]["revision"]
    assert save(client, project, {}).status_code == 409
    assert save(client, project, headers, confirmed=False).status_code == 422
    assert save(client, project, headers).status_code == 200
    assert save(client, project, headers).json()["status"] == "replayed"
    assert save(client, project, headers, operation_id="different-save-operation").status_code == 409


def test_non_ascii_project_context_header_is_refused_as_changed_not_a_server_error(setup):
    client, project, _, _, _ = setup
    headers = {"X-Lightwork-Project-Context": "contéxt".encode()}
    assert client.get(api.BASE + f"/{project}", headers=headers).status_code == 409
    assert save(client, project, headers).status_code == 409


def test_explicit_planning_share_does_not_expose_source_and_revocation_is_immediate(setup):
    client, project, goal, active, _ = setup
    headers, _ = context(client, project)
    assert save(client, project, headers, action="member", payload={"member": "user:colleague", "allowed": True}).status_code == 200
    colleague_headers, model = context(client, project, **{"X-Test-User": "colleague"})
    assert not model["workspace"]["can_edit"]
    assert client.get(api.BASE + f"/{project}/sources/result/{goal}", headers=colleague_headers).status_code == 404
    assert save(client, project, colleague_headers, expected_revision=1).status_code == 404
    active["user:colleague"] = False
    assert client.get(api.BASE + f"/{project}", headers=colleague_headers).status_code in {403, 404}


def test_typed_adapters_use_exact_native_review_and_durable_receipt(setup):
    client, project, goal, _, _ = setup
    response = client.post("/test-adapter", json={"entry": "projects.milestone", "args": {"title": "Evidence ready", "goals": [str(goal)]},
                                               "execute": True, "operation_id": "copilot-milestone-one"})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "confirmed" and response.json()["recovery"] == "replayed"
    assert "Exact reviewed task" in str(response.json()["review"])
    state = context(client, project)[1]
    assert state["workspace"]["milestones"][0]["state"] == "work complete"
    assert {row.id for row in adapters.entries()} == {"projects." + name for name in (
        "status", "details", "milestone", "reorder", "dependency", "member", "context", "remove_milestone", "remove_context", "defaults")}


def test_source_adapter_reviews_complete_text_and_binds_native_version(setup):
    client, project, goal, _, world = setup
    response = client.post("/test-adapter", json={"entry": "projects.context", "args": {"source": f"result/{goal}"}})
    assert response.status_code == 200 and response.json()["review"][-1]["after"] == "Private source content"
    prepared = response.json()["native"]
    world.set_goal_status(goal, "done", result="Changed after source review")
    headers, _ = context(client, project)
    assert save(client, project, headers, **prepared).status_code == 409


def test_global_feature_ceiling_cannot_be_enabled_by_tenant_only(setup, monkeypatch):
    client, project, _, _, _ = setup
    monkeypatch.setattr(config, "load_global_config", lambda: {"features": {"project_workspaces": False}})
    monkeypatch.setattr(config, "get_features", lambda: {"project_workspaces": True})
    assert client.get(api.BASE + f"/{project}").status_code == 403
