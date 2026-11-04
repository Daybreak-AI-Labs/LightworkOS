"""Actual HTTP contracts over local governed records and current RBAC policy."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import audit, config
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.world_model import WorldModel
from maverick_dashboard import app as dashboard
from maverick_dashboard import project_reviews_api as api
from maverick_dashboard import rbac


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in (
        "MAVERICK_TENANT",
        "MAVERICK_TENANT_BY_USER",
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text(
        '[features]\nproject_reviews=true\n[dashboard]\ndefault_role="viewer"\n', encoding="utf-8"
    )
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *args, **kwargs: True)
    worlds = {
        tenant: WorldModel(tmp_path / (tenant + ".sqlite3")) for tenant in ("tenant-a", "tenant-b")
    }
    world = worlds["tenant-a"]
    project = world.create_project("Private customer project", owner="user:owner")
    goal = world.create_goal("Private customer result", "", owner="user:owner", project_id=project)
    world.set_goal_status(goal, "done", result="Sensitive captured result with limitations.")
    for principal in ("user:owner", "user:reviewer", "user:third"):
        rbac.set_tenant_role("tenant-a", principal, "operator", actor="user:owner")
    active = dict.fromkeys(("user:owner", "user:reviewer", "user:third"), True)
    monkeypatch.setattr(
        api.scim_groups, "active_for_principal", lambda principal: active.get(principal)
    )
    monkeypatch.setattr(dashboard, "_world", lambda: worlds[current_tenant_id_strict()])
    app = FastAPI()

    @app.middleware("http")
    async def identity(request: Request, call_next):
        subject = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + subject, sub=subject)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)

    app.include_router(api.router)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield client, project, goal, world, active
    for value in worlds.values():
        value.close()
    config.reset_config_cache()


def context(client, user="owner"):
    response = client.get(api.BASE, headers={"X-Test-User": user})
    assert response.status_code == 200, response.text
    return {"X-Test-User": user, "X-Lightwork-Review-Context": response.json()["context"]}


def packet(setup):
    client, project, goal, _, _ = setup
    headers = context(client)
    granted = client.put(
        api.BASE + f"/projects/{project}/members",
        headers=headers,
        json={
            "member": "user:reviewer",
            "allowed": True,
            "expected_revision": 0,
            "request_id": "grant-reviewer",
        },
    )
    assert granted.status_code == 200, granted.text
    preview = client.get(api.BASE + f"/projects/{project}/goals/{goal}/preview").json()
    response = client.post(
        api.BASE + f"/projects/{project}/packets",
        headers=headers,
        json={
            "goal_id": goal,
            "reviewer": "user:reviewer",
            "note": "Review evidence and limitations.",
            "due_at": time.time() + 3600,
            "source_version": preview["source_version"],
            "expected_team_revision": granted.json()["revision"],
            "request_id": "send-review-packet",
        },
    )
    return response, granted.json(), headers


def test_assigned_packet_does_not_grant_live_task_access_and_unassigned_search_leaks_nothing(setup):
    client, project, goal, world, _ = setup
    response, _, _ = packet(setup)
    assert response.status_code == 200, response.text
    saved = response.json()
    third = client.get(api.BASE + "?q=Private", headers={"X-Test-User": "third"}).json()
    assert third["counts"] == {"total": 0, "pending": 0, "overdue": 0}
    assert "Sensitive captured" not in str(third) and "Private customer" not in str(third)
    review_headers = context(client, "reviewer")
    read = client.get(api.BASE + "/packets/" + saved["id"], headers=review_headers)
    assert read.status_code == 200 and read.headers["Cache-Control"] == "private, no-store"
    decided = client.post(
        api.BASE + "/packets/" + saved["id"] + "/responses",
        headers=review_headers,
        json={
            "action": "approve",
            "note": "Evidence reviewed.",
            "expected_revision": saved["revision"],
            "source_version": saved["source_version"],
            "request_id": "approve-packet",
        },
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["live_goal_signoff"] is False
    assert world.signoff_for(goal) is None
    assert world.get_goal(goal).status == "done"
    assert client.get(api.BASE + f"/projects/{project}", headers=review_headers).status_code == 404


def test_record_search_uses_current_review_authority_and_metadata_only(setup, monkeypatch):
    from maverick_dashboard import record_search, record_search_sources

    response, team, headers = packet(setup)
    assert response.status_code == 200, response.text
    saved = response.json()
    client, project, _, _, _ = setup

    def find(subject, tenant="tenant-a"):
        request = SimpleNamespace(state=SimpleNamespace(
            principal=SimpleNamespace(principal="user:" + subject, sub=subject)))
        with tenant_scope(tenant=tenant):
            return record_search.search(
                {"project reviews": lambda: record_search_sources._project_reviews(request)},
                query="Private", kind="decision",
            )

    found = find("reviewer")
    assert found["total"] == 1
    assert found["items"][0]["href"] == "/project-reviews#packet=" + saved["id"]
    assert "Sensitive captured" not in str(found)
    assert "Review evidence and limitations" not in str(found)
    assert "user:owner" not in str(found)
    for subject, tenant in (("third", "tenant-a"), ("reviewer", "tenant-b")):
        hidden = find(subject, tenant)
        assert hidden["total"] == 0 and "Private customer" not in str(hidden)
    revoked = client.put(api.BASE + f"/projects/{project}/members", headers=headers, json={
        "member": "user:reviewer", "allowed": False,
        "expected_revision": team["revision"], "request_id": "revoke-for-search",
    })
    assert revoked.status_code == 200, revoked.text
    assert find("reviewer")["total"] == 0
    monkeypatch.setattr(api.config, "get_features", lambda: {"project_reviews": False})
    monkeypatch.setattr(api, "ProjectReviews", lambda *args, **kwargs: pytest.fail("Disabled search opened the review store"))
    disabled = find("owner")
    # Switched off is not a failed search: the source reports not available
    # and the results stay complete, without opening the review store.
    assert disabled["coverage"] == [{"source": "project reviews", "state": "not available", "indexed": None}]
    assert disabled["complete"] is True


def test_feature_gate_workspace_context_current_membership_and_scim_fail_closed(setup, monkeypatch):
    client, project, _, _, active = setup
    headers = context(client)
    payload = {
        "member": "user:reviewer",
        "allowed": True,
        "expected_revision": 0,
        "request_id": "grant-reviewer",
    }
    assert client.put(api.BASE + f"/projects/{project}/members", json=payload).status_code == 409
    changed_context = {**headers, "X-Test-Tenant": "tenant-b"}
    assert client.put(
        api.BASE + f"/projects/{project}/members", headers=changed_context, json=payload
    ).status_code in {403, 409}
    active["user:reviewer"] = False
    assert (
        client.put(
            api.BASE + f"/projects/{project}/members", headers=headers, json=payload
        ).status_code
        == 404
    )
    active["user:reviewer"] = True
    rbac.remove_tenant_role("tenant-a", "user:reviewer", actor="user:owner")
    assert (
        client.put(
            api.BASE + f"/projects/{project}/members", headers=headers, json=payload
        ).status_code
        == 404
    )
    monkeypatch.setattr(config, "get_features", lambda: {"project_reviews": False})
    assert client.get(api.BASE).status_code == 403


def test_current_suite_restriction_filters_metadata_before_counts(setup, monkeypatch):
    client, project, goal, world, _ = setup
    world.set_goal_domain(goal, "finance_sox")
    monkeypatch.setattr(api.suite_grants, "granted_suites", lambda _principal: frozenset())
    overview = client.get(api.BASE + f"/projects/{project}")
    assert overview.status_code == 200, overview.text
    assert overview.json()["goals"] == []
    assert client.get(api.BASE + f"/projects/{project}/goals/{goal}/preview").status_code == 404


def test_every_browser_read_rejects_changed_account_context_before_source_lookup(setup):
    client, project, goal, _, _ = setup
    headers = {**context(client), "X-Test-User": "reviewer"}
    for suffix in ("", f"/projects/{project}", f"/projects/{project}/goals/{goal}/preview", "/packets/PRP-unavailable"):
        response = client.get(api.BASE + suffix, headers=headers)
        assert response.status_code == 409, response.text
        assert "workspace changed" in response.json()["detail"]


def test_non_ascii_review_context_header_is_refused_as_changed_not_a_server_error(setup):
    client, _, _, _, _ = setup
    response = client.get(api.BASE, headers={"X-Lightwork-Review-Context": "contéxt".encode()})
    assert response.status_code == 409, response.text
    assert "workspace changed" in response.json()["detail"]
