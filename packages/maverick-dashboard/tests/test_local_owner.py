"""Real owner enrollment/session transitions without external identity calls."""
from __future__ import annotations

import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

PASSPHRASE = "a long local owner fixture phrase"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    import os
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.load_global_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.config_source_errors", lambda **k: [])
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")


def request(*, peer="127.0.0.1", host="127.0.0.1:8765", origin="http://127.0.0.1:8765", extra=()):
    return Request({"type": "http", "method": "POST", "scheme": "http", "path": "/auth/local-owner",
                    "query_string": b"", "server": ("127.0.0.1", 8765), "client": (peer, 1234),
                    "headers": [(b"host", host.encode()), (b"origin", origin.encode()), *extra]})


def enroll():
    from maverick_dashboard import local_owner
    return local_owner.enroll(request(), email="owner@example.com", password=PASSPHRASE, confirm=True)


def test_first_owner_closes_anonymous_access_and_reuses_current_roles():
    from maverick_dashboard import auth, invites, local_owner, rbac
    assert auth.anonymous_local_access_allowed()
    assert local_owner.available(request())
    token = enroll()
    assert not auth.anonymous_local_access_allowed()
    assert invites.invites_enabled()
    assert rbac.get_stored_role("user:owner@example.com") == "admin"
    assert PASSPHRASE not in local_owner.path().read_text()
    scope = dict(request().scope)
    scope["headers"] = [*scope["headers"], (b"cookie", ("mvk_session=" + token).encode())]
    assert invites.local_session_principal(Request(scope)).principal == "user:owner@example.com"
    with pytest.raises(HTTPException, match="already been claimed"):
        enroll()
    # An independently assigned administrator permits a deliberate demotion.
    rbac.set_role("user:second@example.com", "admin")
    rbac.set_role("user:owner@example.com", "viewer")
    local_owner.login(request(), email="owner@example.com", password=PASSPHRASE)
    assert rbac.get_stored_role("user:owner@example.com") == "viewer"
    rbac.remove_user("user:owner@example.com")
    with pytest.raises(HTTPException, match="no longer has an assigned role"):
        local_owner.login(request(), email="owner@example.com", password=PASSPHRASE)
    assert rbac.get_stored_role("user:owner@example.com") is None


@pytest.mark.parametrize("kwargs", [
    {"peer": "192.0.2.5"}, {"host": "attacker.example"}, {"origin": "https://attacker.example"},
    {"extra": ((b"x-forwarded-for", b"127.0.0.1"),)}, {"extra": ((b"forwarded", b"for=127.0.0.1"),)},
])
def test_remote_cross_site_or_forwarded_cannot_claim(kwargs):
    from maverick_dashboard import local_owner
    with pytest.raises(HTTPException):
        local_owner.enroll(request(**kwargs), email="owner@example.com", password=PASSPHRASE, confirm=True)
    assert not local_owner.claimed()


@pytest.mark.parametrize("cfg", [{"dashboard": {"local_owner_setup": False}},
                                {"dashboard": {"invites": False}}, {"auth": {"oidc": {"enabled": False}}}])
def test_managed_policy_is_not_waived(monkeypatch, cfg):
    from maverick_dashboard import local_owner
    monkeypatch.setattr("maverick.config.load_global_config", lambda: cfg)
    with pytest.raises(HTTPException):
        enroll()
    assert not local_owner.claimed()


def test_existing_roster_prevents_claim():
    from maverick_dashboard import local_owner, rbac
    rbac.set_role("user:existing@example.com", "viewer")
    with pytest.raises(HTTPException, match="Existing identity"):
        enroll()
    assert not local_owner.claimed()


def test_pending_claim_is_fail_closed_and_password_resumable(monkeypatch):
    from maverick_dashboard import auth, local_owner, rbac
    original = rbac.set_role
    monkeypatch.setattr(rbac, "set_role", lambda *a, **k: (_ for _ in ()).throw(OSError("interrupted")))
    with pytest.raises(OSError):
        enroll()
    assert not auth.anonymous_local_access_allowed()
    assert json.loads(local_owner.path().read_text())["status"] == "pending"
    monkeypatch.setattr(rbac, "set_role", original)
    with pytest.raises(HTTPException):
        local_owner.login(request(), email="other@example.com", password=PASSPHRASE)
    local_owner.login(request(), email="owner@example.com", password=PASSPHRASE)
    assert json.loads(local_owner.path().read_text())["status"] == "ready"


def test_login_rate_limit_and_corrupt_claim_never_reopen_admin():
    from maverick_dashboard import auth, local_owner
    enroll()
    for _ in range(5):
        with pytest.raises(HTTPException) as denied:
            local_owner.login(request(), email="owner@example.com", password="an incorrect long fixture phrase")  # pragma: allowlist secret - deliberately incorrect test password
        assert denied.value.status_code == 401
    with pytest.raises(HTTPException) as limited:
        local_owner.login(request(), email="owner@example.com", password=PASSPHRASE)
    assert limited.value.status_code == 429
    local_owner.path().write_text("not JSON")
    assert not auth.anonymous_local_access_allowed()
    with pytest.raises(HTTPException) as corrupt:
        local_owner.login(request(), email="owner@example.com", password=PASSPHRASE)
    assert corrupt.value.status_code == 503


def test_actual_http_enrollment_cookie_and_fresh_login():
    from maverick_dashboard.app import app
    with TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 53210),
                    headers={"Origin": "http://127.0.0.1:8765"}, follow_redirects=False) as client:
        form = client.get("/auth/local-owner")
        assert form.status_code == 200
        assert form.headers["referrer-policy"] == "same-origin"
        response = client.post("/auth/local-owner", data={"email": "owner@example.com", "password": PASSPHRASE, "confirm": "yes"})
        assert response.status_code == 303, response.text
        assert "mvk_session=" in response.headers["set-cookie"]
        assert client.get("/api/v1/features/modules").status_code == 200
        client.cookies.clear()
        assert client.get("/api/v1/features/modules").status_code == 401
        assert client.get("/auth/local-login").headers["referrer-policy"] == "same-origin"
        response = client.post("/auth/local-login", data={"email": "owner@example.com", "password": PASSPHRASE})
        assert response.status_code == 303, response.text


def test_first_owner_starts_in_a_selected_workspace():
    """A fresh install's owner works in a real workspace from the first page.

    Left in the unbound root, every workspace-scoped panel the owner opens
    (a flow run's learning example, the activity log's protection status)
    answered 409 "select an active tenant", while the shell called that root
    "Main workspace". The workspace was created only when an HTML tenant gate
    refused, which stranded anything made before it in the unbound root.
    """
    from maverick.tenant.registry import get_tenant
    from maverick_dashboard import workspace_tenants
    from maverick_dashboard.app import app
    with TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 53210),
                    headers={"Origin": "http://127.0.0.1:8765"}, follow_redirects=False) as client:
        response = client.post("/auth/local-owner", data={"email": "owner@example.com", "password": PASSPHRASE, "confirm": "yes"})
        assert response.status_code == 303, response.text
        assert workspace_tenants.get_selection("user:owner@example.com") == "local"
        assert get_tenant("local") is not None
        active = client.get("/api/v1/workspace/active-tenant")
        assert active.status_code == 200, active.text
        assert (active.json()["tenant_id"], active.json()["source"]) == ("local", "principal_selection")
        status = client.get("/api/v1/audit/unified/status")
        assert status.status_code == 200, status.text
        capture = client.get("/api/v1/flows/no-such-flow/runs/no-such-run/episode-capture/withdrawal")
        assert "select an active tenant" not in capture.text


def test_owner_claim_is_protected_recovery_authority(tmp_path):
    from maverick import backup
    from maverick_dashboard import local_owner
    enroll()
    assert backup._accounting_file("dashboard-owner.json", local_owner.path())
    assert backup._accounting_file("tenants/example/dashboard-owner.json", local_owner.path())


def test_oversized_claim_denies_before_read_and_alias_policy_cannot_reopen_session(monkeypatch):
    from maverick_dashboard import auth, invites, local_owner
    enroll()
    monkeypatch.setenv("LIGHTWORK_DASHBOARD_INVITES", "0")
    assert not invites.invites_enabled()
    assert not auth.anonymous_local_access_allowed()
    monkeypatch.delenv("LIGHTWORK_DASHBOARD_INVITES")
    local_owner.path().write_bytes(b"x" * 8193)
    monkeypatch.setattr("maverick.file_lock.atomic_read_text", lambda *a: pytest.fail("Oversized owner claim read"))
    with pytest.raises(HTTPException) as failure:
        local_owner.login(request(), email="owner@example.com", password=PASSPHRASE)
    assert failure.value.status_code == 503


def test_named_owner_invite_workspace_and_captured_review(monkeypatch, tmp_path):
    """No principal injection: both identities come from real signed cookies."""
    import re
    import time

    from maverick import config
    from maverick.world_model import WorldModel
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import project_reviews_api, rbac, suite_grants

    # Project reviews remain an explicitly enabled module; the local owner
    # capability does not turn it on or run a provider to produce a result.
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"features": {"project_reviews": True}})
    world = WorldModel(tmp_path / "review-fixture.sqlite3")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    options = dict(base_url="http://127.0.0.1:8765", client=("127.0.0.1", 53210),
                   headers={"Origin": "http://127.0.0.1:8765"}, follow_redirects=False)
    with TestClient(dashboard.app, **options) as owner:
        accepted = owner.post("/auth/local-owner", data={"email": "owner@example.com", "password": PASSPHRASE, "confirm": "yes"})
        assert accepted.status_code == 303, accepted.text
        # The owner starts in the first workspace; the browser client sends its guard.
        owner.headers["X-Lightwork-Expected-Tenant"] = "local"
        created = owner.post("/api/v1/admin/tenants", json={"id": "customer-workspace", "display_name": "Customer workspace"})
        assert created.status_code == 201, created.text
        selected = owner.put("/api/v1/workspace/active-tenant", json={"tenant_id": "customer-workspace"})
        assert selected.status_code == 200, selected.text
        owner.headers["X-Lightwork-Expected-Tenant"] = "customer-workspace"
        invitation = owner.post("/users/invite", data={"email": "reviewer@example.com", "role": "operator"})
        assert invitation.status_code == 200, invitation.text
        token = re.search(r"/auth/invite/(inv_[A-Za-z0-9_-]+)", invitation.text)
        assert token, invitation.text
        reviewer = TestClient(dashboard.app, **options)
        try:
            joined = reviewer.post("/auth/invite/" + token[1], data={
                "password": "a long reviewer fixture phrase",  # pragma: allowlist secret
                "password2": "a long reviewer fixture phrase"})  # pragma: allowlist secret
            assert joined.status_code == 303, joined.text
            assert rbac.get_stored_role("user:reviewer@example.com") == "operator"
            assert reviewer.put("/api/v1/workspace/active-tenant", json={"tenant_id": "customer-workspace"}).status_code in {403, 404}
            role = owner.put("/api/v1/admin/tenants/customer-workspace/roles/user:reviewer@example.com", json={"role": "operator"})
            assert role.status_code == 204, role.text
            departments = owner.post("/users/suites/set", data={"principal": "user:reviewer@example.com", "suites": "finance"})
            assert departments.status_code == 303, departments.text
            assert suite_grants.granted_suites("user:reviewer@example.com") == frozenset({"finance"})
            selected = reviewer.put("/api/v1/workspace/active-tenant", json={"tenant_id": "customer-workspace"})
            assert selected.status_code == 200, selected.text
            reviewer.headers["X-Lightwork-Expected-Tenant"] = "customer-workspace"
            project_response = owner.post("/projects", data={"name": "Review fixture"})
            assert project_response.status_code == 303, project_response.text
            project = int(project_response.headers["location"].rsplit("/", 1)[1])
            assert world.get_project(project)["owner"] == "user:owner@example.com"
            goal = world.create_goal("Synthetic review fixture", "", owner="user:owner@example.com", project_id=project)
            world.set_goal_status(goal, "done", result="Synthetic result. No provider was called.")
            base = project_reviews_api.BASE
            inbox = owner.get(base)
            assert inbox.status_code == 200, inbox.text
            context = {"X-Lightwork-Review-Context": inbox.json()["context"]}
            grant = owner.put(base + f"/projects/{project}/members", headers=context, json={"member": "user:reviewer@example.com", "allowed": True, "expected_revision": 0, "request_id": "first-owner-reviewer"})
            assert grant.status_code == 200, grant.text
            preview = owner.get(base + f"/projects/{project}/goals/{goal}/preview", headers=context)
            assert preview.status_code == 200, preview.text
            sent = owner.post(base + f"/projects/{project}/packets", headers=context, json={"goal_id": goal, "reviewer": "user:reviewer@example.com", "note": "Review this captured fixture.", "due_at": time.time() + 3600, "source_version": preview.json()["source_version"], "expected_team_revision": grant.json()["revision"], "request_id": "first-owner-send"})
            assert sent.status_code == 200, sent.text
            packet = sent.json()
            review_inbox = reviewer.get(base)
            assert review_inbox.status_code == 200, review_inbox.text
            reviewed = reviewer.post(base + "/packets/" + packet["id"] + "/responses", headers={"X-Lightwork-Review-Context": review_inbox.json()["context"]}, json={"action": "approve", "note": "Reviewed synthetic evidence.", "expected_revision": packet["revision"], "source_version": packet["source_version"], "request_id": "first-owner-approve"})
            assert reviewed.status_code == 200, reviewed.text
            assert reviewed.json()["live_goal_signoff"] is False
            assert world.signoff_for(goal) is None
            assert owner.delete("/api/v1/admin/tenants/customer-workspace/roles/user:reviewer@example.com").status_code == 204
            assert reviewer.get(base + "/packets/" + packet["id"]).status_code in {403, 404}
        finally:
            reviewer.close()
    world.close()
