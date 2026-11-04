"""Admin tenant-provisioning API (/api/v1/admin/tenants).

A control-plane surface so operators can spin tenants up/down over HTTP instead
of shelling in for `maverick tenant ...`. Auth-off TestClient => the local
caller is admin (matches the rest of the API). The registry and per-tenant
workspaces are isolated under a temp MAVERICK_HOME so nothing touches real data.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # rbac's role stores live under Path.home()/.maverick (global control-plane
    # files), which ignore MAVERICK_HOME -- so without redirecting them, a test
    # that sets a global/tenant role (e.g. user:alice -> viewer) would leak into
    # the shared session home and make later suites see that principal demoted.
    import maverick_dashboard.rbac as rbac
    roles_dir = tmp_path / "home" / ".maverick"
    monkeypatch.setattr(rbac, "store_path", lambda: roles_dir / "dashboard-users.json")
    monkeypatch.setattr(
        rbac, "tenant_store_path", lambda: roles_dir / "dashboard-tenant-roles.json"
    )
    yield


def test_create_list_get_roundtrip():
    r = client.post("/api/v1/admin/tenants", json={"id": "acme", "plan": "enterprise"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"] == "acme"
    assert body["plan"] == "enterprise"
    assert body["status"] == "active"
    assert body["max_daily_dollars"] == 0.0  # no cap unless one is chosen
    # The response tells the operator where to drop acme's own config.toml.
    assert body["config_path"].endswith("/config.toml")
    assert "tenants/acme/" in body["config_path"].replace("\\", "/")

    # It shows up in the list and is fetchable.
    assert any(t["id"] == "acme" for t in client.get("/api/v1/admin/tenants").json())
    assert client.get("/api/v1/admin/tenants/acme").json()["plan"] == "enterprise"


def test_create_is_anchored_in_global_audit(monkeypatch):
    import maverick.audit as audit

    calls = []
    monkeypatch.setattr(
        audit,
        "record_global",
        lambda kind, **payload: calls.append((kind, payload)) or True,
    )
    response = client.post(
        "/api/v1/admin/tenants",
        json={"id": "audited", "plan": "enterprise", "max_daily_dollars": 12},
    )

    assert response.status_code == 201, response.text
    assert calls == [
        (
            audit.EventKind.TENANT_CREATED,
            {
                "agent": "local",
                "goal_id": None,
                "actor": "local",
                "tenant": "audited",
                "plan": "enterprise",
                "max_daily_dollars": 12.0,
            },
        )
    ]


def test_audit_refusal_rolls_back_tenant_publication(monkeypatch):
    import maverick.audit as audit

    def refuse(*_args, **_kwargs):
        raise audit.AuditRefused("custody unavailable")

    monkeypatch.setattr(audit, "record_global", refuse)
    response = client.post("/api/v1/admin/tenants", json={"id": "unlogged"})

    assert response.status_code == 503
    assert "identifier remains reserved" in response.json()["detail"]
    assert client.get("/api/v1/admin/tenants/unlogged").status_code == 404

    monkeypatch.setattr(audit, "record_global", lambda *args, **kwargs: True)
    assert client.post("/api/v1/admin/tenants", json={"id": "unlogged"}).status_code == 409
    retry = client.post("/api/v1/admin/tenants", json={"display_name": "Unlogged"})
    assert retry.status_code == 201, retry.text
    assert retry.json()["id"] == "unlogged-2"


@pytest.mark.parametrize("purge", [False, True])
def test_deleted_workspace_cannot_adopt_old_membership_or_payload(purge, monkeypatch):
    from maverick.paths import data_dir, maverick_home
    from maverick_dashboard import rbac

    # Exercise the real installation-level role path, including orphan roles.
    monkeypatch.setattr(rbac, "tenant_store_path", lambda: maverick_home() / "dashboard-tenant-roles.json")
    assert client.post("/api/v1/admin/tenants", json={"id": "former"}).status_code == 201
    rbac.set_tenant_role("former", "user:old", "admin")
    root = data_dir(tenant="former")
    (root / "synthetic.txt").write_text("old private fixture", encoding="utf-8")
    if purge:
        # Remove never erases in one step: erasure is a separate reviewed action.
        shortcut = client.request("DELETE", "/api/v1/admin/tenants/former?purge=true")
        assert shortcut.status_code == 409, shortcut.text
        assert "Review erasure" in shortcut.json()["detail"]
        assert (root / "synthetic.txt").exists()
        assert rbac.get_tenant_role("former", "user:old") == "admin"
    removed = client.request("DELETE", "/api/v1/admin/tenants/former")
    assert removed.status_code == 204, removed.text
    if purge:
        review = client.post("/api/v1/workspace-erasure/review", json={"workspace": "former"})
        assert review.status_code == 200, review.text
        erased = client.post("/api/v1/workspace-erasure/apply",
                             json={"token": review.json()["token"], "confirmed": True})
        assert erased.status_code == 200, erased.text
        assert erased.json()["status"] == "confirmed"
        assert not (root / "synthetic.txt").exists()
    refused = client.post("/api/v1/admin/tenants", json={"id": "former"})
    assert refused.status_code == 409
    assert "history" in refused.json()["detail"]
    fresh = client.post("/api/v1/admin/tenants", json={"display_name": "Former"})
    assert fresh.status_code == 201, fresh.text
    assert fresh.json()["id"] == "former-2"
    assert rbac.get_tenant_role("former-2", "user:old") is None
    assert not (data_dir(tenant="former-2") / "synthetic.txt").exists()
    assert rbac.get_tenant_role("former", "user:old") is None
    assert "former" not in rbac._load_tenant()
    removed_list = client.get("/api/v1/admin/tenants/removed/list")
    assert removed_list.status_code == 200
    assert removed_list.json()[0]["restorable"] is not purge


def test_restore_retained_workspace_is_paused_and_reinvites_members(monkeypatch):
    from maverick.paths import data_dir, maverick_home
    from maverick_dashboard import rbac, settings_store, workspace_tenants

    monkeypatch.setattr(rbac, "tenant_store_path", lambda: maverick_home() / "dashboard-tenant-roles.json")
    assert client.post("/api/v1/admin/tenants", json={"id": "recover", "display_name": "Recover"}).status_code == 201
    rbac.set_tenant_role("recover", "user:former", "admin")
    workspace_tenants.set_selection("user:former", "recover")
    settings_store.set_active_tenant("recover")
    (data_dir(tenant="recover") / "private.txt").write_text("retained data", encoding="utf-8")

    removed = client.request(
        "DELETE", "/api/v1/admin/tenants/recover",
        headers={"x-lightwork-expected-tenant": "recover"},
    )
    assert removed.status_code == 204, removed.text
    assert workspace_tenants.get_selection("user:former") is None
    assert rbac.get_tenant_role("recover", "user:former") is None
    assert settings_store.active_tenant() is None

    newer = client.post("/api/v1/admin/tenants", json={"display_name": "Recover"})
    assert newer.status_code == 201, newer.text
    assert newer.json()["id"] == "recover-2"
    assert not (data_dir(tenant="recover-2") / "private.txt").exists()
    assert client.get("/tenants").status_code == 200
    assert "Restore as paused" in client.get("/tenants").text

    restored = client.post("/api/v1/admin/tenants/recover/restore")
    assert restored.status_code == 200, restored.text
    assert restored.json()["status"] == "suspended"
    assert restored.json()["display_name"] == "Recover (recovered)"
    assert (data_dir(tenant="recover") / "private.txt").read_text(encoding="utf-8") == "retained data"
    assert rbac.get_tenant_role("recover", "user:former") is None
    assert workspace_tenants.get_selection("user:former") is None
    assert client.post("/api/v1/admin/tenants", json={"id": "recover"}).status_code == 409
    assert client.request("DELETE", "/api/v1/admin/tenants/recover").status_code == 204
    assert client.post("/api/v1/admin/tenants", json={"id": "recover"}).status_code == 409


def test_deleted_workspace_cleanup_can_be_retried_after_membership_store_failure(monkeypatch):
    from maverick.paths import maverick_home
    from maverick_dashboard import rbac

    monkeypatch.setattr(rbac, "tenant_store_path", lambda: maverick_home() / "dashboard-tenant-roles.json")
    assert client.post("/api/v1/admin/tenants", json={"id": "retry"}).status_code == 201
    rbac.set_tenant_role("retry", "user:former", "admin")
    original = rbac.clear_tenant_roles
    def refuse_cleanup(_tenant):
        raise OSError("write failed")

    monkeypatch.setattr(rbac, "clear_tenant_roles", refuse_cleanup)
    failed = client.request("DELETE", "/api/v1/admin/tenants/retry")
    assert failed.status_code == 503
    assert rbac.get_tenant_role("retry", "user:former") is None  # tombstone denies even with stale file
    monkeypatch.setattr(rbac, "clear_tenant_roles", original)
    assert client.request("DELETE", "/api/v1/admin/tenants/retry").status_code == 204
    assert "retry" not in rbac._load_tenant()


def test_tenant_has_no_cap_unless_one_is_chosen():
    default = client.post("/api/v1/admin/tenants", json={"id": "default-cap"})
    bounded = client.post(
        "/api/v1/admin/tenants",
        json={"id": "bounded", "max_daily_dollars": 5},
    )

    assert default.status_code == 201
    assert default.json()["max_daily_dollars"] == 0.0
    assert bounded.status_code == 201
    assert bounded.json()["max_daily_dollars"] == 5.0


def test_duplicate_is_409():
    assert client.post("/api/v1/admin/tenants", json={"id": "dup"}).status_code == 201
    assert client.post("/api/v1/admin/tenants", json={"id": "dup"}).status_code == 409


def test_unknown_tenant_is_404():
    assert client.get("/api/v1/admin/tenants/ghost").status_code == 404
    assert client.post("/api/v1/admin/tenants/ghost/suspend").status_code == 404


def test_suspend_resume_plan_quota():
    client.post("/api/v1/admin/tenants", json={"id": "acme", "plan": "free"})

    assert client.post("/api/v1/admin/tenants/acme/suspend").json()["status"] == "suspended"
    assert client.post("/api/v1/admin/tenants/acme/resume").json()["status"] == "active"

    assert client.post(
        "/api/v1/admin/tenants/acme/plan", json={"plan": "pro"}
    ).json()["plan"] == "pro"

    out = client.post(
        "/api/v1/admin/tenants/acme/quota", json={"max_daily_dollars": 42.5}
    ).json()
    assert out["max_daily_dollars"] == 42.5


def test_bad_plan_rejected_by_schema():
    r = client.post("/api/v1/admin/tenants", json={"id": "acme", "plan": "platinum"})
    assert r.status_code == 422  # not a valid plan enum


def test_delete_removes_tenant():
    client.post("/api/v1/admin/tenants", json={"id": "acme"})
    assert client.request("DELETE", "/api/v1/admin/tenants/acme").status_code == 204
    assert client.get("/api/v1/admin/tenants/acme").status_code == 404


def test_admin_required_when_caller_is_viewer(monkeypatch):
    """A non-admin authenticated caller is forbidden (403)."""
    import maverick_dashboard.auth as auth
    # Simulate an authenticated, non-admin principal: has_permission consults
    # the caller's role, and "view" lacks "admin".
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:viewer")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "viewer")
    assert client.get("/api/v1/admin/tenants").status_code == 403
    assert client.post("/api/v1/admin/tenants", json={"id": "x"}).status_code == 403


def test_tenant_admin_cannot_manage_other_tenant_roles(monkeypatch):
    """Tenant-scoped admin must not satisfy global tenant-admin APIs."""
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    assert client.post("/api/v1/admin/tenants", json={"id": "globex"}).status_code == 201
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    tok = set_tenant("acme")
    try:
        assert auth.role_for_principal("user:alice") == "admin"
        r = client.put(
            "/api/v1/admin/tenants/globex/roles/user:bob",
            json={"role": "viewer"},
        )
    finally:
        reset_tenant(tok)

    assert r.status_code == 403
    assert rbac.get_tenant_role("globex", "user:bob") is None


def test_workspace_admin_manages_existing_members_only_in_their_workspace(monkeypatch):
    from maverick_dashboard import auth, rbac

    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    assert client.post("/api/v1/admin/tenants", json={"id": "globex"}).status_code == 201
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    rbac.set_tenant_role("acme", "user:bob", "operator")
    rbac.set_tenant_role("globex", "user:carol", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    assert client.get("/api/v1/admin/tenants/acme/roles").json() == {
        "user:alice": "admin", "user:bob": "operator",
    }
    assert client.get("/api/v1/admin/tenants/globex/roles").status_code == 403
    assert client.put("/api/v1/admin/tenants/globex/roles/user:carol",
                      json={"role": "viewer"}).status_code == 403
    assert client.delete("/api/v1/admin/tenants/globex/roles/user:carol").status_code == 403
    assert client.put("/api/v1/admin/tenants/acme/roles/user:new",
                      json={"role": "viewer"}).status_code == 409
    assert client.put("/api/v1/admin/tenants/acme/roles/user:bob",
                      json={"role": "viewer"}).status_code == 204
    assert client.delete("/api/v1/admin/tenants/acme/roles/user:bob").status_code == 204
    assert rbac.get_tenant_role("acme", "user:bob") is None
    assert rbac.get_tenant_role("globex", "user:carol") == "viewer"

    # Every call rechecks the requested workspace's current membership.
    rbac.remove_tenant_role("acme", "user:alice")
    assert client.get("/api/v1/admin/tenants/acme/roles").status_code == 403


def test_workspace_admin_scope_requires_active_workspace_and_api_key_admin_scope(monkeypatch):
    from maverick_dashboard import auth, rbac

    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(auth, "api_key_permissions", lambda request: frozenset({"view"}))
    assert client.get("/api/v1/admin/tenants/acme/roles").status_code == 403
    monkeypatch.setattr(auth, "api_key_permissions", lambda request: None)
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    assert client.post("/api/v1/admin/tenants/acme/suspend").status_code == 200
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    assert client.get("/api/v1/admin/tenants/acme/roles").status_code == 403


def test_workspace_admin_cannot_grant_above_own_role_or_clear_to_broader_fallback(monkeypatch):
    from maverick_dashboard import auth, rbac

    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    rbac.set_custom_role("workspace-lead", ["admin", "view"])
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "workspace-lead")
    rbac.set_role("user:bob", "operator")
    rbac.set_tenant_role("acme", "user:bob", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    assert client.put("/api/v1/admin/tenants/acme/roles/user:bob",
                      json={"role": "admin"}).status_code == 409
    assert client.put("/api/v1/admin/tenants/acme/roles/user:bob",
                      json={"role": "operator"}).status_code == 409
    assert client.delete("/api/v1/admin/tenants/acme/roles/user:bob").status_code == 409
    assert rbac.get_tenant_role("acme", "user:bob") == "viewer"
    rbac.set_tenant_role("acme", "user:bob", "operator")
    assert client.put("/api/v1/admin/tenants/acme/roles/user:bob",
                      json={"role": "viewer"}).status_code == 409


def test_workspace_admin_cannot_remove_self_or_last_admin(monkeypatch):
    from maverick_dashboard import auth, rbac

    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    assert client.put("/api/v1/admin/tenants/acme/roles/user:alice",
                      json={"role": "viewer"}).status_code == 409
    assert client.delete("/api/v1/admin/tenants/acme/roles/user:alice").status_code == 409
    assert rbac.get_tenant_role("acme", "user:alice") == "admin"

    # Even an installation admin must designate a successor before clearing
    # the final direct workspace administrator.
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    assert client.delete("/api/v1/admin/tenants/acme/roles/user:alice").status_code == 409
    assert client.put("/api/v1/admin/tenants/acme/roles/user:bob",
                      json={"role": "admin"}).status_code == 204
    assert client.delete("/api/v1/admin/tenants/acme/roles/user:alice").status_code == 204


def test_a_typed_in_erasure_review_is_not_a_review_this_server_prepared():
    """unseal_from_str returns any unsealed text unchanged, so the token must be
    required to be sealed before its expiry, actor and acknowledgements count."""
    import json
    import time

    from maverick.paths import maverick_home
    from maverick_dashboard import workspace_erasure

    forged = json.dumps({
        "purpose": workspace_erasure.PURPOSE, "workspace": "former", "context": "x", "actor": "local",
        "home": str(maverick_home().resolve()), "operation": "a" * 48, "expires_at": time.time() + 10 ** 9,
        "revision": "r", "previous_attempt": False, "changes": []})
    for path in ("/api/v1/workspace-erasure/apply", "/api/v1/workspace-erasure/original"):
        body = {"token": forged, "confirmed": True} if path.endswith("apply") else {"token": forged}
        response = client.post(path, json=body)
        assert response.status_code == 404, (path, response.text)
    with pytest.raises(Exception) as unavailable:
        workspace_erasure._open(forged)
    assert getattr(unavailable.value, "status_code", None) == 404


@pytest.mark.parametrize("spelling", ["acme", " acme", "acme "])
def test_the_workspace_this_installation_is_fixed_to_is_recognised_by_identity(spelling, monkeypatch):
    from maverick_dashboard import workspace_erasure
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    assert workspace_erasure._is_pinned_workspace(spelling) is True
    assert workspace_erasure._is_pinned_workspace("acme-two") is False
    monkeypatch.setenv("MAVERICK_TENANT", "café")
    assert workspace_erasure._is_pinned_workspace("café") is True            # NFC and NFD are one id
    monkeypatch.delenv("MAVERICK_TENANT")
    monkeypatch.setattr("maverick.client.client_id", lambda: "bound-client")
    assert workspace_erasure._is_pinned_workspace("bound-client") is True          # the [client] id binding too


# ---- audit outage: reducing actions apply first, granting actions audit first ----

def _refuse_global_audit(monkeypatch):
    import maverick.audit as audit

    def refuse(*_args, **_kwargs):
        raise audit.AuditRefused("custody unavailable")

    monkeypatch.setattr(audit, "record_global", refuse)


def _accept_global_audit(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record_global", lambda *args, **kwargs: True)


def test_suspend_stands_when_its_audit_is_refused_and_the_message_says_so(monkeypatch):
    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    _refuse_global_audit(monkeypatch)
    response = client.post("/api/v1/admin/tenants/acme/suspend")
    assert response.status_code == 503
    # Access-reducing: an audit outage must never keep access alive.
    assert client.get("/api/v1/admin/tenants/acme").json()["status"] == "suspended"
    detail = response.json()["detail"]
    assert "paused" in detail and "refused to record" in detail
    assert "nothing was changed" not in detail.lower()


def test_resume_is_audited_before_it_happens(monkeypatch):
    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    assert client.post("/api/v1/admin/tenants/acme/suspend").status_code == 200
    _refuse_global_audit(monkeypatch)
    response = client.post("/api/v1/admin/tenants/acme/resume")
    assert response.status_code == 503
    # Access-granting: with no activity record the workspace stays paused.
    assert client.get("/api/v1/admin/tenants/acme").json()["status"] == "suspended"
    assert "nothing was changed" in response.json()["detail"].lower()
    _accept_global_audit(monkeypatch)
    assert client.post("/api/v1/admin/tenants/acme/resume").json()["status"] == "active"


def test_delete_stands_when_its_audit_is_refused_and_a_retry_records_it(monkeypatch):
    assert client.post("/api/v1/admin/tenants", json={"id": "gone"}).status_code == 201
    _refuse_global_audit(monkeypatch)
    response = client.request("DELETE", "/api/v1/admin/tenants/gone")
    assert response.status_code == 503
    assert client.get("/api/v1/admin/tenants/gone").status_code == 404
    detail = response.json()["detail"]
    assert "removed" in detail and "refused to record" in detail
    assert "nothing was changed" not in detail.lower()
    _accept_global_audit(monkeypatch)
    assert client.request("DELETE", "/api/v1/admin/tenants/gone").status_code == 204


def test_restore_is_audited_before_it_happens(monkeypatch):
    assert client.post("/api/v1/admin/tenants", json={"id": "back"}).status_code == 201
    assert client.request("DELETE", "/api/v1/admin/tenants/back").status_code == 204
    _refuse_global_audit(monkeypatch)
    response = client.post("/api/v1/admin/tenants/back/restore")
    assert response.status_code == 503
    assert "nothing was changed" in response.json()["detail"].lower()
    assert client.get("/api/v1/admin/tenants/back").status_code == 404
    assert client.get("/api/v1/admin/tenants/removed/list").json()[0]["restorable"] is True
    _accept_global_audit(monkeypatch)
    restored = client.post("/api/v1/admin/tenants/back/restore")
    assert restored.status_code == 200 and restored.json()["status"] == "suspended"


def test_a_restore_that_then_fails_is_recorded_as_failed(monkeypatch):
    # The restore is recorded before it runs; a refusal after that left only
    # "restored" in the activity log for a workspace that stayed removed.
    import maverick.audit as audit
    from maverick.tenant import registry

    assert client.post("/api/v1/admin/tenants", json={"id": "lost"}).status_code == 201
    assert client.request("DELETE", "/api/v1/admin/tenants/lost").status_code == 204
    kinds = []
    monkeypatch.setattr(audit, "record_global", lambda kind, *a, **k: kinds.append(str(kind)) or True)

    def gone(tenant_id):
        raise ValueError("The retained workspace records are no longer available.")

    monkeypatch.setattr(registry, "restore_tenant", gone)
    response = client.post("/api/v1/admin/tenants/lost/restore")
    assert response.status_code == 409
    assert kinds == ["tenant_restored", "tenant_restore_failed"]


def test_tenant_role_routes_take_the_cross_process_fence_off_the_event_loop(monkeypatch):
    """Nothing in these handlers is awaited, so declaring them ``async`` ran the
    cross-process authority fence and the role files on the event loop."""
    import asyncio
    import contextlib

    import maverick.authority_effects as effects

    assert client.post("/api/v1/admin/tenants", json={"id": "acme"}).status_code == 201
    seen = []

    @contextlib.contextmanager
    def fence():
        try:
            asyncio.get_running_loop()
            seen.append("event loop")
        except RuntimeError:
            seen.append("worker thread")
        yield

    monkeypatch.setattr(effects, "authority_effect_fence", fence)
    assert client.put("/api/v1/admin/tenants/acme/roles/user:bob", json={"role": "viewer"}).status_code == 204
    assert client.get("/api/v1/admin/tenants/acme/roles").json() == {"user:bob": "viewer"}
    assert client.request("DELETE", "/api/v1/admin/tenants/acme/roles/user:bob").status_code == 204
    assert seen and set(seen) == {"worker thread"}
