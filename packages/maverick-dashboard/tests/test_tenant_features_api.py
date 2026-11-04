"""Per-tenant feature overrides API + console page.

Overrides layer on top of the plan's entitlements: an admin can grant a feature
the plan lacks or revoke one it includes, per tenant. Auth-off TestClient => the
local caller is admin (matches the rest of the API). The registry and per-tenant
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
    # files) which ignore MAVERICK_HOME -- redirect them so a role set here never
    # leaks into the shared session home.
    import maverick_dashboard.rbac as rbac
    roles_dir = tmp_path / "home" / ".maverick"
    monkeypatch.setattr(rbac, "store_path", lambda: roles_dir / "dashboard-users.json")
    monkeypatch.setattr(
        rbac, "tenant_store_path", lambda: roles_dir / "dashboard-tenant-roles.json"
    )
    yield


def _create(tenant_id, plan="free"):
    r = client.post("/api/v1/admin/tenants", json={"id": tenant_id, "plan": plan})
    assert r.status_code == 201, r.text


def test_get_features_shape():
    _create("acme", plan="pro")
    body = client.get("/api/v1/admin/tenants/acme/features").json()
    assert body["plan"] == "pro"
    assert set(body["plan_features"]) == {"core", "grpc", "channels"}
    assert body["overrides"] == {"add": [], "remove": []}
    assert set(body["plan_features"]) <= set(body["effective"])
    assert body["catalog"][:4] == ["core", "channels", "audit_export", "grpc"]
    assert "department:finance" in body["catalog"]


def test_put_override_add_grants_feature_plan_lacks():
    _create("acme", plan="free")
    r = client.put(
        "/api/v1/admin/tenants/acme/features",
        json={"add": ["audit_export"], "remove": []},
    )
    assert r.status_code == 200, r.text
    assert "audit_export" in r.json()["effective"]
    body = client.get("/api/v1/admin/tenants/acme/features").json()
    assert body["overrides"]["add"] == ["audit_export"]
    assert "audit_export" in body["effective"]


def test_put_override_remove_revokes_plan_feature():
    _create("acme", plan="pro")
    r = client.put(
        "/api/v1/admin/tenants/acme/features",
        json={"add": [], "remove": ["grpc"]},
    )
    assert r.status_code == 200, r.text
    assert "grpc" not in r.json()["effective"]


def test_put_unknown_feature_rejected():
    _create("acme")
    r = client.put(
        "/api/v1/admin/tenants/acme/features",
        json={"add": ["totally_made_up"], "remove": []},
    )
    assert r.status_code == 400
    assert "unknown feature" in r.json()["detail"]


def test_put_overlap_rejected():
    _create("acme")
    r = client.put(
        "/api/v1/admin/tenants/acme/features",
        json={"add": ["grpc"], "remove": ["grpc"]},
    )
    assert r.status_code == 400
    assert "both add and remove" in r.json()["detail"]


def test_unknown_tenant_is_404():
    assert client.get("/api/v1/admin/tenants/ghost/features").status_code == 404
    assert (
        client.put(
            "/api/v1/admin/tenants/ghost/features", json={"add": [], "remove": []}
        ).status_code
        == 404
    )


def test_admin_required(monkeypatch):
    _create("acme")
    import maverick_dashboard.auth as auth
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:viewer")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "viewer")
    assert client.get("/api/v1/admin/tenants/acme/features").status_code == 403
    assert (
        client.put(
            "/api/v1/admin/tenants/acme/features", json={"add": [], "remove": []}
        ).status_code
        == 403
    )


def test_past_due_get_plan_features_is_downgraded_baseline():
    _create("acme", plan="enterprise")
    from maverick.tenant import registry as tr
    tr.set_billing_status("acme", tr.BILLING_PAST_DUE)
    body = client.get("/api/v1/admin/tenants/acme/features").json()
    # plan_features is the effective baseline (free tier while past-due), so the
    # UI's add/remove diff is taken against it and a no-change save records
    # nothing spurious for the downgraded features.
    assert set(body["plan_features"]) == {"core"}
    assert "audit_export" not in body["effective"]


def test_features_page_renders():
    _create("acme", plan="pro")
    text = client.get("/tenants/acme/features").text
    assert "Workspace features" in text
    assert 'value="department:finance"' in text
    # the page carries the PUT-target form the light JS submits.
    assert 'id="features-form"' in text
    assert 'data-tenant-id="acme"' in text
