"""Per-tenant RBAC: a principal can hold a different role in each tenant.

Tenant memberships override the GLOBAL stored role for that tenant only; the
config-pinned bootstrap admin stays globally admin regardless (can't be locked
out of a tenant). No active tenant / no membership => unchanged global behaviour.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # store_path()/tenant_store_path() use Path.home(); point HOME at tmp too.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    yield


def test_tenant_membership_store_roundtrip():
    from maverick_dashboard import rbac
    assert rbac.list_tenant_roles("acme") == {}
    rbac.set_tenant_role("acme", "user:alice", "admin")
    rbac.set_tenant_role("acme", "user:bob", "viewer")
    assert rbac.get_tenant_role("acme", "user:alice") == "admin"
    assert rbac.list_tenant_roles("acme") == {"user:alice": "admin", "user:bob": "viewer"}
    # Distinct tenants are independent.
    assert rbac.get_tenant_role("globex", "user:alice") is None
    rbac.remove_tenant_role("acme", "user:alice")
    assert rbac.get_tenant_role("acme", "user:alice") is None


def test_bad_role_rejected():
    from maverick_dashboard import rbac
    with pytest.raises(ValueError):
        rbac.set_tenant_role("acme", "user:x", "superuser")


def test_corrupt_tenant_role_store_does_not_fall_back_to_global_operator():
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:alice", "operator")
    path = rbac.tenant_store_path()
    path.write_text('{"acme":{"user:alice":"not-a-role"}}', encoding="utf-8")
    tok = set_tenant("acme")
    try:
        assert auth.role_for_principal("user:alice") is None
    finally:
        reset_tenant(tok)


def test_role_for_principal_uses_tenant_membership(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    # Global role for alice is viewer; in acme she is an operator.
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "operator")

    # No active tenant -> global role.
    assert auth.role_for_principal("user:alice") == "viewer"

    # Active tenant acme -> tenant membership wins.
    tok = set_tenant("acme")
    try:
        assert auth.role_for_principal("user:alice") == "operator"
    finally:
        reset_tenant(tok)

    # A tenant with no membership for alice -> falls back to global role.
    tok = set_tenant("globex")
    try:
        assert auth.role_for_principal("user:alice") == "viewer"
    finally:
        reset_tenant(tok)


def test_bootstrap_admin_stays_admin_in_every_tenant(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    # Even if someone tries to demote root within a tenant, bootstrap wins.
    rbac.set_tenant_role("acme", "user:root", "viewer")
    tok = set_tenant("acme")
    try:
        assert auth.role_for_principal("user:root") == "admin"
    finally:
        reset_tenant(tok)


# --- per-user tenancy incompatibility (the api:<principal> pin) --------------
# Under MAVERICK_TENANT_BY_USER every request is pinned to the caller's OWN
# tenant (api:<principal>), so a role assigned to a *named* tenant can never be
# the active tenant. Named-tenant roles are silently dead there; the mutation is
# now rejected, and the read path keeps the global role.

def test_named_tenant_role_does_not_apply_under_per_user_pin():
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:alice", "operator")
    rbac.set_tenant_role("acme", "user:alice", "viewer")  # named-tenant assignment
    # Per-user tenancy pins alice to her OWN tenant, not "acme" -> the named
    # "viewer" role does not apply; she keeps her global "operator".
    tok = set_tenant("api:user:alice")
    try:
        assert auth.role_for_principal("user:alice") == "operator"
    finally:
        reset_tenant(tok)


def test_tenant_role_assignment_rejected_under_per_user_tenancy(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard.api import (
        _reject_tenant_role_assignment_under_per_user_tenancy as guard,
    )

    # Named-tenant deployment (default): per-tenant roles apply -> no rejection.
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    guard()  # must not raise

    # Per-user tenancy: the assignment would be dead, so reject it (409).
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    with pytest.raises(HTTPException) as ei:
        guard()
    assert ei.value.status_code == 409
    assert "per-user tenancy" in ei.value.detail


def test_remove_active_per_user_tenant_role_allowed_under_per_user_tenancy(
    monkeypatch,
):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import api, auth, rbac

    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.setattr(api, "require_permission", lambda request, permission: None)
    monkeypatch.setattr(api, "_get_tenant_or_404", lambda tenant_id: object())

    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("api:user:alice", "user:alice", "admin")

    tok = set_tenant("api:user:alice")
    try:
        assert auth.role_for_principal("user:alice") == "admin"
        # The gate reads the request's workspace-people context header.
        from starlette.requests import Request
        request = Request({"type": "http", "method": "DELETE", "path": "/", "headers": [], "query_string": b""})
        response = api.remove_tenant_role(request, "api:user:alice", "user:alice")
        assert response.status_code == 204
        assert rbac.get_tenant_role("api:user:alice", "user:alice") is None
        assert auth.role_for_principal("user:alice") == "viewer"
    finally:
        reset_tenant(tok)
