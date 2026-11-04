"""Blocking or allowing a tool edits the deployment-wide overlay, so only a global role may.

``POST /api/v1/permissions/tools/{name}/disable|enable`` writes
``runtime-overrides.toml``, the shared control-plane file every workspace reads
(see ``test_app_global_control_plane_authz``). It was gated with the
tenant-aware ``require_permission``, so an operator role held only inside one
workspace could block a tool for every workspace, or clear a block a global
administrator had set. It now uses the global gate, like ``/styles/set``.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import runtime_overrides
from maverick.oidc import VerifiedPrincipal
from maverick.paths import reset_tenant, set_tenant
from maverick_dashboard import auth, rbac
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
DISABLE = "/api/v1/permissions/tools/shell/disable"
ENABLE = "/api/v1/permissions/tools/shell/enable"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_ADMINS", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(rbac, "store_path", lambda: home / "dashboard-users.json")
    monkeypatch.setattr(
        rbac, "tenant_store_path", lambda: home / "dashboard-tenant-roles.json"
    )
    monkeypatch.setattr(
        runtime_overrides, "OVERRIDES_PATH", home / "runtime-overrides.toml"
    )
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token,
            issuer="https://issuer.example",
            audience="maverick",
            claims={"sub": token},
        ),
    )


def _tenant_operator() -> dict[str, str]:
    """alice is a viewer deployment-wide but an operator inside workspace acme."""
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "operator")
    return {"Authorization": "Bearer alice"}


def _as_tenant_operator(method: str, path: str):
    headers = _tenant_operator()
    token = set_tenant("acme")
    try:
        # Prove the only reason alice may operate is her workspace membership.
        assert auth.role_for_principal("user:alice") == "operator"
        assert auth.global_role_for_principal("user:alice") == "viewer"
        return getattr(client, method)(path, headers=headers)
    finally:
        reset_tenant(token)


def test_workspace_operator_cannot_block_a_tool_for_the_whole_deployment():
    response = _as_tenant_operator("post", DISABLE)

    assert response.status_code == 403
    assert runtime_overrides.denied_tools() == set()


def test_workspace_operator_cannot_clear_a_block_a_global_admin_set():
    runtime_overrides.disable_tool("shell")

    response = _as_tenant_operator("post", ENABLE)

    assert response.status_code == 403
    assert runtime_overrides.denied_tools() == {"shell"}


def test_global_operator_can_still_block_and_allow_a_tool():
    rbac.set_role("user:root", "operator")
    headers = {"Authorization": "Bearer root"}

    assert client.post(DISABLE, headers=headers).status_code == 204
    assert runtime_overrides.denied_tools() == {"shell"}
    assert client.post(ENABLE, headers=headers).status_code == 200
    assert runtime_overrides.denied_tools() == set()


def test_permissions_page_does_not_offer_the_toggle_to_a_workspace_operator():
    page = _as_tenant_operator("get", "/permissions")

    assert page.status_code == 200
    assert "View only" in page.text
    assert 'class="btn perm-toggle"' not in page.text


def test_permissions_page_offers_the_toggle_to_a_global_operator():
    rbac.set_role("user:root", "operator")

    page = client.get("/permissions", headers={"Authorization": "Bearer root"})

    assert page.status_code == 200
    assert 'class="btn perm-toggle"' in page.text
