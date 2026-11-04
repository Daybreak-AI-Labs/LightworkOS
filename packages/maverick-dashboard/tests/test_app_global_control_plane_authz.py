"""Deployment-global dashboard pages must ignore tenant-local admin grants.

The runtime overlays, channel settings, plugin loader, output style, and tenant
roster are shared control-plane state.  A tenant membership may grant ``admin``
inside that tenant, but it must not grant visibility or mutation authority over
those deployment-wide resources.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import auth, rbac
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


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
        rbac,
        "tenant_store_path",
        lambda: home / "dashboard-tenant-roles.json",
    )
    from maverick import runtime_overrides

    monkeypatch.setattr(
        runtime_overrides,
        "OVERRIDES_PATH",
        home / "runtime-overrides.toml",
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


def _tenant_admin_headers() -> dict[str, str]:
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    return {"Authorization": "Bearer alice"}


@pytest.mark.parametrize(
    "path",
    (
        "/styles",
        "/plugins",
        "/mcp",
        "/channels",
        "/api/v1/plugins",
        "/api/v1/mcp",
        "/api/v1/channels",
        "/api/v1/providers",
        "/tenants",
        "/tenants/overview",
        "/api/v1/tenants/overview",
    ),
)
def test_tenant_admin_cannot_read_deployment_control_plane(path):
    from maverick.paths import reset_tenant, set_tenant

    headers = _tenant_admin_headers()
    token = set_tenant("acme")
    try:
        # Prove this principal is an admin only because of the active tenant.
        assert auth.role_for_principal("user:alice") == "admin"
        assert auth.global_role_for_principal("user:alice") == "viewer"
        response = client.get(path, headers=headers)
    finally:
        reset_tenant(token)

    assert response.status_code == 403


@pytest.mark.parametrize(
    "path",
    (
        "/api/v1/plugins",
        "/api/v1/mcp",
        "/api/v1/channels",
        "/api/v1/providers",
    ),
)
def test_global_admin_can_read_deployment_control_plane_api(path):
    rbac.set_role("user:root", "admin")

    response = client.get(path, headers={"Authorization": "Bearer root"})

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("path", "data"),
    (
        ("/styles/set", {"name": "concise"}),
        ("/plugins/toggle", {"name": "example", "action": "enable"}),
        ("/plugins/install", {"name": "example"}),
        (
            "/mcp/add",
            {"transport": "stdio", "name": "example", "command": "example"},
        ),
        ("/mcp/remove", {"name": "example"}),
        ("/channels/save", {"channel": "slack", "enabled": "on"}),
        ("/channels/clear", {"channel": "slack"}),
    ),
)
def test_tenant_admin_cannot_mutate_deployment_control_plane(path, data, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    if path == "/plugins/install":
        monkeypatch.setenv("MAVERICK_ALLOW_PLUGIN_INSTALL", "1")
        monkeypatch.setattr(
            "maverick.plugins.install_plugin",
            lambda _name: pytest.fail("global authorization gate was bypassed"),
        )
    headers = _tenant_admin_headers()
    token = set_tenant("acme")
    try:
        response = client.post(path, data=data, headers=headers, follow_redirects=False)
    finally:
        reset_tenant(token)

    assert response.status_code == 403


def test_plugin_install_authorizes_before_disclosing_opt_in_state(monkeypatch):
    """A tenant admin must learn nothing about deployment install policy."""
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import app as app_mod

    monkeypatch.delenv("MAVERICK_ALLOW_PLUGIN_INSTALL", raising=False)
    monkeypatch.setattr(
        app_mod,
        "_plugin_install_enabled",
        lambda: pytest.fail("install policy was inspected before global authorization"),
    )
    headers = _tenant_admin_headers()
    token = set_tenant("acme")
    try:
        response = client.post(
            "/plugins/install",
            data={"name": "example"},
            headers=headers,
            follow_redirects=False,
        )
    finally:
        reset_tenant(token)

    assert response.status_code == 403


def test_tenant_admin_cannot_enroll_loopback_partner_even_when_operator_enabled(
    monkeypatch,
):
    """Both authorities are required: operator opt-in is not tenant authority."""
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK", "1")
    headers = _tenant_admin_headers()
    token = set_tenant("acme")
    try:
        response = client.post(
            "/api/v1/partner/tenants",
            headers=headers,
            json={
                "name": "local test estate",
                "base_url": "http://127.0.0.1:9000",
                "trusted_test_estate_loopback": True,
            },
        )
    finally:
        reset_tenant(token)

    assert response.status_code == 403
