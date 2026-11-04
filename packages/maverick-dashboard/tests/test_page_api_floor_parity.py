"""Backing API reads must honor the security floor of their workspace page."""
from __future__ import annotations

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient


@pytest.fixture
def scoped_client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api, app, auth

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:customer")
    monkeypatch.setattr(api, "_security_register_snapshot", lambda: {"source": "security"})
    monkeypatch.setattr(api, "_board_workspace", lambda board: {"source": board})
    config.reset_config_cache()
    api._world_cache.clear()
    yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    api._world_cache.clear()


@pytest.mark.parametrize("page,endpoint", [
    ("/security", "/api/v1/security"),
    ("/security", "/api/v1/dashboards/security"),
    ("/privacy", "/api/v1/dashboards/privacy"),
    ("/finance", "/api/v1/dashboards/finance"),
])
@pytest.mark.parametrize("role,expected", [
    ("viewer", 403),
    ("auditor", 403),
    ("operator", 200),
    ("admin", 200),
])
def test_backing_reads_follow_workspace_floor(scoped_client, page, endpoint, role, expected):
    from maverick_dashboard import rbac, ui_visibility

    assert ui_visibility.page_for(page)["floor"] == "operate"
    rbac.set_role("user:customer", role)
    response = scoped_client.get(endpoint)
    assert response.status_code == expected, response.text


def test_finance_board_reads_follow_department_grant(scoped_client):
    from maverick_dashboard import rbac, suite_grants

    rbac.set_role("user:customer", "operator")
    suite_grants.set_suites("user:customer", ["legal"])
    for path in (
        "/finance", "/finance/board",
        "/api/v1/dashboards/finance", "/api/v1/finance/board",
    ):
        assert scoped_client.get(path).status_code == 403, path

    suite_grants.set_suites("user:customer", ["finance"])
    assert scoped_client.get("/finance/board").status_code == 200
    assert scoped_client.get("/api/v1/dashboards/finance").status_code == 200
    assert scoped_client.get("/api/v1/finance/board").status_code == 200


@pytest.mark.parametrize("page,endpoint", [
    ("/compliance", "/api/v1/compliance/report.md"),
    ("/compliance", "/api/v1/compliance/report.csv"),
    ("/cache", "/api/v1/cache/stats"),
    ("/permissions", "/api/v1/permissions"),
    ("/tools", "/api/v1/tools"),
    ("/external-agents", "/api/v1/external-agents"),
    ("/external-agents", "/api/v1/external-agents/agent-1"),
])
def test_view_floor_reads_stay_available_to_viewers(
    scoped_client, monkeypatch, page, endpoint,
):
    from types import SimpleNamespace

    from maverick import external_agents, sandbox, tools
    from maverick_dashboard import api, app, rbac, ui_visibility

    assert ui_visibility.page_for(page)["floor"] == "view"
    rbac.set_role("user:customer", "viewer")
    monkeypatch.setattr(api, "_compliance_checks", lambda _framework: ("all", []))
    monkeypatch.setattr(app, "_permissions_snapshot", dict)
    monkeypatch.setattr(app, "_permissions_tool_page", lambda *_args, **_kwargs: {"tools": []})
    monkeypatch.setattr(sandbox, "build_sandbox", lambda: object())
    monkeypatch.setattr(tools, "base_registry", lambda **_kwargs: SimpleNamespace(all=list))
    monkeypatch.setattr(external_agents, "enabled", lambda: False)
    monkeypatch.setattr(external_agents, "status", dict)
    monkeypatch.setattr(external_agents, "roster", list)
    monkeypatch.setattr(external_agents, "agent_detail", lambda agent_id: {"id": agent_id})

    if page in {"/compliance", "/cache", "/permissions", "/tools"}:
        assert scoped_client.get(page).status_code == 403  # presentation policy
    response = scoped_client.get(endpoint)
    assert response.status_code == 200, response.text


def test_page_floor_keeps_api_key_scopes_and_rejects_unknown_pages(monkeypatch, tmp_path):
    from maverick_dashboard import auth, rbac

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:customer", "operator")
    monkeypatch.setattr(auth, "_authorization_principal", lambda _request: "user:customer")
    # A current operate-scoped API key: each gate re-verifies the bearer.
    from types import SimpleNamespace
    key = SimpleNamespace(principal="user:customer",
                          claims={"via": "api_key", "api_key_id": "key-1", "workspace": ""})
    monkeypatch.setattr(auth, "_authenticate_api_key", lambda _request, _token: key)
    request = Request({"type": "http", "method": "GET", "path": "/",
                       "headers": [(b"authorization", b"Bearer test-key")]})
    request.state.principal = key
    request.state.api_key_id = "key-1"
    request.state.api_key_permissions = frozenset({"operate"})
    request.state.api_key_scopes = frozenset({"tasks:write"})
    auth.require_page_permission(request, "/security")
    with pytest.raises(HTTPException) as denied:
        auth.require_page_permission(request, "/cache")
    assert denied.value.status_code == 403
    with pytest.raises(RuntimeError, match="exact page security floor"):
        auth.require_page_permission(request, "/missing-page")


def test_hiding_a_page_does_not_revoke_its_role_permission(scoped_client):
    from maverick_dashboard import rbac, ui_visibility

    rbac.set_role("user:customer", "operator")
    ui_visibility.set_visibility("/security", "operator", False)
    assert scoped_client.get("/security").status_code == 403
    assert scoped_client.get("/api/v1/security").status_code == 200


# Live screens the registry now governs so the page finder can offer them.
# A role finds each one exactly when the screen's own route admits that role.
REGISTERED_SCREENS = (
    "/help", "/notifications", "/my-work", "/conversations", "/get-started/employee",
    "/project-workspaces", "/devices", "/access-requests", "/budget",
    "/cost-reconciliation", "/provider-spending",
)


@pytest.mark.parametrize("role", ["viewer", "auditor", "operator", "admin"])
def test_registered_screens_are_offered_exactly_where_their_routes_admit(scoped_client, role):
    from maverick_dashboard import rbac, ui_visibility

    rbac.set_role("user:customer", role)
    finder = scoped_client.get("/nav/finder")
    assert finder.status_code == 200
    for path in REGISTERED_SCREENS:
        assert ui_visibility.page_for(path)["path"] == path
        offered = f'href="{path}"' in finder.text
        status = scoped_client.get(path).status_code
        assert status in {200, 403}, (role, path, status)
        assert offered == (status == 200), (role, path, status)
    # The installation-wide spending page stays with administrators.
    assert ('href="/provider-spending"' in finder.text) == (role == "admin")


# Pages whose registry floor once sat below their route's own check, so search
# and the sidebar offered them to roles the route then refused.
FLOOR_MATCHED_SCREENS = ("/safety", "/oversight", "/plugins")


@pytest.mark.parametrize("role", ["viewer", "auditor", "operator", "admin"])
def test_floor_matched_screens_are_offered_exactly_where_their_routes_admit(scoped_client, role):
    from maverick_dashboard import rbac

    rbac.set_role("user:customer", role)
    finder = scoped_client.get("/nav/finder")
    assert finder.status_code == 200
    for path in FLOOR_MATCHED_SCREENS:
        offered = f'href="{path}"' in finder.text
        status = scoped_client.get(path).status_code
        assert status in {200, 403}, (role, path, status)
        assert offered == (status == 200), (role, path, status)
