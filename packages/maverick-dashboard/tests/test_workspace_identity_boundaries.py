"""Workspace identity boundaries: the workspace-admin roster, the OIDC login
restart and the fixed-workspace refusal. No provider calls."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app._world_cache.clear()
    return TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_workspace_admin_never_loads_installation_roster(monkeypatch, isolated):
    from maverick_dashboard import admin_pages, auth, invites, rbac

    monkeypatch.setattr(auth, "has_global_permission", lambda *_: False)
    monkeypatch.setattr(auth, "caller_principal", lambda *_: "user:workspace-admin")
    monkeypatch.setattr(admin_pages, "_workspace_options", lambda *_: ([{"id": "a", "name": "A"}], "a"))
    monkeypatch.setattr(rbac, "list_tenant_roles", lambda _: {"user:colleague": "viewer"})
    def forbidden():
        raise AssertionError("installation roster must not be read")
    monkeypatch.setattr(rbac, "list_users", forbidden)
    # The shared invitation store is filtered to the administered workspace
    # before anything reaches the page.
    import time
    later = time.time() + 3600
    mine = invites.Invite("i-a", "new@a.example", "viewer", "user:workspace-admin", 0.0, later, tenant="a")
    other = invites.Invite("i-b", "private@b.example", "admin", "user:root", 0.0, later, tenant="b")
    monkeypatch.setattr(invites, "list_invites", lambda: [mine, other])
    request = Request({"type": "http", "method": "GET", "path": "/users", "headers": [], "query_string": b""})
    context = admin_pages._users_context(request)
    assert context["global_admin"] is False
    assert [p["principal"] for p in context["people"]] == ["user:colleague"]
    assert context["users"] == []
    assert context["workspace_pending_invites"] == [mine]
    assert "private@b.example" not in repr(context)


def test_login_failure_has_safe_fresh_restart(isolated):
    from maverick_dashboard.oidc_login import _login_error_response

    response = _login_error_response("//attacker.example/token")
    text = response.body.decode()
    assert response.status_code == 401
    assert "Restart sign-in" in text
    assert "attacker.example" not in text
    assert "return_to=%2F" in text
    assert response.headers["cache-control"] == "no-store"


def test_fixed_workspace_selection_is_refused(monkeypatch, isolated):
    monkeypatch.setenv("MAVERICK_TENANT", "pinned")
    response = isolated.put("/api/v1/workspace/active-tenant", json={"tenant_id": None})
    assert response.status_code == 409
    assert "fixed workspace" in response.text
