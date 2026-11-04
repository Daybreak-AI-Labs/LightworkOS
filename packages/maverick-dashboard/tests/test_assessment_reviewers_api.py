from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick_dashboard import assessment_reviewers_api as api
from maverick_dashboard import rbac


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch):
    state = SimpleNamespace(permissions=[], workspace="acme", caller="user:carol@example.com")
    monkeypatch.setattr(api, "require_permission", lambda _r, p: state.permissions.append(p))
    monkeypatch.setattr(api, "_active_workspace", lambda: state.workspace)
    monkeypatch.setattr(rbac, "list_users", lambda: {"user:alice@example.com": "admin"})
    monkeypatch.setattr(
        rbac,
        "list_tenant_roles",
        lambda tenant: {"acme": {"user:bob@example.com": "operator"},
                        "other": {"user:mallory@example.com": "admin"}}.get(tenant, {}),
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal=state.caller)
        return await call_next(request)

    app.include_router(api.router, prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1"), state


def test_lists_real_principals_of_the_active_workspace(client) -> None:
    test_client, state = client
    items = test_client.get("/api/v1/assess/reviewers").json()["items"]
    principals = [item["principal"] for item in items]
    assert principals[0] == "user:carol@example.com" and items[0]["is_you"] is True
    assert "user:alice@example.com" in principals and "user:bob@example.com" in principals
    assert "user:mallory@example.com" not in principals
    assert state.permissions == ["operate"]
    assert all(not item["label"].startswith("user:") for item in items)


def test_without_a_workspace_only_global_people_and_the_caller(client) -> None:
    test_client, state = client
    state.workspace = None
    principals = [i["principal"] for i in test_client.get("/api/v1/assess/reviewers").json()["items"]]
    assert "user:bob@example.com" not in principals and "user:alice@example.com" in principals


def test_permission_is_checked_before_listing(client, monkeypatch) -> None:
    from fastapi import HTTPException

    test_client, _state = client

    def deny(_request, _permission):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(api, "require_permission", deny)
    assert test_client.get("/api/v1/assess/reviewers").status_code == 403


def test_an_unreadable_role_store_fails_closed(client, monkeypatch) -> None:
    test_client, _state = client

    def broken():
        raise rbac.RbacStoreError("unreadable")

    monkeypatch.setattr(rbac, "list_users", broken)
    assert test_client.get("/api/v1/assess/reviewers").status_code == 503
