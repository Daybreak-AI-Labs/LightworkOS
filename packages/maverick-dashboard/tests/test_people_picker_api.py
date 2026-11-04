from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick_dashboard import people_picker_api as api
from maverick_dashboard import rbac


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch):
    state = SimpleNamespace(permissions=[], workspace="acme", caller="user:local")
    monkeypatch.setattr(api, "require_permission", lambda _r, p: state.permissions.append(p))
    monkeypatch.setattr(api, "_active_workspace", lambda: state.workspace)
    monkeypatch.setattr(rbac, "list_users", lambda: {"user:alice@example.com": "admin"})
    monkeypatch.setattr(
        rbac,
        "list_tenant_roles",
        lambda tenant: {"acme": {"user:bob": "operator"}, "other": {"user:mallory": "admin"}}.get(tenant, {}),
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal=state.caller)
        return await call_next(request)

    app.include_router(api.router, prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1"), state


def test_lists_people_of_the_active_workspace_only(client) -> None:
    test_client, state = client
    body = test_client.get("/api/v1/people/assignable").json()
    labels = [item["label"] for item in body["items"]]
    assert labels[0] == "Local operator"  # the caller comes first
    assert "alice@example.com" in labels and "bob" in labels
    assert "mallory" not in labels
    assert state.permissions == ["operate"]
    for item in body["items"]:
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", item["ref"])
    alice = next(item for item in body["items"] if item["label"] == "alice@example.com")
    assert alice["ref"] == api.person_ref("user:alice@example.com")
    assert alice["ref"].startswith("person:") and "alice" not in alice["ref"]


def test_without_a_workspace_only_global_people_and_the_caller_are_listed(client) -> None:
    test_client, state = client
    state.workspace = None
    labels = [item["label"] for item in test_client.get("/api/v1/people/assignable").json()["items"]]
    assert "bob" not in labels and "alice@example.com" in labels


def test_an_unreadable_role_store_fails_closed(client, monkeypatch) -> None:
    test_client, _state = client

    def broken():
        raise rbac.RbacStoreError("unreadable")

    monkeypatch.setattr(rbac, "list_users", broken)
    assert test_client.get("/api/v1/people/assignable").status_code == 503
