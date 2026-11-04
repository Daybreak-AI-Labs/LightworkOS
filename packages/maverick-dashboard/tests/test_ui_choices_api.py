"""The people picker list: operate floor, current workspace only."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config
from maverick.paths import tenant_scope
from maverick_dashboard import rbac
from maverick_dashboard import ui_choices_api as api


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_DASHBOARD_ADMINS",
                 "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text('[dashboard]\ndefault_role="viewer"\n', encoding="utf-8")
    config.reset_config_cache()
    rbac.set_tenant_role("tenant-a", "user:ann@example.com", "operator", actor="user:setup")
    rbac.set_tenant_role("tenant-a", "user:bob@example.com", "viewer", actor="user:setup")
    rbac.set_tenant_role("tenant-b", "user:carol@example.com", "operator", actor="user:setup")
    app = FastAPI()

    @app.middleware("http")
    async def identity(request: Request, call_next):
        subject = request.headers.get("X-Test-User", "ann@example.com")
        request.state.principal = SimpleNamespace(principal="user:" + subject, sub=subject)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)

    app.include_router(api.router)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        yield c
    config.reset_config_cache()


def test_operator_sees_only_their_workspace_members(client):
    response = client.get("/api/v1/choices/people")
    assert response.status_code == 200
    values = [row["value"] for row in response.json()["people"]]
    assert values == ["user:ann@example.com", "user:bob@example.com"]
    assert all(row["label"] and not row["label"].startswith("user:") for row in response.json()["people"])


def test_other_workspace_is_separate(client):
    response = client.get("/api/v1/choices/people", headers={"X-Test-User": "carol@example.com",
                                                             "X-Test-Tenant": "tenant-b"})
    assert response.status_code == 200
    assert [row["value"] for row in response.json()["people"]] == ["user:carol@example.com"]


def test_viewer_cannot_list_people(client):
    response = client.get("/api/v1/choices/people", headers={"X-Test-User": "bob@example.com"})
    assert response.status_code == 403
