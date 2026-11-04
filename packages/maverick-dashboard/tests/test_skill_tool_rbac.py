"""Authorization on skill / generated-tool management endpoints.

Installing, authoring, or removing a skill -- and removing a generated tool --
changes the code the agent loads on its next run. That is a control-plane
mutation and must require ``admin`` (like ``/plugins/install`` and
``/plugins/toggle``), not merely an authenticated session. Without an RBAC
gate on these five routes, with ``[dashboard] default_role = "viewer"`` an
authenticated read-only principal could delete/install agent code. The
process-wide ``MAVERICK_ALLOW_SKILL_INSTALL`` opt-in is not a role check.

Regression guard: each route must consult ``require_permission("admin")`` and
propagate its 403.
"""
from __future__ import annotations

import maverick_dashboard.api as apimod
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))


@pytest.fixture
def _deny_non_admin(monkeypatch):
    """Simulate RBAC denying a non-admin caller and record the permission asked."""
    seen: list[str] = []

    def deny(request, perm):
        seen.append(perm)
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(apimod, "require_permission", deny)
    return seen


def test_install_skill_requires_admin(_deny_non_admin):
    r = client.post("/api/v1/skills", json={"source": "gh:acme/skill"})
    assert r.status_code == 403
    assert "admin" in _deny_non_admin


def test_create_skill_requires_admin(_deny_non_admin):
    r = client.post(
        "/api/v1/skills/create",
        json={"name": "s", "instructions": "do x", "triggers": ["t"]},
    )
    assert r.status_code == 403
    assert "admin" in _deny_non_admin


def test_catalog_install_requires_admin(_deny_non_admin):
    r = client.post("/api/v1/catalog/skills/install", json={"name": "some-skill"})
    assert r.status_code == 403
    assert "admin" in _deny_non_admin


def test_remove_skill_requires_admin(_deny_non_admin):
    r = client.request("DELETE", "/api/v1/skills/some-skill")
    assert r.status_code == 403
    assert "admin" in _deny_non_admin


def test_remove_generated_tool_requires_admin(_deny_non_admin):
    r = client.request("DELETE", "/api/v1/generated-tools/some-tool")
    assert r.status_code == 403
    assert "admin" in _deny_non_admin


def test_admin_passes_gate(monkeypatch):
    # With permission granted (auth-off local-admin case), the gate doesn't block:
    # the DELETE proceeds to a real 404 (no such generated tool), not a 403.
    monkeypatch.setattr(apimod, "require_permission", lambda request, perm: None)
    r = client.request("DELETE", "/api/v1/generated-tools/definitely-missing")
    assert r.status_code != 403
