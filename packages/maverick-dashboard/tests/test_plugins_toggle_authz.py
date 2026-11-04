"""Authorization on /plugins/toggle.

Enabling a plugin loads its code on the next goal -- a deployment control-plane
change that must require a global admin, like /plugins/install. Regression guard
for the gaps where the route checked only same-origin or a tenant-local role.
"""
from __future__ import annotations

import maverick_dashboard.app as appmod
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

client = TestClient(appmod.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))


def test_toggle_is_gated_on_admin(monkeypatch):
    # Simulate the global RBAC gate denying a non-admin caller: the route must
    # propagate its 403 (not silently toggle).
    seen = []

    def deny(request, perm):
        seen.append(perm)
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(appmod, "require_global_permission", deny)
    r = client.post("/plugins/toggle", data={"name": "x", "action": "enable"})
    assert r.status_code == 403
    assert "admin" in seen


def test_toggle_works_when_authorized(monkeypatch):
    # With permission granted (the auth-off local-admin case), the gate doesn't
    # block: same-origin + admin pass and the route proceeds (redirect, not 403).
    monkeypatch.setattr(appmod, "require_global_permission", lambda request, perm: None)
    r = client.post(
        "/plugins/toggle", data={"name": "nonexistent-plugin", "action": "reset"},
        follow_redirects=False,
    )
    assert r.status_code != 403
