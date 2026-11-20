"""Work needs a workspace once the installation has workspaces.

Seen live: a colleague invited with "Invite someone by email" had no workspace
("You do not have access to a workspace yet"), yet could start tasks and team
runs. They ran in the installation root, outside every workspace's approvals,
spending views and records, on the installation's AI account.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException


def _gate(monkeypatch, *, tenant, workspaces, bound=""):
    from maverick_dashboard import _shared

    monkeypatch.setattr("maverick.paths.current_tenant_id", lambda: tenant)
    monkeypatch.setattr("maverick.tenant.registry.list_tenants", lambda: list(workspaces))
    if bound:
        monkeypatch.setenv("MAVERICK_TENANT", bound)
    else:
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    return _shared.require_workspace_for_work


def test_no_workspace_means_no_new_work_once_workspaces_exist(monkeypatch):
    gate = _gate(monkeypatch, tenant=None, workspaces=["local"])
    with pytest.raises(HTTPException) as refused:
        gate()
    assert refused.value.status_code == 409
    assert "workspace" in refused.value.detail and "administrator" in refused.value.detail


@pytest.mark.parametrize("tenant,workspaces,bound", [
    ("local", ["local"], ""),      # working in a workspace
    (None, [], ""),                # an installation that never made a workspace
    (None, ["local"], "acme"),     # a deployment bound to one workspace
])
def test_work_still_starts_where_it_should(monkeypatch, tenant, workspaces, bound):
    _gate(monkeypatch, tenant=tenant, workspaces=workspaces, bound=bound)()


def test_every_work_start_checks_it(monkeypatch):
    from maverick_dashboard import _shared

    calls = []
    monkeypatch.setattr(_shared, "require_workspace_for_work", lambda: calls.append(1))
    monkeypatch.setattr(_shared, "require_task_settings_or_400", lambda: None)
    try:
        _shared.require_provider_or_400()
    except HTTPException:
        pass
    assert calls == [1]


def test_a_team_cannot_be_made_outside_every_workspace(monkeypatch):
    from fastapi.testclient import TestClient
    from maverick_dashboard import api
    from maverick_dashboard.app import app

    _gate(monkeypatch, tenant=None, workspaces=["local"])
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr("maverick.fleet.save_fleet", lambda *_a, **_k: pytest.fail("saved a team"))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    made = client.post("/api/v1/fleets", json={"name": "Desk", "agents": [{"name": "a", "role": "operator"}]})
    assert made.status_code == 409 and "workspace" in made.json()["detail"]


def test_hiring_into_a_new_team_needs_a_workspace_too(monkeypatch):
    # Seen live: the job-description "add to a team" step created a team in
    # the installation root for a person with no workspace.
    from fastapi.testclient import TestClient
    from maverick_dashboard import api
    from maverick_dashboard.app import app

    _gate(monkeypatch, tenant=None, workspaces=["local"])
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr("maverick.jd_hiring.add_pack_to_fleet", lambda *_a, **_k: pytest.fail("made a team"))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    made = client.post("/api/v1/fleets/Desk/agents", json={"pack": "finance_ap"})
    assert made.status_code == 409 and "Workspace in the menu" in made.json()["detail"]


def test_a_team_has_at_most_a_hundred_agents():
    from maverick_dashboard.api_schemas import FleetCreateIn
    from pydantic import ValidationError

    FleetCreateIn(name="Desk", agents=[{"name": f"a{i}", "role": "viewer"} for i in range(100)])
    with pytest.raises(ValidationError):
        FleetCreateIn(name="Desk", agents=[{"name": f"a{i}", "role": "viewer"} for i in range(101)])
