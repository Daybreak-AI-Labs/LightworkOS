"""The /workflows index: your saved templates + agent playbooks, with quick
edit / automate actions and a 'New workflow' button. Closes Maya's "the
Workflows nav opens a blank builder" finding by making it a real list.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from test_support.navigation import assert_navigation_link


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.templates as tpl
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tmp_path / ".maverick" / "templates")


def test_index_lists_user_templates_and_playbooks(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    tdir = tmp_path / ".maverick" / "templates"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "weekly-report.md").write_text(
        "---\nowner: local\ntitle: Weekly report\nparams:\n  - topic\n---\nbody\n", encoding="utf-8")
    import maverick.domain_edit as de
    monkeypatch.setattr(de, "list_agents", lambda: [
        {"name": "invoice-clerk", "suite": "finance", "description": "pays invoices",
         "is_override": True, "has_workflow": True},
        {"name": "vanilla", "suite": "x", "description": "",
         "is_override": False, "has_workflow": True},   # not overridden -> excluded
    ])
    response = _client().get("/workflows")
    assert response.status_code == 200, response.text
    t = response.text
    # user template listed with edit + automate deep-links
    assert "Weekly report" in t and "/workflow-builder?edit=weekly-report" in t
    assert "/workflow-builder?template=weekly-report" in t
    # only the overridden playbook with a workflow is "yours"
    assert "invoice-clerk" in t and "/workflow-builder?edit_agent=invoice-clerk" in t
    assert "vanilla" not in t
    assert "Create workflow" in t and "Agent playbooks" in t


def test_index_empty_states(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.domain_edit as de
    monkeypatch.setattr(de, "list_agents", list)
    t = _client().get("/workflows").text
    # shared .mv-empty component now backs these
    assert "No templates yet" in t and "No agent playbooks yet" in t
    assert "mv-empty" in t


def test_flows_off_index_has_an_in_product_enable_path(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import flow

    monkeypatch.setattr(flow, "enabled", lambda: False)
    page = _client().get("/workflows")
    assert page.status_code == 200
    assert "Flows are turned off" in page.text
    assert 'href="/learning#lrn-flows-on"' in page.text


def test_flows_off_index_does_not_offer_admin_control_to_others(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import importlib

    from maverick import flow

    dashboard = importlib.import_module("maverick_dashboard.app")
    monkeypatch.setattr(flow, "enabled", lambda: False)
    monkeypatch.setattr(dashboard, "has_global_permission", lambda *_: False)
    page = _client().get("/workflows")
    assert page.status_code == 200
    assert "Ask an administrator to turn on workflows." in page.text
    assert 'href="/learning#lrn-flows-on"' not in page.text


def test_no_flows_guide_uses_the_designer_without_promising_copilot_creation(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import flow
    from maverick.flow import store

    monkeypatch.setattr(flow, "enabled", lambda: True)
    monkeypatch.setattr(store, "list_flow_summaries", lambda *, owner: [])
    page = _client().get("/workflows")
    assert page.status_code == 200
    assert 'href="/flows/designer">Open the flow designer</a>' in page.text
    assert "Copilot can explain the steps" in page.text
    assert "ask Copilot to build one" not in page.text


def test_nav_workflows_points_to_index(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.domain_edit as de
    monkeypatch.setattr(de, "list_agents", list)
    t = _client().get("/workflows").text
    assert_navigation_link(t, "/workflows", "Workflows")
    designer = _client().get("/flows/designer").text
    assert '<a class="back-link" href="/workflows">' in designer and ">Back to Workflows<" in designer
    assert 'href="/workflows" class="active" aria-current="page"' in designer


def test_saved_flows_are_reachable_from_nav(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import flow
    from maverick.flow import store

    monkeypatch.setattr(flow, "enabled", lambda: True)
    monkeypatch.setattr(store, "list_flow_summaries", lambda *, owner: [
        {"id": "renewals", "name": "Customer renewals", "nodes": 4},
    ])
    page = _client().get("/workflows")
    assert page.status_code == 200
    assert_navigation_link(page.text, "/workflows", "Workflows")
    assert "Customer renewals" in page.text
    assert 'href="/flows/designer/renewals"' in page.text


@pytest.mark.parametrize(("role", "can_operate"), [("viewer", False), ("operator", True)])
def test_workflow_index_actions_match_current_role(monkeypatch, tmp_path, role, can_operate):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    from maverick import flow
    from maverick.flow import store
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth, rbac, ui_visibility

    principal = f"user:{role}"
    rbac.set_role(principal, role)
    monkeypatch.setattr(auth, "caller_principal", lambda _request: principal)
    monkeypatch.setattr(dashboard, "caller_principal", lambda _request: principal)
    if role == "viewer":
        ui_visibility.set_visibility("/workflows", role, True)
    monkeypatch.setattr(flow, "enabled", lambda: True)
    monkeypatch.setattr(store, "list_flow_summaries", lambda *, owner: [
        {"id": "renewals", "name": "Customer renewals", "nodes": 4},
    ])
    page = _client().get("/workflows")
    assert page.status_code == 200
    assert "Customer renewals" in page.text
    assert ('href="/flows/designer/renewals"' in page.text) is can_operate
    assert ('href="/flows/designer">New flow</a>' in page.text) is can_operate
    assert ('href="/flows/analytics">Analytics</a>' in page.text) is can_operate
    assert ("You can review saved work here." in page.text) is not can_operate
