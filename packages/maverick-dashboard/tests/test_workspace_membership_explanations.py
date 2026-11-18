"""Owner-bound pages explain a missing workspace membership and a turned-off switch.

Installation administrators are not implicitly members of a workspace (see
``test_config_admin_still_needs_explicit_workspace_membership``), so these
pages must say that, and how to fix it, instead of a generic role refusal or
"Page not found". A turned-off feature is a 200 page, not a 403.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

HTML = {"Accept": "text/html"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    app._world_cache.clear()
    original_routes = list(app.app.router.routes)
    yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    app.app.router.routes[:] = original_routes
    config.reset_config_cache()


def _features(monkeypatch, **switches):
    from maverick import config

    monkeypatch.setattr(config, "get_features", lambda: dict(switches))


@pytest.mark.parametrize(("path", "switch"), [
    ("/my-data", "personal_data_controls"),
    ("/deliverable-bundles", "deliverable_bundles"),
    ("/deliverable-bundles?goal=33", "deliverable_bundles"),
    ("/task-handoffs", "task_handoffs"),
    ("/companion", "employee_companions"),
])
def test_a_turned_off_feature_page_is_the_standard_turned_off_state(client, monkeypatch, path, switch):
    _features(monkeypatch)
    response = client.get(path, headers=HTML)
    assert response.status_code == 200, response.text
    assert "turned off." in response.text
    assert f'href="/settings/all?id=features.{switch}"' in response.text
    assert "Permission required" not in response.text and "Page not found" not in response.text


def _membership_admin(monkeypatch, admin):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "is_dashboard_admin", lambda principal: admin)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "admin" if admin else "viewer")


def test_an_installation_administrator_is_told_to_add_themselves(monkeypatch):
    from maverick_dashboard.access_explanations import MEMBERSHIP_REQUIRED, membership_required

    _membership_admin(monkeypatch, True)
    detail = membership_required("user:owner", "My data").detail
    assert detail["code"] == MEMBERSHIP_REQUIRED
    assert "installation administrator, but not a member of this workspace" in detail["message"]
    assert "Users → Workspace members" in detail["message"]
    assert detail["next_action"] == {"label": "Add yourself as a member", "href": "/users#wm-root"}
    assert all(len(sentence.split()) <= 25 for sentence in detail["message"].split(". "))


def test_a_colleague_outside_the_workspace_is_told_who_can_add_them(monkeypatch):
    from maverick_dashboard.access_explanations import membership_required

    _membership_admin(monkeypatch, False)
    detail = membership_required("user:colleague", "Your companion").detail
    assert "not a member of this workspace" in detail["message"]
    assert "Ask a workspace administrator" in detail["message"]
    assert detail["next_action"]["href"] == "/workspace/tenant"


def test_the_browser_page_shows_the_membership_reason_and_next_step(client, monkeypatch):
    from maverick_dashboard import app
    from maverick_dashboard.access_explanations import membership_required

    _membership_admin(monkeypatch, True)

    @app.app.get("/__membership_probe")
    def probe():
        raise membership_required("user:owner", "My data")

    response = client.get("/__membership_probe", headers=HTML)
    assert response.status_code == 403
    assert "Workspace membership needed" in response.text
    assert "not a member of this workspace" in response.text
    assert 'href="/users#wm-root"' in response.text and "Add yourself as a member" in response.text
    assert "Your current role cannot use this page" not in response.text
    api = client.get("/__membership_probe")
    assert api.json()["detail"]["code"] == "workspace_membership_required"


def test_my_data_names_membership_not_a_role(monkeypatch):
    from maverick_dashboard import personal_data_api as api

    _membership_admin(monkeypatch, True)
    monkeypatch.setattr(api.auth, "require_permission", lambda *a, **k: None)
    monkeypatch.setattr(api.auth, "caller_principal", lambda request: "user:owner")
    monkeypatch.setattr(api.personal_identity, "principal_current", lambda principal: False)
    with pytest.raises(HTTPException) as error:
        api._actor(object())
    assert error.value.status_code == 403
    assert error.value.detail["code"] == "workspace_membership_required"


def test_bundles_explain_membership_before_any_task_lookup(monkeypatch):
    from maverick_dashboard import deliverable_bundles_api as api
    from maverick_dashboard import project_reviews_api

    _membership_admin(monkeypatch, True)
    monkeypatch.setattr(api.auth, "require_permission", lambda *a, **k: None)
    monkeypatch.setattr(api.auth, "caller_principal", lambda request: "user:owner")
    monkeypatch.setattr(api.config, "config_source_errors", lambda **k: [])
    monkeypatch.setattr(api.config, "get_features", lambda: {"deliverable_bundles": True})
    monkeypatch.setattr(api, "current_tenant_id_strict", lambda: "demo")
    monkeypatch.setattr(project_reviews_api, "_eligible", lambda *a: False)
    request = type("R", (), {"headers": {}})()
    with pytest.raises(HTTPException) as error:
        api.service(request)
    assert error.value.status_code == 403
    assert error.value.detail["code"] == "workspace_membership_required"
    assert "Sharing selected deliverables needs workspace membership" in error.value.detail["message"]


def test_a_task_link_to_bundles_is_never_page_not_found(client, monkeypatch):
    from maverick_dashboard import deliverable_bundles_api as api

    _features(monkeypatch, deliverable_bundles=True)

    class Refusing:
        def candidates(self, goal):
            raise AssertionError("the page must not pre-read another person's task")

    monkeypatch.setattr(api, "service", lambda request, **k: Refusing())
    response = client.get("/deliverable-bundles?goal=33", headers=HTML)
    assert response.status_code == 200
    assert 'data-goal="33"' in response.text
