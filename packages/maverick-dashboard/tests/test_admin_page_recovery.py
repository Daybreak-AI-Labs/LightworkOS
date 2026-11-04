"""Administrative saves must remain responsive and recover without partial state."""
from __future__ import annotations

import asyncio
import importlib
import threading
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from maverick.paths import current_tenant_id, tenant_scope
from maverick_dashboard import admin_pages, settings_store

ADMIN_OPERATIONS = [
    ("settings_set_model", "maverick.runtime_overrides", "clear_default_model", {}, None),
    ("settings_set_budget", "maverick.runtime_overrides", "clear_budget", {}, None),
    ("settings_set_role_models", "maverick.runtime_overrides", "set_role_models", {}, None),
    ("settings_set_allowed_models", "maverick.runtime_overrides", "set_allowed_models", {}, None),
    ("settings_set_provider", "maverick_dashboard.settings_store", "rotate_provider", {"provider": "openai"}, None),
    ("settings_test_provider", "maverick_dashboard.integration_readiness", "test_provider", {"provider": "openai"}, None),
    ("settings_set_capabilities", "maverick_dashboard.settings_store", "_write", {}, None),
    ("settings_set_ui_visibility", "maverick_dashboard.ui_visibility", "apply_selection", {}, None),
    ("settings_reset_ui_visibility", "maverick_dashboard.ui_visibility", "clear_overrides", {}, None),
    ("users_page", "maverick_dashboard.admin_pages", "_users_context", {}, {}),
    ("users_set_role", "maverick_dashboard.rbac", "set_role", {"principal": "user:alice", "role": "viewer"}, None),
    ("users_remove", "maverick_dashboard.rbac", "remove_user", {"principal": "user:alice"}, None),
    ("users_save_custom_role", "maverick_dashboard.rbac", "set_custom_role", {"name": "reviewer"}, None),
    ("users_delete_custom_role", "maverick_dashboard.rbac", "delete_custom_role", {"name": "reviewer"}, None),
    ("users_invite", "maverick_dashboard.invites", "send_invite_email", {"email": "alice@example.test", "role": "viewer"}, (False, "test delivery")),
    ("users_invite_revoke", "maverick_dashboard.invites", "revoke_invite", {"invite_id": "invite-a"}, None),
    ("users_set_suites", "maverick_dashboard.suite_grants", "set_suites", {"principal": "user:alice"}, None),
    ("users_remove_suites", "maverick_dashboard.suite_grants", "remove_grant", {"principal": "user:alice"}, None),
]


@pytest.mark.parametrize("operation", ADMIN_OPERATIONS, ids=[row[0] for row in ADMIN_OPERATIONS])
def test_admin_io_yields_to_another_request_and_preserves_tenant(monkeypatch, operation):
    from maverick import config
    from maverick_dashboard import auth, invites

    name, module_name, method, data, result = operation
    if name == "users_remove":
        from maverick_dashboard.access_explanations import standard_role
        data = {**data, "expected_standard": standard_role(data["principal"])["revision"]}
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    scopes = []

    def slow_operation(*args, **kwargs):
        scopes.append(current_tenant_id())
        entered.set()
        try:
            assert release.wait(10), "test I/O was never released"
        finally:
            finished.set()
        return result

    # Isolate the scheduling contract. Real authentication, form persistence
    # and last-admin protections are exercised by the existing API suites.
    monkeypatch.setattr(auth, "require_global_permission", lambda request, permission: None)
    monkeypatch.setattr(auth, "require_permission", lambda request, permission: None)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:owner")
    page = SimpleNamespace(
        _require_same_origin=lambda request: None,
        templates=SimpleNamespace(TemplateResponse=lambda *args, **kwargs: HTMLResponse("users")),
    )
    monkeypatch.setattr(admin_pages, "_app", lambda: page)
    monkeypatch.setattr(admin_pages, "_users_context", lambda request: {})
    monkeypatch.setattr(admin_pages, "_refresh_models_quietly", lambda provider: None)
    monkeypatch.setattr(config, "provider_configuration_state", lambda provider: {"configured": True})
    from maverick_dashboard import provider_readiness
    monkeypatch.setattr(provider_readiness, "workspace_readiness",
                        lambda: {"providers": [{"name": "openai", "configured": True}]})
    monkeypatch.setattr(invites, "invites_enabled", lambda: True)
    monkeypatch.setattr(invites, "create_invite", lambda *args, **kwargs: (
        SimpleNamespace(email="alice@example.test", expires_at=0.0), "test-invite-link",
    ))
    monkeypatch.setattr(importlib.import_module(module_name), method, slow_operation)
    app = FastAPI()
    method_name = "GET" if name == "users_page" else "POST"
    app.add_api_route("/slow", getattr(admin_pages, name), methods=[method_name])

    @app.get("/probe")
    async def probe():
        return {"io_finished": finished.is_set()}

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
            headers={"Origin": "http://127.0.0.1"},
        ) as client:
            with tenant_scope(tenant="client-a"):
                failsafe = threading.Timer(3, release.set)
                failsafe.start()
                pending = asyncio.create_task(client.request(method_name, "/slow", data=data))
                try:
                    assert await asyncio.to_thread(entered.wait, 10)
                    response = await client.get("/probe")
                    assert response.json() == {"io_finished": False}
                finally:
                    release.set()
                    failsafe.cancel()
                    completed = await pending
                assert completed.status_code == (200 if name in {"users_page", "users_invite"} else 303)

    asyncio.run(exercise())
    assert scopes and set(scopes) == {"client-a"}


@pytest.fixture
def settings_client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    dashboard._world_cache.clear()
    return TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, raise_server_exceptions=False)


@pytest.mark.parametrize("section", ["capabilities"])
def test_toggle_form_publishes_one_complete_selection(monkeypatch, settings_client, section):
    defaults = settings_store.CAPABILITY_DEFAULTS if section == "capabilities" else settings_store.FEATURE_DEFAULTS
    for name in defaults:
        settings_store.set_toggle(section, name, True)
    snapshots = []
    original_write = settings_store._write

    def observe(data):
        original_write(data)
        snapshots.append(settings_store.load_overlay()[section])

    monkeypatch.setattr(settings_store, "_write", observe)
    response = settings_client.post("/settings/" + section, data={}, follow_redirects=False)
    assert response.status_code == 303
    assert snapshots == [dict.fromkeys(defaults, False)], "readers observed a partly saved selection"


@pytest.mark.parametrize("section", ["capabilities"])
def test_toggle_form_file_failure_keeps_state_and_allows_retry(monkeypatch, settings_client, section):
    from maverick import config, file_lock

    name = "browser" if section == "capabilities" else "skills"
    settings_store.set_toggle(section, name, True)
    path = config.dashboard_overrides_path()
    before = path.read_bytes()
    original_write = file_lock.atomic_write_text

    def unavailable(target, *args, **kwargs):
        if target == path:
            raise OSError("test disk unavailable")
        return original_write(target, *args, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_write_text", unavailable)
    response = settings_client.post("/settings/" + section, data={}, follow_redirects=False)
    assert response.status_code == 503
    assert path.read_bytes() == before
    monkeypatch.setattr(file_lock, "atomic_write_text", original_write)
    retry = settings_client.post("/settings/" + section, data={}, follow_redirects=False)
    assert retry.status_code == 303
    assert settings_store.load_overlay()[section][name] is False


@pytest.mark.parametrize("section", ["capabilities"])
def test_toggle_form_preserves_invalid_section_for_recovery(settings_client, section):
    from maverick import config

    path = config.dashboard_overrides_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(section + ' = ["invalid"]\n', encoding="utf-8")
    before = path.read_bytes()
    response = settings_client.post("/settings/" + section, data={}, follow_redirects=False)
    assert response.status_code == 503
    assert path.read_bytes() == before


def test_retired_whole_feature_form_leaves_every_switch_unchanged(settings_client):
    """Feature switches now save one at a time from All settings. The old
    whole-form submission is refused before any write, so a stale form can
    never turn every unlisted switch off."""
    from maverick import config

    for name in settings_store.FEATURE_DEFAULTS:
        settings_store.set_toggle("features", name, True)
    path = config.dashboard_overrides_path()
    before = path.read_bytes()
    response = settings_client.post("/settings/features", data={}, follow_redirects=False)
    assert response.status_code == 409
    assert "Your draft is kept" in response.json()["detail"]
    assert path.read_bytes() == before
    assert settings_store.load_overlay()["features"] == dict.fromkeys(settings_store.FEATURE_DEFAULTS, True)
