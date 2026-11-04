"""In-app setup changes real configuration and workspace-private bindings."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config, connections
from maverick import vendor_onboarding_setup as setup
from maverick.paths import tenant_scope
from maverick_dashboard import rbac
from maverick_dashboard import vendor_setup_api as api


@pytest.fixture
def client(tmp_path, monkeypatch):
    import os
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    rbac.set_role("user:owner", "admin")
    rbac.set_role("user:other", "operator")
    rbac.set_tenant_role("tenant-a", "user:owner", "admin")
    rbac.set_tenant_role("tenant-a", "user:other", "operator")
    application = FastAPI()
    @application.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)
    application.include_router(api.router)
    from maverick_dashboard.vendor_onboarding_api import router as workflow_router
    from maverick_dashboard.vendor_onboarding_composition import (
        attach_vendor_onboarding_composition,
    )
    application.include_router(workflow_router, prefix="/api/v1")
    attach_vendor_onboarding_composition(application)
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as value:
        yield value
    config.reset_config_cache()


def reviewed(row):
    return {"confirm": True, "context": row["context"], "configuration": row["configuration"]}


def activate(client):
    before = client.get("/api/v1/vendor-setup")
    assert before.status_code == 200, before.text
    response = client.post("/api/v1/vendor-setup/enable", json=reviewed(before.json()))
    assert response.status_code == 200, response.text
    return response.json()


def credential(tenant="tenant-a", *, owner="user:owner", name="jira-customer"):
    with tenant_scope(tenant=tenant):
        return connections.set_connection(name, connector="jira", base_url="https://example.atlassian.net", token="synthetic-private-token", owner=owner)


def bind(client, record, *, owner=None):
    status = client.get("/api/v1/vendor-setup").json()
    return client.put("/api/v1/vendor-setup", json={**reviewed(status), "expected_revision": status["revision"], "ticket": record["name"], "ticket_revision": record["revision"], "resource_owner": owner if owner is not None else status["binding"]["resource_owner"] or "user:owner"})


def test_fresh_workspace_has_actionable_setup_and_upload_only_has_no_drive_requirement(client):
    fresh = client.get("/api/v1/vendor-setup")
    assert fresh.status_code == 200, fresh.text
    readiness = fresh.json()["readiness"]
    assert readiness["state"] == "setup_required" and not readiness["configuration_complete"]
    assert {action["id"] for action in readiness["actions"]} == {"enable", "owner", "jira", "save"}
    assert next(action for action in readiness["actions"] if action["id"] == "jira")["href"] == "/connections"
    assert readiness["live_provider_verified"] is False
    activate(client)
    saved = bind(client, credential())
    assert saved.status_code == 200, saved.text
    ready = saved.json()["readiness"]
    assert ready["state"] == "configured" and ready["configuration_complete"]
    assert ready["actions"] == [] and ready["live_provider_verified"] is False


def test_unsupported_profile_shows_recovery_action_without_entering_records(client, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unsupported deployment entered workflow storage or composition")

    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "2")
    monkeypatch.setattr(setup, "current", forbidden)
    monkeypatch.setattr(setup, "owner_policy", forbidden)
    monkeypatch.setattr(connections, "list_connections", forbidden)
    monkeypatch.setattr(client.app.state, "vendor_onboarding_binding_factory", forbidden)
    before = client.get("/api/v1/vendor-setup")
    assert before.status_code == 200, before.text
    state = before.json()
    assert state["readiness"]["state"] == "blocked"
    assert state["readiness"]["actions"][0]["href"] == "#vs-deployment"
    assert not state["readiness"]["configuration_complete"]
    denied = client.post("/api/v1/vendor-setup/enable", json=reviewed(state))
    assert denied.status_code == 409
    assert not config.dashboard_overrides_path().exists()
    denied = client.post("/api/v1/vendor-onboarding/cases", json={"vendor_name": "Blocked vendor", "project": "VEND", "purpose": "Unsupported topology"})
    assert denied.status_code == 409, denied.text
    assert denied.json()["detail"]["next_action"]
    assert denied.json()["detail"]["retryable"] is False


def test_activation_and_upload_only_binding_are_real_and_tenant_private(client):
    state = activate(client)
    assert state["modules_enabled"] and state["connections_enabled"]
    assert state["live_provider_verified"] is False
    actual = config.load_global_config()
    assert all(actual[key]["enable"] for key in setup.REQUIRED_MODULES)
    record = credential()
    saved = bind(client, record)
    assert saved.status_code == 200, saved.text
    assert saved.json()["binding"]["resource_owner"] == "user:owner"
    assert "synthetic-private-token" not in saved.text
    with tenant_scope(tenant="tenant-a"):
        effective = setup.settings(config.load_config())
        assert effective.enable and effective.ticket_connection == record["name"]
        assert effective.document_connection == "unconfigured-drive"
    foreign = client.get("/api/v1/vendor-setup", headers={"X-Test-Tenant": "tenant-b"})
    assert foreign.status_code == 200 and foreign.json()["revision"] == 0
    assert record["name"] not in foreign.text
    created = client.post("/api/v1/vendor-onboarding/cases", json={"vendor_name": "Synthetic upload-only vendor", "project": "VEND", "purpose": "Review synthetic evidence"})
    assert created.status_code == 201, created.text
    assert created.json()["owner"] == "user:owner"
    assert client.get("/api/v1/vendor-onboarding/cases").json()["cases"][0]["id"] == created.json()["id"]


def test_stale_credentials_context_or_role_cannot_bind(client):
    activate(client)
    old = credential()
    new = credential()
    denied = bind(client, old)
    assert denied.status_code == 409
    with tenant_scope(tenant="tenant-a"):
        assert setup.current() is None
    status = client.get("/api/v1/vendor-setup").json()
    payload = {**reviewed(status), "expected_revision": 0, "ticket": new["name"], "ticket_revision": new["revision"], "resource_owner": "user:owner"}
    assert client.put("/api/v1/vendor-setup", json=payload, headers={"X-Test-Tenant": "tenant-b"}).status_code == 409
    assert client.get("/api/v1/vendor-setup", headers={"X-Test-User": "other"}).status_code == 403
    assert client.get("/api/v1/vendor-setup", headers={"X-Test-Tenant": "tenant-b", "X-Lightwork-Setup-Context": status["context"]}).status_code == 409
    assert bind(client, credential(name="foreign-jira", owner="user:foreign")).status_code == 409


def test_non_ascii_setup_context_header_is_refused_as_changed_not_a_server_error(client):
    response = client.get("/api/v1/vendor-setup", headers={"X-Lightwork-Setup-Context": "contéxt".encode()})
    assert response.status_code == 409, response.text


def test_authority_generation_compare_and_swap_and_stable_resource_owner(client):
    activate(client)
    credential_a = credential()
    saved = bind(client, credential_a)
    assert saved.status_code == 200, saved.text
    old = saved.json()
    credential_b = credential(name="jira-second")
    changed = bind(client, credential_b)
    assert changed.status_code == 200
    assert changed.json()["binding"]["resource_owner"] == old["binding"]["resource_owner"]
    stale = client.put("/api/v1/vendor-setup", json={**reviewed(old), "expected_revision": old["revision"], "ticket": credential_a["name"], "ticket_revision": credential_a["revision"], "resource_owner": "user:owner"})
    assert stale.status_code == 409


def test_validation_then_concurrent_corrections_commit_only_one_binding(client):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    activate(client)
    records = [credential(name="jira-first"), credential(name="jira-second")]
    status = client.get("/api/v1/vendor-setup").json()
    base = {**reviewed(status), "expected_revision": 0, "resource_owner": "user:other"}
    malformed = client.put("/api/v1/vendor-setup", json={
        **base, "ticket": "invalid connection name", "ticket_revision": records[0]["revision"],
    })
    assert malformed.status_code == 422
    assert malformed.json()["detail"][0]["loc"] == ["body", "ticket"]
    assert client.get("/api/v1/vendor-setup").json()["revision"] == 0
    ready = Barrier(2)

    def submit(record):
        ready.wait(timeout=10)
        return client.put("/api/v1/vendor-setup", json={
            **base, "ticket": record["name"], "ticket_revision": record["revision"],
        })

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(submit, records))
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = next(response.json() for response in responses if response.status_code == 200)
    current = client.get("/api/v1/vendor-setup").json()
    assert current["revision"] == winner["revision"] == 1
    assert current["binding"] == winner["binding"]
    assert current["binding"]["resource_owner"] == "user:other"


def test_response_failure_after_save_is_recoverable_by_read_only_overview(client, monkeypatch):
    from fastapi import HTTPException

    activate(client)
    record = credential()
    real_overview = api.overview

    def lose_write_response(request, response):
        if request.method == "PUT":
            raise HTTPException(503, "Synthetic response failure after local save")
        return real_overview(request, response)

    monkeypatch.setattr(api, "overview", lose_write_response)
    interrupted = bind(client, record)
    assert interrupted.status_code == 503
    # The GET route and local binding store are real; no second PUT is needed.
    recovered = client.get("/api/v1/vendor-setup")
    assert recovered.status_code == 200
    assert recovered.json()["revision"] == 1
    assert recovered.json()["binding"]["ticket_connection"] == record["name"]
    assert recovered.json()["readiness"]["state"] == "configured"


def test_false_deployment_connection_override_and_unconfirmed_change_are_not_waived(client, monkeypatch):
    monkeypatch.setenv("LIGHTWORK_CONNECTIONS", "0")
    state = client.get("/api/v1/vendor-setup").json()
    assert client.post("/api/v1/vendor-setup/enable", json=reviewed(state), headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.post("/api/v1/vendor-setup/enable", json={**reviewed(state), "confirm": False}).status_code == 422
    assert client.post("/api/v1/vendor-setup/enable", json=reviewed(state)).status_code == 409
    assert not config.dashboard_overrides_path().exists()


def test_initial_owner_is_explicit_and_distinct_from_credential_authority(client):
    activate(client)
    record = credential()
    status = client.get("/api/v1/vendor-setup").json()
    response = client.put("/api/v1/vendor-setup", json={**reviewed(status), "expected_revision": 0,
        "ticket": record["name"], "ticket_revision": record["revision"], "resource_owner": "user:other"})
    assert response.status_code == 200, response.text
    assert response.json()["binding"]["resource_owner"] == "user:other"
    assert response.json()["owner_locked"] is True
    with tenant_scope(tenant="tenant-a"):
        assert connections.get_connection(record["name"])["owner"] == "user:owner"
        assert not connections._may_use(connections.get_connection(record["name"]), "user:other")
    created = client.post("/api/v1/vendor-onboarding/cases", json={"vendor_name": "Selected owner vendor", "project": "VEND", "purpose": "Synthetic selected ownership"})
    assert created.status_code == 201, created.text
    assert created.json()["owner"] == "user:other"
    assert bind(client, record, owner="user:owner").status_code == 409
    changed = bind(client, credential(name="jira-replacement"), owner="user:other")
    assert changed.status_code == 200 and changed.json()["binding"]["resource_owner"] == "user:other"


@pytest.mark.parametrize("invalid", ["foreign", "revoked", "inactive", "viewer", "service"])
def test_initial_owner_must_still_be_an_active_eligible_workspace_member(client, monkeypatch, invalid):
    activate(client)
    record = credential()
    status = client.get("/api/v1/vendor-setup").json()
    assert status["eligible_owners"] == ["user:other", "user:owner"]
    assert status["binding"]["resource_owner"] == "" and status["owner_locked"] is False
    owner = "user:other"
    if invalid == "foreign":
        owner = "user:foreign"
        rbac.set_tenant_role("tenant-b", owner, "operator")
    elif invalid == "revoked":
        rbac.remove_tenant_role("tenant-a", owner)
    elif invalid == "inactive":
        monkeypatch.setattr(api.scim_groups, "active_for_principal", lambda principal: principal != owner)
    elif invalid == "viewer":
        rbac.set_tenant_role("tenant-a", owner, "viewer")
    else:
        owner = "service:robot"
        rbac.set_tenant_role("tenant-a", owner, "operator")
    denied = client.put("/api/v1/vendor-setup", json={**reviewed(status), "expected_revision": 0,
        "ticket": record["name"], "ticket_revision": record["revision"], "resource_owner": owner})
    assert denied.status_code == 409, denied.text
    assert owner not in client.get("/api/v1/vendor-setup").json()["eligible_owners"]
    with tenant_scope(tenant="tenant-a"):
        assert setup.current() is None


def test_initial_owner_is_rechecked_after_credential_validation(client, monkeypatch):
    from maverick import vendor_onboarding_adapters as adapters
    activate(client)
    record = credential()
    resolve = adapters.resolve_connection
    def revoke(*args, **kwargs):
        result = resolve(*args, **kwargs)
        rbac.remove_tenant_role("tenant-a", "user:other")
        return result
    monkeypatch.setattr(adapters, "resolve_connection", revoke)
    denied = bind(client, record, owner="user:other")
    assert denied.status_code == 409 and "access changed" in denied.text
    with tenant_scope(tenant="tenant-a"):
        assert setup.current() is None


def test_initial_setup_has_no_implicit_actor_owner_default(client):
    activate(client)
    record = credential()
    status = client.get("/api/v1/vendor-setup").json()
    missing = client.put("/api/v1/vendor-setup", json={**reviewed(status), "expected_revision": 0,
        "ticket": record["name"], "ticket_revision": record["revision"]})
    assert missing.status_code == 422
    with tenant_scope(tenant="tenant-a"):
        assert setup.current() is None


def test_historical_cases_keep_their_owner_when_configuration_is_missing(client):
    from maverick_dashboard import settings_store
    activate(client)
    record = credential()
    overlay = settings_store._load_overlay_for_update()
    overlay["vendor_onboarding"].update(resource_owner="user:other", ticket_connection=record["name"])
    settings_store._write(overlay)
    config.reset_config_cache()
    configured = client.get("/api/v1/vendor-setup").json()
    assert configured["owner_locked"] and configured["owner_source"] == "configured"
    created = client.post("/api/v1/vendor-onboarding/cases", json={"vendor_name": "Historical owner vendor", "project": "VEND", "purpose": "Preserve actual historical ownership"})
    assert created.status_code == 201, created.text
    overlay["vendor_onboarding"].pop("resource_owner")
    settings_store._write(overlay)
    config.reset_config_cache()
    status = client.get("/api/v1/vendor-setup").json()
    assert status["owner_locked"] and status["owner_source"] == "historical"
    assert status["binding"]["resource_owner"] == "user:other"
    assert bind(client, record, owner="user:owner").status_code == 409
    saved = bind(client, record, owner="user:other")
    assert saved.status_code == 200 and saved.json()["binding"]["resource_owner"] == "user:other"
    assert client.get("/api/v1/vendor-onboarding/cases").json()["cases"][0]["id"] == created.json()["id"]


def test_vendor_onboarding_turns_off_keeps_setup_and_is_audited(client, monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    activate(client)
    record = credential()
    assert bind(client, record).status_code == 200
    state = client.get("/api/v1/vendor-setup").json()
    assert state["modules_enabled"] is True
    assert client.post("/api/v1/vendor-setup/disable", json={**reviewed(state), "confirm": False}).status_code == 422
    assert client.post("/api/v1/vendor-setup/disable", json=reviewed(state), headers={"Origin": "https://attacker.example"}).status_code == 403
    response = client.post("/api/v1/vendor-setup/disable", json=reviewed(state))
    assert response.status_code == 200, response.text
    after = response.json()
    assert after["modules_enabled"] is False and after["connections_enabled"] is True
    assert after["binding"]["ticket_connection"] == record["name"] and after["revision"] == state["revision"]
    assert (config.load_config().get("vendor_management") or {}).get("enable") is True
    assert [(row["section"], row["key"], row["old"], row["new"]) for row in rows] == [("vendor_onboarding", "enable", True, False)]
    with tenant_scope(tenant="tenant-a"):
        assert setup.current()["binding"]["ticket_connection"] == record["name"]
    again = client.post("/api/v1/vendor-setup/enable", json=reviewed(after))
    assert again.status_code == 200 and again.json()["binding"]["ticket_connection"] == record["name"]
