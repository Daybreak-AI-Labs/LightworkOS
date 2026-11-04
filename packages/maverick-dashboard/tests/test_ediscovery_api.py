from __future__ import annotations

import io
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick import audit, ediscovery
from maverick import paths as paths_module
from maverick.world_model import WorldModel
from maverick_dashboard import (
    compliance_controls_api,
    personal_data_requests,
    rbac,
    system_checks_api,
)
from maverick_dashboard import ediscovery_api as api

ALICE = "user:cli:alice"
BASE = "/api/v1/ediscovery/matters"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import crypto_at_rest
    from maverick.paths import tenant_scope

    state = {"enabled": True, "tenant": "ws-a", "role": "auditor"}
    ledger = tmp_path / "ledger.sqlite3"
    world = WorldModel(tmp_path / "world.db")
    # The companion and inbox stores live under a private home and the active workspace.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "27" * 32)
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "unused.key")

    recorded: list[tuple[str, dict]] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: recorded.append((payload.get("verb", kind), payload)) or True)
    monkeypatch.setattr(ediscovery, "enabled", lambda: state["enabled"])
    monkeypatch.setattr(ediscovery, "store_path", lambda tenant=None: ledger)
    monkeypatch.setattr(paths_module, "current_tenant_id", lambda: state["tenant"])
    monkeypatch.setattr(paths_module, "current_tenant_id_strict", lambda: state["tenant"])

    def permitted(request: Request, permission: str) -> None:
        if permission not in rbac.permissions_for(str(request.headers.get("X-Role", "viewer"))):
            raise HTTPException(status_code=403, detail="denied")

    def has(request: Request, permission: str) -> bool:
        try:
            permitted(request, permission)
        except HTTPException:
            return False
        return True

    monkeypatch.setattr(api, "require_global_permission", permitted)
    monkeypatch.setattr(api, "has_global_permission", has)
    monkeypatch.setattr("maverick_dashboard._shared._world", lambda: world)

    app = FastAPI()
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Role": "auditor"})
    with tenant_scope(tenant="ws-a"):
        yield SimpleNamespace(client=client, state=state, world=world, recorded=recorded, ledger=ledger)
    world.close()


def _seed(world: WorldModel) -> dict:
    alice_goal = world.create_goal("Alice task", owner=ALICE)
    conv = world.get_or_create_conversation("cli", "alice").id
    world.append_turn(conv, "user", "alice remark", goal_id=alice_goal)
    bob_conv = world.get_or_create_conversation("cli", "bob").id
    world.append_turn(bob_conv, "user", "bob remark")
    return {"conv": conv, "bob_conv": bob_conv, "goal": alice_goal}


def _body(**overrides) -> dict:
    body = {"name": "Acme dispute", "description": "", "custodians": [ALICE],
            "record_kinds": ["goals", "chats", "attachments", "approvals"]}
    body.update(overrides)
    return body


def test_every_route_is_absent_while_the_feature_is_off(env):
    env.state["enabled"] = False
    for role in ("auditor", "admin", "viewer"):
        headers = {"X-Role": role}
        assert env.client.get(BASE, headers=headers).status_code == 404
        assert env.client.post(BASE, json=_body(), headers=headers).status_code == 404
    assert env.client.get(f"{BASE}/mtr-0000000000000000/export").status_code == 404


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_matter_details_are_refused_without_the_audit_permission(env, role):
    headers = {"X-Role": role}
    assert env.client.get(BASE, headers=headers).status_code == 403
    assert env.client.post(BASE, json=_body(), headers=headers).status_code == 403
    assert ediscovery.MatterStore(env.ledger).list("ws-a") == []


@pytest.mark.parametrize("role", ["auditor", "admin"])
def test_auditors_and_admins_manage_matters_and_export_them(env, role):
    headers = {"X-Role": role}
    created = env.client.post(BASE, json=_body(), headers=headers)
    assert created.status_code == 201, created.text
    matter = created.json()
    assert matter["revision"] == 1 and matter["status"] == "active"
    assert "tenant_id" not in matter and "schema" not in matter

    edited = env.client.patch(f"{BASE}/{matter['id']}", headers=headers,
                              json={"expected_revision": 1, "date_from": "2001-01-01", "date_to": "2001-12-31"})
    assert edited.status_code == 200, edited.text
    assert edited.json()["revision"] == 2 and edited.json()["custodians"] == [ALICE]
    stale = env.client.patch(f"{BASE}/{matter['id']}", headers=headers,
                             json={"expected_revision": 1, "name": "Old"})
    assert stale.status_code == 409

    cleared = env.client.patch(f"{BASE}/{matter['id']}", headers=headers,
                               json={"expected_revision": 2, "date_to": None})
    assert cleared.json()["date_to"] is None and cleared.json()["date_from"] == "2001-01-01"

    exported = env.client.get(f"{BASE}/{matter['id']}/export", headers=headers)
    assert exported.status_code == 200, exported.text
    assert exported.headers["content-type"] == "application/zip"
    assert exported.headers["cache-control"] == "no-store"
    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        assert "manifest.json" in archive.namelist()
    assert list((env.ledger.parent / "exports").glob("*.zip")) == []

    released = env.client.post(f"{BASE}/{matter['id']}/release", headers=headers, json={"expected_revision": 3})
    assert released.status_code == 200 and released.json()["status"] == "released"
    after = env.client.patch(f"{BASE}/{matter['id']}", headers=headers,
                             json={"expected_revision": 4, "name": "Later"})
    assert after.status_code == 409
    assert [verb for verb, _ in env.recorded] == [
        "ediscovery_matter_created", "ediscovery_matter_edited", "ediscovery_matter_edited",
        "ediscovery_matter_exported", "ediscovery_matter_released"]


def test_invalid_input_and_unknown_fields_are_refused(env):
    assert env.client.post(BASE, json=_body(extra="x")).status_code == 422
    assert env.client.post(BASE, json=_body(record_kinds=["email"])).status_code == 422
    assert env.client.post(BASE, json=_body(custodians=[])).status_code == 422
    assert env.client.post(BASE, json=_body(date_from="2026-13-01")).status_code == 422
    assert env.client.get(f"{BASE}/not-a-matter").status_code == 404


def test_matters_are_invisible_to_another_workspace(env):
    created = env.client.post(BASE, json=_body()).json()
    env.state["tenant"] = "ws-b"
    assert env.client.get(BASE).json()["matters"] == []
    assert env.client.get(f"{BASE}/{created['id']}").status_code == 404
    assert env.client.post(f"{BASE}/{created['id']}/release", json={"expected_revision": 1}).status_code == 404


def test_page_section_is_offered_only_to_audit_access(env):
    from maverick_dashboard.ediscovery_api import page_context

    auditor = page_context(SimpleNamespace(headers={"X-Role": "auditor"}))
    operator = page_context(SimpleNamespace(headers={"X-Role": "operator"}))
    assert auditor == {"ediscovery_enabled": True, "ediscovery_can_audit": True}
    assert operator == {"ediscovery_enabled": True, "ediscovery_can_audit": False}
    env.state["enabled"] = False
    assert page_context(SimpleNamespace(headers={"X-Role": "auditor"}))["ediscovery_can_audit"] is False


def test_self_service_deletion_reports_a_held_closure_and_keeps_it(env, monkeypatch):
    seeded = _seed(env.world)
    created = env.client.post(BASE, json=_body()).json()
    assert created["status"] == "active"
    scope = {"conversation_ids": [seeded["conv"]], "goal_ids": [seeded["goal"]], "episode_ids": []}
    outcome = personal_data_requests._erase_conversations(env.world, {}, {"scope": scope})
    assert outcome["state"] == "held"
    assert outcome["message"] == ediscovery.LEGAL_HOLD_MESSAGE
    assert "Alice" not in outcome["message"] and "Acme" not in outcome["message"]
    assert env.world.conn.execute("SELECT COUNT(*) FROM turns WHERE conversation_id=?",
                                  (seeded["conv"],)).fetchone()[0] == 1


def test_admin_erase_of_a_person_is_refused_with_the_plain_message(env, monkeypatch):
    seeded = _seed(env.world)
    env.client.post(BASE, json=_body())
    monkeypatch.setattr(compliance_controls_api, "_world_for_request", lambda: env.world)
    result = compliance_controls_api._run_erase("cli", "alice", "admin-user")
    assert result["erased"] is False
    assert result["message"] == ediscovery.LEGAL_HOLD_MESSAGE
    assert env.world.conn.execute("SELECT COUNT(*) FROM turns WHERE conversation_id=?",
                                  (seeded["conv"],)).fetchone()[0] == 1


def test_tidy_up_of_old_records_is_paused_by_an_active_matter(env):
    env.client.post(BASE, json=_body())
    with pytest.raises(HTTPException) as refused:
        system_checks_api._cleanup_run(30, 30)
    assert refused.value.status_code == 409
    assert ediscovery.LEGAL_HOLD_MESSAGE not in str(refused.value.detail)
    env.state["tenant"] = "ws-b"
    ediscovery.assert_no_active_matters()  # another workspace's matter does not hold this one


def test_compliance_page_shows_legal_holds_only_when_enabled_and_nonced(monkeypatch):
    import re

    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app

    monkeypatch.setattr(ediscovery, "enabled", lambda: True)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    page = client.get("/compliance")
    assert page.status_code == 200
    assert 'id="edh-title"' in page.text
    nonce = re.search(r'<script nonce="([^"]+)"[^>]*>\s*\(function \(\) \{\s*"use strict";\s*var API = "/api/v1/ediscovery', page.text)
    assert nonce is not None
    assert not re.search(r"<[^>]+\son[a-z]+=", page.text.split('id="edh-title"', 1)[1].split("</section>", 1)[0])

    monkeypatch.setattr(ediscovery, "enabled", lambda: False)
    assert 'id="edh-title"' not in client.get("/compliance").text


def test_switch_is_a_privacy_setting_off_by_default_that_the_settings_page_turns_on(tmp_path, monkeypatch):
    from maverick import config
    from maverick_dashboard import settings_catalog as catalog
    from maverick_dashboard.app import app

    from test_support.settings_pages import save_catalog

    row = catalog.BY_ID["ediscovery.enable"]
    assert row.default is False and row.group == "Privacy" and row.reader == "maverick.ediscovery"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    config.reset_config_cache()
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert ediscovery.enabled() is False
    assert client.get(BASE).status_code == 404
    saved = save_catalog(client, "/api/v1/settings/catalog",
                         json={"changes": [{"id": "ediscovery.enable", "value": True}]})
    assert saved.status_code == 200, saved.text
    config.reset_config_cache()
    assert ediscovery.enabled() is True
    assert client.get(BASE).status_code != 404


def test_retention_review_shows_a_workspace_blocked_while_a_matter_is_active(env, monkeypatch):
    from maverick.tenant import registry
    from maverick_dashboard import retention_maintenance
    from maverick_dashboard import retention_runs as native

    monkeypatch.setattr(registry, "get_tenant", lambda tid: SimpleNamespace(id=tid, display_name="Acme"))
    monkeypatch.setattr(native, "_policy", dict)
    monkeypatch.setattr(retention_maintenance, "authorize", lambda request, expected_context=None: ("admin", {}))
    monkeypatch.setattr(retention_maintenance, "context_for", lambda request: {})
    request = SimpleNamespace(headers={})
    assert retention_maintenance.policy(request)["workspaces"][0]["blocked"] is False
    created = env.client.post(BASE, json=_body())
    assert created.status_code == 201
    assert retention_maintenance.policy(request)["workspaces"][0]["blocked"] is True
    env.client.post(f"{BASE}/{created.json()['id']}/release", json={"expected_revision": 1})
    assert retention_maintenance.policy(request)["workspaces"][0]["blocked"] is False


def _companion_with_one_exchange(owner: str):
    from maverick.employee_companion import EmployeeCompanionStore

    store = EmployeeCompanionStore()
    policy = store.policy(owner)
    store.update_policy(owner, actor="user:admin", expected_revision=policy["revision"], enabled=True,
                        allowed_sources=["own_tasks"], allowed_tools=["task_status"], retention_days=1)
    store.record_exchange(owner, message="companion private question", response="You have one active task.",
                          source_refs=["task:17"], expected_revision=store.policy(owner)["revision"])
    return store


def test_companion_clear_is_held_on_the_review_path_the_employee_route_and_self_service(env, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import employee_companion_api, product_operations_companion

    owner = "user:owner"
    store = _companion_with_one_exchange(owner)
    assert env.client.post(BASE, json=_body(custodians=[owner], record_kinds=["chats"])).status_code == 201
    row = {"owner": owner, "reviewer": "admin", "channel": "dashboard", "user_id": "owner"}

    outcome = personal_data_requests._erase_target(env.world, row, {"store": "companion_history"})
    assert outcome == {"state": "held", "message": ediscovery.LEGAL_HOLD_MESSAGE,
                       "retained": "No companion message was erased."}

    monkeypatch.setattr(employee_companion_api, "_authority", lambda request, **kwargs: (owner, "ws-a", {}))
    def clear(actor, tenant, context, companions):
        return companions.clear_history(actor, actor=actor)

    with pytest.raises(HTTPException) as route:
        employee_companion_api._call_sync(SimpleNamespace(), clear, write=True)
    assert route.value.status_code == 409 and route.value.detail == ediscovery.LEGAL_HOLD_MESSAGE

    monkeypatch.setattr(product_operations_companion, "_current", lambda request: (owner, None))
    prepared = {"revision": store.history_review(owner)["revision"]}
    with pytest.raises(HTTPException) as self_service:
        product_operations_companion.execute(SimpleNamespace(), None, {}, prepared, "a" * 32)
    assert self_service.value.status_code == 409 and self_service.value.detail == ediscovery.LEGAL_HOLD_MESSAGE
    assert [item["message"] for item in store.held_exchanges(owner)] == ["companion private question"]


def test_inbox_erasure_request_is_held_before_any_message_is_erased(env, monkeypatch, tmp_path):
    from maverick import audit as audit_module
    from maverick import config
    from maverick import conversation_inbox as inbox_module

    owner = "user:owner"
    (tmp_path / "config.toml").write_text('[conversation_inbox]\nenabled=true\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    config.reset_config_cache()
    monkeypatch.setattr(audit_module, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(inbox_module, "current_authority", lambda goal: (owner, None))
    goal = env.world.create_goal("Original task", "Original private brief", owner=owner)
    env.world.set_goal_status(goal, "active")
    inbox = inbox_module.ConversationInbox(env.world, principal=owner, authorize=lambda goal: None)
    inbox.submit(goal, operation_id="b" * 32, mode="queue", text="Exact next request")
    record_id = inbox._read(env.world.get_goal(goal))[0]["id"]
    revision = inbox_module.STORE.get(record_id)["revision"]
    assert env.client.post(BASE, json=_body(custodians=[owner], record_kinds=["chats"])).status_code == 201

    row = {"owner": owner, "reviewer": "admin", "channel": "dashboard", "user_id": "owner", "id": "dsar-1"}
    outcome = personal_data_requests._erase_target(env.world, row, {
        "store": "conversation_inbox", "records": [{"id": record_id, "revision": revision}]})
    assert outcome["state"] == "held" and outcome["message"] == ediscovery.LEGAL_HOLD_MESSAGE
    assert [item["text"] for item in inbox_module.owned_items(owner)] == ["Exact next request"]
    assert inbox_module.STORE.get(record_id)["revision"] == revision
    config.reset_config_cache()


def test_an_archive_is_removed_even_when_its_download_is_cut_off(tmp_path):
    import asyncio

    archive = tmp_path / "legal-matter.zip"
    archive.write_bytes(b"personal data" * 100)
    response = api._ArchiveResponse(archive, media_type="application/zip")
    sent: list[str] = []
    # A server's receive() hands over the request once and then waits for the
    # client to say more or go away. Starlette 1.8 watches it for the
    # disconnect while the file streams, so a receive() that answers at once
    # forever would spin; the fake behaves like the real channel instead.
    disconnected = asyncio.Event()
    pending = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        if pending:
            return pending.pop()
        await disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message["type"])
        if message["type"] == "http.response.body":
            disconnected.set()
            raise ConnectionResetError("the reviewer's connection dropped")

    scope = {"type": "http", "method": "GET", "headers": []}
    with pytest.raises(ConnectionResetError):
        asyncio.run(response(scope, receive, send))
    assert sent == ["http.response.start", "http.response.body"]
    assert not archive.exists()


def test_archives_left_by_an_export_that_never_finished_are_swept(env):
    import os
    import time

    created = env.client.post(BASE, json=_body()).json()
    exports = env.ledger.parent / "exports"
    exports.mkdir(exist_ok=True)
    stale = exports / "mtr-0000000000000000-deadbeef.zip"
    stale.write_bytes(b"left behind")
    old = time.time() - 7200
    os.utime(stale, (old, old))
    assert env.client.get(f"{BASE}/{created['id']}/export").status_code == 200
    assert not stale.exists()


def test_the_matter_list_is_capped_and_says_so(env, monkeypatch):
    monkeypatch.setattr(api, "MAX_LISTED", 2)
    for name in ("First", "Second", "Third"):
        assert env.client.post(BASE, json=_body(name=name)).status_code == 201
    body = env.client.get(BASE).json()
    assert len(body["matters"]) == 2 and body["truncated"] is True
    assert env.client.get(BASE).status_code == 200


def test_reading_matter_details_is_audited_without_custodians_and_fails_closed(env, monkeypatch):
    created = env.client.post(BASE, json=_body()).json()
    env.client.get(BASE)
    env.client.get(f"{BASE}/{created['id']}")
    views = [payload for verb, payload in env.recorded if verb in {"ediscovery_matters_listed",
                                                                   "ediscovery_matter_viewed"}]
    assert [verb for verb, _ in env.recorded][-2:] == ["ediscovery_matters_listed", "ediscovery_matter_viewed"]
    assert views[-1]["matter_id"] == created["id"] and views[-1]["actor"] == "local"
    assert ALICE not in str(views) and "Acme dispute" not in str(views)

    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: False)
    refused = env.client.get(BASE)
    assert refused.status_code == 503 and "were not shown" in refused.json()["detail"]
    assert "Acme dispute" not in refused.text


@pytest.mark.parametrize("role, allowed", [("admin", True), ("auditor", True),
                                           ("operator", False), ("viewer", False)])
def test_the_real_permission_gate_admits_only_admins_and_auditors(tmp_path, monkeypatch, role, allowed):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from maverick import config
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:reviewer")
    rbac.set_role("user:reviewer", role)
    monkeypatch.setattr(ediscovery, "enabled", lambda: True)
    monkeypatch.setattr(ediscovery, "store_path", lambda tenant=None: tmp_path / "ledger.sqlite3")
    monkeypatch.setattr(paths_module, "current_tenant_id_strict", lambda: "ws-a")
    app = FastAPI()
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get(BASE)
    assert (response.status_code == 200) is allowed, (role, response.status_code)
    if not allowed:
        assert response.status_code == 403
    config.reset_config_cache()


def test_tidy_up_is_paused_by_a_recorded_privacy_rights_hold(env, monkeypatch):
    from maverick.audit import preservation

    monkeypatch.setattr(preservation, "preservation_snapshot", lambda: {"blocked": True})
    with pytest.raises(HTTPException) as refused:
        system_checks_api._cleanup_run(30, 30)
    assert refused.value.status_code == 409
    assert refused.value.detail == "Recorded preservation holds block broad deletion in this workspace."


def test_tidy_up_runs_unchanged_when_no_hold_is_recorded(env):
    # No privacy-rights ledger exists in this temporary home, so nothing is held.
    assert system_checks_api._cleanup_run(30, 30) == {"conversations": 0, "activity": 0, "duplicate_checks": 0}


def test_a_linked_messaging_account_is_accepted_only_in_its_exact_form(env):
    account = "account:" + "a" * 64 + ":person:" + "b" * 64
    created = env.client.post(BASE, json=_body(custodians=[account]))
    assert created.status_code == 201, created.text
    assert created.json()["custodians"] == [account]
    assert env.client.post(BASE, json=_body(custodians=["user:slack:" + account])).status_code == 422
    assert env.client.post(BASE, json=_body(custodians=["account:" + "a" * 63 + ":person:" + "b" * 64])).status_code == 422


def test_legal_holds_form_says_how_to_find_a_linked_account(monkeypatch):
    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app

    monkeypatch.setattr(ediscovery, "enabled", lambda: True)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    page = client.get("/compliance")
    assert page.status_code == 200
    assert 'id="edh-custodian-help"' in page.text
    assert "account:" in page.text and ":person:" in page.text
    assert "A person&rsquo;s data" in page.text  # where an administrator finds the account


def _old_chat(world: WorldModel) -> None:
    import time as _time

    world.get_or_create_conversation("web", "old-chat")
    with world._writing() as conn:  # noqa: SLF001 -- backdate the one conversation the preview counts
        conn.execute("UPDATE conversations SET last_seen = ?", (_time.time() - 200 * 86400,))


def test_tidy_up_preview_reports_a_held_workspace_as_held_with_no_counts(env, monkeypatch):
    from maverick.audit import preservation

    _old_chat(env.world)
    assert system_checks_api._cleanup_preview(90, 30) == {
        "conversations": 1, "activity": 0, "days": 90, "activity_days": 30}
    monkeypatch.setattr(preservation, "preservation_snapshot", lambda: {"blocked": True})
    # The preview must not promise removals the run will refuse; the run keeps refusing too.
    assert system_checks_api._cleanup_preview(90, 30) == {
        "conversations": 0, "activity": 0, "days": 90, "activity_days": 30, "held": True}
    with pytest.raises(HTTPException) as refused:
        system_checks_api._cleanup_run(90, 30)
    assert refused.value.status_code == 409


def test_tidy_up_asks_for_a_workspace_before_it_reports_a_hold(env, monkeypatch):
    from maverick import world_model_backends
    from maverick.audit import preservation

    # An unbound shared database: the hold ledger cannot be read against a workspace, so it fails
    # closed with its own message.  The workspace choice must be reported first, as before.
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(paths_module, "current_tenant_id", lambda: None)

    def unbound_ledger():
        raise RuntimeError("Preservation ledger workspace binding is invalid")

    monkeypatch.setattr(preservation, "preservation_snapshot", unbound_ledger)
    for run in (lambda: system_checks_api._cleanup_preview(90, 30), lambda: system_checks_api._cleanup_run(90, 30)):
        with pytest.raises(HTTPException) as refused:
            run()
        assert refused.value.status_code == 409
        assert refused.value.detail == "Choose a workspace first. Nothing was changed."
