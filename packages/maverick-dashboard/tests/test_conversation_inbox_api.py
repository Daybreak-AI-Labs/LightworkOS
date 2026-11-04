"""Local HTTP and native admission without model or network calls."""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import audit, config
from maverick import conversation_inbox as core
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.world_model import WorldModel
from maverick_dashboard import app as dashboard
from maverick_dashboard import conversation_inbox_api as api
from maverick_dashboard import conversation_inbox_scheduler as worker
from maverick_dashboard import rbac


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text('[conversation_inbox]\nenabled=true\n[dashboard]\ndefault_role="viewer"\n', encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *args, **kwargs: True)
    worlds = {tenant: WorldModel(tmp_path / (tenant + ".db")) for tenant in ("tenant-a", "tenant-b")}
    world = worlds["tenant-a"]
    goal = world.create_goal("Active original", "Original private brief", owner="user:owner")
    world.set_goal_status(goal, "active")
    for principal in ("user:owner", "user:other"):
        rbac.set_tenant_role("tenant-a", principal, "operator", actor="user:owner")
    monkeypatch.setattr(dashboard, "_world", lambda: worlds[current_tenant_id_strict()])
    monkeypatch.setattr(core, "current_authority", lambda goal: ("owner", None))
    monkeypatch.setattr(worker, "current_authority", lambda goal: ("owner", None))
    worker._scheduler_stop.clear()
    application = FastAPI()
    @application.middleware("http")
    async def identity(request: Request, call_next):
        subject = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + subject, sub=subject)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)
    application.include_router(api.router)
    @application.post("/test-inbox-adapter")
    async def adapter(request: Request):
        from maverick_dashboard.product_operations_conversation import entries
        body = await request.json()
        entry = next(row for row in entries() if row.id == body["entry"])
        args = entry.input_model.model_validate(body["args"]).model_dump()
        selection = {"kind": "goal", "id": goal}
        preview = entry.prepare(request, selection, args)
        result = entry.execute(request, selection, args, preview.native, body["operation_id"])
        replay = entry.recover(request, selection, args, preview.native, body["operation_id"])
        return {"status": result.status, "recovery": replay.status, "details": result.details}
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield client, world, goal
    for world in worlds.values():
        world.close()
    config.reset_config_cache()


def post(client, goal, **changes):
    current = client.get(f"/api/v1/conversation-inbox/{goal}")
    assert current.status_code == 200, current.text
    body = {"context": current.json()["context"], "operation_id": uuid.uuid4().hex,
            "mode": "queue", "text": "Exact queued message", "expected_generation": current.json()["generation"]}
    body.update(changes)
    return client.post(f"/api/v1/conversation-inbox/{goal}", data=body)


def record(world, goal):
    inbox = core.ConversationInbox(world, principal="user:owner", authorize=lambda goal: None)
    return inbox._read(world.get_goal(goal))[0]["id"]


def test_native_context_owner_and_immutable_receipt(setup):
    client, world, goal = setup
    token = uuid.uuid4().hex
    sent = post(client, goal, operation_id=token)
    assert sent.status_code == 200, sent.text
    item = sent.json()["item"]
    edited = post(client, goal, item_id=item["id"], expected_revision=item["revision"], text="Revised message")
    assert edited.status_code == 200, edited.text
    receipt = client.get(f"/api/v1/conversation-inbox/{goal}/receipts/{token}")
    assert receipt.json()["item"]["text"] == "Exact queued message"
    assert receipt.json()["items"][0]["text"] == "Revised message"
    stale = post(client, goal, context="old-workspace")
    assert stale.status_code == 409 and stale.json()["detail"]["code"] == "context_changed"
    assert client.get(f"/api/v1/conversation-inbox/{goal}", headers={"X-Test-User": "other"}).status_code == 403
    assert len(world.list_goals()) == 1


def test_file_upload_edits_keep_exact_owned_files_and_stale_edits_refuse(setup):
    client, _, goal = setup
    state = client.get(f"/api/v1/conversation-inbox/{goal}").json()
    response = client.post(f"/api/v1/conversation-inbox/{goal}", data={"context": state["context"], "operation_id": uuid.uuid4().hex,
        "mode": "queue", "text": "Use this file"}, files=[("files", ("evidence.txt", b"Selected evidence", "text/plain"))])
    assert response.status_code == 200, response.text
    item = response.json()["item"]
    assert item["files"][0]["filename"] == "evidence.txt"
    response = post(client, goal, item_id=item["id"], expected_revision=9)
    assert response.status_code == 409
    response = post(client, goal, item_id=item["id"], expected_revision=1, keep_files='["not-an-owned-file"]')
    assert response.status_code == 400


def test_independent_runs_while_original_active_and_repeat_never_dispatches_twice(setup, monkeypatch):
    from maverick import runner, world_model
    client, world, goal = setup
    response = post(client, goal, mode="independent", independent_context="none")
    assert response.status_code == 200, response.text
    dispatched = []
    monkeypatch.setattr(world_model, "open_world", lambda: world)
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: None)
    def run(new_goal, **kwargs):
        dispatched.append(new_goal)
        assert world.get_goal(goal).status == "active"
        world.set_goal_status(new_goal, "done", result="Independent result")
    monkeypatch.setattr(runner, "run_goal_in_background", run)
    with tenant_scope(tenant="tenant-a"):
        worker.execute_record(record(world, goal))
        worker.execute_record(record(world, goal))
    assert len(dispatched) == 1 and world.get_goal(dispatched[0]).parent_id is None
    assert world.get_goal(goal).status == "active"
    current = client.get(f"/api/v1/conversation-inbox/{goal}").json()["items"][0]
    assert current["state"] == "submitted" and current["goal_id"] == dispatched[0]


def test_queue_preserves_thread_idle_fence_and_starts_once_after_original_finishes(setup, monkeypatch):
    from maverick import runner, world_model
    client, world, goal = setup
    response = post(client, goal)
    assert response.status_code == 200
    calls = []
    monkeypatch.setattr(world_model, "open_world", lambda: world)
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: None)
    monkeypatch.setattr(runner, "run_goal_in_background", lambda gid, **kwargs: calls.append(gid))
    with tenant_scope(tenant="tenant-a"):
        key = record(world, goal)
        worker.execute_record(key)
        assert not calls and len(world.list_goals()) == 1
        world.set_goal_status(goal, "done", result="Original result")
        worker.execute_record(key)
        worker.execute_record(key)
    assert len(calls) == 1 and world.get_goal(calls[0]).parent_id == goal


def test_old_tab_cannot_resurrect_erased_message_and_replay_remains_tombstoned(setup):
    client, world, goal = setup
    token = uuid.uuid4().hex
    assert post(client, goal, operation_id=token).status_code == 200
    with tenant_scope(tenant="tenant-a"):
        inventory = core.owned_inventory("user:owner")
        assert len(inventory) == 1
        target = inventory[0]
        exported = core.export_owned("user:owner", target["id"], target["revision"])
        assert exported["items"][0]["text"] == "Exact queued message"
        core.erase_owned("user:owner", target["id"], target["revision"], uuid.uuid4().hex, actor="user:privacy-reviewer")
    result = post(client, goal, expected_generation=0)
    assert result.status_code == 409
    replay = post(client, goal, expected_generation=0, operation_id=token)
    assert replay.status_code == 200 and replay.json()["item"]["state"] == "erased"
    assert replay.json()["item"]["text"] == "" and len(world.list_goals()) == 1


def test_interrupted_file_admission_retains_one_draft_and_explicit_retry_recovers(setup, monkeypatch):
    from maverick import runner, world_model
    client, world, goal = setup
    assert post(client, goal, mode="independent").status_code == 200
    monkeypatch.setattr(world_model, "open_world", lambda: world)
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: None)
    publish = worker.publish_files
    def fail(*args):
        raise OSError("controlled local interruption")
    monkeypatch.setattr(worker, "publish_files", fail)
    calls = []
    monkeypatch.setattr(runner, "run_goal_in_background", lambda gid, **kwargs: calls.append(gid))
    with tenant_scope(tenant="tenant-a"):
        key = record(world, goal)
        worker.execute_record(key)
    state = client.get(f"/api/v1/conversation-inbox/{goal}").json()
    item = state["items"][0]
    assert item["state"] == "blocked" and item["goal_id"] and not calls
    draft = item["goal_id"]
    result = client.patch(f"/api/v1/conversation-inbox/{goal}/{item['id']}", json={"context": state["context"],
        "operation_id": uuid.uuid4().hex, "expected_revision": item["revision"], "action": "retry_dispatch"})
    assert result.status_code == 200, result.text
    monkeypatch.setattr(worker, "publish_files", publish)
    with tenant_scope(tenant="tenant-a"):
        worker.execute_record(key)
        worker.execute_record(key)
    assert calls == [draft] and len(world.list_goals()) == 2


def test_uncertain_dispatch_is_never_reinvoked_after_restart(setup, monkeypatch):
    from maverick import runner, world_model
    from maverick.attachment_submissions import SubmissionStore
    from maverick.governed_operations import digest
    client, world, goal = setup
    item = post(client, goal, mode="independent").json()["item"]
    monkeypatch.setattr(world_model, "open_world", lambda: world)
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: None)
    calls = []
    monkeypatch.setattr(runner, "run_goal_in_background", lambda gid, **kwargs: calls.append(gid))
    with tenant_scope(tenant="tenant-a"):
        inbox = core.ConversationInbox(world, principal="user:owner", authorize=lambda goal: None)
        inbox.transition(goal, item["id"], revision=item["revision"], state="dispatching", message="claim")
        store = SubmissionStore(world)
        receipt = store.create(token="conversation-inbox:" + item["id"], fingerprint=digest([item["text"], None, [], "independent"]),
            owner="user:owner", title=item["text"], description=item["text"], manifest=[], chat_text=item["text"])
        store.update(receipt["key"], state="ready", message="prepared")
        assert store.claim_dispatch(receipt["key"])
        worker.execute_record(record(world, goal))
    assert calls == []
    state = client.get(f"/api/v1/conversation-inbox/{goal}").json()["items"][0]
    assert state["state"] == "submitted" and state["goal_id"] == receipt["goal_id"]


def test_new_capability_has_typed_policy_catalog_and_installer_opt_out(monkeypatch):
    # On by default (the owner's choice on 4 October): people can add
    # guidance while a task runs. The installer offers an explicit "off",
    # which is written and stays off.
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    from maverick_dashboard import settings_catalog
    from maverick_installer import wizard
    fields = [row for row in settings_catalog.SETTINGS if row.section == "conversation_inbox"]
    assert {row.key for row in fields} == {"enabled", "guidance", "queue", "independent", "max_pending"}
    assert all(row.group in settings_catalog.GROUPS for row in fields)
    assert settings_catalog.BY_ID["conversation_inbox.enabled"].default is True
    document = tomllib.loads("\n".join(wizard._cfg_advanced({"allow_conversation_inbox": True}, [])))
    assert document["conversation_inbox"] == {"enabled": True, "guidance": True, "queue": True, "independent": True, "max_pending": 20}
    assert "conversation_inbox" not in tomllib.loads("\n".join(wizard._cfg_advanced({}, [])))
    declined = tomllib.loads("\n".join(wizard._cfg_advanced({"allow_conversation_inbox": False}, [])))
    assert declined["conversation_inbox"] == {"enabled": False}
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_, default=False, **__: default)
    monkeypatch.setattr(wizard, "_q_select", lambda *_, default=None, **__: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *_, default="", **__: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *_, **__: [])
    assert wizard.pick_advanced()["allow_conversation_inbox"] is True


def test_typed_copilot_uses_native_scope_receipts_and_explicit_guidance_decision(setup):
    client, world, goal = setup
    def act(entry, args):
        response = client.post("/test-inbox-adapter", json={"entry": entry, "args": args, "operation_id": uuid.uuid4().hex})
        assert response.status_code == 200, response.text
        assert response.json()["recovery"] == "replayed"
        return response.json()["details"]["item"]
    item = act("conversation.send", {"mode": "guidance", "text": "Explicit guidance"})
    assert item["state"] == "needs_decision"
    item = act("conversation.edit", {"item": item["id"], "text": "Edited explicit guidance"})
    item = act("conversation.decide", {"item": item["id"], "action": "approve_guidance", "decision": "append"})
    assert item["state"] == "guidance_ready" and len(world.list_goals()) == 1
    assert client.get(f"/api/v1/conversation-inbox/{goal}").json()["items"][0]["text"] == "Edited explicit guidance"


def test_reviewed_snapshot_is_exact_and_pending_edit_retains_original_context(setup):
    client, world, goal = setup
    state = client.get(f"/api/v1/conversation-inbox/{goal}").json()
    old = state["target"]["snapshot_version"]
    world.set_goal_status(goal, "active", result="A newer partial result")
    stale = post(client, goal, mode="independent", independent_context="conversation_snapshot", expected_snapshot=old)
    assert stale.status_code == 409
    current = client.get(f"/api/v1/conversation-inbox/{goal}").json()["target"]["snapshot_version"]
    sent = post(client, goal, mode="independent", independent_context="conversation_snapshot", expected_snapshot=current)
    assert sent.status_code == 200, sent.text
    item = sent.json()["item"]
    world.set_goal_status(goal, "active", result="Later work changed again")
    edited = post(client, goal, mode="independent", item_id=item["id"], expected_revision=item["revision"],
                  independent_context="conversation_snapshot", expected_snapshot=item["snapshot_version"], text="Revised request, same context")
    assert edited.status_code == 200, edited.text
    assert edited.json()["item"]["snapshot_version"] == current


def test_native_inbox_and_project_assets_are_served_as_javascript(setup):
    client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    for name in ("lightwork-conversation-inbox.js", "lightwork-project-workspaces.js"):
        response = client.get("/static/" + name)
        assert response.status_code == 200, response.text
        assert "javascript" in response.headers["content-type"]


def test_blocked_admission_cannot_be_rewritten_and_cancel_releases_fifo_queue(setup, monkeypatch):
    from maverick import runner, world_model
    client, world, goal = setup
    first = post(client, goal, text="First queued task").json()["item"]
    second = post(client, goal, text="Second queued task").json()["item"]
    world.set_goal_status(goal, "done")
    monkeypatch.setattr(world_model, "open_world", lambda: world)
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: None)
    publish = worker.publish_files
    def fail(*args):
        raise OSError("Controlled attachment interruption")
    monkeypatch.setattr(worker, "publish_files", fail)
    calls = []
    monkeypatch.setattr(runner, "run_goal_in_background", lambda gid, **kwargs: calls.append(gid))
    with tenant_scope(tenant="tenant-a"):
        key = record(world, goal)
        worker.execute_record(key)
        worker.execute_record(key, second["id"])
    state = client.get(f"/api/v1/conversation-inbox/{goal}").json()
    blocked = next(item for item in state["items"] if item["id"] == first["id"])
    assert blocked["state"] == "blocked" and blocked["may_edit"] is False and not calls
    revised = post(client, goal, item_id=blocked["id"], expected_revision=blocked["revision"], text="Different task")
    assert revised.status_code == 409
    cancelled = client.patch(f"/api/v1/conversation-inbox/{goal}/{blocked['id']}", json={
        "context": state["context"], "operation_id": uuid.uuid4().hex,
        "expected_revision": blocked["revision"], "action": "cancel"})
    assert cancelled.status_code == 200, cancelled.text
    assert world.get_goal(blocked["goal_id"]).status == "cancelled"
    monkeypatch.setattr(worker, "publish_files", publish)
    with tenant_scope(tenant="tenant-a"):
        worker.execute_record(key, second["id"])
    assert len(calls) == 1 and world.get_goal(calls[0]).title == "Second queued task"


def test_closed_source_keeps_owned_receipts_and_cancellation_without_new_execution(setup, monkeypatch):
    from maverick import task_handoffs
    client, world, goal = setup
    token = uuid.uuid4().hex
    item = post(client, goal, operation_id=token).json()["item"]
    monkeypatch.setattr(task_handoffs, "closure", lambda world, goal: {"state": "accepted"})
    def closed(world, goal):
        raise PermissionError("Task execution was handed off")
    monkeypatch.setattr(task_handoffs, "require_open", closed)
    state = client.get(f"/api/v1/conversation-inbox/{goal}").json()
    assert state["execution_closed"] and state["can_cancel"]
    assert client.get(f"/api/v1/conversation-inbox/{goal}/receipts/{token}").json()["received"]
    assert post(client, goal).status_code == 403
    cancelled = client.patch(f"/api/v1/conversation-inbox/{goal}/{item['id']}", json={
        "context": state["context"], "operation_id": uuid.uuid4().hex,
        "expected_revision": item["revision"], "action": "cancel"})
    assert cancelled.status_code == 200 and cancelled.json()["item"]["state"] == "cancelled"
    assert len(world.list_goals()) == 1


def test_the_composer_explanations_are_plain_and_translated():
    """While a task runs, the composer says what each message will do in plain
    words, in every draft language."""
    import re as _re
    from pathlib import Path

    from maverick_dashboard import i18n_journeys
    script = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"
              / "lightwork-conversation-inbox.js").read_text(encoding="utf-8")
    explanations = _re.search(r"const text=\{guidance:'(.*?)',queue:'(.*?)',independent:'(.*?)'\}", script)
    assert explanations is not None
    turned_off = "Sending messages during a task is turned off for this workspace. You can send a follow-up once the task finishes."
    assert turned_off in script and "Background messages are disabled" not in script
    for sentence in [*(text.replace("\\'", "'") for text in explanations.groups()), turned_off]:
        assert not _re.search(r"billable|runner|consumes|snapshot|policy", sentence), sentence
        for lang in i18n_journeys.TRANSLATION_LANGS:
            assert i18n_journeys.text(sentence, lang) != sentence, (lang, sentence)
