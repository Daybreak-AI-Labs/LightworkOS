"""Real encrypted inbox records: exact receipts, policy, edits and checkpoint recovery."""
from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
from maverick import audit, config
from maverick import conversation_inbox as module
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.world_model import WorldModel


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text('[conversation_inbox]\nenabled=true\n', encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(module, "current_authority", lambda goal: ("owner", None))
    with tenant_scope(tenant="tenant-a"), WorldModel(tmp_path / "world.db") as world:
        goal = world.create_goal("Original task", "Original private brief", owner="user:owner")
        world.set_goal_status(goal, "active")
        allowed = {"yes": True}
        def authorize(goal):
            if not allowed["yes"]:
                raise PermissionError("revoked")
        inbox = module.ConversationInbox(world, principal="user:owner", authorize=authorize)
        yield world, goal, inbox, allowed
    config.reset_config_cache()


def send(inbox, goal, **changes):
    return inbox.submit(goal, **{"operation_id": uuid.uuid4().hex, "mode": "queue", "text": "Exact next request", **changes})


def approve(inbox, goal, item, **changes):
    return inbox.change(goal, item["id"], **{"operation_id": uuid.uuid4().hex, "expected_revision": item["revision"],
        "action": "approve_guidance", "decision": "append", "expected_review": inbox.state(goal)["guidance_review_version"], **changes})


def test_ack_survives_reopen_and_retry_is_exact_without_creating_task(setup):
    world, goal, inbox, _ = setup
    token = uuid.uuid4().hex
    item = send(inbox, goal, operation_id=token)
    reopened = module.ConversationInbox(world, principal="user:owner", authorize=lambda goal: None)
    assert reopened.receipt(goal, token)["item"] == item
    assert send(reopened, goal, operation_id=token) == item
    with pytest.raises(RecordConflict):
        send(reopened, goal, operation_id=token, text="Different bytes")
    assert len(world.list_goals()) == 1 and world.get_goal(goal).status == "active"
    raw = module.STORE.get(inbox._read(world.get_goal(goal))[0]["id"])
    assert "Exact next request" not in json.dumps(raw)


def test_file_edit_cas_cancel_and_immutable_operation_receipt(setup):
    _, goal, inbox, _ = setup
    token = uuid.uuid4().hex
    file = module.file_record("evidence.txt", "text/plain", b"private evidence")
    item = send(inbox, goal, operation_id=token, files=[file])
    edited = send(inbox, goal, item_id=item["id"], expected_revision=item["revision"], keep_files=[file["id"]], text="Revised next request")
    assert edited["files"] == item["files"] and "data" not in edited["files"][0]
    assert inbox.receipt(goal, token)["item"]["text"] == "Exact next request"
    with pytest.raises(RecordConflict):
        send(inbox, goal, item_id=item["id"], expected_revision=1)
    cancelled = inbox.change(goal, item["id"], expected_revision=edited["revision"], operation_id=uuid.uuid4().hex, action="cancel")
    assert cancelled["state"] == "cancelled"
    with pytest.raises(RecordConflict):
        send(inbox, goal, item_id=item["id"], expected_revision=cancelled["revision"])


def test_guidance_requires_fresh_explicit_decision_and_exact_checkpoint_ack(setup):
    world, goal, inbox, _ = setup
    item = send(inbox, goal, mode="guidance", text="Add the exact approved constraint")
    messages = []
    module.checkpoint(world, goal, checkpoint_id="first", messages=messages)
    assert messages == [] and len(world.list_goals()) == 1
    reviewed = inbox.state(goal)["guidance_review_version"]
    second = send(inbox, goal, mode="guidance", text="A possibly conflicting direction")
    with pytest.raises(RecordConflict):
        approve(inbox, goal, item, expected_review=reviewed)
    ready = approve(inbox, goal, item, decision="replace_pending")
    assert ready["state"] == "guidance_ready"
    assert next(row for row in inbox.state(goal)["items"] if row["id"] == second["id"])["state"] == "cancelled"
    module.checkpoint(world, goal, checkpoint_id="episode:root:7", messages=messages)
    consumed = inbox.state(goal)["items"][0]
    assert consumed["state"] == "consumed"
    assert consumed["acknowledgement"]["text"] == item["text"]
    assert consumed["acknowledgement"]["checkpoint"] == "episode:root:7"
    assert item["text"] in messages[0]["content"] and len(world.list_goals()) == 1
    module.checkpoint(world, goal, checkpoint_id="next", messages=messages)
    assert len(messages) == 1
    restored = []
    module.checkpoint(world, goal, checkpoint_id="restart", messages=restored)
    assert restored == messages


def test_compacted_history_does_not_redeliver_consumed_guidance(setup, monkeypatch):
    world, goal, inbox, _ = setup
    item = send(inbox, goal, mode="guidance", text="Use only the approved vendor list",
                files=[module.file_record("vendors.txt", "text/plain", b"Approved vendors")])
    approve(inbox, goal, item)
    published, publish = [], module.publish_files
    monkeypatch.setattr(module, "publish_files", lambda *args: published.append(args) or publish(*args))
    messages = [{"role": "user", "content": "Original brief"}]
    module.checkpoint(world, goal, checkpoint_id="12:root:3", messages=messages)
    assert len(messages) == 2 and len(published) == 1
    # Compaction summarized the delivered turn, and its marker, away.
    compacted = [messages[0], {"role": "user", "content": "<stream-summary turns=\"5\">done</stream-summary>"}]
    module.checkpoint(world, goal, checkpoint_id="12:root:4", messages=compacted)
    module.checkpoint(world, goal, checkpoint_id="12:root:9", messages=compacted)
    assert len(compacted) == 2 and len(published) == 1
    # A history resumed from before the consuming checkpoint, or a retried
    # episode, has not seen it and still receives the exact same guidance.
    resumed = [messages[0]]
    module.checkpoint(world, goal, checkpoint_id="12:root:2", messages=resumed)
    assert resumed == messages
    retried = [messages[0]]
    module.checkpoint(world, goal, checkpoint_id="13:root:0", messages=retried)
    assert retried == messages


def test_revocation_and_disabled_modes_do_not_create_or_consume_work(setup, monkeypatch):
    world, goal, inbox, allowed = setup
    item = send(inbox, goal, mode="guidance")
    approve(inbox, goal, item)
    allowed["yes"] = False
    with pytest.raises(PermissionError):
        send(inbox, goal)
    def revoked(goal):
        raise PermissionError("revoked")
    monkeypatch.setattr(module, "current_authority", revoked)
    with pytest.raises(PermissionError):
        module.checkpoint(world, goal, checkpoint_id="revoked", messages=[])
    allowed["yes"] = True
    assert inbox.state(goal)["items"][0]["state"] == "guidance_ready"
    monkeypatch.setattr(module.config, "load_global_config", lambda: {"conversation_inbox": {"enabled": True, "independent": False}})
    with pytest.raises(PermissionError):
        send(inbox, goal, mode="independent")


def test_deferred_owner_authority_rechecks_inherited_suite(tmp_path, monkeypatch):
    from maverick.tenant import registry
    from maverick_dashboard import auth, rbac, scim_groups

    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    monkeypatch.setattr(module, "current_tenant_id_strict", lambda: "tenant-a")
    monkeypatch.setattr(registry, "assert_tenant_active", lambda tenant_id: None)
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda principal: True)
    monkeypatch.setattr(rbac, "get_tenant_role", lambda tenant_id, principal: "operator")
    monkeypatch.setattr(rbac, "permissions_for", lambda role: {"operate"})
    monkeypatch.setattr(auth, "stored_automation_identity", lambda owner: (owner, "owner", frozenset({"finance"})))
    goal = SimpleNamespace(owner="user:owner", domain="client_fork")

    with pytest.raises(PermissionError, match="department"):
        module.current_authority(goal)


def test_worker_claim_fences_edits_and_checkpoint_files_are_exact(setup):
    world, goal, inbox, _ = setup
    item = send(inbox, goal, mode="guidance", files=[module.file_record("notes.txt", "text/plain", b"Exact private note")])
    approve(inbox, goal, item)
    module.checkpoint(world, goal, checkpoint_id="file-checkpoint", messages=[])
    consumed = inbox.state(goal)["items"][0]
    assert world.list_attachments(goal)[0].sha256 == item["files"][0]["sha256"]
    assert consumed["acknowledgement"]["files"] == item["files"]
    with pytest.raises(RecordConflict):
        inbox.change(goal, item["id"], expected_revision=consumed["revision"], operation_id=uuid.uuid4().hex, action="cancel")


def test_other_owner_workspace_and_reused_metadata_cannot_read_inbox(setup):
    world, goal, inbox, _ = setup
    send(inbox, goal)
    with pytest.raises(PermissionError):
        module.ConversationInbox(world, principal="user:other", authorize=lambda goal: None).state(goal)
    with tenant_scope(tenant="tenant-b"), pytest.raises(PermissionError):
        inbox.state(goal)


@pytest.mark.parametrize(("global_table", "active_table", "enabled"), [
    ({}, {}, True),                                   # on by default
    ({"enabled": False}, {}, False),                  # an organization "off" stays off
    ({}, {"enabled": False}, False),                  # so does a workspace "off"
    ({"enabled": True}, {"enabled": True}, True),
])
def test_messages_during_a_task_are_on_by_default_and_off_stays_off(monkeypatch, global_table,
                                                                     active_table, enabled):
    monkeypatch.setattr(module.config, "config_source_errors", lambda include_tenant=False: [])
    monkeypatch.setattr(module.config, "load_global_config",
                        lambda: {"conversation_inbox": dict(global_table)})
    monkeypatch.setattr(module.config, "load_config", lambda: {"conversation_inbox": dict(active_table)})
    assert module.policy()["enabled"] is enabled
    assert module.policy()["modes"] == ["guidance", "queue", "independent"]


def test_owned_inventory_is_not_capped_by_other_owners_records(monkeypatch):
    class _Store:
        def iter_record_ids(self, *, start_after, limit):
            start = int(start_after or 0)
            return [(str(n), f"r{n}") for n in range(start + 1, min(start + limit, 10_050) + 1)]

        def get(self, record_id):
            return {"owner": "user:someone-else"}

    monkeypatch.setattr(module, "STORE", _Store())
    assert module.owned_inventory("user:alice") == []
    monkeypatch.setattr(module, "_MAX_INVENTORY_SCAN", 100)
    with pytest.raises(ValueError, match="narrower"):
        module.owned_inventory("user:alice")
