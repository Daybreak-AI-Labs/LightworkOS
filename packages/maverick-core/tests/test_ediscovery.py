from __future__ import annotations

import gc
import hashlib
import json
import sqlite3
import uuid
import zipfile
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from maverick import audit, config, ediscovery, ediscovery_export, records_gc
from maverick.audit import preservation, retention
from maverick.paths import tenant_scope
from maverick.world_model import WorldModel

ALICE = "user:cli:alice"
BOB = "user:cli:bob"
PAST = {"date_from": "2001-01-01", "date_to": "2001-01-02"}


@pytest.fixture(autouse=True)
def _workspace_home(tmp_path, monkeypatch):
    """A private home and workspace for the employee companion and inbox stores that exports read."""
    from maverick import crypto_at_rest

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    # A synthetic test-only at-rest key; no deployment credentials are read.
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "27" * 32)
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "unused.key")
    with tenant_scope(tenant="ws-a"):
        yield


@pytest.fixture()
def events(monkeypatch):
    recorded: list[tuple[str, dict]] = []

    def record(kind, *, agent="system", goal_id=None, **payload):
        recorded.append((payload.get("verb", kind), dict(payload)))
        return True

    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: record(kind, **payload))
    return recorded


@pytest.fixture()
def world(tmp_path):
    handle = WorldModel(tmp_path / "world.db")
    yield handle
    handle.close()


@pytest.fixture()
def ledger(tmp_path, monkeypatch):
    """The matter ledger for the active workspace, kept under the test's temp directory."""
    from maverick import paths

    path = tmp_path / "ledger.sqlite3"
    monkeypatch.setattr(ediscovery, "store_path", lambda tenant=None: path)
    monkeypatch.setattr(paths, "current_tenant_id", lambda: "ws-a")
    return path



def _values(**overrides):
    values = {"name": "Acme dispute", "description": "Contract review",
              "custodians": [ALICE], "record_kinds": ["goals", "chats", "attachments", "approvals"]}
    values.update(overrides)
    return values


def _seed(world):
    alice_goal = world.create_goal("Alice task", owner=ALICE)
    bob_goal = world.create_goal("Bob task", owner=BOB)
    alice_conv = world.get_or_create_conversation("cli", "alice").id
    bob_conv = world.get_or_create_conversation("cli", "bob").id
    world.append_turn(alice_conv, "user", "alice private remark", goal_id=alice_goal)
    world.append_turn(bob_conv, "user", "bob private remark", goal_id=bob_goal)
    world.add_attachment(alice_goal, "alice.txt", "text/plain", 3, "a" * 64, "/tmp/alice.txt")
    world.add_attachment(bob_goal, "bob.txt", "text/plain", 3, "b" * 64, "/tmp/bob.txt")
    world.start_episode(alice_goal)
    world.create_approval("send_contract", requested_by=ALICE, detail="alice approval")
    world.create_approval("send_contract", requested_by=BOB, detail="bob approval")
    return {"alice_goal": alice_goal, "bob_goal": bob_goal, "alice_conv": alice_conv, "bob_conv": bob_conv}


# ---- configuration gate -------------------------------------------------------

def test_feature_is_off_unless_enable_is_strictly_true(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    for loaded, expected in [({}, False), ({"ediscovery": {"enable": "true"}}, False),
                             ({"ediscovery": {"enable": 1}}, False), ({"ediscovery": {"enable": True}}, True)]:
        monkeypatch.setattr(config, "load_config", lambda loaded=loaded: loaded)
        assert ediscovery.enabled() is expected, loaded
    monkeypatch.setattr(config, "load_config", dict)
    with pytest.raises(ediscovery.EdiscoveryDisabled):
        ediscovery.require_enabled()


def test_matter_recorded_while_enabled_keeps_binding_after_disable(monkeypatch, events):
    with tenant_scope(tenant="ws-a"):
        ediscovery.MatterStore(ediscovery.store_path()).create("ws-a", actor="auditor", values=_values())
        monkeypatch.setattr(ediscovery, "enabled", lambda: False)
        assert ediscovery.active_matter_count() == 1


# ---- validation ---------------------------------------------------------------

@pytest.mark.parametrize("values", [
    _values(name=""),
    _values(name="x" * 201),
    _values(name="bad\x07name"),
    _values(custodians=[]),
    _values(custodians=["user:cli:has space"]),
    _values(custodians=["alice"]),
    _values(custodians=["user:"]),
    _values(custodians=["user:cli:"]),
    _values(record_kinds=[]),
    _values(record_kinds=["goals", "goals"]),
    _values(record_kinds=["email"]),
    _values(date_from="2026-02-30"),
    _values(date_from="2026-03-02", date_to="2026-03-01"),
    _values(owner="someone"),
])
def test_invalid_matter_input_is_refused(tmp_path, values, events):
    store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
    with pytest.raises(ediscovery.MatterValidationError):
        store.create("ws-a", actor="auditor", values=values)
    assert store.list("ws-a") == []


# ---- audited lifecycle ----------------------------------------------------------

def test_create_edit_release_are_audited_and_revision_checked(tmp_path, events):
    store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
    matter = store.create("ws-a", actor="auditor", values=_values())
    assert matter["revision"] == 1 and matter["status"] == "active"

    edited = store.update("ws-a", matter["id"], actor="auditor", expected_revision=1,
                          values={"custodians": [ALICE, BOB]})
    assert edited["revision"] == 2 and edited["custodians"] == [ALICE, BOB]
    assert edited["date_from"] is None  # a partial edit never clears untouched fields

    with pytest.raises(ediscovery.MatterConflict):
        store.update("ws-a", matter["id"], actor="auditor", expected_revision=1, values={"name": "Old"})

    released = store.release("ws-a", matter["id"], actor="auditor", expected_revision=2)
    assert released["status"] == "released" and released["released_by"] == "auditor"
    with pytest.raises(ediscovery.MatterConflict):
        store.update("ws-a", matter["id"], actor="auditor", expected_revision=3, values={"name": "Later"})

    verbs = [verb for verb, _ in events]
    assert verbs == ["ediscovery_matter_created", "ediscovery_matter_edited", "ediscovery_matter_released"]
    created_detail = events[0][1]
    assert created_detail["custodian_count"] == 1
    assert ALICE not in json.dumps(events)  # audit names no custodian


def test_change_is_not_saved_when_its_audit_record_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: False)
    store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
    with pytest.raises(ediscovery.EdiscoveryError, match="audit record"):
        store.create("ws-a", actor="auditor", values=_values())
    assert store.list("ws-a") == []


def test_matters_are_tenant_scoped_and_integrity_checked(tmp_path, events):
    store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
    matter = store.create("ws-a", actor="auditor", values=_values())
    with pytest.raises(ediscovery.MatterNotFound):
        store.get("ws-b", matter["id"])
    assert store.list("ws-b") == []
    with pytest.raises(ediscovery.MatterNotFound):
        store.release("ws-b", matter["id"], actor="auditor", expected_revision=1)

    with sqlite3.connect(tmp_path / "ledger.sqlite3") as connection:
        connection.execute("UPDATE matters SET payload_json=replace(payload_json,'Acme','Other')")
    with pytest.raises(ediscovery.EdiscoveryError, match="could not be verified"):
        store.get("ws-a", matter["id"])


def test_active_matters_are_read_per_workspace(tmp_path, events):
    with tenant_scope(tenant="ws-a"):
        ediscovery.MatterStore(ediscovery.store_path()).create("ws-a", actor="auditor", values=_values())
        assert ediscovery.active_matter_count() == 1
    with tenant_scope(tenant="ws-b"):
        assert ediscovery.active_matter_count() == 0


# ---- broad purge gates ----------------------------------------------------------

def test_active_matter_blocks_broad_purge_and_release_lifts_it(events, monkeypatch):
    purged = []
    monkeypatch.setattr(retention, "purge_world_messages", lambda **kw: purged.append(kw))
    with tenant_scope(tenant="ws-a"):
        store = ediscovery.MatterStore(ediscovery.store_path())
        matter = store.create("ws-a", actor="auditor", values=_values())
        snapshot = preservation.preservation_snapshot()
        # People reviewing their own data see this snapshot: it must not reveal a matter.
        assert snapshot["blocked"] is False
        assert not {"active_matters", "broad_purge_blocked"} & set(snapshot)
        with pytest.raises(retention.RetentionScopeError):
            retention.enforce(config={"messages_days": 1}, _fleet_child=True)
        with pytest.raises(ediscovery.LegalHoldApplies):
            records_gc.prune_world(_FakeWorld(), days=1, events_days=1)
        assert purged == []

        store.release("ws-a", matter["id"], actor="auditor", expected_revision=1)
        retention.enforce(config={"messages_days": 1}, _fleet_child=True)
        assert len(purged) == 1
        assert records_gc.prune_world(_FakeWorld(), days=1, events_days=1) == (0, 0, 0)


class _FakeWorld:
    def prune_conversations(self, **kwargs):
        return 0

    def prune_goal_events(self, **kwargs):
        return 0

    def prune_processed_messages(self, **kwargs):
        return 0


# ---- per-person erasure ---------------------------------------------------------

def test_erasure_refused_only_for_in_scope_records(world, ledger, events):
    seeded = _seed(world)
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor",
                                          values=_values(record_kinds=["goals", "chats", "attachments"]))

    message = ediscovery.erasure_refusal(world, conversation_ids=[seeded["alice_conv"]],
                                         goal_ids=[seeded["alice_goal"]])
    assert message == ediscovery.LEGAL_HOLD_MESSAGE
    assert "Acme" not in message and "custodian" not in message.lower()
    assert ediscovery.erasure_refusal(world, conversation_ids=[seeded["bob_conv"]],
                                      goal_ids=[seeded["bob_goal"]]) is None


def test_erasure_of_another_person_and_out_of_range_records_is_allowed(world, ledger, events):
    seeded = _seed(world)
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(**PAST))
    assert ediscovery.erasure_refusal(world, conversation_ids=[seeded["alice_conv"]],
                                      goal_ids=[seeded["alice_goal"]]) is None
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=[BOB]))
    assert ediscovery.erasure_refusal(world, conversation_ids=[seeded["bob_conv"]],
                                      goal_ids=[seeded["bob_goal"]]) == ediscovery.LEGAL_HOLD_MESSAGE


def test_each_refusal_is_audited_with_the_actor_and_no_content(world, ledger, events):
    seeded = _seed(world)
    matter = ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values())
    with pytest.raises(ediscovery.LegalHoldApplies):
        ediscovery.assert_erasure_permitted(world, conversation_ids=[seeded["alice_conv"]],
                                            goal_ids=[seeded["alice_goal"]], actor="reviewer-1")
    refusals = [payload for verb, payload in events if verb == "ediscovery_erasure_refused"]
    assert refusals == [{"verb": "ediscovery_erasure_refused", "matter_id": matter["id"], "actor": "reviewer-1",
                         "conversations": 1, "goals": 1}]
    assert "alice" not in json.dumps(refusals) and "remark" not in json.dumps(refusals)


def test_a_refused_audit_record_still_refuses_the_erasure_with_the_hold_message(world, ledger, events, monkeypatch):
    from maverick import incident_attachment_metadata
    from maverick.audit import AuditRefused

    seeded = _seed(world)
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(
        record_kinds=["chats", "attachments"]))

    def refuse_audit(kind, **payload):
        raise AuditRefused("audit is required")

    monkeypatch.setattr(audit, "audit_event", refuse_audit)
    assert ediscovery.erasure_refusal(world, conversation_ids=[seeded["alice_conv"]], goal_ids=[],
                                      actor="reviewer-1") == ediscovery.LEGAL_HOLD_MESSAGE
    uploader = incident_attachment_metadata.principal_ref_for_subject("ws-a", ALICE)
    assert ediscovery.incident_attachment_refusal("ws-a", principal_ref=uploader,
                                                  created_at=0.0, actor="reviewer-1") == ediscovery.LEGAL_HOLD_MESSAGE


def test_matter_kinds_limit_what_is_held(world, ledger, events):
    seeded = _seed(world)
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(record_kinds=["approvals"]))
    assert ediscovery.erasure_refusal(world, conversation_ids=[seeded["alice_conv"]],
                                      goal_ids=[seeded["alice_goal"]]) is None


def test_closure_through_another_persons_chat_is_held_when_it_reaches_a_custodian_goal(world, ledger, events):
    seeded = _seed(world)
    world.append_turn(seeded["bob_conv"], "assistant", "linked to alice's task", goal_id=seeded["alice_goal"])
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values())
    assert ediscovery.erasure_refusal(world, conversation_ids=[seeded["bob_conv"]],
                                      goal_ids=[seeded["alice_goal"]]) == ediscovery.LEGAL_HOLD_MESSAGE


def test_incident_attachment_refusal_reads_the_ledger_of_the_workspace_it_is_given(events):
    from maverick import incident_attachment_metadata
    from maverick.paths import tenant_scope

    ediscovery.MatterStore(ediscovery.store_path("ws-a")).create("ws-a", actor="auditor", values=_values(
        record_kinds=["attachments"]))
    uploader = incident_attachment_metadata.principal_ref_for_subject("ws-a", ALICE)
    with tenant_scope(tenant="ws-b"):  # the active workspace is not the matter's workspace
        assert ediscovery.incident_attachment_refusal("ws-a", principal_ref=uploader,
                                                      created_at=0.0) == ediscovery.LEGAL_HOLD_MESSAGE
        assert ediscovery.incident_attachment_refusal("ws-b", principal_ref=uploader, created_at=0.0) is None


def test_released_matter_no_longer_holds_erasure(world, ledger, events):
    seeded = _seed(world)
    store = ediscovery.MatterStore(ledger)
    matter = store.create("ws-a", actor="auditor", values=_values())
    store.release("ws-a", matter["id"], actor="auditor", expected_revision=1)
    assert ediscovery.erasure_refusal(world, conversation_ids=[seeded["alice_conv"]],
                                      goal_ids=[seeded["alice_goal"]]) is None


def test_cli_erase_stops_before_deleting_anything(world, ledger, events, tmp_path):
    from maverick import cli as cli_mod

    seeded = _seed(world)
    db = tmp_path / "world.db"
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values())
    world.close()
    result = CliRunner().invoke(cli_mod.main, ["--db", str(db), "erase", "--channel", "cli",
                                               "--user", "alice", "--yes"])
    assert result.exit_code != 0
    assert ediscovery.LEGAL_HOLD_MESSAGE in result.output
    check = WorldModel(db)
    try:
        rows = check.conn.execute("SELECT COUNT(*) FROM turns WHERE conversation_id=?",
                                  (seeded["alice_conv"],)).fetchone()[0]
        assert rows == 1
    finally:
        check.close()


# ---- export ----------------------------------------------------------------------

def test_export_contains_exactly_the_scoped_records_with_verifiable_signature(world, ledger, events, tmp_path):
    _seed(world)
    store = ediscovery.MatterStore(ledger)
    matter = store.create("ws-a", actor="auditor", values=_values())

    result = ediscovery_export.export_matter(world, matter, actor="auditor", out_dir=tmp_path / "exports")
    archive_path = result["path"]
    assert archive_path.exists() and result["records"] > 0

    with zipfile.ZipFile(archive_path) as archive:
        assert set(archive.namelist()) == {"goals.jsonl", "chats.jsonl", "attachments.jsonl",
                                           "approvals.jsonl", "manifest.json"}
        raw = b"".join(archive.read(name) for name in archive.namelist())
        assert b"alice private remark" in raw and b"bob private remark" not in raw
        assert b"bob approval" not in raw and b"bob.txt" not in raw
        goals = [json.loads(line) for line in archive.read("goals.jsonl").splitlines()]
        assert {row["record_type"] for row in goals} == {"goal", "run"}
        assert all(row.get("owner", ALICE) == ALICE for row in goals if row["record_type"] == "goal")
        attachments = [json.loads(line) for line in archive.read("attachments.jsonl").splitlines()]
        assert [row["filename"] for row in attachments] == ["alice.txt"]
        approvals = [json.loads(line) for line in archive.read("approvals.jsonl").splitlines()]
        assert [row["detail"] for row in approvals] == ["alice approval"]
        manifest = json.loads(archive.read("manifest.json"))
        for entry in manifest["files"]:
            data = archive.read(entry["path"])
            assert len(data) == entry["bytes"]
            assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        assert manifest["matter"]["id"] == matter["id"]
        assert manifest["matter"]["custodians"] == [ALICE]

    from maverick.audit.signing import trusted_audit_public_keys

    verdict = ediscovery_export.verify_export(archive_path, trusted_keys=trusted_audit_public_keys())
    assert verdict["valid"] is True, verdict
    assert ediscovery_export.verify_export(archive_path, trusted_keys={})["valid"] is False

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive_path) as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == "goals.jsonl":
                data = data.replace(b"Alice task", b"Edited task")
            target.writestr(name, data)
    from maverick.audit.signing import trusted_audit_public_keys as keys

    assert "goals.jsonl" in ediscovery_export.verify_export(tampered, trusted_keys=keys())["problems"]
    assert [event[0] for event in events][-1] == "ediscovery_matter_exported"


def test_export_is_bounded_and_leaves_no_partial_file(world, ledger, events, tmp_path):
    _seed(world)
    matter = ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values())
    with pytest.raises(ediscovery.MatterExportTooLarge, match="too large"):
        ediscovery_export.export_matter(world, matter, actor="auditor", out_dir=tmp_path / "exports",
                                        max_bytes=10)
    assert list((tmp_path / "exports").glob("*.zip")) == []


def test_export_is_refused_when_its_audit_record_cannot_be_written(world, ledger, monkeypatch, tmp_path):
    _seed(world)
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: True)
    matter = ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values())
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: False)
    with pytest.raises(ediscovery.MatterExportError, match="audit record"):
        ediscovery_export.export_matter(world, matter, actor="auditor", out_dir=tmp_path / "exports")
    assert list((tmp_path / "exports").glob("*.zip")) == []


def test_unenumerable_scope_fails_closed(world, ledger, events, monkeypatch):
    seeded = _seed(world)
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values())
    monkeypatch.setattr(ediscovery, "MAX_SCOPE_ROWS", 0)
    with pytest.raises(ediscovery.LegalHoldApplies):
        ediscovery.assert_erasure_permitted(world, conversation_ids=[seeded["bob_conv"]], goal_ids=[])


def test_unreadable_ledger_refuses_erasure_and_bulk_purge(world, ledger, events):
    seeded = _seed(world)
    ledger.write_bytes(b"this is not a sqlite ledger")
    with pytest.raises(ediscovery.LegalHoldApplies) as erasure:
        ediscovery.assert_erasure_permitted(world, conversation_ids=[seeded["bob_conv"]], goal_ids=[])
    assert str(erasure.value) == ediscovery.HOLD_UNVERIFIED_MESSAGE
    with pytest.raises(ediscovery.LegalHoldApplies) as purge:
        ediscovery.assert_no_active_matters()
    assert str(purge.value) == ediscovery.HOLD_UNVERIFIED_MESSAGE
    assert world.conn.execute("SELECT COUNT(*) FROM turns").fetchone()[0] == 2


def test_whole_client_erasure_is_refused_while_a_matter_is_active(tmp_path, monkeypatch, events):
    from maverick import client

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.setenv("MAVERICK_BACKUP_SIGNING_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    client.reset_client_cache()
    try:
        # The ledger lives in the client's own root, which is what erasure would remove.
        ledger_path = ediscovery.store_path("acme")
        ediscovery.MatterStore(ledger_path).create("acme", actor="auditor", values=_values())
        with pytest.raises(client.ClientErasureError, match="legal hold is active"):
            client.erase_client()
        assert ledger_path.exists()
    finally:
        client.reset_client_cache()


def test_sweep_reports_a_held_workspace_as_held_in_preview_and_run_and_sweeps_the_rest(monkeypatch, events):
    from types import SimpleNamespace

    from maverick import paths

    class _SweepWorld(_FakeWorld):
        def purge_goal_events_before(self, cutoff, dry_run=False):
            return 0

    matter = {"id": "mtr-0123456789abcdef", "custodians": [ALICE], "record_kinds": ["goals"],
              "date_from": None, "date_to": None}
    monkeypatch.setattr(ediscovery, "active_matters",
                        lambda: [matter] if paths.current_tenant_id() == "ws-a" else [])
    tenants = [SimpleNamespace(id="ws-a", display_name="Acme"), SimpleNamespace(id="ws-b", display_name="Beta")]
    for dry_run in (True, False):
        rows = {row["workspace"]: row for row in records_gc.sweep_workspaces(
            tenants, days=1, events_days=1, dry_run=dry_run, open_world=_SweepWorld)}
        assert rows["ws-a"]["held"] is True and rows["ws-a"]["conversations"] == 0
        assert rows["ws-a"]["activity"] == 0 and "held" not in rows["ws-b"]


# ---- employee companion and conversation inbox -----------------------------------

OWNER = "user:owner"
ADMIN_USER = "user:admin"


def _companion_store():
    from maverick.employee_companion import EmployeeCompanionStore

    return EmployeeCompanionStore()


def _companion_exchange(store, owner=OWNER, message="companion private question"):
    policy = store.policy(owner)
    store.update_policy(owner, actor=ADMIN_USER, expected_revision=policy["revision"], enabled=True,
                        allowed_sources=["own_tasks"], allowed_tools=["task_status"], retention_days=1)
    return store.record_exchange(owner, message=message, response="You have one active task.",
                                 source_refs=["task:17"], expected_revision=store.policy(owner)["revision"])


@pytest.fixture()
def inbox_setup(tmp_path, monkeypatch):
    from maverick import paths

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text('[conversation_inbox]\nenabled=true\n', encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    from maverick import conversation_inbox

    monkeypatch.setattr(conversation_inbox, "current_authority", lambda goal: (OWNER, None))
    with WorldModel(tmp_path / "inbox-world.db") as world:
        goal = world.create_goal("Original task", "Original private brief", owner=OWNER)
        world.set_goal_status(goal, "active")
        inbox = conversation_inbox.ConversationInbox(world, principal=OWNER, authorize=lambda goal: None)
        yield SimpleNamespace(world=world, goal=goal, inbox=inbox, module=conversation_inbox, paths=paths)
    config.reset_config_cache()


def test_companion_clear_is_refused_for_a_held_exchange_and_keeps_it(events, ledger):
    store = _companion_store()
    _companion_exchange(store)
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=[OWNER],
                                                                                  record_kinds=["chats"]))
    with pytest.raises(ediscovery.LegalHoldApplies) as refused:
        store.clear_history(OWNER, actor=OWNER)
    assert str(refused.value) == ediscovery.LEGAL_HOLD_MESSAGE
    assert [item["message"] for item in store.held_exchanges(OWNER)] == ["companion private question"]
    refusals = [payload for verb, payload in events if verb == "ediscovery_erasure_refused"]
    assert refusals and refusals[-1]["chat_records"] == 1 and "private" not in json.dumps(refusals)


def test_companion_clear_is_allowed_for_another_person_or_outside_the_dates(events, ledger):
    store = _companion_store()
    _companion_exchange(store)
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=["user:someone"],
                                                                                  record_kinds=["chats"]))
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=[OWNER],
                                                                                  record_kinds=["chats"],
                                                                                  **PAST))
    store.clear_history(OWNER, actor=OWNER)
    assert store.held_exchanges(OWNER) == []


def test_companion_retention_keeps_a_held_exchange_until_the_matter_is_released(events, ledger):
    store = _companion_store()
    _companion_exchange(store)
    matter = ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(
        custodians=[OWNER], record_kinds=["chats"]))
    policy = store.policy(OWNER)
    store.update_policy(OWNER, actor=ADMIN_USER, expected_revision=policy["revision"], enabled=False,
                        allowed_sources=["own_tasks"], allowed_tools=["task_status"], retention_days=1)
    assert len(store.history(OWNER)) == 1
    ediscovery.MatterStore(ledger).release("ws-a", matter["id"], actor="auditor", expected_revision=1)
    assert store.history(OWNER) == []


def test_erasing_an_inbox_message_is_refused_for_a_held_conversation_and_keeps_it(inbox_setup, events, ledger):
    s = inbox_setup
    item = s.inbox.submit(s.goal, operation_id=uuid.uuid4().hex, mode="queue", text="Exact next request")
    record_id = s.inbox._read(s.world.get_goal(s.goal))[0]["id"]
    revision = s.module.STORE.get(record_id)["revision"]
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=[OWNER],
                                                                                  record_kinds=["chats"]))
    assert [row["text"] for row in s.module.owned_items(OWNER)] == ["Exact next request"]
    with pytest.raises(ediscovery.LegalHoldApplies):
        s.module.erase_owned(OWNER, record_id, revision, uuid.uuid4().hex, actor=OWNER)
    assert s.module.owned_items(OWNER)[0]["text"] == "Exact next request"
    assert item["id"] in {row["id"] for row in s.module.owned_items(OWNER)}


def test_inbox_message_outside_the_matter_dates_is_erasable(inbox_setup, events, ledger):
    s = inbox_setup
    s.inbox.submit(s.goal, operation_id=uuid.uuid4().hex, mode="queue", text="Exact next request")
    record_id = s.inbox._read(s.world.get_goal(s.goal))[0]["id"]
    revision = s.module.STORE.get(record_id)["revision"]
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=[OWNER],
                                                                                  record_kinds=["chats"], **PAST))
    result = s.module.erase_owned(OWNER, record_id, revision, uuid.uuid4().hex, actor=OWNER)
    assert result["status"] == "confirmed"
    assert s.module.owned_items(OWNER) == []


def test_export_includes_the_held_companion_exchanges_and_inbox_messages(inbox_setup, events, ledger, tmp_path):
    s = inbox_setup
    _companion_exchange(_companion_store())
    s.inbox.submit(s.goal, operation_id=uuid.uuid4().hex, mode="queue", text="Exact next request")
    matter = ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(
        custodians=[OWNER], record_kinds=["chats"]))
    result = ediscovery_export.export_matter(s.world, matter, actor="auditor", out_dir=tmp_path / "exports")
    assert result["records"] == 2 and result["files"][0]["records"] == 2
    from maverick.audit.signing import trusted_audit_public_keys

    assert ediscovery_export.verify_export(result["path"], trusted_keys=trusted_audit_public_keys())["valid"] is True
    with zipfile.ZipFile(result["path"]) as archive:
        rows = [json.loads(line) for line in archive.read("chats.jsonl").splitlines()]
    kinds = sorted(row["record_type"] for row in rows)
    assert kinds == ["companion_exchange", "conversation_message"]
    assert {row["owner"] for row in rows} == {OWNER}
    assert any(row.get("text") == "Exact next request" for row in rows)


def test_a_cli_custodian_holds_every_local_repl_session_like_the_cli_erase_does(world, ledger, events):
    from maverick.cli import _conversation_user_matches

    local = world.get_or_create_conversation("cli", "local:4f2a9c").id
    other = world.get_or_create_conversation("cli", "localhost").id
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=["user:cli:local"],
                                                                                  record_kinds=["chats"]))
    assert _conversation_user_matches("local:4f2a9c", "local", "cli") is True
    assert ediscovery.erasure_refusal(world, conversation_ids=[local], goal_ids=[]) == ediscovery.LEGAL_HOLD_MESSAGE
    assert ediscovery.erasure_refusal(world, conversation_ids=[other], goal_ids=[]) is None


# ---- linked messaging accounts as custodians ---------------------------------------

ACCOUNT = "account:" + "a" * 64 + ":person:" + "b" * 64
DIGEST = "d" * 64


@pytest.mark.parametrize("custodian", [
    "account:" + "A" * 64 + ":person:" + "b" * 64,           # upper-case hex is never produced
    "account:" + "a" * 63 + ":person:" + "b" * 64,           # one hex character short
    "account:" + "a" * 64 + ":person:" + "b" * 65,           # one hex character long
    "account:" + "a" * 64 + ":person:" + "g" * 64,           # not hex
    "account:" + "a" * 64 + ":" + "b" * 64,                  # missing the person part
    ACCOUNT + ":conversation:" + DIGEST,                     # a thread key is not a custodian
    "user:slack:" + ACCOUNT,                                 # refused: write the account form alone
    "user:telegram:account:" + "a" * 64 + ":person:" + "b" * 64,
    "user:slack:" + ACCOUNT + ":conversation:" + DIGEST,     # a thread key is not a custodian either
    "user:slack:account:" + "a" * 63 + ":person:" + "b" * 64,   # channel form, one hex character short
    "user:slack:account:" + "a" * 64 + ":person:" + "b" * 63,   # channel form, one hex character short
    "user:slack:account:" + "a" * 64,                        # channel form without the person part
    "user:slack:account:" + "a" * 64 + ":person:" + "b" * 64 + ":conversation:" + DIGEST,
    "user:account:" + ACCOUNT,                               # an account is never a channel name
])
def test_account_custodians_must_be_written_exactly(tmp_path, custodian, events):
    store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
    with pytest.raises(ediscovery.MatterValidationError):
        store.create("ws-a", actor="auditor", values=_values(custodians=[custodian]))
    assert store.list("ws-a") == []


@pytest.mark.parametrize("custodian", ["user:slack:accountant", "user:cli:account", "user:account"])
def test_principals_that_only_mention_account_are_still_ordinary_custodians(tmp_path, custodian, events):
    store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
    matter = store.create("ws-a", actor="auditor", values=_values(custodians=[custodian]))
    assert matter["custodians"] == [custodian]


def test_account_custodian_in_the_exact_form_is_saved_and_listed(tmp_path, events):
    store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
    matter = store.create("ws-a", actor="auditor", values=_values(custodians=[ACCOUNT, ALICE]))
    assert matter["custodians"] == sorted([ACCOUNT, ALICE])


@pytest.mark.parametrize("stored", [
    ACCOUNT,
    ACCOUNT + ":conversation:" + DIGEST,
    ACCOUNT + ":conversation:" + "0123456789abcdef" * 4,
])
def test_account_custodian_matches_its_chats_and_thread_variants(stored):
    assert ediscovery.account_user_matches(stored, ACCOUNT) is True


@pytest.mark.parametrize("stored", [
    ACCOUNT + "0",                                      # bare prefix: a longer identifier
    ACCOUNT + ":",
    ACCOUNT + ":conversation:",
    ACCOUNT + ":conversation:" + "d" * 63,              # one hex character short
    ACCOUNT + ":conversation:" + "d" * 65,
    ACCOUNT + ":conversation:" + "D" * 64,              # upper-case hex is never produced
    ACCOUNT + ":conversation:" + "d" * 63 + "g",
    ACCOUNT + ":thread:" + DIGEST,
    ACCOUNT + ":conversation:" + DIGEST + ":extra",
    "xx" + ACCOUNT,                                     # a substring is not a match
    "account:" + "a" * 64 + ":person:" + "c" * 64,      # another person under the same account
    "account:" + "a" * 64 + ":person:" + "b" * 63,
    "user:slack:" + ACCOUNT,                            # a principal id is a different subject
    None,
])
def test_near_miss_identifiers_never_match_an_account_custodian(stored):
    assert ediscovery.account_user_matches(stored, ACCOUNT) is False


def test_account_custodian_holds_its_chats_threads_and_goals_but_not_near_misses(world, ledger, events):
    exact = world.get_or_create_conversation("slack", ACCOUNT).id
    thread = world.get_or_create_conversation("slack", f"{ACCOUNT}:conversation:{DIGEST}").id
    near = world.get_or_create_conversation("slack", ACCOUNT + "0").id
    other = world.get_or_create_conversation("slack", "account:" + "a" * 64 + ":person:" + "c" * 64).id
    for conv, text in [(exact, "account remark"), (thread, "account thread remark"),
                       (near, "near remark"), (other, "other person remark")]:
        world.append_turn(conv, "user", text)
    held_goal = world.create_goal("Account task", owner=f"user:slack:{ACCOUNT}")
    telegram_goal = world.create_goal("Telegram account task", owner=f"user:telegram:{ACCOUNT}")
    near_goal = world.create_goal("Near task", owner=f"user:slack:{ACCOUNT}0")
    ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(custodians=[ACCOUNT],
                                                                                  record_kinds=["goals", "chats"]))
    for conv_id in (exact, thread):
        assert ediscovery.erasure_refusal(world, conversation_ids=[conv_id], goal_ids=[]) == ediscovery.LEGAL_HOLD_MESSAGE
    for goal_id in (held_goal, telegram_goal):
        assert ediscovery.erasure_refusal(world, conversation_ids=[], goal_ids=[goal_id]) == ediscovery.LEGAL_HOLD_MESSAGE
    assert ediscovery.erasure_refusal(world, conversation_ids=[near, other], goal_ids=[near_goal]) is None


def test_export_of_an_account_custodian_holds_exactly_its_records(world, ledger, events, tmp_path):
    exact = world.get_or_create_conversation("slack", ACCOUNT).id
    thread = world.get_or_create_conversation("slack", f"{ACCOUNT}:conversation:{DIGEST}").id
    near = world.get_or_create_conversation("slack", ACCOUNT + "0").id
    world.append_turn(exact, "user", "account remark")
    world.append_turn(thread, "user", "account thread remark")
    world.append_turn(near, "user", "near remark")
    world.create_goal("Account task", owner=f"user:slack:{ACCOUNT}")
    world.create_goal("Near task", owner=f"user:slack:{ACCOUNT}0")
    matter = ediscovery.MatterStore(ledger).create("ws-a", actor="auditor", values=_values(
        custodians=[ACCOUNT], record_kinds=["goals", "chats"]))

    result = ediscovery_export.export_matter(world, matter, actor="auditor", out_dir=tmp_path / "exports")
    with zipfile.ZipFile(result["path"]) as archive:
        raw = b"".join(archive.read(name) for name in archive.namelist())
    assert b"account remark" in raw and b"account thread remark" in raw
    assert b"Account task" in raw
    assert b"near remark" not in raw and b"Near task" not in raw
    from maverick.audit.signing import trusted_audit_public_keys

    assert ediscovery_export.verify_export(result["path"], trusted_keys=trusted_audit_public_keys())["valid"] is True


def test_every_matter_ledger_connection_closes_when_its_call_returns(tmp_path, monkeypatch):
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    opened = []
    real_connect = sqlite3.connect
    fail_pragma = {"on": False}

    class _PragmaFails(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA synchronous=FULL" and fail_pragma["on"]:
                raise sqlite3.OperationalError("pragma failed")
            return super().execute(sql, *args)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_PragmaFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(ediscovery.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        store = ediscovery.MatterStore(tmp_path / "ledger.sqlite3")
        assert store.list("ws-a") == []
        fail_pragma["on"] = True
        with pytest.raises(sqlite3.OperationalError):
            store.list("ws-a")
        fail_pragma["on"] = False
        assert store.list("ws-a") == []
    finally:
        gc.enable()
    assert len(opened) >= 4
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
