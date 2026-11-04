"""Signed pre-delete erasure receipts and complete goal-graph deletion."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.erasure_receipts import (
    AUXILIARY_ERASURE_STORES,
    GOAL_LINKED_STORES,
    RECEIPT_STORES,
    ErasurePlanChanged,
    ErasureReceiptError,
    build_manifest,
    load_verified_erasure_closure,
    load_verified_receipt,
    persist_erasure_closure,
    persist_receipt,
    receipt_is_durable,
    retire_expired_receipts,
    validate_manifest,
)
from maverick.erasure_verify import verify_erasure
from maverick.world_model import SCHEMA_VERSION, WorldModel


def _seed_complete_graph(world: WorldModel, attachment_path: Path) -> dict:
    from maverick.attachment_submissions import SubmissionStore
    from maverick.goal_mutations import edit_result

    conv = world.get_or_create_conversation("telegram", "alice")
    root = SubmissionStore(world).create(
        token="private-submission-key", fingerprint="private-request-fingerprint",
        owner="alice", title="root subject goal", description="private request",
        manifest=[],
    )["goal_id"]
    child = world.create_goal("child subject goal", parent_id=root)
    grandchild = world.create_goal("grandchild subject goal", parent_id=child)
    world.append_turn(conv.id, "user", "private request", goal_id=root)

    episode = world.start_episode(grandchild)
    world._temporal_memory = True
    world.upsert_fact(
        f"derived-private-{episode}",
        "private episode-derived fact",
        episode_id=episode,
    )
    world.add_artifact(child, "text", "private artifact", "private content")
    attachment_path.write_text("private attachment", encoding="utf-8")
    world.add_attachment(
        grandchild,
        "private.txt",
        "text/plain",
        attachment_path.stat().st_size,
        "a" * 64,
        str(attachment_path),
    )
    world.append_event(child, "researcher", "note", "private event")
    world.record_goal_origin(root, "webhook", "private-origin")
    world.append_message(grandchild, "assistant", "private message")
    assert world.mark_message_processed(
        "telegram",
        f"private-{conv.id}",
        grandchild,
    )
    world.ask("private question", goal_id=child)
    world.create_share_link(grandchild, created_by="reviewer")
    world.set_goal_status(grandchild, "done", result="private result")
    # Populate the human-edit receipt store through its real transaction so
    # complete-scope checks prove the private receipt is erased as well.
    edit_result(world, grandchild, text="private revised result",
                expected_updated_at=world.get_goal(grandchild).updated_at,
                operation_id="e" * 32, actor="alice")
    assert world.record_signoff(
        grandchild,
        "approved",
        decided_by="reviewer",
        note="private approval",
    )
    return {
        "conversation_id": conv.id,
        "goal_ids": [root, child, grandchild],
        "episode_ids": [episode],
    }


def _manifest_for(world: WorldModel, conversation_id: int) -> tuple[dict, dict]:
    plan = world.plan_conversation_erasure([conversation_id])
    manifest = build_manifest(
        tenant_id="shared",
        conversation_ids=plan["conversation_ids"],
        goal_ids=plan["goal_ids"],
        episode_ids=plan["episode_ids"],
    )
    return plan, manifest


def _canonical(value: dict) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_receipt_is_subject_free_signed_durable_and_tenant_scoped(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    seeded = _seed_complete_graph(world, tmp_path / "private.txt")
    _plan, manifest = _manifest_for(world, seeded["conversation_id"])

    signed = persist_receipt(world, manifest)
    recovered = load_verified_receipt(
        world,
        signed["receipt_id"],
        expected_tenant="shared",
    )

    assert recovered == signed
    assert receipt_is_durable(world, signed, expected_tenant="shared")
    stored = world.get_erasure_receipt(
        signed["receipt_id"],
        tenant_id="shared",
    )
    assert stored is not None
    assert "alice" not in stored
    assert "telegram" not in stored
    assert "user_id" not in stored
    assert set(signed) == {
        "schema",
        "receipt_id",
        "tenant_id",
        "issued_at",
        "retained_until",
        "conversation_ids",
        "goal_ids",
        "episode_ids",
        "expected_stores",
        "payload_sha256",
        "key_id",
        "signature",
    }
    with pytest.raises(ErasureReceiptError, match="not found|another tenant"):
        load_verified_receipt(
            world,
            signed["receipt_id"],
            expected_tenant="other",
        )


def test_manifest_cannot_shorten_the_governed_retention_period():
    manifest = build_manifest(
        tenant_id="shared",
        conversation_ids=[1],
        goal_ids=[],
    )
    manifest["retained_until"] = (
        datetime.fromisoformat(manifest["issued_at"].replace("Z", "+00:00"))
        + timedelta(days=1)
    ).isoformat().replace("+00:00", "Z")

    with pytest.raises(ErasureReceiptError, match="retention period"):
        validate_manifest(manifest)


def test_receipt_missing_new_submission_scope_cannot_claim_complete_erasure():
    manifest = build_manifest(tenant_id="shared", conversation_ids=[1], goal_ids=[1])
    manifest["expected_stores"].remove("attachment_submissions")
    with pytest.raises(ErasureReceiptError, match="complete store scope"):
        validate_manifest(manifest)


@pytest.mark.usefixtures("local_audit_key_custody")
def test_receipt_records_key_era_and_survives_authorized_rotation(tmp_path):
    from maverick.audit.signing import rotate_audit_keypair

    world = WorldModel(tmp_path / "world.db")
    old = persist_receipt(
        world,
        build_manifest(
            tenant_id="shared",
            conversation_ids=[1],
            goal_ids=[],
        ),
    )
    new_key_id = rotate_audit_keypair()
    new = persist_receipt(
        world,
        build_manifest(
            tenant_id="shared",
            conversation_ids=[2],
            goal_ids=[],
        ),
    )

    assert new_key_id != old["key_id"]
    assert new["key_id"] == new_key_id
    assert load_verified_receipt(
        world,
        old["receipt_id"],
        expected_tenant="shared",
    ) == old


def test_all_goal_linked_stores_are_counted_and_descendants_are_erased(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    attachment = tmp_path / "private.txt"
    seeded = _seed_complete_graph(world, attachment)
    plan, manifest = _manifest_for(world, seeded["conversation_id"])
    signed = persist_receipt(world, manifest)

    assert plan["goal_ids"] == seeded["goal_ids"]
    before = world.count_erasure_receipt_residuals(
        manifest["conversation_ids"],
        manifest["goal_ids"],
        manifest["episode_ids"],
    )
    assert set(before) == set(RECEIPT_STORES)
    assert all(before[store] > 0 for store in RECEIPT_STORES)

    pre_report = verify_erasure(
        "alice",
        channel="telegram",
        receipt=signed,
        world=world,
    )
    assert set(GOAL_LINKED_STORES).issubset(pre_report["residual"])

    goals, paths, removed_turns = world.erase_conversations(
        [seeded["conversation_id"]],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )
    assert goals == set(seeded["goal_ids"])
    assert paths == [str(attachment)]
    assert removed_turns == 1
    attachment.unlink()
    closure = persist_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    )
    assert closure["stores"] == dict.fromkeys(AUXILIARY_ERASURE_STORES, 0)
    assert load_verified_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    ) == closure
    assert all(world.get_goal(goal_id) is None for goal_id in seeded["goal_ids"])
    assert world.count_erasure_receipt_residuals(
        manifest["conversation_ids"],
        manifest["goal_ids"],
        manifest["episode_ids"],
    ) == dict.fromkeys(RECEIPT_STORES, 0)

    report = verify_erasure(
        "alice",
        channel="telegram",
        receipt=signed,
        world=world,
    )
    assert report["clean"] is True
    assert report["durable_proof"] is True
    assert report["durable_closure"] is True
    assert report["indeterminate"] is False
    assert report["residual"] == {}
    assert report["receipt_id"] == signed["receipt_id"]


def test_large_sqlite_erasure_closure_never_exceeds_parameter_bound(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    conversation = world.get_or_create_conversation("telegram", "large-user")
    root = world.create_goal("large closure root")
    world.append_turn(
        conversation.id,
        "user",
        "large private request",
        goal_id=root,
    )
    now = time.time()
    with world._writing() as connection:
        connection.executemany(
            "INSERT INTO goals("
            "parent_id, title, status, created_at, updated_at"
            ") VALUES(?, ?, 'pending', ?, ?)",
            (
                (root, f"child-{index}", now, now)
                for index in range(600)
            ),
        )

    raw_connection = world.conn

    class BoundedConnection:
        """Emulate a conservative SQLite compile-time variable ceiling."""

        def execute(self, sql, parameters=()):
            assert len(parameters) <= 500, sql
            return raw_connection.execute(sql, parameters)

        def __getattr__(self, name):
            return getattr(raw_connection, name)

    world.conn = BoundedConnection()
    plan = world.plan_conversation_erasure([conversation.id])
    assert len(plan["goal_ids"]) == 601
    signed = persist_receipt(
        world,
        build_manifest(
            tenant_id="shared",
            conversation_ids=plan["conversation_ids"],
            goal_ids=plan["goal_ids"],
            episode_ids=plan["episode_ids"],
        ),
    )
    removed, _paths, removed_turns = world.erase_conversations(
        [conversation.id],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )
    assert len(removed) == 601
    assert removed_turns == 1
    persist_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    )
    report = verify_erasure(
        "large-user",
        channel="telegram",
        receipt=signed,
        world=world,
    )
    assert report["clean"] is True


def test_plan_change_aborts_before_any_mutation(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    seeded = _seed_complete_graph(world, tmp_path / "private.txt")
    plan, manifest = _manifest_for(world, seeded["conversation_id"])
    persist_receipt(world, manifest)
    late_child = world.create_goal(
        "arrived after receipt",
        parent_id=seeded["goal_ids"][-1],
    )

    with pytest.raises(ErasurePlanChanged, match="closure changed"):
        world.erase_conversations(
            [seeded["conversation_id"]],
            expected_conversation_ids=plan["conversation_ids"],
            expected_goal_ids=plan["goal_ids"],
            expected_episode_ids=plan["episode_ids"],
        )

    assert world.get_goal(seeded["goal_ids"][0]) is not None
    assert world.get_goal(late_child) is not None
    assert world.list_conversations("telegram")


def test_episode_added_after_receipt_aborts_before_any_mutation(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    seeded = _seed_complete_graph(world, tmp_path / "private.txt")
    plan, manifest = _manifest_for(world, seeded["conversation_id"])
    persist_receipt(world, manifest)
    late_episode = world.start_episode(seeded["goal_ids"][-1])

    with pytest.raises(ErasurePlanChanged, match="closure changed"):
        world.erase_conversations(
            [seeded["conversation_id"]],
            expected_conversation_ids=plan["conversation_ids"],
            expected_goal_ids=plan["goal_ids"],
            expected_episode_ids=plan["episode_ids"],
        )

    assert world.get_goal(seeded["goal_ids"][0]) is not None
    assert world.conn.execute(
        "SELECT COUNT(*) FROM episodes WHERE id = ?",
        (late_episode,),
    ).fetchone()[0] == 1
    assert world.list_conversations("telegram")


def test_history_only_subject_fact_is_a_residual_not_a_false_clean(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    conversation = world.get_or_create_conversation("telegram", "alice")
    world._temporal_memory = True
    key = "user:telegram:alice:preference"
    world.upsert_fact(key, "private historical preference")
    assert world.delete_fact(key) == 1
    assert world.facts_matching("telegram:alice") == {}
    assert world.fact_history_matching("telegram:alice")

    plan = world.plan_conversation_erasure([conversation.id])
    signed = persist_receipt(
        world,
        build_manifest(
            tenant_id="shared",
            conversation_ids=plan["conversation_ids"],
            goal_ids=plan["goal_ids"],
            episode_ids=plan["episode_ids"],
        ),
    )
    world.erase_conversations(
        [conversation.id],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )
    persist_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    )

    report = verify_erasure(
        "alice",
        channel="telegram",
        receipt=signed,
        world=world,
    )
    assert report["counts"]["facts"] == 0
    assert report["counts"]["fact_history"] == 1
    assert report["residual"]["fact_history"] == 1
    assert report["clean"] is False


def test_orphaned_episode_fact_ids_remain_receipt_verifiable(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    seeded = _seed_complete_graph(world, tmp_path / "private.txt")
    plan, manifest = _manifest_for(world, seeded["conversation_id"])
    signed = persist_receipt(world, manifest)
    world.erase_conversations(
        [seeded["conversation_id"]],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )
    episode_id = plan["episode_ids"][0]
    # Emulate a backend defect/orphan after the episode row has disappeared.
    # The v2 receipt carries exact episode ids, so verification does not need
    # the deleted parent row to find these residuals.
    world.conn.execute("PRAGMA foreign_keys = OFF")
    with world._writing() as conn:
        conn.execute(
            "INSERT INTO facts(key, value, source_episode_id, updated_at) "
            "VALUES(?, ?, ?, ?)",
            ("orphan-private-fact", "private", episode_id, time.time()),
        )
        conn.execute(
            "INSERT INTO fact_history("
            "key, value, source_episode_id, valid_from"
            ") VALUES(?, ?, ?, ?)",
            ("orphan-private-fact", "private", episode_id, time.time()),
        )
    world.conn.execute("PRAGMA foreign_keys = ON")
    persist_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    )

    report = verify_erasure(
        "alice",
        channel="telegram",
        receipt=signed,
        world=world,
    )
    assert report["residual"]["episode_facts"] == 1
    assert report["residual"]["episode_fact_history"] == 1
    assert report["clean"] is False


def test_unsigned_same_process_manifest_counts_but_never_certifies(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    seeded = _seed_complete_graph(world, tmp_path / "private.txt")
    plan, manifest = _manifest_for(world, seeded["conversation_id"])
    world.erase_conversations(
        [seeded["conversation_id"]],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )

    report = verify_erasure(
        "alice",
        channel="telegram",
        receipt=manifest,
        world=world,
    )

    assert all(report["counts"][store] == 0 for store in RECEIPT_STORES)
    assert report["durable_proof"] is False
    assert report["indeterminate"] is True
    assert report["clean"] is False
    assert "erasure_receipt" in report["errors"]


def test_signed_scope_receipt_without_auxiliary_closure_never_certifies(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    seeded = _seed_complete_graph(world, tmp_path / "private.txt")
    plan, manifest = _manifest_for(world, seeded["conversation_id"])
    signed = persist_receipt(world, manifest)
    world.erase_conversations(
        [seeded["conversation_id"]],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )

    report = verify_erasure(
        "alice",
        channel="telegram",
        receipt=signed,
        world=world,
    )

    assert report["durable_proof"] is True
    assert report["durable_closure"] is False
    assert report["clean"] is False
    assert report["indeterminate"] is True
    assert set(AUXILIARY_ERASURE_STORES).issubset(report["errors"])


def test_auxiliary_closure_is_subject_free_idempotent_and_tamper_evident(
    tmp_path,
):
    world = WorldModel(tmp_path / "world.db")
    signed = persist_receipt(
        world,
        build_manifest(
            tenant_id="shared",
            conversation_ids=[1],
            goal_ids=[],
        ),
    )
    closure = persist_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    )
    repeated = persist_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    )

    assert repeated == closure
    raw = world.get_erasure_receipt(
        closure["closure_id"],
        tenant_id="shared",
    )
    assert raw is not None
    assert "alice" not in raw
    assert "telegram" not in raw
    assert "user_id" not in raw

    with world._writing() as conn:
        conn.execute("DROP TRIGGER erasure_receipts_no_update")
        tampered = json.loads(raw)
        tampered["stores"]["attachment_files"] = 1
        conn.execute(
            "UPDATE erasure_receipts SET manifest = ? WHERE receipt_id = ?",
            (_canonical(tampered), closure["closure_id"]),
        )

    with pytest.raises(
        ErasureReceiptError,
        match="prove every auxiliary store|digest is invalid",
    ):
        load_verified_erasure_closure(
            world,
            signed,
            expected_tenant="shared",
        )


def test_bare_posthoc_subject_scan_never_overclaims(tmp_path):
    world = WorldModel(tmp_path / "world.db")

    report = verify_erasure("nobody", channel="telegram", world=world)

    assert report["residual"] == {}
    assert report["clean"] is False
    assert report["indeterminate"] is True
    assert report["durable_proof"] is False
    assert set(GOAL_LINKED_STORES).issubset(report["errors"])


def test_missing_receipt_and_one_store_failure_are_indeterminate(
    tmp_path,
    monkeypatch,
):
    world = WorldModel(tmp_path / "world.db")
    missing = verify_erasure(
        "nobody",
        channel="telegram",
        receipt_id="0" * 32,
        world=world,
    )
    assert missing["clean"] is False
    assert missing["indeterminate"] is True
    assert "not found" in missing["errors"]["erasure_receipt"]

    seeded = _seed_complete_graph(world, tmp_path / "private.txt")
    plan, manifest = _manifest_for(world, seeded["conversation_id"])
    signed = persist_receipt(world, manifest)
    world.erase_conversations(
        [seeded["conversation_id"]],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )
    persist_erasure_closure(
        world,
        signed,
        expected_tenant="shared",
    )
    original = world.count_erasure_receipt_store

    def fail_one_store(store, conversation_ids, goal_ids, episode_ids):
        if store == "share_links":
            raise OSError("share-link index unavailable")
        return original(store, conversation_ids, goal_ids, episode_ids)

    monkeypatch.setattr(world, "count_erasure_receipt_store", fail_one_store)
    partial = verify_erasure(
        "alice",
        channel="telegram",
        receipt=signed,
        world=world,
    )
    assert partial["clean"] is False
    assert partial["indeterminate"] is True
    assert partial["stores"]["share_links"]["checked"] is False
    assert partial["stores"]["signoffs"]["checked"] is True
    assert "share-link index unavailable" in partial["errors"]["share_links"]


def test_storage_immutability_retention_and_signature_tamper_detection(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    current = persist_receipt(
        world,
        build_manifest(
            tenant_id="shared",
            conversation_ids=[1],
            goal_ids=[2],
        ),
    )

    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        with world._writing() as conn:
            conn.execute(
                "UPDATE erasure_receipts SET manifest = '{}' "
                "WHERE receipt_id = ?",
                (current["receipt_id"],),
            )
    with pytest.raises(sqlite3.DatabaseError, match="retention is active"):
        with world._writing() as conn:
            conn.execute(
                "DELETE FROM erasure_receipts WHERE receipt_id = ?",
                (current["receipt_id"],),
            )

    old = datetime.now(timezone.utc) - timedelta(days=365 * 8)
    expired = persist_receipt(
        world,
        build_manifest(
            tenant_id="shared",
            conversation_ids=[3],
            goal_ids=[],
            now=old,
        ),
    )
    with pytest.raises(ErasureReceiptError, match="expired"):
        load_verified_receipt(
            world,
            expired["receipt_id"],
            expected_tenant="shared",
        )
    assert retire_expired_receipts(world, tenant_id="shared") == 1
    assert world.get_erasure_receipt(
        expired["receipt_id"],
        tenant_id="shared",
    ) is None
    assert world.get_erasure_receipt(
        current["receipt_id"],
        tenant_id="shared",
    ) is not None

    with world._writing() as conn:
        conn.execute("DROP TRIGGER erasure_receipts_no_update")
        raw = conn.execute(
            "SELECT manifest FROM erasure_receipts WHERE receipt_id = ?",
            (current["receipt_id"],),
        ).fetchone()[0]
        tampered = json.loads(raw)
        tampered["goal_ids"] = sorted(set([*tampered["goal_ids"], 999]))
        conn.execute(
            "UPDATE erasure_receipts SET manifest = ? WHERE receipt_id = ?",
            (_canonical(tampered), current["receipt_id"]),
        )

    with pytest.raises(ErasureReceiptError, match="digest is invalid"):
        load_verified_receipt(
            world,
            current["receipt_id"],
            expected_tenant="shared",
        )


def test_v28_sqlite_database_migrates_to_receipt_schema(tmp_path):
    path = tmp_path / "legacy.db"
    WorldModel(path).close()
    conn = sqlite3.connect(path)
    try:
        conn.execute("DROP TRIGGER erasure_receipts_no_early_delete")
        conn.execute("DROP TRIGGER erasure_receipts_no_update")
        conn.execute("DROP TABLE erasure_receipts")
        conn.execute("UPDATE schema_version SET version = 28")
        conn.commit()
    finally:
        conn.close()

    upgraded = WorldModel(path)
    assert upgraded.schema_version == SCHEMA_VERSION
    objects = {
        (row[0], row[1])
        for row in upgraded.conn.execute(
            "SELECT name, type FROM sqlite_master "
            "WHERE name LIKE 'erasure_receipts%'"
        )
    }
    assert ("erasure_receipts", "table") in objects
    assert ("erasure_receipts_no_update", "trigger") in objects
    assert ("erasure_receipts_no_early_delete", "trigger") in objects


def _cli_world() -> WorldModel:
    return WorldModel(Path.home() / ".maverick" / "world.db")


def test_cli_emits_opaque_receipt_and_supports_posthoc_proof():
    world = _cli_world()
    _seed_complete_graph(world, Path.home() / "private.txt")
    world.close()

    erased = CliRunner().invoke(
        main,
        ["erase", "--channel", "telegram", "--user", "alice", "--yes"],
    )
    assert erased.exit_code == 0, erased.output
    match = re.search(r"erasure receipt: ([0-9a-f]{32})", erased.output)
    assert match is not None
    assert "conversation_ids" not in erased.output
    assert "goal_ids" not in erased.output
    assert "durable proof: yes" in erased.output
    assert "verification: CLEAN" in erased.output

    proof = CliRunner().invoke(
        main,
        [
            "erase-verify",
            "--channel",
            "telegram",
            "--user",
            "alice",
            "--receipt-id",
            match.group(1),
        ],
    )
    assert proof.exit_code == 0, proof.output
    assert "CLEAN" in proof.output


def _assert_cli_auxiliary_failure_withholds_certificate(
    monkeypatch,
    failure_surface: str,
) -> None:
    from maverick import cli as cli_module

    world = _cli_world()
    _seed_complete_graph(world, Path.home() / "private.txt")
    world.close()

    if failure_surface == "attachment":
        monkeypatch.setattr(
            cli_module,
            "_unlink_erasure_attachments",
            lambda _paths: (0, ["OSError (errno 5)"]),
        )
    elif failure_surface == "user_notes":
        from maverick import user_notes

        monkeypatch.setattr(
            user_notes,
            "erase_notes",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError(5, "note write denied")
            ),
        )
    elif failure_surface == "llm_cache":
        from maverick.cache import llm as llm_cache

        cache_path = Path.home() / "cache.sqlite3"
        cache_path.write_bytes(b"present")
        monkeypatch.setattr(llm_cache, "default_db_path", lambda: cache_path)
        monkeypatch.setattr(
            llm_cache,
            "LLMCache",
            lambda: (_ for _ in ()).throw(OSError(5, "cache write denied")),
        )
    elif failure_surface == "audit_scrub":
        from maverick import audit

        monkeypatch.setattr(
            audit,
            "scrub_user",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError(5, "audit rewrite denied")
            ),
        )
    elif failure_surface == "audit_record":
        from maverick import audit

        monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    else:  # pragma: no cover - test helper contract
        raise AssertionError(f"unsupported failure surface: {failure_surface}")

    erased = CliRunner().invoke(
        main,
        ["erase", "--channel", "telegram", "--user", "alice", "--yes"],
    )
    assert erased.exit_code == 0, erased.output
    assert "verification: CLEAN" not in erased.output
    assert "auxiliary closure: no" in erased.output
    assert "without a clean certificate" in erased.output

    match = re.search(r"erasure receipt: ([0-9a-f]{32})", erased.output)
    assert match is not None
    proof = CliRunner().invoke(
        main,
        [
            "erase-verify",
            "--channel",
            "telegram",
            "--user",
            "alice",
            "--receipt-id",
            match.group(1),
        ],
    )
    assert proof.exit_code == 1, proof.output
    assert "INDETERMINATE" in proof.output


@pytest.mark.parametrize(
    "failure_surface",
    [
        "attachment",
        "user_notes",
        "llm_cache",
        "audit_scrub",
        "audit_record",
    ],
)
def test_cli_auxiliary_failures_never_emit_false_clean(
    monkeypatch,
    failure_surface,
):
    _assert_cli_auxiliary_failure_withholds_certificate(
        monkeypatch,
        failure_surface,
    )


def test_cli_audit_policy_refusal_propagates_after_deletion(monkeypatch):
    from maverick import audit
    from maverick.audit import AuditWriteRefused

    world = _cli_world()
    seeded = _seed_complete_graph(world, Path.home() / "private.txt")
    world.close()

    def refuse(*_args, **_kwargs):
        raise AuditWriteRefused("configured signing floor refused the row")

    monkeypatch.setattr(audit, "record", refuse)
    erased = CliRunner().invoke(
        main,
        ["erase", "--channel", "telegram", "--user", "alice", "--yes"],
    )

    assert erased.exit_code == 1
    assert isinstance(erased.exception, AuditWriteRefused)
    assert "verification: CLEAN" not in erased.output
    # The subject deletion committed before the external audit sink refused;
    # the command must report failure without pretending it rolled back.
    check = _cli_world()
    assert check.get_goal(seeded["goal_ids"][0]) is None
    assert check.list_conversations("telegram") == []


def test_receipt_failure_does_not_block_cli_deletion(monkeypatch):
    world = _cli_world()
    seeded = _seed_complete_graph(world, Path.home() / "private.txt")
    world.close()

    def signing_outage(*_args, **_kwargs):
        raise OSError("off-host signer unavailable")

    monkeypatch.setattr(
        "maverick.erasure_receipts.persist_receipt",
        signing_outage,
    )
    erased = CliRunner().invoke(
        main,
        ["erase", "--channel", "telegram", "--user", "alice", "--yes"],
    )

    assert erased.exit_code == 0, erased.output
    assert "deletion will continue" in erased.output
    assert "durable proof: no" in erased.output
    assert "without a clean certificate" in erased.output
    check = _cli_world()
    assert check.get_goal(seeded["goal_ids"][0]) is None
    assert check.list_conversations("telegram") == []


def test_manifest_failure_still_uses_the_in_memory_plan_for_deletion(
    monkeypatch,
):
    world = _cli_world()
    seeded = _seed_complete_graph(world, Path.home() / "private.txt")
    world.close()

    def manifest_outage(*_args, **_kwargs):
        raise RuntimeError("manifest builder unavailable")

    monkeypatch.setattr(
        "maverick.erasure_receipts.build_manifest",
        manifest_outage,
    )
    erased = CliRunner().invoke(
        main,
        ["erase", "--channel", "telegram", "--user", "alice", "--yes"],
    )

    assert erased.exit_code == 0, erased.output
    assert "manifest could not be created" in erased.output
    assert "verification will remain indeterminate" in erased.output
    assert "without a clean certificate" in erased.output
    check = _cli_world()
    assert check.get_goal(seeded["goal_ids"][0]) is None
    assert check.list_conversations("telegram") == []


class _PostgresEraseCursor:
    def __init__(self):
        self.calls: list[tuple[str, tuple | None]] = []
        self.rowcount = 0
        self._rows = iter(
            [
                [(10, "slack", "alice")],
                [(20,)],
                [(20,), (21,), (22,)],
                [(30,)],
                [("/tmp/private.txt",)],
            ]
        )

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))
        self.rowcount = 2 if sql.lstrip().startswith("DELETE FROM turns") else 1

    def fetchall(self):
        return next(self._rows)


def test_postgres_delete_contract_covers_descendants_and_every_child(
    monkeypatch,
):
    from maverick.world_model_backends import postgres

    cursor = _PostgresEraseCursor()
    world = postgres.PostgresWorldModel.__new__(postgres.PostgresWorldModel)

    @contextmanager
    def tx():
        yield cursor

    monkeypatch.setattr(world, "_tx", tx)
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: True)

    goals, paths, turns = world.erase_conversations(
        [10],
        expected_conversation_ids=[10],
        expected_goal_ids=[20, 21, 22],
        expected_episode_ids=[30],
    )

    assert goals == {20, 21, 22}
    assert paths == ["/tmp/private.txt"]
    assert turns == 2
    statements = "\n".join(sql for sql, _params in cursor.calls)
    assert "WITH RECURSIVE goal_tree" in statements
    assert statements.count("g.tenant_id = %s") >= 3
    for table in (
        "artifacts",
        "attachments",
        "goal_events",
        "goal_origins",
        "messages",
        "processed_messages",
        "questions",
        "share_links",
        "signoffs",
    ):
        assert f"DELETE FROM {table} WHERE goal_id = ANY(%s)" in statements
    assert "DELETE FROM fact_history" in statements
    assert "DELETE FROM facts" in statements
    assert "DELETE FROM episodes" in statements
    assert "DELETE FROM goals" in statements
    assert "DELETE FROM conversations" in statements
