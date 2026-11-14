"""Workspace recovery and tenant-bound writes keep their original authority."""
from __future__ import annotations

import io
import json
import tarfile

import pytest


def test_pilot_recording_requires_current_enrollment(tmp_path, monkeypatch):
    from maverick.work_discovery import CapturePolicy
    from maverick.work_discovery_planning import OpportunityPlans
    from maverick.work_discovery_store import EnrollmentRequired, WorkDiscoveryStore

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    store = WorkDiscoveryStore("owner", "device", tenant="acme", clock=lambda: 1800000000,
                               authority_check=lambda _: None)
    store.enroll(CapturePolicy(enabled=True, capture_level="guided"))
    plans = OpportunityPlans(store)
    with store._transaction() as conn:
        plan = plans._write(conn, {
            "opportunity_id": "a" * 24, "assumptions": {}, "samples": [],
            "stage": "pilot", "expires_at": 1800086400,
        })
    store.revoke_enrollment()
    with pytest.raises(EnrollmentRequired):
        plans.record_run(plan["opportunity_id"], expected_revision=plan["revision"], sample={
            "sample_id": "pilot-one", "manual_minutes": 10,
            "remaining_minutes": 3, "accepted": True,
        })
    assert plans.list()[0]["samples"] == []
    assert plans.delete(plan["opportunity_id"], expected_revision=plan["revision"])


def test_snapshot_rejects_later_unsafe_member_before_first_write(tmp_path):
    from maverick.workspace_snapshot import restore_snapshot

    store = tmp_path / "store"
    store.mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    existing = dest / "first.txt"
    existing.write_text("keep this current file")
    with tarfile.open(store / "snap-0001.tar.gz", "w:gz") as archive:
        first = tarfile.TarInfo("first.txt")
        first.size = 3
        archive.addfile(first, io.BytesIO(b"old"))
        archive.addfile(tarfile.TarInfo("../escape"), io.BytesIO())
    with pytest.raises(ValueError, match="unsafe"):
        restore_snapshot(store, "snap-0001", dest)
    assert existing.read_text() == "keep this current file"
    assert not (tmp_path / "escape").exists()


def test_dek_cache_uses_the_requested_tenants_ttl(tmp_path, monkeypatch):
    from maverick import config
    from maverick.tenant import kms

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_KMS_DEK_CACHE_TTL", raising=False)
    monkeypatch.setattr(config, "load_config", lambda: {"kms": {"dek_cache_ttl": 0}})
    clock = [1000.0]
    monkeypatch.setattr(kms, "_now", lambda: clock[0])
    for tenant, ttl in (("short", 1), ("long", 100)):
        directory = tmp_path / "tenants" / tenant
        directory.mkdir(parents=True)
        (directory / "config.toml").write_text(f"[kms]\ndek_cache_ttl = {ttl}\n")

    class CountingKMS:
        def __init__(self):
            self.unwraps = 0

        def wrap(self, value, *, context=None):
            return value

        def unwrap(self, value, *, context=None):
            self.unwraps += 1
            return value

    short, long = CountingKMS(), CountingKMS()
    kms._clear_cache()
    try:
        kms.tenant_dek("short", kms=short)
        kms.tenant_dek("long", kms=long)
        clock[0] += 2
        kms.tenant_dek("short", kms=short)
        kms.tenant_dek("long", kms=long)
        assert (short.unwraps, long.unwraps) == (1, 0)
        monkeypatch.setenv("MAVERICK_KMS_DEK_CACHE_TTL", "1")
        kms.tenant_dek("long", kms=long)
        assert long.unwraps == 1
        monkeypatch.setenv("MAVERICK_KMS_DEK_CACHE_TTL", "nan")
        kms.tenant_dek("long", kms=long)  # an invalid lifetime bypasses the cache
        assert long.unwraps == 2
    finally:
        kms._clear_cache()


def test_replaced_and_expired_reviews_retire_only_unused_safety_snapshots(tmp_path, monkeypatch):
    from maverick import backup, client, config, file_lock
    from maverick import workspace_recovery as recovery
    from maverick.paths import data_dir

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    for name in ("MAVERICK_TENANT", "MAVERICK_WORLD_BACKEND", "MAVERICK_PG_DSN",
                 "MAVERICK_BACKUP_SIGNING_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    client.reset_client_cache()
    try:
        root = file_lock.ensure_private_directory(data_dir())
        (root / "record.txt").write_text("original")
        recovery.configure_key()
        snapshot = recovery.create()
        first = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin")
        monkeypatch.setattr(recovery, "MAX_SNAPSHOTS", 2)
        second = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin")
        assert not (recovery._store() / (first["safety_snapshot"] + ".tgz")).exists()
        assert {r["id"] for r in recovery.list_snapshots()} == {snapshot["id"], second["safety_snapshot"]}
        review_path = recovery._store() / "review.json"
        review = json.loads(review_path.read_text())
        review.pop("authentication")
        review["expires_at"] = 1
        file_lock.atomic_write_text(review_path, json.dumps(backup._authenticate_for_write(review, recovery._key())))
        receipt_path = recovery._store() / "last-restore.json"
        file_lock.atomic_write_text(receipt_path, json.dumps(backup._authenticate_for_write({
            "state": "completion_unconfirmed", "snapshot": snapshot["id"],
            "safety_snapshot": second["safety_snapshot"],
        }, recovery._key())))
        with pytest.raises(recovery.RecoveryError, match="snapshot limit"):
            recovery.create()
        assert recovery._archive(second["safety_snapshot"]).exists()
        # A protected review is consumed, but its archive remains referenced
        # by the restore receipt. Reinstall the same signed expired review to
        # exercise cleanup once that independent retention hold is absent.
        receipt_path.unlink()
        file_lock.atomic_write_text(review_path, json.dumps(backup._authenticate_for_write(review, recovery._key())))
        created = recovery.create()
        assert not (recovery._store() / (second["safety_snapshot"] + ".tgz")).exists()
        assert recovery._archive(created["id"]).exists()
    finally:
        client.reset_client_cache()


def test_scoped_postgres_questions_require_a_goal(postgres_test_dsn, monkeypatch):
    from maverick.paths import tenant_scope
    from maverick.world_model_backends import postgres
    from maverick.world_model_backends.postgres import PostgresWorldModel

    world = PostgresWorldModel(dsn=postgres_test_dsn)
    try:
        with tenant_scope(tenant="question-owner"):
            with pytest.raises(ValueError, match="goal"):
                world.ask("which record?")
            goal = world.create_goal("review")
            question = world.ask("which record?", goal_id=goal)
            assert [q.id for q in world.open_questions()] == [question]
        with tenant_scope(tenant="another-owner"):
            assert world.open_questions() == []
            assert not world.answer(question, "foreign answer")
        with tenant_scope(tenant="question-owner"):
            assert world.answer(question, "the reviewed record")
        monkeypatch.setattr(postgres, "_active_tenant", lambda: None)
        assert world.ask("legacy shared question") > 0
    finally:
        world.close()


def test_postgres_legacy_backfill_filters_malformed_operations(postgres_test_dsn, caplog):
    import hashlib

    from maverick.provider_cost_cap import _OPERATION_ID
    from maverick.world_model_backends.postgres import PostgresWorldModel

    world = PostgresWorldModel(dsn=postgres_test_dsn)
    operation = {"operation_id": "valid-operation", "attempt_no": 1, "category": "inference",
                 "parent_category": "inference", "service": None}
    operations = [operation,
                  {**operation, "operation_id": []},
                  {**operation, "operation_id": None},
                  {**operation, "attempt_no": "bad"},
                  {**operation, "attempt_no": 1.5},
                  {**operation, "attempt_no": 10 ** 30},
                  {**operation, "attempt_no": True},
                  {**operation, "category": None}]
    identifiers = ["v" * 192, "x" * 193, "bad space", "bad\n", "non-ascii-é",
                   "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(128))]
    operations.extend({**operation, "operation_id": identifier} for identifier in identifiers)
    accepted = ["valid-operation", *(identifier for identifier in identifiers if _OPERATION_ID.fullmatch(identifier))]
    receipts = {f"request-{index}": {"operation": item} for index, item in enumerate(operations)}
    receipts["bad-scope"] = {"operation": operation, "operation_scope_sha256": identifiers[-1]}
    receipts[identifiers[-1]] = {"operation": {**operation, "operation_id": "another-valid-operation"}}
    raw = json.dumps(receipts)
    try:
        with world._tx() as cursor:
            cursor.execute("INSERT INTO provider_cap_receipts VALUES (%s, %s, %s)",
                           ("2026-11", "test-provider", raw))
            cursor.execute("INSERT INTO provider_spend VALUES (%s, %s, %s)",
                           ("2026-11", "test-provider", 12.5))
            world._backfill_provider_operation_attempts(cursor)
        with world._tx() as cursor:
            cursor.execute("SELECT operation_id, attempt_no FROM provider_operation_attempts ORDER BY operation_id")
            assert cursor.fetchall() == [(identifier, 1) for identifier in sorted(accepted)]
            cursor.execute("SELECT receipts_json FROM provider_cap_receipts")
            assert cursor.fetchone()[0] == raw
            cursor.execute("SELECT dollars FROM provider_spend")
            assert cursor.fetchone()[0] == 12.5
            world._backfill_provider_operation_attempts(cursor)
        assert f"Skipped {len(receipts) - len(accepted)} malformed legacy provider operation receipt(s)" in caplog.text
    finally:
        world.close()


@pytest.mark.parametrize("damage", ["truncated", "bad-signature", "moved-home"])
def test_unusable_pending_review_never_blocks_recovery(tmp_path, monkeypatch, caplog, damage):
    import shutil

    from maverick import client, config, file_lock
    from maverick import workspace_recovery as recovery
    from maverick.paths import data_dir

    home = tmp_path / "home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    for name in ("MAVERICK_TENANT", "MAVERICK_WORLD_BACKEND", "MAVERICK_PG_DSN",
                 "MAVERICK_BACKUP_SIGNING_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    client.reset_client_cache()
    try:
        root = file_lock.ensure_private_directory(data_dir())
        (root / "record.txt").write_text("original")
        recovery.configure_key()
        snapshot = recovery.create()
        pending = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin")
        review_path = recovery._store() / "review.json"
        if damage == "truncated":
            review_path.write_text(review_path.read_text()[:40])
        elif damage == "bad-signature":
            review = json.loads(review_path.read_text())
            review["expires_at"] = 1
            review_path.write_text(json.dumps(review))
        else:
            moved = tmp_path / "moved"
            shutil.copytree(home, moved)
            monkeypatch.setenv("MAVERICK_HOME", str(moved))
            client.reset_client_cache()
            review_path = recovery._store() / "review.json"
        safety = recovery._archive(pending["safety_snapshot"])
        assert safety.exists()
        created = recovery.create()
        assert recovery._archive(created["id"]).exists()
        assert safety.exists()
        assert not review_path.exists()
        assert list(recovery._store().glob("review.json.unusable-*"))
        assert "review.json" in caplog.text
        again = recovery.prepare_restore(snapshot["id"], isolated=True, actor="admin")
        assert again["safety_snapshot"] != pending["safety_snapshot"]
        assert safety.exists()
    finally:
        client.reset_client_cache()


def test_unreadable_dek_cache_policy_unwraps_again_instead_of_refusing(tmp_path, monkeypatch, caplog):
    from maverick.tenant import kms

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    global_config = tmp_path / "config.toml"
    global_config.write_text("[kms]\ndek_cache_ttl = 100\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(global_config))
    monkeypatch.delenv("MAVERICK_KMS_DEK_CACHE_TTL", raising=False)
    (tmp_path / "tenants" / "acme").mkdir(parents=True)

    class CountingKMS:
        unwraps = 0

        def wrap(self, value, *, context=None):
            return value

        def unwrap(self, value, *, context=None):
            self.unwraps += 1
            return value

    counting = CountingKMS()
    kms._clear_cache()
    try:
        dek = kms.tenant_dek("acme", kms=counting)
        assert kms.tenant_dek("acme", kms=counting) == dek and counting.unwraps == 0
        global_config.write_text("[kms\ndek_cache_ttl = 100\n")  # one typo
        assert kms.tenant_dek("acme", kms=counting) == dek
        assert counting.unwraps == 1  # the cache was bypassed, not trusted
        monkeypatch.setenv("MAVERICK_KMS_DEK_CACHE_TTL", "nan")
        assert kms.tenant_dek("acme", kms=counting) == dek
        assert counting.unwraps == 2
        assert "data-key cache" in caplog.text
    finally:
        kms._clear_cache()


def test_postgres_legacy_backfill_skips_duplicate_operation_attempts(postgres_test_dsn, caplog):
    from maverick.world_model_backends.postgres import PostgresWorldModel

    world = PostgresWorldModel(dsn=postgres_test_dsn)
    operation = {"operation_id": "shared-operation", "attempt_no": 1, "category": "inference",
                 "parent_category": "inference", "service": None}
    try:
        with world._tx() as cursor:
            cursor.execute("INSERT INTO provider_cap_receipts VALUES (%s, %s, %s)", (
                "2026-11", "test-provider",
                json.dumps({"request-a": {"operation": operation}, "request-b": {"operation": operation}})))
            cursor.execute("INSERT INTO provider_cap_receipts VALUES (%s, %s, %s)", (
                "2026-11", "other-provider", json.dumps({"request-c": {"operation": operation}})))
            world._backfill_provider_operation_attempts(cursor)
        with world._tx() as cursor:
            cursor.execute("SELECT operation_id, attempt_no FROM provider_operation_attempts")
            assert cursor.fetchall() == [("shared-operation", 1)]
            cursor.execute("SELECT count(*) FROM provider_cap_receipts")
            assert cursor.fetchone()[0] == 2
        assert "Skipped 2 duplicate legacy provider operation receipt(s)" in caplog.text
    finally:
        world.close()
