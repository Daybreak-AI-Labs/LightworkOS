"""Offline A2A migration against disposable native PostgreSQL, with no providers."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sqlite3
import subprocess
import sys
import time

import pytest
from maverick import a2a_migration as migration
from maverick import control_plane_lease, crypto_at_rest
from maverick.a2a_store import META_ID, SharedTaskStore
from maverick.a2a_tasks import TaskEngine, _DurableTaskStore, _RpcError
from maverick.file_lock import (
    atomic_create_bytes,
    atomic_read_text,
    ensure_private_directory,
    private_path_is_restricted,
)
from maverick.governed_records import GovernedRecordBackendError
from maverick.paths import data_dir, tenant_scope

from test_support.postgres_authority import authority as authority

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"), reason="dedicated Postgres service unavailable")


@pytest.fixture
def shared_migration(authority, monkeypatch):
    backend, _, _ = authority
    monkeypatch.setenv("MAVERICK_PG_DSN", backend()._dsn)
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    control_plane_lease.release()
    yield
    control_plane_lease.release()


def _msg(number):
    return {"message": {"role": "user", "parts": [{"kind": "text", "text": f"effect-{number}"}],
                        "messageId": f"migrate-{number}"}}


def _source(count=3):
    """Use the legacy owner directly; shared routing correctly refuses local files."""
    calls = []
    with tenant_scope(tenant="alpha"):
        engine = TaskEngine(runner=lambda text, **kwargs: calls.append(text) or "settled")
        engine._store = _DurableTaskStore()
        tasks = []
        for number in range(count):
            task, created = engine._new_or_existing_task(_msg(number), "agent:alice")
            assert created
            if number != 1:
                asyncio.run(engine._run(task))
            tasks.append(task)
        source = data_dir("a2a", "tasks.sqlite3")
        # A well-formed retained-consumption tombstone models the legacy store's
        # terminal body eviction, without shrinking unrelated product quotas.
        if count > 2:
            with contextlib.closing(sqlite3.connect(source)) as connection, connection:
                connection.execute("UPDATE a2a_task_claims SET status='tombstone', snapshot_json=NULL WHERE task_id=?", (tasks[2].id,))
                connection.execute(
                    "UPDATE a2a_task_meta SET snapshot_bytes=(SELECT COALESCE(SUM(length(CAST(snapshot_json AS BLOB))),0) "
                    "FROM a2a_task_claims WHERE tenant='alpha') WHERE tenant='alpha'")
        with contextlib.closing(sqlite3.connect(source)) as connection:
            rows = connection.execute("SELECT * FROM a2a_task_claims ORDER BY principal,message_key").fetchall()
    return source, tasks, calls, rows


def _meta():
    with SharedTaskStore()._batch("alpha") as batch:
        return batch.load(META_ID)


def _assert_consumed(tasks, calls):
    count = len(calls)
    with tenant_scope(tenant="alpha"):
        engine = TaskEngine(runner=lambda text, **kwargs: calls.append("DUPLICATE") or "wrong", durable=True)
        result = asyncio.run(engine.send(_msg(0), "agent:alice"))
        assert result == tasks[0].to_dict()
        with pytest.raises(_RpcError, match="indeterminate"):
            asyncio.run(engine.send(_msg(1), "agent:alice"))
        if len(tasks) > 2:
            with pytest.raises(_RpcError, match="consumed|expired"):
                asyncio.run(engine.send(_msg(2), "agent:alice"))
    assert len(calls) == count


def test_migration_preserves_terminal_unknown_and_tombstone_across_multiple_pages(shared_migration):
    source, tasks, calls, before = _source(43)
    result = migration.migrate_local_tasks("alpha")
    assert result["status"] == "complete" and result["source_claims"] == 43
    assert not source.exists()
    archive = source.with_name(result["archive"])
    assert private_path_is_restricted(archive, 0o600)
    with contextlib.closing(sqlite3.connect(archive)) as connection:
        assert connection.execute("SELECT * FROM a2a_task_claims ORDER BY principal,message_key").fetchall() == before
    marker = source.with_suffix(".authority.sealed")
    assert crypto_at_rest.is_sealed_str(marker.read_text())
    meta = _meta()
    assert meta["state"] == "ready" and meta["imported_count"] == meta["claim_count"] == 43
    assert meta["snapshot_bytes"] == result["target_snapshot_bytes"]
    _assert_consumed(tasks, calls)
    assert migration.migrate_local_tasks("alpha") == result
    assert not source.exists()


_INTERRUPT_CHILD = r'''
import sys, time, traceback
from pathlib import Path
from maverick import a2a_migration as migration
from maverick.governed_record_batch import RecordBatch
from maverick.file_lock import atomic_write_text
stage, ready = sys.argv[1:]
def pause():
    atomic_write_text(Path(ready), "owned interruption boundary reached")
    while True:
        time.sleep(1)
save = RecordBatch.save
claims = 0
def controlled_save(self, record, **kwargs):
    global claims
    saved = save(self, record, **kwargs)
    if record["id"].startswith("a2-c-"):
        claims += 1
        if stage == "second-page-uncommitted" and claims == 25:
            pause()
    return saved
RecordBatch.save = controlled_save
import_page = migration._import_page
def controlled_page(batch, meta, *args):
    if stage == "first-page-committed" and meta["imported_count"] == 20:
        pause()
    return import_page(batch, meta, *args)
migration._import_page = controlled_page
archive = migration._archive_source
def controlled_archive(*args):
    if stage == "ready-before-archive":
        pause()
    return archive(*args)
migration._archive_source = controlled_archive
unlink = Path.unlink
def controlled_unlink(self, *args, **kwargs):
    is_source = self.name == "tasks.sqlite3"
    if is_source and stage == "archive-published":
        pause()
    result = unlink(self, *args, **kwargs)
    if is_source and stage == "cutover-complete":
        pause()
    return result
Path.unlink = controlled_unlink
try:
    migration.migrate_local_tasks("alpha")
except Exception as error:
    frames = traceback.extract_tb(error.__traceback__)
    safe = type(error).__name__ + ": " + "; ".join(f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}" for frame in frames)
    atomic_write_text(Path(ready + ".failure"), safe)
    raise SystemExit(3) from None
'''


@pytest.mark.parametrize("stage", ["first-page-committed", "second-page-uncommitted", "ready-before-archive", "archive-published", "cutover-complete"])
def test_actual_migration_process_kill_resumes_without_replaying_work(shared_migration, tmp_path, stage):
    source, tasks, calls, before = _source(43)
    ready = tmp_path / "migration-child-ready"
    child = subprocess.Popen([sys.executable, "-c", _INTERRUPT_CHILD, stage, str(ready)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 30
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        failure = ready.with_name(ready.name + ".failure")
        assert ready.exists(), atomic_read_text(failure) if failure.exists() else "migration child did not reach the requested boundary"
        child.kill()
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)
    meta = _meta()
    assert meta["imported_count"] == (20 if stage in {"first-page-committed", "second-page-uncommitted"} else 43)
    if stage != "cutover-complete":
        with tenant_scope(tenant="alpha"), pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(TaskEngine(runner=lambda text, **kwargs: calls.append("DUPLICATE"), durable=True).send(_msg(0), "agent:alice"))
    result = migration.migrate_local_tasks("alpha")
    assert result["status"] == "complete"
    assert not source.exists()
    with contextlib.closing(sqlite3.connect(source.with_name(result["archive"]))) as connection:
        assert connection.execute("SELECT * FROM a2a_task_claims ORDER BY principal,message_key").fetchall() == before
    _assert_consumed(tasks, calls)


def test_wrong_tenant_source_is_rejected_before_binding_or_target_creation(shared_migration):
    source, _, _, _ = _source()
    with tenant_scope(tenant="beta"):
        wrong = data_dir("a2a", "tasks.sqlite3")
    ensure_private_directory(wrong.parent)
    wrong.write_bytes(source.read_bytes())
    with pytest.raises(ValueError, match="other tenant"):
        migration.migrate_local_tasks("beta")
    assert source.exists() and wrong.exists()
    assert not wrong.with_suffix(".authority.sealed").exists()


@pytest.mark.parametrize("quota", ["_MAX_DURABLE_CLAIMS", "_MAX_DURABLE_RETAINED_BYTES"])
def test_quota_failure_keeps_local_source_and_does_not_admit_shared_work(shared_migration, monkeypatch, quota):
    source, _, _, before = _source()
    monkeypatch.setattr(migration, quota, 1)
    with pytest.raises(ValueError, match="quota"):
        migration.migrate_local_tasks("alpha")
    assert source.exists() and not source.with_suffix(".authority.sealed").exists()
    with contextlib.closing(sqlite3.connect(source)) as connection:
        assert connection.execute("SELECT * FROM a2a_task_claims ORDER BY principal,message_key").fetchall() == before


def test_source_change_between_resumed_batches_is_rejected(shared_migration, monkeypatch):
    source, _, _, _ = _source(43)
    original = migration._import_page
    def fail_after_first(batch, meta, *args):
        if meta["imported_count"] == 20:
            raise RuntimeError("controlled migration interruption")
        return original(batch, meta, *args)
    monkeypatch.setattr(migration, "_import_page", fail_after_first)
    with pytest.raises(GovernedRecordBackendError):
        migration.migrate_local_tasks("alpha")
    assert _meta()["imported_count"] == 20
    monkeypatch.setattr(migration, "_import_page", original)
    with contextlib.closing(sqlite3.connect(source)) as connection, connection:
        connection.execute("UPDATE a2a_task_claims SET request_digest=? WHERE task_id=(SELECT task_id FROM a2a_task_claims LIMIT 1)", ("a" * 64,))
    with pytest.raises(GovernedRecordBackendError):
        migration.migrate_local_tasks("alpha")
    assert _meta()["imported_count"] == 20 and source.exists()


@pytest.mark.parametrize("corruption", ["plaintext", "invalid-ciphertext", "accounting"])
def test_unverifiable_source_is_rejected_before_shared_binding(shared_migration, corruption):
    source, _, _, _ = _source()
    with contextlib.closing(sqlite3.connect(source)) as connection, connection:
        if corruption == "accounting":
            connection.execute("UPDATE a2a_task_meta SET snapshot_bytes=snapshot_bytes+1")
        else:
            row = connection.execute("SELECT task_id,snapshot_json FROM a2a_task_claims WHERE status='terminal' LIMIT 1").fetchone()
            if corruption == "plaintext":
                replacement = _DurableTaskStore._decode_snapshot("alpha", row[1])
            else:
                replacement = row[1][:-8] + "AAAAAAAA"
            connection.execute("UPDATE a2a_task_claims SET snapshot_json=? WHERE task_id=?", (replacement, row[0]))
    with pytest.raises((ValueError, crypto_at_rest.EncryptionUnavailable)):
        migration.migrate_local_tasks("alpha")
    assert source.exists() and not source.with_suffix(".authority.sealed").exists()
    assert not list(source.parent.glob("tasks.migrated-*.sqlite3"))


def test_existing_target_generation_is_not_overwritten(shared_migration):
    source, _, _, _ = _source()
    with tenant_scope(tenant="alpha"):
        original_id = SharedTaskStore().bind_authority("alpha")
    before = _meta()
    with pytest.raises(GovernedRecordBackendError):
        migration.migrate_local_tasks("alpha")
    assert _meta() == before and _meta()["authority_id"] == original_id
    assert source.exists()


def test_planted_archive_is_never_overwritten_and_cutover_can_resume(shared_migration, monkeypatch):
    source, tasks, calls, _ = _source()
    original = migration._archive_source
    planted = []
    def plant_before_archive(source, tenant, shared, authority_id, plan):
        path = migration._archive_path(source, plan["source_sha256"])
        atomic_create_bytes(path, b"different existing archive")
        planted.append(path)
        return original(source, tenant, shared, authority_id, plan)
    monkeypatch.setattr(migration, "_archive_source", plant_before_archive)
    with pytest.raises(ValueError, match="different content"):
        migration.migrate_local_tasks("alpha")
    assert source.exists() and _meta()["state"] == "ready"
    assert planted[0].read_bytes() == b"different existing archive"
    planted[0].unlink()  # Only this test's explicitly planted file is removed.
    monkeypatch.setattr(migration, "_archive_source", original)
    assert migration.migrate_local_tasks("alpha")["status"] == "complete"
    _assert_consumed(tasks, calls)


def test_archive_copy_failure_retains_source_and_resumes_from_ready(shared_migration, monkeypatch):
    source, tasks, calls, _ = _source(23)
    original = migration._file_chunks
    def fail_copy(path, *, expected_sha256=None):
        for chunk in original(path, expected_sha256=expected_sha256):
            yield chunk
            if expected_sha256 is not None:
                raise OSError("controlled archive copy interruption")
    monkeypatch.setattr(migration, "_file_chunks", fail_copy)
    with pytest.raises(OSError, match="controlled archive"):
        migration.migrate_local_tasks("alpha")
    assert source.exists() and _meta()["state"] == "ready"
    assert not list(source.parent.glob("tasks.migrated-*.sqlite3"))
    assert not list(source.parent.glob(".tasks.migrated-*.tmp"))
    monkeypatch.setattr(migration, "_file_chunks", original)
    assert migration.migrate_local_tasks("alpha")["status"] == "complete"
    _assert_consumed(tasks, calls)


def test_completed_receipt_rejects_changed_archive_without_recreating_local_authority(shared_migration):
    source, _, _, _ = _source()
    result = migration.migrate_local_tasks("alpha")
    marker = source.with_suffix(".authority.sealed").read_bytes()
    source.with_name(result["archive"]).write_bytes(b"altered retained archive")
    with pytest.raises(ValueError, match="does not match"):
        migration.migrate_local_tasks("alpha")
    assert not source.exists()
    assert source.with_suffix(".authority.sealed").read_bytes() == marker


def test_source_content_change_after_import_cannot_be_committed_as_its_archive(shared_migration, monkeypatch):
    source, _, _, _ = _source()
    original = migration._archive_source
    def change_before_archive(source, tenant, shared, authority_id, plan):
        with contextlib.closing(sqlite3.connect(source)) as connection, connection:
            connection.execute("UPDATE a2a_task_claims SET request_digest=? WHERE task_id=(SELECT task_id FROM a2a_task_claims LIMIT 1)", ("b" * 64,))
        return original(source, tenant, shared, authority_id, plan)
    monkeypatch.setattr(migration, "_archive_source", change_before_archive)
    with pytest.raises(ValueError, match="source.*changed|digest.*match"):
        migration.migrate_local_tasks("alpha")
    assert source.exists()
    assert not list(source.parent.glob("tasks.migrated-*.sqlite3"))


@pytest.mark.parametrize("mode", ["running", "override"])
def test_migration_requires_stopped_and_enforced_control_plane(shared_migration, monkeypatch, mode):
    source, _, _, _ = _source()
    if mode == "running":
        control_plane_lease.acquire()
    else:
        monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "1")
    with pytest.raises(GovernedRecordBackendError, match="stop the control plane"):
        migration.migrate_local_tasks("alpha")
    assert source.exists() and not source.with_suffix(".authority.sealed").exists()


def test_actual_cli_migration_and_required_tenant(shared_migration):
    from click.testing import CliRunner
    from maverick.cli import main

    source, tasks, calls, _ = _source()
    runner = CliRunner()
    missing = runner.invoke(main, ["a2a", "migrate-claims"])
    assert missing.exit_code == 2 and "--tenant" in missing.output
    assert source.exists() and not source.with_suffix(".authority.sealed").exists()
    result = runner.invoke(main, ["a2a", "migrate-claims", "--tenant", "alpha"])
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.output)
    assert receipt["status"] == "complete" and receipt["source_claims"] == 3
    assert not source.exists()
    _assert_consumed(tasks, calls)
