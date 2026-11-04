"""Metadata queries remain complete, tenant-scoped and rebuildable after crashes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.flow import payloads, run_index, store


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def legacy(run_id, *, updated=1, status="completed", owner="user:alice", due=None):
    row = store.FlowRun(run_id=run_id, flow_id="example", status=status, owner=owner,
                        updated=updated, resume_at=due).to_dict()
    store._write_json(store._runs_dir() / (run_id + ".json"), row)
    return row


def test_metadata_history_limits_decodes_and_never_loads_execution_values(monkeypatch):
    for i in range(100):
        legacy(f"run-{i:04d}", updated=i)
    store.rebuild_run_index()
    monkeypatch.setattr(payloads, "decode", lambda *_args: pytest.fail("metadata hydrated data"))
    monkeypatch.setattr(run_index, "atomic_read_text", lambda *_args: pytest.fail("metadata decoded JSON file"))
    rows = store.list_run_metadata(limit=7, owner="user:alice")
    assert [row.run_id for row in rows] == [f"run-{i:04d}" for i in range(99, 92, -1)]
    assert all(row.metadata_only for row in rows)
    with pytest.raises(payloads.FlowPayloadError, match="complete execution data"):
        store.save_run(rows[0])


def test_original_run_identity_survives_safe_filename_and_rebuild():
    run = store.FlowRun(run_id="old/imported.run", flow_id="example", status="completed")
    store.save_run(run)
    assert store.list_run_metadata()[0].run_id == run.run_id
    store.rebuild_run_index()
    assert store.list_runs()[0].run_id == run.run_id


def test_due_and_active_records_have_no_newest_thousand_cutoff(monkeypatch):
    from maverick_dashboard.automation_queue import _active_run_count

    for i in range(1007):
        legacy(f"due-{i:04d}", status="paused_delay", due=10, updated=i)
    for i in range(1001):
        legacy(f"done-{i:04d}", updated=i + 10000)
    rows = list(store.iter_run_metadata(statuses={"paused_delay"}, due_before=20, batch_size=83))
    assert len(rows) == len({row.run_id for row in rows}) == 1007
    monkeypatch.setattr(store, "load_run", lambda *_a, **_kw: pytest.fail("admission hydrated data"))
    assert _active_run_count("example", "due-0000") == 1006
    from maverick_dashboard import automation_queue as aq

    resumed = []
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setattr(aq, "_run_for_active_tenants", lambda _name, callback: callback())
    monkeypatch.setattr(aq, "_reconcile_flow_crons", lambda: None)
    monkeypatch.setattr(aq, "enqueue_flow_resume", lambda _flow, run_id, **_kw: resumed.append(run_id))
    aq._handle_flow_sweep()
    assert len(resumed) == len(set(resumed)) == 1007


@pytest.mark.parametrize("after_json", [False, True])
def test_interrupted_mutation_reconciles_exact_dirty_row(after_json):
    legacy("existing")
    store.rebuild_run_index()
    with pytest.raises(RuntimeError, match="process stopped"):
        with run_index.mutation(store._runs_dir(), "existing"):
            if after_json:
                legacy("existing", status="paused_delay", due=4)
            raise RuntimeError("process stopped")
    row = store.list_run_metadata()[0]
    assert row.status == ("paused_delay" if after_json else "completed")


@pytest.mark.parametrize("after_json", [False, True])
def test_process_exit_retains_repair_intent(after_json):
    import maverick

    legacy("crashed")
    store.rebuild_run_index()
    code = """
import os, sys
from pathlib import Path
import maverick
from maverick.flow import run_index, store
assert Path(maverick.__file__).resolve() == Path(sys.argv[1]).resolve()
with run_index.mutation(store._runs_dir(), 'crashed'):
    if sys.argv[2] == 'yes':
        store._write_json(store._runs_dir() / 'crashed.json',
                         {'run_id':'crashed','flow_id':'example','status':'paused_delay'})
    os._exit(23)
"""
    child = subprocess.run([sys.executable, "-c", code, maverick.__file__,
                            "yes" if after_json else "no"], check=False, timeout=30,
                           capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
    assert child.returncode == 23, child.stderr
    assert store.list_run_metadata()[0].status == ("paused_delay" if after_json else "completed")


def test_simultaneous_mutations_keep_each_run_in_index():
    def save(i):
        store.save_run(store.FlowRun(run_id=f"thread-{i}", flow_id="example", status="running"))

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(save, range(24)))
    assert len(store.list_run_metadata(limit=None)) == 24


def test_absent_corrupt_and_interrupted_index_rebuild(monkeypatch):
    for i in range(5):
        legacy(f"legacy-{i}")
    real_sync = run_index._sync_row

    def fail_third(c, root, run_id, **kwargs):
        if run_id == "legacy-2":
            raise RuntimeError("rebuild stopped")
        return real_sync(c, root, run_id, **kwargs)

    monkeypatch.setattr(run_index, "_sync_row", fail_third)
    with pytest.raises(RuntimeError, match="rebuild stopped"):
        store.list_run_metadata()
    monkeypatch.setattr(run_index, "_sync_row", real_sync)
    assert len(store.list_run_metadata()) == 5
    from maverick.file_lock import atomic_write_bytes

    atomic_write_bytes(store._runs_dir().parent / "run-index.sqlite3", b"not a SQLite database")
    assert len(store.list_run_metadata()) == 5


def test_deleted_or_corrupt_selected_canonical_row_is_not_served():
    legacy("a", updated=2)
    legacy("b", updated=1)
    store.rebuild_run_index()
    (store._runs_dir() / "a.json").unlink()
    assert [row.run_id for row in store.list_run_metadata()] == ["b"]
    (store._runs_dir() / "b.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(payloads.FlowPayloadError, match="metadata needs recovery"):
        store.list_run_metadata()


def test_selected_owner_change_checked_against_canonical_metadata():
    legacy("a", owner="user:alice")
    store.rebuild_run_index()
    legacy("a", owner="user:bob")
    assert store.list_run_metadata(owner="user:alice") == []
    assert store.list_run_metadata(owner="user:bob")[0].run_id == "a"


def test_tenant_isolation_and_explicit_offline_restore_rebuild():
    from maverick.paths import tenant_scope

    with tenant_scope(tenant="alpha"):
        legacy("same", owner="user:alice")
        assert len(store.list_run_metadata()) == 1
    with tenant_scope(tenant="beta"):
        assert store.list_run_metadata() == []
        legacy("restored", owner="user:bob")
        store.rebuild_run_index()
        assert [run.run_id for run in store.list_run_metadata()] == ["restored"]
    with tenant_scope(tenant="alpha"):
        assert [run.run_id for run in store.list_run_metadata()] == ["same"]


@pytest.mark.parametrize("replace_existing", [False, True])
def test_signed_restore_rebuilds_index_before_first_read(tmp_path, replace_existing):
    from maverick import backup

    legacy("saved", status="paused_delay", due=5)
    store.rebuild_run_index()
    root = store._runs_dir().parent.parent
    # Keep the open archive outside the replacement target on Windows.
    archive = tmp_path.parent / (tmp_path.name + "-snapshot.tgz")
    with backup.recovery_scope(root, None, bytes(range(32))):
        backup.create_backup(archive)
        legacy("saved", status="completed")
        legacy("retained")
        store.rebuild_run_index()
        backup.restore_backup(archive, force=True, replace_existing=replace_existing)
    marker = store._runs_dir().parent / ".run-index-rebuild"
    assert marker.exists()
    rows = {run.run_id: run.status for run in store.list_run_metadata()}
    assert rows["saved"] == "paused_delay"
    assert ("retained" in rows) is not replace_existing
    assert not marker.exists()


def test_failed_restore_rolls_back_index_invalidation(tmp_path, monkeypatch):
    import hashlib

    from maverick import backup

    legacy("saved", status="completed")
    store.rebuild_run_index()
    root = store._runs_dir().parent.parent
    stage = tmp_path / "staged"
    relative = "flows/runs/saved.json"
    path = stage / relative
    path.parent.mkdir(parents=True)
    raw = json.dumps({"run_id": "saved", "flow_id": "example", "status": "paused_delay"}).encode()
    path.write_bytes(raw)
    original = backup._write_journal

    def fail_commit(tx, body, key):
        if body["state"] == "committed":
            raise RuntimeError("restore stopped before commit")
        return original(tx, body, key)

    monkeypatch.setattr(backup, "_write_journal", fail_commit)
    with pytest.raises(RuntimeError, match="restore stopped"):
        backup._apply_transaction(root, stage, {relative: (hashlib.sha256(raw).hexdigest(), len(raw))},
                                  key=bytes(range(32)))
    assert not (store._runs_dir().parent / ".run-index-rebuild").exists()
    assert store.list_run_metadata()[0].status == "completed"


def test_queue_run_lookup_uses_exact_tenant_kind_and_terminal_latest(tmp_path):
    from maverick.job_queue import JobQueue

    queue = JobQueue(tmp_path / "queue.db")
    old = queue.enqueue("flow_run", {"run_id": "same", "tenant": "alpha"})
    latest = queue.enqueue("flow_run", {"run_id": "same", "tenant": "alpha"})
    queue.complete(latest)
    queue.enqueue("flow_resume", {"run_id": "same", "tenant": "alpha"})
    queue.enqueue("flow_run", {"run_id": "same", "tenant": "beta"})
    queue.enqueue("flow_run", {"run_id": "same"})
    with queue._transaction() as c:
        unrelated = json.dumps({"run_id": "unrelated", "tenant": "alpha"})
        c.executemany(
            "INSERT INTO jobs(kind,payload,run_at,status,created_at,updated_at) "
            "VALUES ('flow_run',?,0,'done',0,0)",
            ((unrelated,) for _ in range(100001)),
        )
        # A malformed legacy payload must not prevent opening the lookup index.
        c.execute("INSERT INTO jobs(kind,payload,run_at,created_at,updated_at) VALUES ('bad','{broken',0,0,0)")
    assert queue.find_for_run("flow_run", "same", "alpha").id == latest != old
    assert queue.find_for_run("flow_run", "same", "alpha").status == "done"
    assert queue.find_for_run("flow_run", "missing", "alpha") is None
    with queue._conn() as c:
        plan = c.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM jobs WHERE kind=? "
            "AND COALESCE(json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END,'$.tenant'),'')=? "
            "AND json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END,'$.run_id')=? "
            "ORDER BY id DESC LIMIT 1",
            ("flow_run", "alpha", "same"),
        ).fetchall()
    assert "idx_jobs_flow_run" in json.dumps([tuple(row) for row in plan])
