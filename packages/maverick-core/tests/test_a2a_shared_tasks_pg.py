"""Real Postgres claims with separate engines and no external/provider calls."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import a2a_tasks, crypto_at_rest
from maverick.a2a_store import META_ID, NAMESPACE, SharedTaskStore
from maverick.a2a_tasks import TaskEngine, _RpcError
from maverick.governed_record_batch import shared_record_batch
from maverick.governed_records import GovernedRecordBackendError
from maverick.paths import data_dir, tenant_scope

from test_support.tcp_partition import LocalPartitionRelay

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"), reason="dedicated Postgres service unavailable")


@pytest.fixture
def shared(postgres_test_dsn, monkeypatch):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    crypto_at_rest._reset_shared_key_identity_for_testing()
    key = secrets.token_bytes(32)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    role = "mvk_a2a_" + uuid.uuid4().hex[:16]
    with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
        password = secrets.token_urlsafe(32)
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS").format(sql.Identifier(role), sql.Literal(password)))
        admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(role), sql.Identifier(role)))
    dsn = make_conninfo(postgres_test_dsn, user=role, password=password, options=f"-c search_path={role}")
    monkeypatch.setenv("MAVERICK_PG_DSN", dsn)
    try:
        yield
    finally:
        with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        crypto_at_rest._reset_shared_key_identity_for_testing()


def msg(text="charge once", message_id="shared-id"):
    return {"message": {"role": "user", "parts": [{"kind": "text", "text": text}], "messageId": message_id}}


def engine(calls):
    return TaskEngine(runner=lambda text, **kwargs: calls.append(text) or "settled", durable=True)


@pytest.mark.parametrize("failure", ["refused", "blackhole-startup"])
def test_bound_warm_engine_transport_failure_cannot_replay_or_run_new_work(shared, monkeypatch, failure):
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    direct = os.environ["MAVERICK_PG_DSN"]
    target = conninfo_to_dict(direct)
    calls = []
    with LocalPartitionRelay((target.get("host", "127.0.0.1"), int(target.get("port", "5432")))) as relay:
        monkeypatch.setenv("MAVERICK_PG_DSN", make_conninfo(direct, host=relay.address[0], port=relay.address[1]))
        monkeypatch.setenv("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", "2")
        with tenant_scope(tenant="alpha"):
            replica = engine(calls)
            first = asyncio.run(replica.send(msg(), "agent:alice"))
            assert replica.get({"id": first["id"]}, "agent:alice") == first
            if failure == "refused":
                relay.close()
            else:
                relay.blackhole()
            started = time.monotonic()
            with pytest.raises(_RpcError, match="unavailable"):
                replica.get({"id": first["id"]}, "agent:alice")
            with pytest.raises(_RpcError, match="unavailable"):
                asyncio.run(replica.send(msg(), "agent:alice"))
            with pytest.raises(_RpcError, match="unavailable"):
                asyncio.run(replica.send(msg(message_id="must-not-run"), "agent:alice"))
            assert time.monotonic() - started < 12
            assert not data_dir("a2a", "tasks.sqlite3").exists()
        assert calls == ["charge once"]
        # The real server is untouched and remains available through its own
        # direct fixture connection. No extra claim reached its authority.
        with psycopg.connect(direct) as connection:
            connection.execute("SELECT set_config('maverick.tenant','alpha',true)")
            rows = connection.execute("SELECT record_id FROM governed_records WHERE namespace=%s", (NAMESPACE,)).fetchall()
            assert len(rows) == 4


_POOLED_PARTITION_CHILD = r'''
import asyncio, json, sys, threading, time, traceback
from pathlib import Path
from maverick import config
from maverick.a2a_tasks import TaskEngine, _RpcError
from maverick.file_lock import atomic_write_text
from maverick.paths import tenant_scope
from test_support.process_result import publish_json_result
ready, advance, outcome = map(Path, sys.argv[1:])
config.load_governed_records_config = lambda: {"governed_records": {"backend":"postgres", "pool_size":1, "pool_timeout_seconds":1}}
config.governed_records_config_source_errors = lambda: []
calls = []
request = {"message":{"role":"user","parts":[{"kind":"text","text":"one local effect"}],"messageId":"pooled-partition"}}
with tenant_scope(tenant="alpha"):
    engine = TaskEngine(runner=lambda text, **kwargs: calls.append(text) or "settled", durable=True)
    first = asyncio.run(engine.send(request, "agent:alice"))
    assert engine.get({"id":first["id"]}, "agent:alice") == first
    atomic_write_text(ready, "bound and warm")
    deadline = time.monotonic() + 15
    while not advance.exists() and time.monotonic() < deadline:
        time.sleep(.01)
    assert advance.exists()
    main_ident = threading.get_ident()
    def diagnostic():
        frames = traceback.extract_stack(sys._current_frames()[main_ident])
        safe = [{"file":Path(frame.filename).name, "line":frame.lineno, "function":frame.name} for frame in frames]
        publish_json_result(outcome.with_suffix(".diagnostic"), safe)
    timer = threading.Timer(3, diagnostic)
    timer.daemon = True
    timer.start()
    try:
        engine.get({"id":first["id"]}, "agent:alice")
    except _RpcError as error:
        result = {"state":"unavailable" if "unavailable" in error.message else "other_rpc", "calls":len(calls)}
    else:
        result = {"state":"cached_success", "calls":len(calls)}
    timer.cancel()
    publish_json_result(outcome, result)
'''


def test_established_pooled_transport_blackhole_is_bounded_and_unavailable(shared, monkeypatch, tmp_path):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    direct = os.environ["MAVERICK_PG_DSN"]
    target = conninfo_to_dict(direct)
    with LocalPartitionRelay((target.get("host", "127.0.0.1"), int(target.get("port", "5432")))) as relay:
        monkeypatch.setenv("MAVERICK_PG_DSN", make_conninfo(direct, host=relay.address[0], port=relay.address[1]))
        monkeypatch.setenv("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", "2")
        monkeypatch.setenv("MAVERICK_PG_STATEMENT_TIMEOUT_MS", "1000")
        monkeypatch.setenv("MAVERICK_PG_IO_TIMEOUT_SECONDS", "1")
        ready, advance, outcome = (tmp_path / name for name in ("warm", "partition", "outcome"))
        child = subprocess.Popen([sys.executable, "-c", _POOLED_PARTITION_CHILD, str(ready), str(advance), str(outcome)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 15
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            assert ready.exists(), "owned child did not establish a warm pooled authority"
            relay.blackhole()
            advance.write_text("observe the existing socket partition")
            deadline = time.monotonic() + 6
            while not outcome.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            diagnostic = outcome.with_suffix(".diagnostic")
            assert outcome.exists(), ("established pooled query exceeded six seconds despite bounded connect/statement policy: "
                                      + (diagnostic.read_text() if diagnostic.exists() else "no stack snapshot"))
            assert json.loads(outcome.read_text()) == {"state": "unavailable", "calls": 1}
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)


def test_shared_terminal_replay_and_ownership_survive_new_engine(shared):
    calls = []
    with tenant_scope(tenant="alpha"):
        first = asyncio.run(engine(calls).send(msg(), "agent:alice"))
        restarted = engine(calls)
        assert asyncio.run(restarted.send(msg(), "agent:alice")) == first
        assert restarted.get({"id": first["id"]}, "agent:alice") == first
        with pytest.raises(_RpcError, match="not found"):
            restarted.get({"id": first["id"]}, "agent:bob")
        with pytest.raises(_RpcError, match="different content"):
            asyncio.run(restarted.send(msg("changed"), "agent:alice"))
    with tenant_scope(tenant="beta"):
        with pytest.raises(_RpcError, match="not found"):
            engine(calls).get({"id": first["id"]}, "agent:alice")
        assert asyncio.run(engine(calls).send(msg(), "agent:alice"))["id"] != first["id"]
    assert calls == ["charge once", "charge once"]


def test_two_replicas_race_one_claim_and_unknown_is_not_reassigned(shared):
    start = threading.Barrier(2)
    calls = []

    def claim():
        with tenant_scope(tenant="alpha"):
            replica = engine(calls)
            # Distinct replica roots would not share the local cutover lock.
            # Exercise the production shared store directly here so only the
            # real Postgres transaction can serialize these claim contenders.
            replica._store = SharedTaskStore()
            start.wait(timeout=10)
            try:
                return replica._new_or_existing_task(msg(), "agent:alice")
            except _RpcError as error:
                return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        result = list(executor.map(lambda _: claim(), range(2)))
    assert sum(isinstance(item, tuple) and item[1] for item in result) == 1
    assert sum(isinstance(item, _RpcError) and "indeterminate" in item.message for item in result) == 1
    with tenant_scope(tenant="alpha"), pytest.raises(_RpcError, match="indeterminate"):
        asyncio.run(engine(calls).send(msg(), "agent:alice"))
    assert calls == []


_TWO_PROCESS_CLAIM_CHILD = r'''
import asyncio, json, sys, time
from pathlib import Path
from maverick.a2a_tasks import TaskEngine, _RpcError
from maverick.paths import tenant_scope
ready, start, effect = map(Path, sys.argv[1:])
def runner(text, **kwargs):
    with effect.open("a", encoding="utf-8") as output:
        output.write("one synthetic effect\n")
        output.flush()
    time.sleep(.2)
    return "settled"
with tenant_scope(tenant="alpha"):
    engine = TaskEngine(runner=runner, durable=True)
    ready.write_text("ready")
    deadline = time.monotonic() + 15
    while not start.exists() and time.monotonic() < deadline:
        time.sleep(.01)
    assert start.exists()
    request = {"message":{"role":"user","parts":[{"kind":"text","text":"two process effect"}],"messageId":"two-process-claim"}}
    try:
        result = asyncio.run(engine.send(request, "agent:alice"))
    except _RpcError as error:
        assert "indeterminate" in error.message
        print(json.dumps({"state":"indeterminate"}))
    else:
        assert result["status"]["state"] == "completed"
        print(json.dumps({"state":"completed", "id":result["id"]}))
'''


def test_actual_two_process_claim_race_with_distinct_roots_has_one_effect(shared, tmp_path):
    start, effect = tmp_path / "start", tmp_path / "effect"
    children = []
    try:
        for index in range(2):
            root = tmp_path / f"replica-{index}"
            root.mkdir()
            ready = tmp_path / f"ready-{index}"
            environment = dict(os.environ, MAVERICK_HOME=str(root), USERPROFILE=str(root))
            child = subprocess.Popen(
                [sys.executable, "-c", _TWO_PROCESS_CLAIM_CHILD, str(ready), str(start), str(effect)],
                env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            children.append((child, ready))
        deadline = time.monotonic() + 15
        while not all(ready.exists() for _, ready in children) and time.monotonic() < deadline:
            assert all(child.poll() is None for child, _ in children), "owned claim contender exited before readiness"
            time.sleep(.01)
        assert all(ready.exists() for _, ready in children)
        start.write_text("race the same message")
        results = []
        for child, _ in children:
            output, _ = child.communicate(timeout=15)
            assert child.returncode == 0, "owned claim contender failed"
            results.append(json.loads(output))
        completed = [result for result in results if result["state"] == "completed"]
        assert completed and len({result["id"] for result in completed}) == 1
        assert all(result["state"] in {"completed", "indeterminate"} for result in results)
        assert effect.read_text().splitlines() == ["one synthetic effect"]
        calls = []
        with tenant_scope(tenant="alpha"):
            result = asyncio.run(engine(calls).send(msg("two process effect", "two-process-claim"), "agent:alice"))
        assert result["id"] == completed[0]["id"] and not calls
    finally:
        for child, _ in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)


def test_shared_capacity_and_snapshot_eviction_keep_consumed_ids(shared, monkeypatch):
    calls = []
    with tenant_scope(tenant="alpha"):
        first = asyncio.run(engine(calls).send(msg(), "agent:alice"))
        store = SharedTaskStore()
        with store._batch("alpha") as batch:
            meta = batch.load(META_ID)
            charge = meta["snapshot_bytes"]
        monkeypatch.setattr(a2a_tasks, "_MAX_DURABLE_RETAINED_BYTES", charge + 100)
        second = asyncio.run(engine(calls).send(msg(message_id="shared-next"), "agent:alice"))
        assert second["id"] != first["id"]
        with pytest.raises(_RpcError, match="consumed|expired"):
            asyncio.run(engine(calls).send(msg(), "agent:alice"))
        monkeypatch.setattr(a2a_tasks, "_MAX_DURABLE_CLAIMS", 2)
        with pytest.raises(_RpcError, match="capacity"):
            asyncio.run(engine(calls).send(msg(message_id="third"), "agent:alice"))
    assert calls == ["charge once", "charge once"]


def test_shared_claim_rolls_back_all_records_and_does_not_retry(shared, monkeypatch):
    from maverick.governed_record_batch import RecordBatch

    original = RecordBatch.save
    with tenant_scope(tenant="alpha"):
        SharedTaskStore().bind_authority("alpha")
    saves = []
    def fail_meta(self, record, **kwargs):
        saved = original(self, record, **kwargs)
        saves.append(record["id"])
        if record["id"] == META_ID:
            raise RuntimeError("injected precommit interruption")
        return saved
    monkeypatch.setattr(RecordBatch, "save", fail_meta)
    calls = []
    with tenant_scope(tenant="alpha"):
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(engine(calls).send(msg(), "agent:alice"))
        assert len(saves) == 3
        monkeypatch.setattr(RecordBatch, "save", original)
        with SharedTaskStore()._batch("alpha") as batch:
            assert batch.oldest_ids(prefix="a2-") == [META_ID]
            assert batch.load(META_ID)["claim_count"] == 0
        asyncio.run(engine(calls).send(msg(), "agent:alice"))
    assert calls == ["charge once"]


def test_shared_key_loss_blocks_cached_read_and_execution(shared, monkeypatch):
    calls = []
    with tenant_scope(tenant="alpha"):
        original = engine(calls)
        first = asyncio.run(original.send(msg(), "agent:alice"))
        monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY")
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(engine(calls).send(msg(), "agent:alice"))
        with pytest.raises(_RpcError, match="unavailable"):
            engine(calls).get({"id": first["id"]}, "agent:alice")
        with pytest.raises(_RpcError, match="unavailable"):
            original.get({"id": first["id"]}, "agent:alice")
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(original.send(msg(), "agent:alice"))
    assert calls == ["charge once"]


def test_durable_shared_binding_refuses_a_local_downgrade_after_restart(shared, monkeypatch):
    from maverick.governed_records import _reset_process_authority_pin_for_testing

    calls = []
    with tenant_scope(tenant="alpha"):
        asyncio.run(engine(calls).send(msg(), "agent:alice"))
        marker = data_dir("a2a", "tasks.authority.sealed")
        assert marker.exists()
        assert crypto_at_rest.is_sealed_str(marker.read_text())
        _reset_process_authority_pin_for_testing()
        monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(engine(calls).send(msg(message_id="new-local-id"), "agent:alice"))
        assert not data_dir("a2a", "tasks.sqlite3").exists()
    assert calls == ["charge once"]


def test_binding_detects_lost_or_replaced_shared_authority_without_reinitializing(shared):
    calls = []
    with tenant_scope(tenant="alpha"):
        original = engine(calls)
        first = asyncio.run(original.send(msg(), "agent:alice"))
        backend = SharedTaskStore()._store._backend()
        with backend._transaction("alpha") as cursor:
            cursor.execute("DELETE FROM governed_records WHERE namespace=%s", (NAMESPACE,))
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(engine(calls).send(msg(), "agent:alice"))
        with pytest.raises(_RpcError, match="unavailable"):
            original.get({"id": first["id"]}, "agent:alice")
        with backend._transaction("alpha") as cursor:
            cursor.execute("SELECT COUNT(*) FROM governed_records")
            assert cursor.fetchone()[0] == 0
    assert calls == ["charge once"]


@pytest.mark.parametrize("operation", ["claim", "save", "load"])
@pytest.mark.parametrize("replacement", ["empty", "different-generation"])
def test_binding_is_rechecked_inside_actual_operation_transaction(
    shared, monkeypatch, operation, replacement,
):
    """A successful preliminary read cannot authorize a later DB generation."""
    calls = []
    with tenant_scope(tenant="alpha"):
        replica = engine(calls)
        first = asyncio.run(replica.send(msg(), "agent:alice"))
        task = replica._tasks[first["id"]]
        store = replica._store
        marker = data_dir("a2a", "tasks.authority.sealed").read_bytes()
        original_bind = store._shared.bind_authority
        boundaries = []

        def replace_after_binding(*args, **kwargs):
            bound = original_bind(*args, **kwargs)
            backend = store._shared._store._backend()
            if replacement == "empty":
                with backend._transaction("alpha") as cursor:
                    cursor.execute("DELETE FROM governed_records WHERE namespace=%s", (NAMESPACE,))
            else:
                with shared_record_batch(backend) as batch:
                    meta = batch.load(META_ID)
                    batch.save({**meta, "authority_id": uuid.uuid4().hex},
                               expected_revision=meta["revision"])
            with backend._transaction("alpha") as cursor:
                cursor.execute("SELECT record_id, revision, record_json FROM governed_records ORDER BY record_id")
                boundaries.append(cursor.fetchall())
            return bound

        monkeypatch.setattr(store._shared, "bind_authority", replace_after_binding)
        with pytest.raises(GovernedRecordBackendError):
            if operation == "claim":
                store.claim(task, message_id="shared-id", request_digest=task.request_digest)
            elif operation == "save":
                store.save(task)
            else:
                store.load(tenant="alpha", principal="agent:alice", task_id=task.id)
        assert len(boundaries) == 1
        backend = store._shared._store._backend()
        with backend._transaction("alpha") as cursor:
            cursor.execute("SELECT record_id, revision, record_json FROM governed_records ORDER BY record_id")
            assert cursor.fetchall() == boundaries[0]
        assert data_dir("a2a", "tasks.authority.sealed").read_bytes() == marker
    assert calls == ["charge once"]


@pytest.mark.parametrize("contents", [b"corrupt binding", b"x" * 17000], ids=["corrupt", "oversized"])
def test_corrupt_or_oversized_binding_blocks_shared_reuse(shared, contents):
    from maverick.file_lock import atomic_write_bytes

    calls = []
    with tenant_scope(tenant="alpha"):
        asyncio.run(engine(calls).send(msg(), "agent:alice"))
        atomic_write_bytes(data_dir("a2a", "tasks.authority.sealed"), contents)
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(engine(calls).send(msg(), "agent:alice"))
    assert calls == ["charge once"]


def test_shared_selection_refuses_legacy_sqlite_and_explicit_override(shared):
    calls = []
    with tenant_scope(tenant="alpha"):
        local = data_dir("a2a", "tasks.sqlite3")
        local.parent.mkdir(parents=True)
        local.write_bytes(b"existing local claim authority")
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(engine(calls).send(msg(), "agent:alice"))
        explicit = TaskEngine(runner=lambda *a, **k: calls.append("wrong"), state_path=local)
        with pytest.raises(_RpcError, match="unavailable"):
            asyncio.run(explicit.send(msg(), "agent:alice"))
        assert local.read_bytes() == b"existing local claim authority"
    assert not calls


def test_shared_batch_stale_handle_and_cross_thread_are_rejected(shared):
    with tenant_scope(tenant="alpha"):
        backend = SharedTaskStore()._store._backend()
        with shared_record_batch(backend) as batch:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(batch.load, META_ID)
                with pytest.raises(GovernedRecordBackendError, match="no longer owned"):
                    future.result()
        with pytest.raises(GovernedRecordBackendError, match="no longer owned"):
            batch.load(META_ID)


def test_shared_rows_are_encrypted_and_rls_applies_without_application_predicate(shared):
    calls = []
    with tenant_scope(tenant="alpha"):
        asyncio.run(engine(calls).send(msg("alpha secret"), "agent:alice"))
    with tenant_scope(tenant="beta"):
        asyncio.run(engine(calls).send(msg("beta secret"), "agent:alice"))
        backend = SharedTaskStore()._store._backend()
        with backend._transaction("beta") as cursor:
            cursor.execute("SELECT tenant_id, namespace, record_json FROM governed_records")
            rows = cursor.fetchall()
            assert rows and all(row[0] == "beta" and row[1] == NAMESPACE for row in rows)
            assert all(crypto_at_rest.is_sealed_str(row[2]) for row in rows)
            assert all("secret" not in row[2] and "alice" not in row[2] for row in rows)
        with backend._raw_transaction() as cursor:
            cursor.execute("SELECT COUNT(*) FROM governed_records")
            assert cursor.fetchone()[0] == 0


_CRASH_CHILD = r'''
import asyncio
import sys
import time
from pathlib import Path
from maverick.a2a_tasks import TaskEngine
from maverick.governed_record_batch import RecordBatch
from maverick.file_lock import atomic_write_text
from maverick.paths import tenant_scope

stage, ready, effect = sys.argv[1:]
def pause():
    atomic_write_text(Path(ready), "transaction boundary reached")
    while True:
        time.sleep(1)
original = RecordBatch.save
def save(self, record, **kwargs):
    saved = original(self, record, **kwargs)
    name = record["id"]
    if stage == "claim-row" and name.startswith("a2-c-") and record.get("status") == "in_progress":
        pause()
    if stage == "lookup-row" and name.startswith("a2-t-"):
        pause()
    if stage == "claim-meta" and name == "a2-meta" and record.get("claim_count", 0) > 0:
        pause()
    if stage == "terminal-row" and name.startswith("a2-c-") and record.get("status") == "terminal":
        pause()
    return saved
RecordBatch.save = save
def runner(text, **kwargs):
    atomic_write_text(Path(effect), "one synthetic effect")
    if stage == "effect":
        pause()
    return "settled"
request = {"message": {"role": "user", "parts": [{"kind":"text", "text":"charge once"}], "messageId":"shared-id"}}
with tenant_scope(tenant="alpha"):
    engine = TaskEngine(runner=runner, durable=True)
    task, created = engine._new_or_existing_task(request, "agent:alice")
    assert created
    if stage == "claim-commit":
        pause()
    asyncio.run(engine._run(task))
    assert task.state == "completed"
    if stage == "terminal-commit":
        pause()
'''


@pytest.mark.parametrize("stage", ["claim-row", "lookup-row", "claim-meta", "claim-commit", "effect", "terminal-row", "terminal-commit"])
def test_actual_replica_kill_at_claim_effect_and_settlement_boundaries(shared, tmp_path, stage):
    ready, effect = tmp_path / "child-ready", tmp_path / "effect"
    child = subprocess.Popen([sys.executable, "-c", _CRASH_CHILD, stage, str(ready), str(effect)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 25
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert ready.exists(), "owned child did not reach the requested transaction boundary"
        child.kill()
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)
    calls = []
    with tenant_scope(tenant="alpha"):
        restarted = engine(calls)
        if stage in {"claim-row", "lookup-row", "claim-meta"}:
            result = asyncio.run(restarted.send(msg(), "agent:alice"))
            assert result["status"]["state"] == "completed"
            assert calls == ["charge once"]
            assert not effect.exists()
        elif stage == "terminal-commit":
            assert asyncio.run(restarted.send(msg(), "agent:alice"))["status"]["state"] == "completed"
            assert not calls
            assert effect.read_text() == "one synthetic effect"
        else:
            with pytest.raises(_RpcError, match="indeterminate"):
                asyncio.run(restarted.send(msg(), "agent:alice"))
            assert not calls
            assert effect.exists() is (stage != "claim-commit")


def test_unbound_captured_scope_cannot_inherit_later_request_tenant():
    from maverick.a2a_tasks import _task_tenant_scope
    from maverick.paths import current_tenant_id

    with tenant_scope(tenant="beta"):
        with _task_tenant_scope(""):
            assert current_tenant_id() is None
        assert current_tenant_id() == "beta"
