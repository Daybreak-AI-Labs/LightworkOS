"""Actual disposable processes contend and crash around shared approval commits."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time

import pytest
from maverick.paths import tenant_scope
from maverick.world_model_backends.postgres import PostgresWorldModel

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"), reason="dedicated Postgres unavailable")

_CHILD = r'''
import contextlib, json, os, sys, time
from pathlib import Path
from maverick.paths import tenant_scope
from maverick.world_model_backends.postgres import PostgresWorldModel

approval, principal, decision, stage, ready, start = sys.argv[1:]
with tenant_scope(tenant="approval-race"), PostgresWorldModel(os.environ["MAVERICK_PG_DSN"]) as world:
    original = world._tx
    def pause():
        Path(ready).write_text("boundary reached")
        while True:
            time.sleep(.01)
    if stage:
        @contextlib.contextmanager
        def controlled():
            with original() as cursor:
                yield cursor
                if stage == "before_commit": pause()
            if stage == "after_commit": pause()
        world._tx = controlled
    else:
        Path(ready).write_text("ready")
        deadline = time.monotonic() + 10
        while not Path(start).exists():
            if time.monotonic() > deadline: raise RuntimeError("test start deadline")
            time.sleep(.01)
    event = world.decide_approval_audited(int(approval), decision, decided_by=principal)
    print(json.dumps(None if event is None else {"id": event.event_id, "status": event.final_status}))
'''


def _child(approval, principal, decision, stage, ready, start):
    environment = os.environ.copy()
    environment["USERPROFILE"] = environment["MAVERICK_HOME"]
    return subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(approval), principal, decision, stage, str(ready), str(start)],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _ready(path, child):
    deadline = time.monotonic() + 15
    while not path.exists() and time.monotonic() < deadline:
        assert child.poll() is None, "disposable approval process exited before its boundary"
        time.sleep(.01)
    assert path.exists(), "disposable approval process missed its boundary deadline"


def _stop(child):
    if child.poll() is None:
        child.kill()
    child.communicate(timeout=5)


def test_two_process_approval_decisions_have_one_pending_finalization(postgres_test_dsn, tmp_path):
    with tenant_scope(tenant="approval-race"), PostgresWorldModel(postgres_test_dsn) as world:
        approval = world.create_approval("synthetic protected operation", requested_by="user:requester")
        start = tmp_path / "start"
        children = []
        try:
            for i, decision in enumerate(("approved", "denied")):
                ready = tmp_path / f"ready-{i}"
                child = _child(approval, f"user:reviewer-{i}", decision, "", ready, start)
                children.append((child, ready))
            for child, ready in children:
                _ready(ready, child)
            start.write_text("race")
            results = []
            for child, _ in children:
                out, _err = child.communicate(timeout=15)
                assert child.returncode == 0, "disposable approval contender failed"
                results.append(json.loads(out))
            assert sum(item is not None for item in results) == 1
            pending = world.pending_approval_audit_events()
            assert len(pending) == 1
            assert world.get_approval(approval).status == "pending"
            event = pending[0]
            assert world.mark_approval_audit_delivered(event.event_id)
            assert world.get_approval(approval).status == event.final_status
            assert world.decide_approval_audited(approval, "approved", decided_by="user:late") is None
            assert world.pending_approval_audit_events() == []
        finally:
            for child, _ in children:
                _stop(child)


@pytest.mark.parametrize("stage", ["before_commit", "after_commit"])
def test_approval_process_kill_retains_same_vote_identity(postgres_test_dsn, tmp_path, stage):
    with tenant_scope(tenant="approval-race"), PostgresWorldModel(postgres_test_dsn) as world:
        approval = world.create_approval("synthetic protected operation", requested_by="user:requester")
        ready = tmp_path / "ready"
        child = _child(approval, "user:reviewer", "approved", stage, ready, tmp_path / "unused")
        try:
            _ready(ready, child)
        finally:
            _stop(child)
        pending = world.pending_approval_audit_events()
        assert len(pending) == (1 if stage == "after_commit" else 0)
        assert world.get_approval(approval).status == "pending"
        event = world.decide_approval_audited(approval, "approved", decided_by="user:reviewer")
        assert event is not None
        assert len(world.pending_approval_audit_events()) == 1
        if pending:
            assert event.event_id == pending[0].event_id
        assert world.mark_approval_audit_delivered(event.event_id)
        replay = world.decide_approval_audited(approval, "approved", decided_by="user:reviewer")
        assert replay.event_id == event.event_id and replay.delivered_at is not None
        assert world.get_approval(approval).status == "approved"


_PARTITION_CHILD = r'''
import contextlib, json, os, sys, time
from pathlib import Path
from maverick.paths import tenant_scope
from maverick.world_model_backends import postgres
from test_support.process_result import publish_json_result

approval, operation, pool_size, ready, start, outcome = sys.argv[1:]
postgres._pool_size = lambda: int(pool_size)
def pause():
    Path(ready).write_text("established connection boundary")
    deadline = time.monotonic() + 15
    while not Path(start).exists():
        if time.monotonic() > deadline: raise RuntimeError("owned test barrier expired")
        time.sleep(.01)
with tenant_scope(tenant="approval-partition"), postgres.PostgresWorldModel(os.environ["MAVERICK_PG_DSN"]) as world:
    assert world.get_approval(int(approval)).status == "pending"
    if operation == "commit_reply":
        original = world._tx
        @contextlib.contextmanager
        def controlled():
            with original() as cursor:
                yield cursor
                pause()
        world._tx = controlled
    else:
        pause()
    try:
        if operation == "read":
            world.get_approval(int(approval))
        else:
            world.decide_approval_audited(int(approval), "approved", decided_by="user:partition-reviewer")
    except Exception as exc:
        # Never emit driver diagnostics, connection strings, or arbitrary exception text.
        result = {"type": type(exc).__name__, "outcome_unknown": bool(getattr(exc, "outcome_unknown", False))}
    else:
        result = {"type": "unexpected_success", "outcome_unknown": False}
    publish_json_result(Path(outcome), result)
'''


def test_partition_outcome_is_invisible_until_complete_publication(tmp_path, monkeypatch):
    from test_support import process_result

    path = tmp_path / "outcome"
    staged = threading.Event()
    release = threading.Event()
    errors = []
    result = {"type": "PostgresIOTimeout", "outcome_unknown": True}
    replace = process_result.replace

    def pause_before_publication(source, destination):
        assert destination == path
        assert json.loads(source.read_text(encoding="utf-8")) == result
        assert not path.exists()
        staged.set()
        assert release.wait(5), "test reader did not observe the unpublished boundary"
        return replace(source, destination)

    def publish():
        try:
            process_result.publish_json_result(path, result)
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(process_result, "replace", pause_before_publication)
    writer = threading.Thread(target=publish)
    writer.start()
    try:
        assert staged.wait(5), "test child result was not staged"
        assert not path.exists()
        release.set()
        writer.join(5)
    finally:
        release.set()
        writer.join(5)
    assert not writer.is_alive()
    assert not errors
    assert json.loads(path.read_text(encoding="utf-8")) == result
    assert not path.with_name("outcome.pending").exists()


@pytest.mark.parametrize("pool_size", [0, 1])
@pytest.mark.parametrize("operation", ["read", "decision", "commit_reply"])
def test_established_approval_partition_is_bounded_without_inferred_decision(
    postgres_test_dsn, tmp_path, monkeypatch, pool_size, operation,
):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from test_support.tcp_partition import LocalPartitionRelay

    key = secrets.token_bytes(32)
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    settings = conninfo_to_dict(postgres_test_dsn)
    with tenant_scope(tenant="approval-partition"), PostgresWorldModel(postgres_test_dsn) as world:
        approval = world.create_approval("synthetic partition operation", requested_by="user:requester")
        with LocalPartitionRelay((settings.get("host", "127.0.0.1"), int(settings.get("port", 5432)))) as relay:
            proxy_dsn = make_conninfo(postgres_test_dsn, host=relay.address[0], port=relay.address[1])
            private_root = tmp_path / "child-private"
            private_root.mkdir()
            ready, start, outcome = (tmp_path / name for name in ("ready", "start", "outcome"))
            environment = os.environ.copy()
            environment.update({
                "MAVERICK_PG_DSN": proxy_dsn,
                "MAVERICK_HOME": str(private_root),
                "USERPROFILE": str(private_root),
                "MAVERICK_PG_IO_TIMEOUT_SECONDS": "1",
                "MAVERICK_PG_CONNECT_TIMEOUT_SECONDS": "2",
                "MAVERICK_PG_STATEMENT_TIMEOUT_MS": "1000",
            })
            child = subprocess.Popen(
                [sys.executable, "-c", _PARTITION_CHILD, str(approval), operation, str(pool_size),
                 str(ready), str(start), str(outcome)],
                env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                _ready(ready, child)
                if operation == "commit_reply":
                    relay.blackhole_responses()
                else:
                    relay.blackhole()
                start.write_text("partition established")
                deadline = time.monotonic() + 6
                while not outcome.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                assert outcome.exists(), "established approval I/O did not return within the owned six-second deadline"
                assert json.loads(outcome.read_text()) == {"type": "PostgresIOTimeout", "outcome_unknown": True}
            finally:
                _stop(child)
        # A lost reply is not evidence that COMMIT failed. Read the untouched
        # direct authority connection after stopping only our child/relay.
        events = world.pending_approval_audit_events()
        assert len(events) == (1 if operation == "commit_reply" else 0)
        assert world.get_approval(approval).status == "pending"
        if events:
            event = world.decide_approval_audited(approval, "approved", decided_by="user:partition-reviewer")
            assert event.event_id == events[0].event_id
            assert len(world.pending_approval_audit_events()) == 1
            assert world.mark_approval_audit_delivered(event.event_id)
            assert world.get_approval(approval).status == "approved"
