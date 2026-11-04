"""Actual process death must not publish half of a claim-history deletion."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from contextlib import closing

import pytest
from maverick import privacy_rights_orchestration as rights

NOW = 2_000_000_000.0
CLAIM_KEY = "claim-crash-original"
BATCH_ID = "batch:" + hashlib.sha256(CLAIM_KEY.encode()).hexdigest()[:32]


def _store(path, now):
    return rights.PrivacyRightsOrchestrationStore(
        path, config_gate=lambda: None, principal_resolver=lambda: "operator",
        digest_key_resolver=lambda _tenant: b"k" * 32, clock=lambda: now,
        token_factory=lambda: "synthetic-private-lease", claim_history_retention_seconds=60,
    )


def _seed_active_lease(store):
    store.enroll_source(
        "tenant-a", "crm", adapter_ref="provider-adapter-v1", credential_ref="env:SYNTHETIC_TOKEN",
        capabilities=sorted(rights.TASK_PHASES), expected_revision=0, idempotency_key="source",
    )
    case = store.open_case(
        "tenant-a", "case", request_version=1, external_request_ref="synthetic-case",
        subject_reference="person@example.test", rights=["access"], retained_until=NOW + 600,
        idempotency_key="open",
    )
    case = store.set_identity_verification(
        "tenant-a", "case", status="verified", evidence_sha256="a" * 64,
        evidence_ref="identity:synthetic", expected_revision=case.revision, idempotency_key="verify",
    )
    store.plan_source_tasks(
        "tenant-a", "case", "crm", phases=["discover"], max_attempts=3,
        expected_case_revision=case.revision, idempotency_key="plan",
    )
    callback, = store.claim_callbacks("tenant-a", limit=1, lease_seconds=300, idempotency_key=CLAIM_KEY)
    return callback


def _seed_retained_and_other_tenant(store):
    with closing(store._connect()) as connection, connection:
        store._begin(connection)
        for tenant, key, created in (("tenant-b", CLAIM_KEY, NOW), ("tenant-a", "retained", NOW + 60)):
            batch = "batch:" + hashlib.sha256(key.encode()).hexdigest()[:32]
            store._insert(
                connection, "rights_claim_batches", ("tenant_id", "batch_id", "created_at"),
                (tenant, batch, created),
                {"tenant_id": tenant, "batch_id": batch, "created_at": created, "callbacks": []},
            )
            store._record_operation(connection, tenant, key, "f" * 64, "claim_batch", batch)


def _pair(connection, tenant, batch):
    operation = connection.execute(
        "SELECT COUNT(*) FROM rights_operations WHERE tenant_id=? AND result_kind='claim_batch' AND result_id=?",
        (tenant, batch),
    ).fetchone()[0]
    receipt = connection.execute(
        "SELECT COUNT(*) FROM rights_claim_batches WHERE tenant_id=? AND batch_id=?", (tenant, batch),
    ).fetchone()[0]
    return operation, receipt


_CHILD = r'''
import json, sqlite3, sys, time
from contextlib import closing
from pathlib import Path
from maverick import privacy_rights_orchestration as rights

path, stage, ready, batch = sys.argv[1:]
store = rights.PrivacyRightsOrchestrationStore(
    path, config_gate=lambda: None, principal_resolver=lambda: "operator",
    digest_key_resolver=lambda _tenant: b"k" * 32, clock=lambda: 2_000_000_061.0,
    claim_history_retention_seconds=60,
)
original = store._connect
def pause(connection):
    operation = connection.execute(
        "SELECT COUNT(*) FROM rights_operations WHERE tenant_id='tenant-a' AND result_kind='claim_batch' AND result_id=?", (batch,)
    ).fetchone()[0]
    receipt = connection.execute(
        "SELECT COUNT(*) FROM rights_claim_batches WHERE tenant_id='tenant-a' AND batch_id=?", (batch,)
    ).fetchone()[0]
    # Existence is the parent's ready signal: publish only the closed,
    # complete checkpoint, never the empty file created by write_text.
    ready_path = Path(ready)
    pending = ready_path.with_suffix(".tmp")
    pending.write_text(json.dumps({"pair": [operation, receipt], "transaction": connection.in_transaction}))
    pending.replace(ready_path)
    while True:
        time.sleep(.01)
class ObservedConnection:
    def __init__(self):
        self.connection = original()
    def __getattr__(self, name):
        return getattr(self.connection, name)
    def execute(self, sql, parameters=()):
        if stage == "before_begin" and sql == "BEGIN IMMEDIATE":
            pause(self.connection)
        result = self.connection.execute(sql, parameters)
        if stage == "between_deletes" and sql.startswith("DELETE FROM rights_operations"):
            pause(self.connection)
        return result
    def __enter__(self):
        self.connection.__enter__()
        return self
    def __exit__(self, *exception):
        try:
            if exception[0] is None and stage == "before_commit":
                pause(self.connection)
            result = self.connection.__exit__(*exception)
            if exception[0] is None and stage == "after_commit":
                # The store's connection is closed on exit, so read the committed state on a fresh one.
                with closing(sqlite3.connect(path)) as fresh:
                    pause(fresh)
            return result
        finally:
            self.connection.close()
store._connect = ObservedConnection
store.claim_callbacks("tenant-a", limit=1, lease_seconds=300, idempotency_key="claim-crash-original")
raise AssertionError("owned process missed its specified transaction boundary")
'''


@pytest.mark.parametrize("stage,pair,in_transaction", [
    ("before_begin", (1, 1), False),
    ("between_deletes", (0, 1), True),
    ("before_commit", (0, 0), True),
    ("after_commit", (0, 0), False),
])
def test_killed_claim_cleanup_preserves_paired_state_and_live_lease(tmp_path, stage, pair, in_transaction):
    path = tmp_path / "rights.sqlite3"
    store = _store(path, NOW)
    callback = _seed_active_lease(store)
    _seed_retained_and_other_tenant(store)
    with closing(sqlite3.connect(path)) as connection:
        assert _pair(connection, "tenant-a", BATCH_ID) == (1, 1)
        history = connection.execute(
            "SELECT payload_json FROM rights_claim_batches WHERE tenant_id='tenant-a' AND batch_id=?", (BATCH_ID,),
        ).fetchone()[0]
        assert "synthetic-private-lease" not in history
    ready = tmp_path / "boundary.json"
    environment = os.environ.copy()
    environment["MAVERICK_HOME"] = str(tmp_path / "child-private")
    environment["USERPROFILE"] = environment["MAVERICK_HOME"]
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(path), stage, str(ready), BATCH_ID],
        env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert ready.exists(), "owned privacy process did not reach its required transaction boundary"
        assert json.loads(ready.read_text()) == {"pair": list(pair), "transaction": in_transaction}
        committed_pair = (0, 0) if stage == "after_commit" else (1, 1)
        # An independent WAL reader must never observe the child's half-delete.
        with closing(sqlite3.connect(path)) as connection:
            assert _pair(connection, "tenant-a", BATCH_ID) == committed_pair
        child.kill()
        child.wait(timeout=5)
        assert child.returncode != 0
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
    # New connections and a new store use the same durable file after the
    # process is gone. No injected exception or graceful rollback substitutes.
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert _pair(connection, "tenant-a", BATCH_ID) == committed_pair
        assert _pair(connection, "tenant-b", BATCH_ID) == (1, 1)
        assert _pair(connection, "tenant-a", "batch:" + hashlib.sha256(b"retained").hexdigest()[:32]) == (1, 1)
    reopened = _store(path, NOW + 61)
    reopened.verify_integrity("tenant-a")
    reopened.verify_integrity("tenant-b")
    assert reopened.claim_callbacks("tenant-a", limit=1, lease_seconds=300, idempotency_key=CLAIM_KEY) == ()
    current, = reopened.list_callbacks("tenant-a", limit=10)
    assert (current.callback_id, current.revision, current.lease_token, current.lease_until, current.state) == (
        callback.callback_id, callback.revision, callback.lease_token, NOW + 300, "leased",
    )
    with closing(sqlite3.connect(path)) as connection:
        assert _pair(connection, "tenant-a", BATCH_ID) == (0, 0)
        assert _pair(connection, "tenant-b", BATCH_ID) == (1, 1)
        assert connection.execute(
            "SELECT COUNT(*) FROM rights_claim_batches WHERE tenant_id='tenant-a'",
        ).fetchone()[0] == 1  # Only the previously retained receipt, no empty-poll history.
