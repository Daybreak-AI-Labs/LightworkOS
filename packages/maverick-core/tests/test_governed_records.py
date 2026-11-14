"""Shared governed-record primitive for product and evidence stores."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading

import pytest
from maverick import governed_records
from maverick.governed_records import (
    GovernedRecordBackendError,
    GovernedRecordCapacityError,
    GovernedRecordStore,
    PostgresGovernedRecordBackend,
)
from maverick.paths import TenantPolicyError, tenant_scope
from maverick.privacy_ops import AuditOutboxError, PrivacyStateError, RecordConflict


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path, monkeypatch):
    from maverick import crypto_at_rest

    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    for name in (
        "MAVERICK_GOVERNED_RECORDS_BACKEND",
        "MAVERICK_ENCRYPTION_KEY",
        "MAVERICK_ENCRYPTION_KEY_DIGEST",
        "MAVERICK_PG_DSN",
        "MAVERICK_REPLICA_COUNT",
        "MAVERICK_WORLD_BACKEND",
    ):
        monkeypatch.delenv(name, raising=False)
    key = b"k" * 32
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv(
        "MAVERICK_ENCRYPTION_KEY_DIGEST",
        "sha256:" + hashlib.sha256(key).hexdigest(),
    )
    yield
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()


def _pin_shared_encryption_key(monkeypatch, key: bytes = b"k" * 32) -> str:
    digest = "sha256:" + hashlib.sha256(key).hexdigest()
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", digest)
    return digest


class _MemoryPg:
    """Small transactional psycopg double; no live service is required."""

    def __init__(self):
        self.rows: dict[tuple[str, str, str], tuple[int, str, float, float]] = {}
        self.sql: list[tuple[str, tuple]] = []
        self.lock = threading.RLock()
        self.table_exists = True
        self.columns = (
            ("tenant_id", "text", "NO"),
            ("namespace", "text", "NO"),
            ("record_id", "text", "NO"),
            ("revision", "bigint", "NO"),
            ("record_json", "text", "NO"),
            ("created_at", "double precision", "NO"),
            ("updated_at", "double precision", "NO"),
        )
        self.primary_key = ["tenant_id", "namespace", "record_id"]
        self.checks = [
            "CHECK ((char_length(tenant_id) >= 1) AND "
            "(char_length(tenant_id) <= 201))",
            "CHECK ((char_length(namespace) >= 1) AND "
            "(char_length(namespace) <= 128))",
            "CHECK ((record_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'::text))",
            "CHECK ((revision >= 1))",
            "CHECK ((octet_length(record_json) <= 25165824))",
        ]
        self.rls_enabled = True
        self.rls_forced = True
        self.superuser = False
        self.bypassrls = False
        self.allow_ddl = True
        self.clock_time = 1_700_000_123.25
        expression = (
            "tenant_id = nullif(current_setting('maverick.tenant', true), '')"
        )
        self.policies: list[tuple] = [(
            "mvk_tenant_isolation",
            "PERMISSIVE",
            ["public"],
            "ALL",
            expression,
            expression,
        )]

    def connect(self, _dsn, *, autocommit=False):
        assert autocommit is False
        return _MemoryConnection(self)


class _MemoryConnection:
    def __init__(self, database: _MemoryPg):
        self.database = database
        self.database.lock.acquire()
        self.snapshot = copy.deepcopy({
            "rows": database.rows,
            "table_exists": database.table_exists,
            "columns": database.columns,
            "primary_key": database.primary_key,
            "checks": database.checks,
            "rls_enabled": database.rls_enabled,
            "rls_forced": database.rls_forced,
            "policies": database.policies,
        })
        self.closed = False

    def cursor(self):
        return _MemoryCursor(self.database)

    def commit(self):
        return None

    def rollback(self):
        self.database.rows.clear()
        self.database.rows.update(self.snapshot["rows"])
        self.database.table_exists = self.snapshot["table_exists"]
        self.database.columns = self.snapshot["columns"]
        self.database.primary_key = self.snapshot["primary_key"]
        self.database.checks = self.snapshot["checks"]
        self.database.rls_enabled = self.snapshot["rls_enabled"]
        self.database.rls_forced = self.snapshot["rls_forced"]
        self.database.policies = self.snapshot["policies"]

    def close(self):
        if not self.closed:
            self.closed = True
            self.database.lock.release()


class _MemoryCursor:
    def __init__(self, database: _MemoryPg):
        self.database = database
        self.result: list[tuple] = []
        self.rowcount = -1

    def execute(self, query, params=()):  # noqa: C901 - explicit SQL contract double
        sql = " ".join(str(query).split())
        values = tuple(params or ())
        self.database.sql.append((sql, values))
        self.result = []
        self.rowcount = -1
        if sql.startswith("SELECT extract(epoch FROM clock_timestamp())"):
            self.result = [(self.database.clock_time,)]
            self.rowcount = 1
            return
        if sql.startswith("SELECT rolsuper, rolbypassrls"):
            self.result = [(
                self.database.superuser,
                self.database.bypassrls,
            )]
            self.rowcount = 1
            return
        if sql.startswith("SELECT to_regclass("):
            self.result = [(
                "governed_records" if self.database.table_exists else None,
            )]
            self.rowcount = 1
            return
        if sql.startswith("SELECT column_name, data_type, is_nullable"):
            self.result = list(self.database.columns)
            self.rowcount = len(self.result)
            return
        if sql.startswith("SELECT array_agg(a.attname"):
            self.result = [(list(self.database.primary_key),)]
            self.rowcount = 1
            return
        if sql.startswith("SELECT pg_get_constraintdef(oid)"):
            self.result = [(check,) for check in self.database.checks]
            self.rowcount = len(self.result)
            return
        if sql.startswith("CREATE TABLE "):
            if not self.database.allow_ddl:
                raise PermissionError("runtime role cannot create tables")
            self.database.table_exists = True
            self.database.rls_enabled = False
            self.database.rls_forced = False
            self.database.policies = []
            self.rowcount = 1
            return
        if sql.startswith("CREATE INDEX "):
            if not self.database.allow_ddl:
                raise PermissionError("runtime role cannot create indexes")
            self.rowcount = 1
            return
        if sql.startswith("ALTER TABLE "):
            if not self.database.allow_ddl:
                raise PermissionError("runtime role cannot alter tables")
            if "ENABLE ROW LEVEL SECURITY" in sql:
                self.database.rls_enabled = True
            if "FORCE ROW LEVEL SECURITY" in sql:
                self.database.rls_forced = True
            self.rowcount = 1
            return
        if sql.startswith("DROP POLICY "):
            if not self.database.allow_ddl:
                raise PermissionError("runtime role cannot drop policies")
            self.database.policies = [
                policy
                for policy in self.database.policies
                if policy[0] != "mvk_tenant_isolation"
            ]
            self.rowcount = 1
            return
        if sql.startswith("CREATE POLICY "):
            if not self.database.allow_ddl:
                raise PermissionError("runtime role cannot create policies")
            expression = (
                "tenant_id = nullif(current_setting('maverick.tenant', true), '')"
            )
            self.database.policies.append((
                "mvk_tenant_isolation",
                "PERMISSIVE",
                ["public"],
                "ALL",
                expression,
                expression,
            ))
            self.rowcount = 1
            return
        if sql.startswith("SELECT relrowsecurity"):
            self.result = [(
                self.database.rls_enabled,
                self.database.rls_forced,
            )]
            self.rowcount = 1
            return
        if sql.startswith("SELECT policyname, permissive"):
            self.result = list(self.database.policies)
            self.rowcount = len(self.result)
            return
        if sql.startswith((
            "SELECT set_config(",
            "SELECT pg_advisory_xact_lock(",
        )):
            self.rowcount = 1
            return
        if sql.startswith("SELECT COUNT(*) FROM governed_records"):
            tenant, namespace = str(values[0]), str(values[1])
            count = sum(
                row_tenant == tenant and row_namespace == namespace
                for row_tenant, row_namespace, _record_id in self.database.rows
            )
            self.result = [(count,)]
            self.rowcount = 1
            return
        if sql.startswith("SELECT namespace, revision, record_json"):
            tenant, active, archived, record_id, _preferred = map(str, values)
            for namespace in (active, archived):
                row = self.database.rows.get((tenant, namespace, record_id))
                if row is not None:
                    self.result = [(namespace, *row)]
                    break
            self.rowcount = len(self.result)
            return
        if sql.startswith("SELECT revision, record_json"):
            key = (str(values[0]), str(values[1]), str(values[2]))
            row = self.database.rows.get(key)
            self.result = [row] if row is not None else []
            self.rowcount = len(self.result)
            return
        if sql.startswith("INSERT INTO governed_records"):
            key = (str(values[0]), str(values[1]), str(values[2]))
            if key in self.database.rows:
                self.rowcount = 0
            else:
                self.database.rows[key] = (
                    int(values[3]),
                    str(values[4]),
                    float(values[5]),
                    float(values[6]),
                )
                self.rowcount = 1
            return
        if sql.startswith("UPDATE governed_records SET namespace="):
            source = (str(values[1]), str(values[2]), str(values[3]))
            target = (str(values[1]), str(values[0]), str(values[3]))
            current = self.database.rows.get(source)
            expected = int(values[4]) if "AND revision=%s" in sql else None
            if (current is None or target in self.database.rows
                    or (expected is not None and current[0] != expected)):
                self.rowcount = 0
            else:
                self.database.rows[target] = self.database.rows.pop(source)
                self.rowcount = 1
            return
        if sql.startswith("UPDATE governed_records"):
            key = (str(values[4]), str(values[5]), str(values[6]))
            current = self.database.rows.get(key)
            if current is None or current[0] != int(values[7]):
                self.rowcount = 0
            else:
                self.database.rows[key] = (
                    int(values[0]),
                    str(values[1]),
                    float(values[2]),
                    float(values[3]),
                )
                self.rowcount = 1
            return
        if sql.startswith("DELETE FROM governed_records"):
            key = (str(values[0]), str(values[1]), str(values[2]))
            current = self.database.rows.get(key)
            if current is None or current[0] != int(values[3]):
                self.rowcount = 0
            else:
                del self.database.rows[key]
                self.rowcount = 1
            return
        if sql.startswith("SELECT record_id, revision"):
            tenant, namespace = str(values[0]), str(values[1])
            matches = [
                (record_id, *row)
                for (row_tenant, row_namespace, record_id), row
                in self.database.rows.items()
                if row_tenant == tenant and row_namespace == namespace
            ]
            self.result = sorted(matches, key=lambda row: (-row[3], row[0]))
            if " LIMIT %s" in sql:
                self.result = self.result[:int(values[2])]
            self.rowcount = len(self.result)
            return
        if sql.startswith("SELECT record_id FROM governed_records"):
            tenant, namespace, cursor, limit = (
                str(values[0]),
                str(values[1]),
                str(values[2]),
                int(values[3]),
            )
            ids = [
                record_id
                for row_tenant, row_namespace, record_id in self.database.rows
                if row_tenant == tenant and row_namespace == namespace
            ]
            ids.sort(key=lambda record_id: (record_id <= cursor, record_id))
            self.result = [(record_id,) for record_id in ids[:limit]]
            self.rowcount = len(self.result)
            return
        raise AssertionError(f"unexpected SQL: {sql}")

    def fetchone(self):
        return self.result[0] if self.result else None

    def fetchall(self):
        return list(self.result)

    def close(self):
        return None


def _postgres_store(namespace="test_postgres", prefix="TGP"):
    database = _MemoryPg()
    backend = PostgresGovernedRecordBackend(
        namespace,
        prefix,
        dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )
    backend._schema_ready = True
    return (
        GovernedRecordStore(
            namespace,
            prefix,
            "test_record",
            backend=backend,
        ),
        backend,
        database,
    )


def test_postgres_authoritative_time_uses_database_clock():
    database = _MemoryPg()
    backend = PostgresGovernedRecordBackend(
        "clock_test",
        "CLK",
        dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )

    assert backend.authoritative_time() == database.clock_time
    assert any(
        sql == "SELECT extract(epoch FROM clock_timestamp())"
        for sql, _params in database.sql
    )


def test_create_update_and_stale_cas_are_audited(monkeypatch):
    import maverick.audit as audit

    # Local single-replica compatibility does not impose the Postgres
    # application-encryption floor.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    events: list[tuple[object, dict]] = []
    monkeypatch.setattr(
        audit,
        "record",
        lambda kind, **payload: events.append((kind, payload)) or True,
    )
    store = GovernedRecordStore("test_governed", "TGR", "test_record")

    long_actor = "alice@example.com/" + "a" * 300
    created = store.create(
        {"id": store.new_id(), "status": "open", "title": "Observed condition"},
        action="create",
        actor=long_actor,
    )
    assert created["revision"] == 1
    assert "_audit_pending" not in created
    assert events[-1][1]["record_type"] == "test_record"
    assert events[-1][1]["action"] == "create"
    assert events[-1][1]["record_sha256"]
    assert events[-1][1]["actor"] != long_actor
    assert "#sha256:" in events[-1][1]["actor"]

    updated = store.update(
        created["id"],
        lambda row: row.update(status="closed"),
        expected_revision=created["revision"],
        action="close",
        actor="bob@example.com",
    )
    assert updated is not None
    assert updated["revision"] == 2
    assert updated["status"] == "closed"

    with pytest.raises(RecordConflict):
        store.update(
            created["id"],
            lambda row: row.update(status="stale"),
            expected_revision=created["revision"],
            action="stale_update",
            actor="mallory@example.com",
        )


def test_local_full_namespace_archives_its_oldest_record_instead_of_refusing(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    events: list[dict] = []
    monkeypatch.setattr(audit, "record", lambda *_args, **row: events.append(row) or True)
    store = GovernedRecordStore("test_capacity", "TCP", "test_record")
    first = store.create({"id": "TCP-first", "status": "closed"}, action="create",
                         actor="operator", max_records=1)

    second = store.create({"id": "TCP-second", "status": "open"}, action="create",
                          actor="operator", max_records=1)

    # The namespace stays at its cap; the oldest record is kept, not deleted.
    assert [row["id"] for row in store.list()] == [second["id"]]
    assert [row["id"] for row in store.list_archived()] == [first["id"]]
    assert store.count() == 1
    kept = store.get(first["id"])
    assert kept["status"] == "closed" and kept["revision"] == first["revision"] + 1
    assert any(row.get("action") == "governed_record_archived" for row in events)
    # Archived records stay updatable by id with ordinary compare-and-swap.
    changed = store.update(first["id"], lambda row: row.update(note="reopened"),
                           expected_revision=kept["revision"], action="note", actor="operator")
    assert changed["note"] == "reopened" and changed["revision"] == kept["revision"] + 1
    # Its id is still taken: creating it again conflicts exactly as before.
    with pytest.raises(RecordConflict):
        store.create({"id": "TCP-first", "status": "open"}, action="create",
                      actor="operator", max_records=10)


def test_full_namespace_never_archives_open_work(monkeypatch):
    # An archived record leaves the store's lists. A request still being worked
    # on (or in a status the store does not declare final) must stay visible,
    # so a namespace full of open work refuses rather than hiding the oldest.
    import maverick.audit as audit

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(audit, "record", lambda *_args, **_row: True)
    for n, record in enumerate(({"status": "requested"}, {"state": "processing"},
                                {"status": "sent"}, {"status": "some-new-status"})):
        store = GovernedRecordStore(f"test_open_{n}", "TOW", "test_record")
        store.create({"id": "TOW-first", **record}, action="create", actor="operator", max_records=1)
        with pytest.raises(GovernedRecordCapacityError, match="capacity has been reached"):
            store.create({"id": "TOW-second", "status": "closed"}, action="create",
                         actor="operator", max_records=1)
        assert [row["id"] for row in store.list()] == ["TOW-first"]
        assert store.list_archived() == []


@pytest.fixture(params=["local", "postgres"])
def archived_delete_store(request, monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_row: True)
    if request.param == "postgres":
        store, backend, database = _postgres_store("test_archived_delete", "TAD")
        archive_backend = PostgresGovernedRecordBackend(
            governed_records._archive_namespace(store.namespace),
            "TAD",
            dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
            connect=database.connect,
        )
    else:
        store = GovernedRecordStore("test_archived_delete", "TAD", "test_record")
        backend = store._backend()
        archive_backend = backend._archive
    store.create({"id": "TAD-first", "status": "done", "owner": "ada"}, action="create",
                 actor="operator", max_records=1)
    store.create({"id": "TAD-second", "status": "done"}, action="create", actor="operator", max_records=1)
    return store, backend, archive_backend


def test_an_archived_record_can_still_be_deleted_by_id(archived_delete_store, monkeypatch):
    # Personal-data erasure reaches archived records without briefly restoring
    # them into a full active namespace, even when the deletion succeeds.
    store, backend, _archive_backend = archived_delete_store

    def unexpected_restore(_record_id):
        pytest.fail("deletion must never restore an archived record")

    monkeypatch.setattr(backend, "restore", unexpected_restore)
    archived = store.list_archived()
    assert [row["id"] for row in archived] == ["TAD-first"]

    assert store.delete("TAD-first", expected_revision=archived[0]["revision"]) is True
    assert store.get("TAD-first") is None
    assert store.list_archived() == []
    assert [row["id"] for row in store.list()] == ["TAD-second"]
    assert store.delete("TAD-first", expected_revision=archived[0]["revision"]) is False


def test_stale_archived_delete_preserves_record_and_active_capacity(archived_delete_store):
    store, backend, _archive_backend = archived_delete_store
    archived = store.list_archived()
    active = store.list()

    with pytest.raises(RecordConflict, match="expected revision"):
        store.delete("TAD-first", expected_revision=archived[0]["revision"] - 1)

    assert backend.load("TAD-first") is None
    assert store.get("TAD-first") == archived[0]
    assert store.list_archived() == archived
    assert store.list() == active
    assert store.count() == 1


def test_archived_delete_with_pending_audit_preserves_archive(archived_delete_store):
    store, backend, archive_backend = archived_delete_store
    current = store.get("TAD-first")
    governed_records._queue_audit(current, "retained", "operator")
    pending = archive_backend.save(current, expected_revision=current["revision"])
    active = store.list()

    with pytest.raises(AuditOutboxError, match="pending audit receipts"):
        store.delete("TAD-first", expected_revision=pending["revision"])

    assert backend.load("TAD-first") is None
    assert store.get("TAD-first") == pending
    assert store.list_archived() == [pending]
    assert store.list() == active
    assert store.count() == 1


def test_local_full_namespace_never_archives_a_record_with_undelivered_activity(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    store = GovernedRecordStore("test_capacity", "TCP", "test_record")
    first = store.create({"id": "TCP-first", "status": "open"}, action="create",
                         actor="operator", max_records=1)
    assert first.get("_audit_pending")

    with pytest.raises(GovernedRecordCapacityError, match="capacity has been reached"):
        store.create({"id": "TCP-second", "status": "open"}, action="create",
                     actor="operator", max_records=1)
    assert [row["id"] for row in store.list()] == [first["id"]]


def test_public_record_id_scan_is_bounded_and_cursor_rotates(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store = GovernedRecordStore("test_scan", "TGR", "test_record")
    for record_id in ("TGR-charlie", "TGR-alpha", "TGR-bravo"):
        store.create(
            {"id": record_id, "status": "open"},
            action="create",
            actor="operator",
        )

    first = list(store.iter_record_ids(limit=2))
    assert [record_id for _cursor, record_id in first] == [
        "TGR-alpha",
        "TGR-bravo",
    ]
    second = list(store.iter_record_ids(start_after=first[-1][0], limit=2))
    assert [record_id for _cursor, record_id in second] == [
        "TGR-charlie",
        "TGR-alpha",
    ]
    assert all(store.get(record_id) is not None for _cursor, record_id in first)


def test_local_backend_rejects_oversized_record_before_creating_a_file(
    tmp_path,
    monkeypatch,
):
    from maverick import privacy_ops
    from maverick.paths import data_dir

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(privacy_ops, "_MAX_PRIVACY_JSON_BYTES", 1_024)
    store = GovernedRecordStore("test_oversized", "TGR", "test_record")
    record_id = store.new_id()

    with pytest.raises(PrivacyStateError, match="16 MiB JSON limit"):
        store.create(
            {"id": record_id, "status": "open", "payload": "x" * 2_000},
            action="create",
            actor="operator",
        )

    assert not (data_dir("test_oversized") / f"{record_id}.json").exists()


@pytest.mark.parametrize("authority_scope", ["tenant", "deployment_global"])
def test_local_bounded_list_reads_no_more_than_limit(monkeypatch, authority_scope):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    namespace = f"test_bounded_{authority_scope}"
    store = GovernedRecordStore(
        namespace,
        "TBL",
        "test_record",
        authority_scope=authority_scope,
    )
    for index in range(5):
        store.create(
            {"id": f"TBL-record{index}", "status": "open", "index": index},
            action="create",
            actor="operator",
        )

    disk_store = store._local_backend._store
    original_read = disk_store._read_path
    reads = []

    def counted_read(path):
        reads.append(path)
        return original_read(path)

    monkeypatch.setattr(disk_store, "_read_path", counted_read)
    rows = store.list(limit=2)

    assert len(rows) == 2
    assert len(reads) == 2
    assert all(row["id"].startswith("TBL-") for row in rows)


def test_local_bounded_list_validates_unselected_paths_before_reads(monkeypatch):
    import maverick.audit as audit
    from maverick.file_lock import atomic_write_text

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store = GovernedRecordStore("test_bounded_paths", "TBP", "test_record")
    for index in range(2):
        store.create(
            {"id": f"TBP-record{index}", "status": "open"},
            action="create",
            actor="operator",
        )

    disk_store = store._local_backend._store
    atomic_write_text(
        disk_store._dir() / "wrong-prefix.json",
        json.dumps({"id": "wrong-prefix", "revision": 1}),
        mode=0o600,
    )
    original_read = disk_store._read_path
    reads = []

    def counted_read(path):
        reads.append(path)
        return original_read(path)

    monkeypatch.setattr(disk_store, "_read_path", counted_read)
    with pytest.raises(PermissionError, match="invalid record path"):
        store.list(limit=1)
    assert reads == []


def test_failed_audit_is_durable_and_retryable(monkeypatch):
    import maverick.audit as audit

    accepted = False

    def _record(*_args, **_kwargs):
        return accepted

    monkeypatch.setattr(audit, "record", _record)
    store = GovernedRecordStore("test_retry", "TGR", "test_record")
    created = store.create(
        {"id": store.new_id(), "status": "open"},
        action="create",
        actor="operator",
    )
    assert created["_audit_pending"]

    accepted = True
    assert store.retry_pending(limit=10) == 1
    loaded = store.get(created["id"])
    assert loaded is not None
    assert loaded["revision"] == created["revision"]
    assert "_audit_pending" not in loaded


def test_retry_pending_rotates_past_the_first_window(monkeypatch):
    import maverick.audit as audit

    accepted = False
    monkeypatch.setattr(audit, "record", lambda *_a, **_k: accepted)
    store = GovernedRecordStore("test_retry_window", "TGW", "test_record")
    for _ in range(6):
        store.create({"id": store.new_id(), "status": "open"},
                     action="create", actor="operator")
    accepted = True
    assert sum(store.retry_pending(limit=2) for _ in range(3)) == 6


def test_public_update_cannot_bypass_revision_or_audit(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store = GovernedRecordStore("test_metadata", "TGR", "test_record")
    created = store.create(
        {"id": store.new_id(), "status": "open"},
        action="create",
        actor="operator",
    )
    with pytest.raises(TypeError, match="metadata_only"):
        store.update(
            created["id"],
            lambda row: row.update(status="closed"),
            expected_revision=created["revision"],
            action="metadata",
            actor="system",
            metadata_only=True,
            queue_audit=False,
        )
    loaded = store.get(created["id"])
    assert loaded is not None
    assert loaded["revision"] == created["revision"]
    assert loaded["status"] == "open"


@pytest.mark.parametrize(
    "reserved",
    [
        {"_audit_pending": []},
        {"created_at": 1.0},
        {"updated_at": 1.0},
        {"revision": 99},
    ],
)
def test_create_rejects_store_reserved_fields(monkeypatch, reserved):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store = GovernedRecordStore("test_reserved", "TGR", "test_record")
    with pytest.raises(ValueError, match="store-reserved"):
        store.create(
            {"id": store.new_id(), "status": "open", **reserved},
            action="create",
            actor="operator",
        )
    assert store.list() == []


def test_actor_is_required_for_governed_mutations(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store = GovernedRecordStore("test_actor", "TGR", "test_record")
    with pytest.raises(ValueError, match="actor"):
        store.create(
            {"id": store.new_id(), "status": "open"},
            action="create",
            actor="",
        )


def test_over_limit_actor_and_action_are_rejected_without_truncation(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store = GovernedRecordStore("test_bounded_actor", "TGR", "test_record")
    record_id = store.new_id()
    with pytest.raises(ValueError, match="actor exceeds"):
        store.create(
            {"id": record_id, "status": "open"},
            action="create",
            actor="a" * 4097,
        )
    with pytest.raises(ValueError, match="action exceeds"):
        store.create(
            {"id": record_id, "status": "open"},
            action="a" * 65,
            actor="operator",
        )
    assert store.list() == []


def test_postgres_round_trip_cas_tenant_scope_and_encrypted_payload(
    monkeypatch,
):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    store, _backend, database = _postgres_store()
    record_id = "TGP-shared1"
    with tenant_scope(tenant="alpha"):
        created = store.create(
            {"id": record_id, "status": "open", "title": "sensitive-title"},
            action="create",
            actor="operator",
        )
        assert created["revision"] == 1
        updated = store.update(
            record_id,
            lambda row: row.update(status="closed"),
            expected_revision=1,
            action="close",
            actor="operator",
        )
        assert updated is not None and updated["revision"] == 2
        with pytest.raises(RecordConflict):
            store.update(
                record_id,
                lambda row: row.update(status="stale"),
                expected_revision=1,
                action="stale",
                actor="operator",
            )
        assert store.get(record_id)["status"] == "closed"

    alpha_key = next(key for key in database.rows if key[0] == "alpha")
    stored_payload = database.rows[alpha_key][1]
    assert stored_payload.startswith("MVKAR1:")
    assert "sensitive-title" not in stored_payload

    with tenant_scope(tenant="beta"):
        assert store.get(record_id) is None
        beta = store.create(
            {"id": record_id, "status": "open", "title": "beta"},
            action="create",
            actor="operator",
        )
        assert beta["revision"] == 1
        assert [row["title"] for row in store.list()] == ["beta"]
    with tenant_scope(tenant="alpha"):
        assert [row["title"] for row in store.list()] == ["sensitive-title"]
        assert store.delete(record_id, expected_revision=updated["revision"]) is True
        assert store.get(record_id) is None
    with tenant_scope(tenant="beta"):
        assert store.get(record_id)["title"] == "beta"

    point_queries = [
        (sql, params)
        for sql, params in database.sql
        if "WHERE tenant_id=%s AND namespace=%s AND record_id=%s" in sql
    ]
    assert point_queries
    assert all(len(params) >= 3 for _, params in point_queries)
    assert any("FOR UPDATE" in sql for sql, _ in point_queries)
    assert any("ON CONFLICT (tenant_id, namespace, record_id)" in sql
               for sql, _ in database.sql)


def test_postgres_list_limit_is_applied_in_sql(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store, _backend, database = _postgres_store("test_bounded_list", "TBL")
    with tenant_scope(tenant="alpha"):
        for suffix in ("first", "second"):
            store.create(
                {"id": f"TBL-{suffix}", "status": "open"},
                action="create",
                actor="operator",
            )
        assert len(store.list(limit=1)) == 1

    assert any(
        sql.endswith("ORDER BY created_at DESC, record_id LIMIT %s")
        and params[-1] == 1
        for sql, params in database.sql
    )


def test_postgres_bounded_create_is_tenant_transactional(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store, _backend, database = _postgres_store(
        "test_capacity",
        "TCP",
    )
    # This covers the admission lock and count; archiving a full namespace is
    # covered against a live database in test_postgres_governed_records_capacity.
    monkeypatch.setattr(GovernedRecordStore, "_archivable", lambda self, backend: False)
    with tenant_scope(tenant="alpha"):
        store.create(
            {"id": "TCP-first", "status": "open"},
            action="create",
            actor="operator",
            max_records=1,
        )
        with pytest.raises(
            GovernedRecordCapacityError,
            match="capacity has been reached",
        ):
            store.create(
                {"id": "TCP-second", "status": "open"},
                action="create",
                actor="operator",
                max_records=1,
            )
    with tenant_scope(tenant="beta"):
        store.create(
            {"id": "TCP-beta", "status": "open"},
            action="create",
            actor="operator",
            max_records=1,
        )

    capacity_sql = [
        sql
        for sql, _params in database.sql
        if sql.startswith("SELECT pg_advisory_xact_lock(")
        or sql.startswith("SELECT COUNT(*) FROM governed_records")
    ]
    assert capacity_sql.count("SELECT COUNT(*) FROM governed_records "
                              "WHERE tenant_id=%s AND namespace=%s") == 3
    assert sum(
        sql.startswith("SELECT pg_advisory_xact_lock(")
        for sql in capacity_sql
    ) == 3
    assert len(database.rows) == 2


def test_shared_record_refuses_legacy_tenant_envelope(monkeypatch):
    from maverick.tenant import kms

    store, _backend, database = _postgres_store("test_tenant_envelope", "TTE")
    blob = b"MVKTEN1\n" + b"\0" * 28
    stored = "MVKAR1:" + base64.b64encode(blob).decode("ascii")
    database.rows[("alpha", "test_tenant_envelope", "TTE-legacy")] = (
        1,
        stored,
        1.0,
        1.0,
    )
    monkeypatch.setattr(
        kms,
        "unseal_for_tenant",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("shared records must not consult node-local tenant DEKs")
        ),
    )

    with tenant_scope(tenant="alpha"):
        with pytest.raises(
            GovernedRecordBackendError,
            match="shared governed-record load failed",
        ):
            store.get("TTE-legacy")


def test_deployment_global_records_use_deployment_key_across_ambient_tenants(
    monkeypatch,
):
    """A global authority must not be encrypted with a request tenant's DEK."""
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    _pin_shared_encryption_key(monkeypatch, b"g" * 32)
    database = _MemoryPg()
    backend = PostgresGovernedRecordBackend(
        "test_global_crypto",
        "TGC",
        dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
        authority_scope="deployment_global",
    )
    backend._schema_ready = True
    store = GovernedRecordStore(
        "test_global_crypto",
        "TGC",
        "test_global_record",
        backend=backend,
        authority_scope="deployment_global",
    )

    with tenant_scope(tenant="alpha"):
        store.create(
            {"id": "TGC-global1", "status": "active", "secret": "fleet"},  # pragma: allowlist secret
            action="create",
            actor="operator",
        )
    with tenant_scope(tenant="beta"):
        loaded = store.get("TGC-global1")

    assert loaded is not None and loaded["secret"] == "fleet"  # pragma: allowlist secret
    ((tenant_key, _namespace, _record_id), row), = tuple(database.rows.items())
    assert len(tenant_key) == 201
    assert row[1].startswith("MVKAR1:")
    assert "fleet" not in row[1]


def test_shared_encryption_floor_fails_before_db_and_withholds_plaintext(
    monkeypatch,
):
    import maverick.audit as audit
    from maverick.crypto_at_rest import unseal_from_str

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    database = _MemoryPg()
    backend = PostgresGovernedRecordBackend(
        "test_encryption_floor",
        "TEF",
        dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
        require_bound_tenant=True,
        require_encryption=True,
    )
    backend._schema_ready = True
    store = GovernedRecordStore(
        "test_encryption_floor",
        "TEF",
        "test_record",
        backend=backend,
    )
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError, match="encryption"):
            store.get("TEF-missing")
        assert database.sql == []

        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        created = store.create(
            {"id": "TEF-record", "status": "open"},
            action="create",
            actor="operator",
        )
        key = next(iter(database.rows))
        revision, payload, created_at, updated_at = database.rows[key]
        assert payload.startswith("MVKAR1:")
        database.rows[key] = (
            revision,
            unseal_from_str(payload),
            created_at,
            updated_at,
        )
        with pytest.raises(PrivacyStateError, match="encryption floor"):
            store.get(created["id"])


def test_shared_key_identity_drift_fails_before_database_access(monkeypatch):
    database = _MemoryPg()
    connect_calls = 0

    def connect(*args, **kwargs):
        nonlocal connect_calls
        connect_calls += 1
        return database.connect(*args, **kwargs)

    first_key = b"a" * 32
    _pin_shared_encryption_key(monkeypatch, first_key)
    backend = PostgresGovernedRecordBackend(
        "test_shared_key_pin",
        "TSK",
        dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=connect,
        require_shared_key_identity=True,
    )
    backend._schema_ready = True

    with tenant_scope(tenant="alpha"):
        assert backend.load("TSK-missing") is None
        admitted_connects = connect_calls

        second_key = b"b" * 32
        _pin_shared_encryption_key(monkeypatch, second_key)
        with pytest.raises(
            GovernedRecordBackendError,
            match="key identity",
        ):
            backend.authoritative_time()
        with pytest.raises(
            GovernedRecordBackendError,
            match="key identity",
        ):
            backend.load("TSK-missing")

    assert connect_calls == admitted_connects


def test_postgres_failed_audit_receipt_is_transactionally_retryable(monkeypatch):
    import maverick.audit as audit

    accepted = False
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: accepted)
    store, _backend, _database = _postgres_store()
    with tenant_scope(tenant="alpha"):
        created = store.create(
            {"id": "TGP-outbox1", "status": "open"},
            action="create",
            actor="operator",
        )
        assert created["_audit_pending"]
        revision = created["revision"]
        accepted = True
        assert store.retry_pending() == 1
        loaded = store.get(created["id"])
        assert loaded is not None
        assert loaded["revision"] == revision
        assert "_audit_pending" not in loaded


def test_postgres_schema_setup_is_advisory_locked(monkeypatch):
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    database = _MemoryPg()
    database.table_exists = False
    database.rls_enabled = False
    database.rls_forced = False
    database.policies = []
    backend = PostgresGovernedRecordBackend(
        "test_schema",
        "TGS",
        dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )
    with tenant_scope(tenant="alpha"):
        assert backend.load("TGS-missing") is None
    sql = [statement for statement, _ in database.sql]
    lock_index = next(
        index for index, statement in enumerate(sql)
        if statement.startswith("SELECT pg_advisory_xact_lock(")
    )
    create_index = next(
        index for index, statement in enumerate(sql)
        if statement.startswith("CREATE TABLE IF NOT EXISTS governed_records")
    )
    assert lock_index < create_index
    assert any("FORCE ROW LEVEL SECURITY" in statement for statement in sql)
    assert len(database.policies) == 1


def test_postgres_schema_rejects_extra_permissive_rls_policy(monkeypatch):
    database = _MemoryPg()
    database.policies.append((
        "allow_everything",
        "PERMISSIVE",
        ["public"],
        "ALL",
        "true",
        "true",
    ))
    backend = PostgresGovernedRecordBackend(
        "test_rls_extra",
        "TRE",
        dsn="postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError, match="incompatible"):
            backend.load("TRE-missing")
    assert {policy[0] for policy in database.policies} == {
        "allow_everything",
        "mvk_tenant_isolation",
    }
    assert not any(
        statement.startswith(("CREATE ", "ALTER ", "DROP "))
        for statement, _ in database.sql
    )


def test_migration_provisioned_schema_uses_verify_only_runtime_path(monkeypatch):
    database = _MemoryPg()
    database.allow_ddl = False
    backend = PostgresGovernedRecordBackend(
        "test_preprovisioned",
        "TPP",
        dsn="postgresql://runtime:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )
    with tenant_scope(tenant="alpha"):
        assert backend.load("TPP-missing") is None
    assert backend._schema_ready is True
    statements = [statement for statement, _ in database.sql]
    assert any(statement.startswith("SELECT column_name") for statement in statements)
    assert any(statement.startswith("SELECT array_agg") for statement in statements)
    assert any(statement.startswith("SELECT pg_get_constraintdef")
               for statement in statements)
    assert not any(
        statement.startswith(("CREATE ", "ALTER ", "DROP "))
        for statement in statements
    )


def test_existing_incompatible_primary_key_fails_without_ddl(monkeypatch):
    database = _MemoryPg()
    database.primary_key = ["namespace", "record_id"]
    backend = PostgresGovernedRecordBackend(
        "test_bad_primary",
        "TBP",
        dsn="postgresql://runtime:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError, match="incompatible"):
            backend.load("TBP-missing")
    assert not any(
        statement.startswith(("CREATE ", "ALTER ", "DROP "))
        for statement, _ in database.sql
    )


def test_existing_schema_missing_identity_bound_fails_without_ddl(monkeypatch):
    database = _MemoryPg()
    database.checks = [
        check for check in database.checks if "char_length(namespace)" not in check
    ]
    backend = PostgresGovernedRecordBackend(
        "test_missing_bound",
        "TMB",
        dsn="postgresql://runtime:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError, match="incompatible"):
            backend.load("TMB-missing")
    assert not any(
        statement.startswith(("CREATE ", "ALTER ", "DROP "))
        for statement, _ in database.sql
    )


@pytest.mark.parametrize("attribute", ["superuser", "bypassrls"])
def test_postgres_runtime_role_must_not_bypass_rls(monkeypatch, attribute):
    database = _MemoryPg()
    setattr(database, attribute, True)
    backend = PostgresGovernedRecordBackend(
        "test_role_boundary",
        "TRB",
        dsn="postgresql://runtime:secret@db.internal/lightwork",  # pragma: allowlist secret
        connect=database.connect,
    )
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError, match="incompatible"):
            backend.load("TRB-missing")


def test_postgres_rechecks_rls_policy_drift_on_every_transaction(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store, _backend, database = _postgres_store("test_rls_drift", "TRD")
    with tenant_scope(tenant="alpha"):
        created = store.create(
            {"id": "TRD-record", "status": "open"},
            action="create",
            actor="operator",
        )
        database.policies.append((
            "later_bypass",
            "PERMISSIVE",
            ["public"],
            "ALL",
            "true",
            "true",
        ))
        with pytest.raises(GovernedRecordBackendError, match="ambiguous"):
            store.get(created["id"])


def test_postgres_rejects_oversize_and_tampered_rows(monkeypatch):
    import maverick.audit as audit
    import maverick.governed_records as governed

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store, _backend, database = _postgres_store("test_bounds", "TBD")
    monkeypatch.setattr(governed, "_MAX_RECORD_JSON_BYTES", 1024)
    with tenant_scope(tenant="alpha"):
        with pytest.raises(ValueError, match="JSON limit"):
            store.create(
                {"id": "TBD-large", "status": "open", "value": "x" * 5000},
                action="create",
                actor="operator",
            )
        assert database.rows == {}

        created = store.create(
            {"id": "TBD-valid", "status": "open"},
            action="create",
            actor="operator",
        )
        key = next(iter(database.rows))
        revision, payload, created_at, updated_at = database.rows[key]
        assert revision == created["revision"]
        database.rows[key] = (revision + 1, payload, created_at, updated_at)
        with pytest.raises(PrivacyStateError, match="revision"):
            store.get(created["id"])


def test_postgres_duplicate_create_has_one_atomic_winner(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store, _backend, _database = _postgres_store("test_create_race", "TCR")
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def create_once(actor: str) -> None:
        with tenant_scope(tenant="alpha"):
            barrier.wait()
            try:
                store.create(
                    {"id": "TCR-same", "status": "open", "actor": actor},
                    action="create",
                    actor=actor,
                )
            except RecordConflict:
                outcomes.append("conflict")
            else:
                outcomes.append("created")

    first = threading.Thread(target=create_once, args=("first",))
    second = threading.Thread(target=create_once, args=("second",))
    first.start()
    second.start()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert sorted(outcomes) == ["conflict", "created"]
    with tenant_scope(tenant="alpha"):
        assert len(store.list()) == 1


def test_postgres_ids_use_full_uuid_entropy_and_legacy_ids_still_validate():
    _store, backend, _database = _postgres_store("test_ids", "TID")
    generated = {backend.new_id() for _ in range(1000)}
    assert len(generated) == 1000
    assert all(
        record_id.startswith("TID-")
        and len(record_id.removeprefix("TID-")) == 32
        for record_id in generated
    )
    # The read validator continues to admit records minted by the old 40-bit
    # implementation; migration does not orphan their existing row ids.
    assert backend.load("TID-0123456789") is None


def test_postgres_errors_do_not_expose_dsn_secret(monkeypatch):
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    dsn = "postgresql://alice:top-secret-password@db.internal/lightwork"  # pragma: allowlist secret

    def fail_connect(value, **_kwargs):
        raise RuntimeError(f"provider rejected {value}")

    backend = PostgresGovernedRecordBackend(
        "test_errors",
        "TGE",
        dsn=dsn,
        connect=fail_connect,
    )
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError) as captured:
            backend.load("TGE-record")
    assert "top-secret-password" not in str(captured.value)
    assert dsn not in str(captured.value)


def test_postgres_value_errors_do_not_expose_dsn_secret(monkeypatch):
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    dsn = "postgresql://alice:value-secret@db.internal/lightwork"  # pragma: allowlist secret

    def fail_connect(value, **_kwargs):
        raise ValueError(f"invalid provider setting {value}")

    backend = PostgresGovernedRecordBackend(
        "test_value_errors",
        "TGV",
        dsn=dsn,
        connect=fail_connect,
    )
    backend._schema_ready = True  # noqa: SLF001 - exercise post-admission I/O
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError) as captured:
            backend.load("TGV-record")
    assert "value-secret" not in str(captured.value)
    assert dsn not in str(captured.value)


def test_enterprise_and_multiple_replicas_fail_closed_without_shared_state(
    monkeypatch,
):
    store = GovernedRecordStore("test_selection", "TGS", "test_record")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    with pytest.raises(GovernedRecordBackendError, match="require Postgres"):
        store.new_id()

    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "auto")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "2")
    with pytest.raises(GovernedRecordBackendError, match="require Postgres"):
        store.new_id()


def test_enterprise_config_remains_readable_before_postgres_is_provisioned(
    tmp_path,
    monkeypatch,
):
    from maverick.config import load_global_config, reset_config_cache

    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    (tmp_path / "config.toml").write_text(
        '[enterprise]\nmode = true\n\n[governed_records]\nbackend = "auto"\n',
        encoding="utf-8",
    )
    reset_config_cache()

    assert load_global_config()["enterprise"]["mode"] is True

    store = GovernedRecordStore("test_enterprise_bootstrap", "TEB", "test_record")
    with pytest.raises(GovernedRecordBackendError, match="require Postgres"):
        store.new_id()


def test_strict_shared_selection_refuses_unbound_or_corrupt_tenant(
    monkeypatch,
):
    store = GovernedRecordStore("test_strict_tenant", "TST", "test_record")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv(
        "MAVERICK_PG_DSN",
        "postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
    )
    with pytest.raises(GovernedRecordBackendError, match="active tenant"):
        store.new_id()

    import maverick.paths as paths

    monkeypatch.setattr(
        paths,
        "current_tenant_id_strict",
        lambda: (_ for _ in ()).throw(TenantPolicyError("corrupt binding")),
    )
    with pytest.raises(TenantPolicyError, match="corrupt binding"):
        store.new_id()


def test_strict_shared_selection_requires_application_encryption(monkeypatch):
    store = GovernedRecordStore("test_strict_crypto", "TSC", "test_record")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv(
        "MAVERICK_PG_DSN",
        "postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
    )
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError, match="encryption"):
            store.new_id()
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        _pin_shared_encryption_key(monkeypatch)
        assert store.new_id().startswith("TSC-")


def test_strict_shared_selection_requires_pinned_fleet_encryption_key(
    monkeypatch,
):
    store = GovernedRecordStore("test_strict_key", "TSK", "test_record")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv(
        "MAVERICK_PG_DSN",
        "postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
    )
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY_DIGEST", raising=False)
    with tenant_scope(tenant="alpha"):
        with pytest.raises(GovernedRecordBackendError, match="key identity"):
            store.new_id()

        key = b"f" * 32
        monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
        with pytest.raises(GovernedRecordBackendError, match="key identity"):
            store.new_id()

        monkeypatch.setenv(
            "MAVERICK_ENCRYPTION_KEY_DIGEST",
            "sha256:" + "0" * 64,
        )
        with pytest.raises(GovernedRecordBackendError, match="key identity"):
            store.new_id()

        _pin_shared_encryption_key(monkeypatch, key)
        assert store.new_id().startswith("TSK-")


def test_standard_postgres_selection_also_requires_application_encryption(
    monkeypatch,
):
    store = GovernedRecordStore("test_standard_crypto", "TPC", "test_record")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv(
        "MAVERICK_PG_DSN",
        "postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
    )
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    with pytest.raises(GovernedRecordBackendError, match="encryption"):
        store.new_id()


def test_standard_postgres_selection_requires_pinned_fleet_key(monkeypatch):
    store = GovernedRecordStore("test_standard_key", "TPK", "test_record")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv(
        "MAVERICK_PG_DSN",
        "postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
    )
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY_DIGEST", raising=False)
    with pytest.raises(GovernedRecordBackendError, match="key identity"):
        store.new_id()


def test_postgres_cutover_refuses_to_hide_local_records(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    store = GovernedRecordStore("test_cutover", "TGC", "test_record")
    with tenant_scope(tenant="alpha"):
        store.create(
            {"id": "TGC-local1", "status": "open"},
            action="create",
            actor="operator",
        )
        monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
        monkeypatch.setenv(
            "MAVERICK_PG_DSN",
            "postgresql://user:secret@db.internal/lightwork",  # pragma: allowlist secret
        )
        # A coordinated cutover restarts every process after changing the
        # authority selector. Simulate that restart while retaining the local
        # legacy records whose cutover guard is under test.
        governed_records._reset_process_authority_pin_for_testing()
        with pytest.raises(GovernedRecordBackendError, match="migrate/import"):
            store.list()


def test_count_reads_ids_never_bodies(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import audit
    monkeypatch.setattr(audit, "record", lambda *_a, **_k: True)
    monkeypatch.setattr(audit, "record_global", lambda *_a, **_k: True)
    from maverick.governed_records import GovernedRecordStore

    store = GovernedRecordStore("count_probe", "CPX", "count_probe")
    assert store.count() == 0
    for index in range(5):
        store.create({"id": f"CPX-{index:03d}", "n": index},
                     action="seed", actor="tester")
    assert store.count() == 5
    assert store.count(maximum=3) == 3  # honest ceiling, single window
