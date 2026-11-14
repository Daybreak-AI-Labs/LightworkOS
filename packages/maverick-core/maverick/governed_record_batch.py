"""Bounded multi-record transactions for a single shared authority namespace.

The caller owns its document schema and audit/outbox semantics. A namespace
using this interface must use it for every mutation. Namespace exclusion, row
revisions, encryption, forced RLS and commit all belong to one transaction;
holding this Python object after that transaction never extends authority.
"""
from __future__ import annotations

import contextlib
import hashlib
import threading
from collections.abc import Iterator
from typing import Any

from .governed_records import (
    GovernedRecordBackendError,
    PostgresGovernedRecordBackend,
    _encode_record,
    _prepared_record,
    _row_record,
    _valid_record_id,
)
from .privacy_ops import RecordConflict


class RecordBatch:
    """An owned, thread-bound transaction with at most 512 record operations.

    Each ``load`` counts as one; ``save`` and ``delete`` each load first, so
    they count as two, which bounds a batch to 256 saves or deletes."""

    def __init__(self, backend: PostgresGovernedRecordBackend, cursor: Any, tenant: str):
        self._backend = backend
        self._cursor = cursor
        self._tenant = tenant
        self._owner = threading.get_ident()
        self._open = True
        self._remaining = 512

    def close(self) -> None:
        self._open = False

    def _admit(self) -> None:
        if not self._open or self._owner != threading.get_ident():
            raise GovernedRecordBackendError("shared record transaction is no longer owned")
        self._remaining -= 1
        if self._remaining < 0:
            raise GovernedRecordBackendError("shared record transaction operation bound exceeded")

    def load(self, record_id: str) -> dict | None:
        self._admit()
        backend = self._backend
        _valid_record_id(record_id, backend.prefix)
        self._cursor.execute(
            "SELECT revision, record_json, created_at, updated_at "
            "FROM governed_records WHERE tenant_id=%s AND namespace=%s "
            "AND record_id=%s FOR UPDATE",
            (self._tenant, backend.namespace, record_id),
        )
        row = self._cursor.fetchone()
        return (_row_record(row, record_id=record_id, prefix=backend.prefix,
                            require_encryption=True) if row is not None else None)

    def save(self, record: dict, *, expected_revision: int) -> dict:
        self._admit()
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
            raise ValueError("shared record revision is invalid")
        backend = self._backend
        record_id = _valid_record_id(record.get("id"), backend.prefix)
        previous = self.load(record_id)
        revision = previous["revision"] if previous else 0
        if revision != expected_revision:
            raise RecordConflict("shared record changed during transaction")
        self._cursor.execute("SELECT extract(epoch FROM clock_timestamp())")
        now = float(self._cursor.fetchone()[0])
        saved = _prepared_record({**record, "created_at": previous["created_at"] if previous else now,
                                  "updated_at": now}, previous, bump_revision=True)
        stored = _encode_record(saved, require_encryption=True)
        self._cursor.execute(
            "INSERT INTO governed_records "
            "(tenant_id, namespace, record_id, revision, record_json, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, namespace, record_id) DO UPDATE SET "
            "revision=EXCLUDED.revision, record_json=EXCLUDED.record_json, "
            "updated_at=EXCLUDED.updated_at "
            "WHERE governed_records.revision=%s",
            (self._tenant, backend.namespace, record_id, saved["revision"], stored,
             saved["created_at"], now, expected_revision),
        )
        if self._cursor.rowcount != 1:
            raise RecordConflict("shared record changed during transaction")
        return saved

    def delete(self, record_id: str, *, expected_revision: int) -> None:
        self._admit()
        record = self.load(record_id)
        if record is None or record["revision"] != expected_revision:
            raise RecordConflict("shared record changed during transaction")
        if record.get("_audit_pending"):
            raise GovernedRecordBackendError("shared record still has pending audit receipts")
        self._cursor.execute(
            "DELETE FROM governed_records WHERE tenant_id=%s AND namespace=%s "
            "AND record_id=%s AND revision=%s",
            (self._tenant, self._backend.namespace, record_id, expected_revision),
        )
        if self._cursor.rowcount != 1:
            raise RecordConflict("shared record changed during transaction")

    def oldest_ids(self, *, prefix: str, limit: int = 100) -> list[str]:
        self._admit()
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("shared record page limit must be from 1 to 100")
        _valid_record_id(prefix + "x", self._backend.prefix)
        # Escape the only wildcard accepted by the record-ID validator; do not
        # rely on deployment-specific text collation for a prefix interval.
        pattern = prefix.replace("_", "\\_") + "%"
        self._cursor.execute(
            "SELECT record_id FROM governed_records WHERE tenant_id=%s AND namespace=%s "
            "AND record_id LIKE %s "
            "ORDER BY created_at, record_id LIMIT %s",
            (self._tenant, self._backend.namespace, pattern, limit),
        )
        return [str(row[0]) for row in self._cursor.fetchall()]


@contextlib.contextmanager
def shared_record_batch(backend: PostgresGovernedRecordBackend) -> Iterator[RecordBatch]:
    """Pin existing shared-store admission through a bounded atomic batch."""
    if not isinstance(backend, PostgresGovernedRecordBackend) or backend.lookup_spec is not None:
        raise GovernedRecordBackendError("shared record batch requires an exclusive namespace")
    tenant = backend._tenant_key()
    with backend._operation("atomic batch"), backend._transaction(tenant) as cursor:
        material = f"governed-record-batch-v1\0{tenant}\0{backend.namespace}".encode()
        key = int.from_bytes(hashlib.sha256(material).digest()[:8], "big", signed=True)
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
        batch = RecordBatch(backend, cursor, tenant)
        try:
            yield batch
        finally:
            # Seal the handle before commit too: a failed commit must not leave
            # a apparently usable cursor or cause automatic write replay.
            batch.close()
