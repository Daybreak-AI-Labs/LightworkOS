"""Versioned A2A claim authority selected with the governed-record backend.

Shared claims use the already qualified encrypted/forced-RLS record table.
Claims, task lookup, quota accounting and terminal-eviction indexes commit
together. An in-progress identity is never leased, expired or reassigned: a
crashed runner's external effect remains unknown and requires reconciliation.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import uuid
from pathlib import Path

from .governed_record_batch import shared_record_batch
from .governed_records import (
    GovernedRecordBackendError,
    GovernedRecordStore,
    PostgresGovernedRecordBackend,
    configured_governed_records_backend,
)

NAMESPACE = "a2a-task-authority-v1"
PREFIX = "a2"
META_ID = "a2-meta"


def _identity(principal: str, message_key: str) -> str:
    # Fixed digest boundaries; the complete constituent digests are retained
    # inside the encrypted row and compared before any cached result is used.
    principal_key = hashlib.sha256(principal.encode("utf-8")).hexdigest()
    return "a2-c-" + hashlib.sha256((principal_key + message_key).encode()).hexdigest()[:59]


def _task_key(task_id: str) -> str:
    return uuid.UUID(task_id).hex


class _Capacity(GovernedRecordBackendError):
    """Rollback a partially prepared claim or snapshot eviction."""


class SharedTaskStore:
    """One namespace, one transaction contract, no fallback on shared failure."""

    def __init__(self, store: GovernedRecordStore | None = None):
        self._store = store or GovernedRecordStore(NAMESPACE, PREFIX, "a2a_task_authority")

    @contextlib.contextmanager
    def _batch(self, tenant: str):
        from .a2a_tasks import _task_tenant_scope

        with _task_tenant_scope(tenant):
            backend = self._store._backend()
            if not isinstance(backend, PostgresGovernedRecordBackend):
                raise GovernedRecordBackendError("shared A2A requires Postgres authority")
            with shared_record_batch(backend) as batch:
                yield batch

    @staticmethod
    def _meta(batch, expected_authority_id: str | None = None) -> dict:
        from .a2a_tasks import _MAX_DURABLE_CLAIMS, _MAX_DURABLE_RETAINED_BYTES

        meta = batch.load(META_ID)
        if meta is None:
            if batch.oldest_ids(prefix="a2-", limit=1):
                raise ValueError("shared A2A accounting is missing from an existing authority")
            meta = {"id": META_ID, "version": 1, "state": "ready", "claim_count": 0,
                    "snapshot_bytes": 0, "revision": 0, "authority_id": uuid.uuid4().hex}
        if meta.get("version") != 1 or meta.get("state") != "ready":
            raise ValueError("shared A2A authority requires migration reconciliation")
        if (not isinstance(meta.get("authority_id"), str)
                or len(meta["authority_id"]) != 32
                or uuid.UUID(meta["authority_id"]).hex != meta["authority_id"]):
            raise ValueError("shared A2A authority identity is invalid")
        if expected_authority_id is not None and not hmac.compare_digest(meta["authority_id"], expected_authority_id):
            raise GovernedRecordBackendError("shared A2A authority binding does not match the database")
        for key, maximum in (("claim_count", _MAX_DURABLE_CLAIMS),
                             ("snapshot_bytes", _MAX_DURABLE_RETAINED_BYTES)):
            value = meta.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError("invalid shared A2A accounting")
        return meta

    def bind_authority(self, tenant: str, *, expected_id: str | None = None) -> str:
        """Establish the durable authority identity before admitting effects."""
        with self._batch(tenant) as batch:
            meta = self._meta(batch, expected_id)
            if meta["revision"] == 0:
                meta = batch.save(meta, expected_revision=0)
            return meta["authority_id"]

    @staticmethod
    def _snapshot(tenant: str, value: str, *, decode: bool = False) -> str:
        from .a2a_tasks import _DurableTaskStore
        from .crypto_at_rest import deployment_key_scope, external_fleet_key_scope

        # Keep the existing ciphertext-byte quota convention. The row envelope
        # additionally protects identities/accounting; neither layer may use an
        # automatically created per-node key in the shared authority.
        with deployment_key_scope(), external_fleet_key_scope():
            fn = _DurableTaskStore._decode_snapshot if decode else _DurableTaskStore._encode_snapshot
            return fn(tenant, value)

    @staticmethod
    def _bound(row: dict, principal: str, message_key: str) -> None:
        principal_key = hashlib.sha256(principal.encode("utf-8")).hexdigest()
        if (row.get("version") != 1
                or not hmac.compare_digest(str(row.get("principal_key", "")), principal_key)
                or not hmac.compare_digest(str(row.get("message_key", "")), message_key)):
            raise ValueError("shared A2A claim binding is invalid")
        if row.get("status") not in {"in_progress", "terminal", "tombstone"}:
            raise ValueError("shared A2A claim status is invalid")

    def _hydrate(self, row: dict, tenant: str, principal: str):
        from .a2a_tasks import _Task

        return _Task.from_durable_snapshot(
            self._snapshot(tenant, row["snapshot_json"], decode=True),
            task_id=row["task_id"], tenant=tenant, principal=principal,
            message_key=row["message_key"], request_digest=row["request_digest"],
        )

    @staticmethod
    def _size(row: dict) -> int:
        snapshot = row.get("snapshot_json")
        if snapshot is None:
            if row.get("status") != "tombstone":
                raise ValueError("shared A2A snapshot is missing")
            return 0
        if not isinstance(snapshot, str):
            raise ValueError("shared A2A snapshot is invalid")
        from .a2a_tasks import _MAX_DURABLE_STORED_SNAPSHOT_BYTES
        size = len(snapshot.encode("utf-8"))
        if size > _MAX_DURABLE_STORED_SNAPSHOT_BYTES:
            raise ValueError("shared A2A snapshot exceeds its byte limit")
        return size

    def _make_room(self, batch, meta: dict, *, old_size: int, new_size: int,
                   exclude_task_id: str = "") -> int:
        from .a2a_tasks import _MAX_DURABLE_RETAINED_BYTES

        retained = meta["snapshot_bytes"]
        target = retained - old_size + new_size
        if target < 0:
            raise ValueError("shared A2A quota accounting is inconsistent")
        if target <= _MAX_DURABLE_RETAINED_BYTES:
            return target
        # A bounded page prevents a huge history from monopolising the claim
        # authority. If it cannot make room, the transaction rolls back and
        # admission reports capacity, never deleting an idempotency identity.
        for index_id in batch.oldest_ids(prefix="a2-d-", limit=60):
            index = batch.load(index_id)
            if index is None:
                raise ValueError("shared A2A terminal index is inconsistent")
            row = batch.load(index["claim_id"])
            if (row is None or row.get("status") != "terminal"
                    or index.get("task_id") != row.get("task_id")):
                raise ValueError("shared A2A terminal index is inconsistent")
            if row["task_id"] == exclude_task_id:
                continue
            target -= self._size(row)
            batch.save({**row, "status": "tombstone", "snapshot_json": None},
                       expected_revision=row["revision"])
            batch.delete(index_id, expected_revision=index["revision"])
            if target <= _MAX_DURABLE_RETAINED_BYTES:
                return target
        raise _Capacity

    def claim(self, task, *, message_id: str, request_digest: str,
              expected_authority_id: str | None = None):
        from .a2a_tasks import _MAX_DURABLE_CLAIMS, _DurableTaskStore

        message_key = _DurableTaskStore._message_key(message_id)
        claim_id = _identity(task.principal, message_key)
        snapshot = self._snapshot(task.tenant, task.durable_snapshot())
        try:
            with self._batch(task.tenant) as batch:
                meta = self._meta(batch, expected_authority_id)
                row = batch.load(claim_id)
                if row is not None:
                    self._bound(row, task.principal, message_key)
                    if not hmac.compare_digest(row["request_digest"], request_digest):
                        return "conflict", None
                    if row["status"] == "in_progress":
                        return "indeterminate", None
                    if row["status"] == "tombstone":
                        return "tombstone", None
                    return "cached", self._hydrate(row, task.tenant, task.principal)
                if meta["claim_count"] >= _MAX_DURABLE_CLAIMS:
                    return "capacity", None
                retained = self._make_room(batch, meta, old_size=0, new_size=len(snapshot.encode("utf-8")))
                batch.save({"id": claim_id, "version": 1,
                            "principal_key": hashlib.sha256(task.principal.encode()).hexdigest(),
                            "message_key": message_key, "request_digest": request_digest,
                            "task_id": task.id, "status": "in_progress", "snapshot_json": snapshot},
                           expected_revision=0)
                batch.save({"id": "a2-t-" + _task_key(task.id), "version": 1,
                            "claim_id": claim_id, "principal_key": hashlib.sha256(task.principal.encode()).hexdigest()},
                           expected_revision=0)
                batch.save({**meta, "claim_count": meta["claim_count"] + 1,
                            "snapshot_bytes": retained}, expected_revision=meta["revision"])
                return "owner", None
        except _Capacity:
            return "capacity", None

    def save(self, task, *, expected_authority_id: str | None = None) -> str:
        from .a2a_tasks import TERMINAL_STATES, _DurableTaskStore

        if task.idempotency_key is None or not task.request_digest:
            raise ValueError("durable A2A task is missing its claim identity")
        captured_tenant, captured_principal, message_id = task.idempotency_key
        if captured_tenant != task.tenant or captured_principal != task.principal:
            raise ValueError("durable A2A task scope changed")
        message_key = _DurableTaskStore._message_key(message_id)
        claim_id = _identity(task.principal, message_key)
        snapshot = self._snapshot(task.tenant, task.durable_snapshot())
        new_status = "terminal" if task.state in TERMINAL_STATES else "in_progress"
        try:
            return self._save(task, claim_id, message_key, snapshot, new_status, expected_authority_id)
        except _Capacity:
            if new_status != "terminal":
                raise ValueError("A2A durable active-state capacity reached") from None
            # Retry is a distinct no-body settlement after a known rollback,
            # never a transport/commit retry. The original identity is still
            # checked under the new transaction before a tombstone is written.
            return self._save(task, claim_id, message_key, None, "tombstone", expected_authority_id)

    def _save(self, task, claim_id: str, message_key: str, snapshot: str | None,
              status: str, expected_authority_id: str | None) -> str:
        with self._batch(task.tenant) as batch:
            meta = self._meta(batch, expected_authority_id)
            row = batch.load(claim_id)
            if row is None:
                raise ValueError("durable A2A claim identity mismatch")
            self._bound(row, task.principal, message_key)
            if row["task_id"] != task.id or not hmac.compare_digest(row["request_digest"], task.request_digest):
                raise ValueError("durable A2A claim identity mismatch")
            if row["status"] == "tombstone":
                return "tombstone"
            if row["status"] == "terminal" and status == "in_progress":
                raise ValueError("durable A2A terminal state cannot be reopened")
            retained = self._make_room(batch, meta, old_size=self._size(row),
                                       new_size=len(snapshot.encode("utf-8")) if snapshot else 0,
                                       exclude_task_id=task.id)
            batch.save({**row, "status": status, "snapshot_json": snapshot}, expected_revision=row["revision"])
            index_id = "a2-d-" + _task_key(task.id)
            index = batch.load(index_id)
            if status == "terminal" and index is None:
                batch.save({"id": index_id, "version": 1, "claim_id": claim_id, "task_id": task.id}, expected_revision=0)
            elif status == "tombstone" and index is not None:
                batch.delete(index_id, expected_revision=index["revision"])
            batch.save({**meta, "snapshot_bytes": retained}, expected_revision=meta["revision"])
            return status

    def load(self, *, tenant: str, principal: str, task_id: str,
             expected_authority_id: str | None = None):
        with self._batch(tenant) as batch:
            self._meta(batch, expected_authority_id)
            try:
                key = _task_key(task_id)
            except (ValueError, TypeError, AttributeError):
                return "missing", None
            index = batch.load("a2-t-" + key)
            principal_key = hashlib.sha256(principal.encode()).hexdigest()
            if index is None or not hmac.compare_digest(str(index.get("principal_key", "")), principal_key):
                return "missing", None
            row = batch.load(index["claim_id"])
            if row is None or row.get("task_id") != task_id:
                raise ValueError("shared A2A task lookup is inconsistent")
            self._bound(row, principal, row["message_key"])
            if row["id"] != _identity(principal, row["message_key"]):
                raise ValueError("shared A2A task lookup binding is invalid")
            if row["status"] != "terminal":
                return row["status"], None
            return "terminal", self._hydrate(row, tenant, principal)


class DurableTaskStore:
    """Select once per process policy; refuse silent local/shared cutovers."""

    def __init__(self, path: Path | None = None):
        from .a2a_tasks import _DurableTaskStore

        self._local = _DurableTaskStore(path)
        self._shared = SharedTaskStore()
        self._explicit_path = path is not None

    def _authority(self, tenant: str, binding_path: Path):
        if configured_governed_records_backend() == "local":
            if binding_path.exists() or binding_path.is_symlink():
                raise GovernedRecordBackendError("shared A2A authority binding forbids local downgrade")
            return self._local, None
        if self._explicit_path:
            raise GovernedRecordBackendError("a local A2A state_path cannot override shared authority")
        path = self._local._path(tenant)
        # Even an empty existing DB may represent lost/partially restored
        # consumption state. Require the offline authenticated migration path;
        # never assume absence of visible rows makes a new shared plane safe.
        if path.exists() or path.is_symlink():
            raise GovernedRecordBackendError(
                "local A2A claims exist; migrate and reconcile the claim ledger before shared admission")
        from .file_lock import atomic_write_text, open_private_read

        if binding_path.exists() or binding_path.is_symlink():
            # Private single-link reads refuse aliased/corrupt markers. This
            # local receipt binds a root to an encrypted shared namespace ID,
            # without pinning rotating passwords or revealing a DSN.
            with os.fdopen(open_private_read(binding_path), "rb") as source:
                raw = source.read(16385)
            if len(raw) > 16384:
                raise GovernedRecordBackendError("shared A2A authority binding is oversized")
            stored = raw.decode("utf-8")
            binding = json.loads(self._shared._snapshot(tenant, stored, decode=True))
            if (not isinstance(binding, dict) or set(binding) != {"version", "tenant", "authority_id"}
                    or binding.get("version") != 1 or binding.get("tenant") != tenant
                    or not isinstance(binding.get("authority_id"), str)
                    or len(binding["authority_id"]) != 32):
                raise GovernedRecordBackendError("shared A2A authority binding is invalid")
            authority_id = self._shared.bind_authority(tenant, expected_id=binding["authority_id"])
        else:
            authority_id = self._shared.bind_authority(tenant)
            binding = {"version": 1, "tenant": tenant, "authority_id": authority_id}
            atomic_write_text(binding_path, self._shared._snapshot(tenant, json.dumps(binding, sort_keys=True)))
        return self._shared, authority_id

    def _invoke(self, operation: str, scope_tenant: str, *args, **kwargs):
        from .file_lock import cross_process_lock

        binding_path = self._local._path(scope_tenant).with_suffix(".authority.sealed")
        # Admission + local I/O share this lock with offline migration. An
        # already-running local claim cannot slip past a cutover marker check.
        with cross_process_lock(binding_path, strict=True):
            authority, authority_id = self._authority(scope_tenant, binding_path)
            if authority_id is not None:
                kwargs["expected_authority_id"] = authority_id
            return getattr(authority, operation)(*args, **kwargs)

    def claim(self, task, *, message_id: str, request_digest: str):
        return self._invoke("claim", task.tenant, task, message_id=message_id, request_digest=request_digest)

    def save(self, task):
        return self._invoke("save", task.tenant, task)

    def load(self, *, tenant: str, principal: str, task_id: str):
        return self._invoke("load", tenant, tenant=tenant, principal=principal, task_id=task_id)
