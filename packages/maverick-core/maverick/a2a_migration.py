"""Offline, restartable import of one private SQLite A2A claim authority.

The original ledger is retained. Shared work stays blocked until every claim,
including indeterminate work and tombstones, is imported. A local encrypted
binding prevents downgrade from recreating an empty SQLite ledger on restart.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path

from .a2a_store import META_ID, SharedTaskStore, _identity, _task_key
from .a2a_tasks import (
    _MAX_DURABLE_CLAIMS,
    _MAX_DURABLE_RETAINED_BYTES,
    TERMINAL_STATES,
    _DurableTaskStore,
    _Task,
    _task_tenant_scope,
)
from .file_lock import (
    atomic_create_bytes_chunks,
    atomic_write_text,
    cross_process_lock,
    ensure_private_file,
    open_private_read,
)
from .governed_records import GovernedRecordBackendError, configured_governed_records_backend


def _source_rows(connection, tenant: str, after: tuple[str, str] | None = None):
    query = (
        "SELECT tenant, principal, message_key, request_digest, task_id, status, snapshot_json "
        "FROM a2a_task_claims WHERE tenant=?"
    )
    params = [tenant]
    if after is not None:
        query += " AND (principal, message_key) > (?, ?)"
        params.extend(after)
    cursor = connection.execute(query + " ORDER BY principal, message_key", params)
    while rows := cursor.fetchmany(20):
        yield rows


def _validated_source(row, tenant: str) -> tuple[dict, str | None]:
    raw = dict(row)
    if raw["tenant"] != tenant or not isinstance(raw["principal"], str) or not raw["principal"]:
        raise ValueError("A2A migration source scope is invalid")
    _task_key(raw["task_id"])
    for field in ("message_key", "request_digest"):
        value = raw[field]
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("A2A migration source identity is invalid")
    if raw["status"] not in {"in_progress", "terminal", "tombstone"}:
        raise ValueError("A2A migration source status is invalid")
    stored = raw["snapshot_json"]
    if raw["status"] == "tombstone":
        if stored is not None:
            raise ValueError("A2A migration tombstone contains a result")
        return raw, None
    plain = _DurableTaskStore._decode_snapshot(tenant, stored)
    value = json.loads(plain)
    if (not isinstance(value, dict) or value.get("state") not in TERMINAL_STATES | {"submitted", "working"}
            or (raw["status"] == "terminal") != (value.get("state") in TERMINAL_STATES)
            or not isinstance(value.get("status_history"), list) or not value["status_history"]
            or not isinstance(value["status_history"][-1], dict)
            or value["status_history"][-1].get("state") != value["state"]):
        raise ValueError("A2A migration snapshot state is inconsistent")
    # Reuse the full existing task/retained-byte/message identity validator for
    # active snapshots as well. Only this temporary validation copy is terminal;
    # the original snapshot and indeterminate claim status are preserved.
    validation = dict(value)
    validation["state"] = "failed"
    validation["status_history"] = [*value["status_history"][:-1], {**value["status_history"][-1], "state": "failed"}]
    _Task.from_durable_snapshot(json.dumps(validation), task_id=raw["task_id"], tenant=tenant,
                               principal=raw["principal"], message_key=raw["message_key"],
                               request_digest=raw["request_digest"])
    return raw, plain


def _inspect_source(connection, tenant: str, shared: SharedTaskStore) -> dict:
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("A2A source SQLite integrity check failed")
    if connection.execute("SELECT 1 FROM a2a_task_claims WHERE tenant != ? LIMIT 1", (tenant,)).fetchone():
        raise ValueError("A2A source contains other tenant claims; use a separately reviewed migration")
    digest = hashlib.sha256()
    count = retained = 0
    for page in _source_rows(connection, tenant):
        for row in page:
            raw, plain = _validated_source(row, tenant)
            logical = {**raw, "snapshot_json": plain}
            digest.update(json.dumps(logical, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n")
            count += 1
            if plain is not None:
                retained += len(shared._snapshot(tenant, plain).encode("utf-8"))
            if count > _MAX_DURABLE_CLAIMS or retained > _MAX_DURABLE_RETAINED_BYTES:
                raise ValueError("A2A migration exceeds the shared claim or snapshot quota")
    meta = connection.execute("SELECT claim_count, snapshot_bytes FROM a2a_task_meta WHERE tenant=?", (tenant,)).fetchone()
    actual = connection.execute(
        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN snapshot_json IS NULL THEN 0 ELSE length(CAST(snapshot_json AS BLOB)) END), 0) "
        "FROM a2a_task_claims WHERE tenant=?", (tenant,),
    ).fetchone()
    if (meta is None and count) or (meta is not None and tuple(meta) != tuple(actual)):
        raise ValueError("A2A source accounting is inconsistent")
    return {"source_sha256": digest.hexdigest(), "source_claims": count, "target_snapshot_bytes": retained}


def _binding(path: Path, tenant: str, shared: SharedTaskStore) -> str:
    if path.exists() or path.is_symlink():
        with os.fdopen(open_private_read(path), "rb") as source:
            value = source.read(16385)
        if len(value) > 16384:
            raise ValueError("A2A authority binding is oversized")
        body = json.loads(shared._snapshot(tenant, value.decode("utf-8"), decode=True))
        if (not isinstance(body, dict) or set(body) != {"version", "tenant", "authority_id"}
                or body.get("version") != 1 or body.get("tenant") != tenant
                or not isinstance(body.get("authority_id"), str)
                or uuid.UUID(body["authority_id"]).hex != body["authority_id"]):
            raise ValueError("A2A authority binding is invalid")
        return body["authority_id"]
    authority_id = uuid.uuid4().hex
    atomic_write_text(path, shared._snapshot(tenant, json.dumps(
        {"version": 1, "tenant": tenant, "authority_id": authority_id}, sort_keys=True)))
    return authority_id


def _migration_meta(batch, authority_id: str, plan: dict) -> dict:
    meta = batch.load(META_ID)
    if meta is None:
        if batch.oldest_ids(prefix="a2-", limit=1):
            raise ValueError("A2A shared namespace already contains unaccounted records")
        return {"id": META_ID, "version": 1, "state": "migrating", "authority_id": authority_id,
                "claim_count": 0, "snapshot_bytes": 0, "imported_count": 0, "last_source_key": None,
                "migration_source_sha256": plan["source_sha256"], "migration_source_claims": plan["source_claims"],
                "migration_source_file_sha256": plan["source_file_sha256"],
                "migration_target_snapshot_bytes": plan["target_snapshot_bytes"], "revision": 0}
    if (meta.get("version") != 1 or meta.get("authority_id") != authority_id
            or meta.get("state") not in {"migrating", "ready"}
            or meta.get("migration_source_sha256") != plan["source_sha256"]
            or meta.get("migration_source_file_sha256") != plan["source_file_sha256"]
            or meta.get("migration_source_claims") != plan["source_claims"]
            or meta.get("migration_target_snapshot_bytes") != plan["target_snapshot_bytes"]):
        raise ValueError("A2A migration source or target no longer matches the saved checkpoint")
    imported = meta.get("imported_count")
    if isinstance(imported, bool) or not isinstance(imported, int) or not 0 <= imported <= plan["source_claims"]:
        raise ValueError("A2A migration progress is invalid")
    if meta["state"] == "migrating" and meta.get("claim_count") != imported:
        raise ValueError("A2A migration accounting is inconsistent")
    return meta


def _import_page(batch, meta: dict, rows, tenant: str, shared: SharedTaskStore) -> dict:
    for row in rows:
        raw, plain = _validated_source(row, tenant)
        snapshot = shared._snapshot(tenant, plain) if plain is not None else None
        claim_id = _identity(raw["principal"], raw["message_key"])
        principal_key = hashlib.sha256(raw["principal"].encode("utf-8")).hexdigest()
        batch.save({"id": claim_id, "version": 1, "principal_key": principal_key,
                    "message_key": raw["message_key"], "request_digest": raw["request_digest"],
                    "task_id": raw["task_id"], "status": raw["status"], "snapshot_json": snapshot}, expected_revision=0)
        batch.save({"id": "a2-t-" + _task_key(raw["task_id"]), "version": 1,
                    "claim_id": claim_id, "principal_key": principal_key}, expected_revision=0)
        if raw["status"] == "terminal":
            batch.save({"id": "a2-d-" + _task_key(raw["task_id"]), "version": 1,
                        "claim_id": claim_id, "task_id": raw["task_id"]}, expected_revision=0)
        meta["claim_count"] += 1
        meta["imported_count"] += 1
        meta["snapshot_bytes"] += len(snapshot.encode("utf-8")) if snapshot else 0
        meta["last_source_key"] = [raw["principal"], raw["message_key"]]
    return batch.save(meta, expected_revision=meta["revision"])


def _import(connection, tenant: str, shared: SharedTaskStore, authority_id: str, plan: dict) -> dict:
    with shared._batch(tenant) as batch:
        meta = _migration_meta(batch, authority_id, plan)
        if meta["revision"] == 0:
            meta = batch.save(meta, expected_revision=0)
    if meta["state"] == "ready":
        if meta["imported_count"] != plan["source_claims"]:
            raise ValueError("A2A migration ready receipt is incomplete")
        return meta
    last = meta["last_source_key"]
    if last is not None and (not isinstance(last, list) or len(last) != 2 or not all(isinstance(item, str) for item in last)):
        raise ValueError("A2A migration source cursor is invalid")
    for rows in _source_rows(connection, tenant, tuple(last) if last else None):
        with shared._batch(tenant) as batch:
            meta = _migration_meta(batch, authority_id, plan)
            meta = _import_page(batch, meta, rows, tenant, shared)
    with shared._batch(tenant) as batch:
        meta = _migration_meta(batch, authority_id, plan)
        if meta["imported_count"] != plan["source_claims"] or meta["snapshot_bytes"] != plan["target_snapshot_bytes"]:
            raise ValueError("A2A migration final accounting does not match its source")
        return batch.save({**meta, "state": "ready"}, expected_revision=meta["revision"])


def _file_chunks(path: Path, *, expected_sha256: str | None = None):
    digest = hashlib.sha256()
    with os.fdopen(open_private_read(path), "rb") as source:
        original = os.fstat(source.fileno())
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
            yield chunk
        final, visible = os.fstat(source.fileno()), path.stat()
        if ((original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns)
                != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
                or (original.st_dev, original.st_ino) != (visible.st_dev, visible.st_ino)):
            raise ValueError("A2A source changed while retaining its archive")
    if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
        raise ValueError("A2A retained source digest does not match its receipt")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for chunk in _file_chunks(path):
        digest.update(chunk)
    return digest.hexdigest()


def _archive_path(source: Path, digest: str) -> Path:
    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("A2A migration source digest is invalid")
    return source.with_name("tasks.migrated-" + digest + ".sqlite3")


def _summary(meta: dict, archive: Path) -> dict:
    return {"status": "complete", "authority_id": meta["authority_id"],
            "source_sha256": meta["migration_source_sha256"], "source_claims": meta["migration_source_claims"],
            "target_snapshot_bytes": meta["migration_target_snapshot_bytes"], "archive": archive.name}


def _completed_receipt(source: Path, binding: Path, tenant: str, shared: SharedTaskStore) -> dict:
    if not binding.is_file():
        raise ValueError("local A2A source ledger and completed migration binding are missing")
    authority_id = _binding(binding, tenant, shared)
    with shared._batch(tenant) as batch:
        meta = shared._meta(batch, authority_id)
    archive = _archive_path(source, meta.get("migration_source_sha256"))
    if (meta.get("imported_count") != meta.get("migration_source_claims")
            or not isinstance(meta.get("migration_source_file_sha256"), str)
            or _file_digest(archive) != meta["migration_source_file_sha256"]):
        raise ValueError("retained A2A migration archive does not match its completed receipt")
    return _summary(meta, archive)


def _archive_source(source: Path, tenant: str, shared: SharedTaskStore, authority_id: str, plan: dict) -> dict:
    digest = plan["source_file_sha256"]
    if _file_digest(source) != digest:
        raise ValueError("A2A migration source changed after its completed import")
    with shared._batch(tenant) as batch:
        meta = _migration_meta(batch, authority_id, plan)
        if meta["state"] != "ready":
            raise ValueError("A2A migration is not ready for archive publication")
    archive = _archive_path(source, plan["source_sha256"])
    if archive.exists() or archive.is_symlink():
        if _file_digest(archive) != digest:
            raise ValueError("retained A2A migration archive already exists with different content")
    else:
        atomic_create_bytes_chunks(archive, _file_chunks(source, expected_sha256=digest))
    # Exclusive publication never overwrites a planted archive. A crash before
    # this unlink leaves two private independent copies; resume verifies them
    # against the committed digest before finishing the same cutover.
    if _file_digest(source) != digest:
        raise ValueError("A2A migration source changed before cutover")
    source.unlink()
    return _summary(meta, archive)


def migrate_local_tasks(tenant: str) -> dict:
    """Stop/fence the local control plane, import, and retain the source ledger.

    This is an explicit offline maintenance operation. It never runs on ordinary
    startup. Source plaintext is refused when current encryption policy requires
    ciphertext; an existing encrypted source needs its original readable keys.
    """
    from . import control_plane_lease

    if not tenant or not isinstance(tenant, str):
        raise ValueError("A2A migration requires one explicit tenant")
    if control_plane_lease.current() is not None or control_plane_lease.override_enabled():
        raise GovernedRecordBackendError("stop the control plane and enable its ownership guard before offline A2A migration")
    if configured_governed_records_backend() != "postgres":
        raise GovernedRecordBackendError("configure the shared Postgres authority before offline A2A migration")
    lease = control_plane_lease.acquire(role="a2a-migration")
    if lease is None:
        raise GovernedRecordBackendError("offline A2A migration requires exclusive control-plane ownership")
    try:
        with _task_tenant_scope(tenant):
            local = _DurableTaskStore()
            source = local._path(tenant)
            binding = source.with_suffix(".authority.sealed")
            shared = SharedTaskStore()
            with cross_process_lock(binding, strict=True):
                if not source.is_file():
                    return _completed_receipt(source, binding, tenant, shared)
                ensure_private_file(source, 0o600)
                identity = source.stat()
                if identity.st_size > 512 * 1024 * 1024:
                    raise ValueError("A2A source ledger exceeds the 512 MiB offline migration bound")
                with local._connect(tenant) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        plan = _inspect_source(connection, tenant, shared)
                        # Journal mode is DELETE and BEGIN IMMEDIATE excludes
                        # other SQLite writers. Bind the retained bytes to this
                        # same source snapshot before any shared import commits.
                        plan["source_file_sha256"] = _file_digest(source)
                        authority_id = _binding(binding, tenant, shared)
                        _import(connection, tenant, shared, authority_id, plan)
                    finally:
                        with contextlib.suppress(sqlite3.Error):
                            connection.execute("ROLLBACK")
                lease.assert_owned()
                visible = source.stat()
                if (identity.st_dev, identity.st_ino) != (visible.st_dev, visible.st_ino):
                    raise ValueError("A2A source identity changed before archive publication")
                return _archive_source(source, tenant, shared, authority_id, plan)
    finally:
        control_plane_lease.release()
