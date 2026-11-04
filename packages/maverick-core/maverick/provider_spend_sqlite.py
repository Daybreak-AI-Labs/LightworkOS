"""Transactional local provider accounting with a retained JSON migration source.

The legacy JSON file is never removed during migration. An active marker is
published only after the database is complete; once published, its absence or
corruption closes admission instead of falling back to the stale JSON copy.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from functools import wraps
from pathlib import Path

from .file_lock import (
    atomic_create_text,
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)

_SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE totals(period TEXT NOT NULL, provider TEXT NOT NULL,
                    dollars REAL NOT NULL, PRIMARY KEY(period, provider));
CREATE TABLE receipts(period TEXT NOT NULL, provider TEXT NOT NULL,
    request_id TEXT NOT NULL, work_item_sha256 TEXT,
    state TEXT NOT NULL CHECK(state IN ('held', 'unknown', 'settled')),
    projected REAL NOT NULL CHECK(projected >= 0), payload TEXT NOT NULL,
    PRIMARY KEY(period, provider, request_id));
CREATE INDEX receipts_work_item ON receipts(work_item_sha256, period, provider, request_id);
CREATE INDEX receipts_state ON receipts(period, provider, state, projected);
CREATE TABLE attempts(attempt_key TEXT PRIMARY KEY, metadata_sha256 TEXT NOT NULL,
    provider TEXT NOT NULL, period TEXT NOT NULL, request_id TEXT NOT NULL);
"""


def database_path(legacy: Path) -> Path:
    return legacy.with_name("provider_spend.sqlite3")


def active_path(legacy: Path) -> Path:
    return legacy.with_name("provider_spend.sqlite3.active")


def seal_path(legacy: Path) -> Path:
    return legacy.with_name("provider_spend.sqlite3.seal")


def is_active(legacy: Path) -> bool:
    return active_path(legacy).exists()


def _digest_file(path: Path) -> str:
    """Digest durable pages, excluding SQLite backup's header counters.

    SQLite's online backup rewrites the change counter at bytes 24–27 and its
    matching version-valid-for value at 92–95, and may reset the schema
    cookie at 40–43. Everything else, including page size and B-tree pages,
    remains covered by the seal.
    """
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        header = stream.read(100)
        if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
            raise sqlite3.DatabaseError("provider accounting database is malformed")
        digest.update(header[:24])
        digest.update(header[28:40])
        digest.update(header[44:92])
        digest.update(header[96:])
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _publish_seal(legacy: Path, database: Path) -> None:
    atomic_write_text(seal_path(legacy), _digest_file(database) + "\n", mode=0o600)


def _mark_seal_pending(legacy: Path) -> None:
    """Flag the seal before a commit so a writer that stops between its SQLite
    commit and its new seal (crash, ENOSPC) leaves a state :func:`ensure` can
    recover. Without the flag a seal mismatch is damage and stays fatal."""
    recorded = atomic_read_text(seal_path(legacy)).split()[0]
    atomic_write_text(seal_path(legacy), recorded + " pending\n", mode=0o600)


def _seal_pending(legacy: Path) -> bool:
    try:
        return atomic_read_text(seal_path(legacy)).split()[1:] == ["pending"]
    except OSError:
        return False  # a missing seal is reported by _connect


def _recover_pending_seal(legacy: Path, database: Path, cap) -> None:
    """Re-seal a ledger whose writer stopped between its commit and its seal.

    A seal flagged pending was written under the authority lock, so once this
    caller holds that lock no writer is mid-flight: the writer died. SQLite
    rolls back a hot journal on open; the ledger is then re-sealed only if it
    passes its own integrity check and every ledger invariant. Unflagged
    mismatches (tampering after a clean commit) never reach this path.
    """
    if not _seal_pending(legacy):
        return
    with cross_process_lock(legacy, strict=True):
        if not _seal_pending(legacy):
            return  # the writer finished while this caller waited for the lock
        ensure_private_file(database, 0o600)
        connection = sqlite3.connect(str(database), timeout=15, isolation_level=None)
        try:
            connection.execute("PRAGMA busy_timeout=15000")
            connection.execute("BEGIN")
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise sqlite3.DatabaseError("provider accounting database failed validation")
            _read_complete(connection, cap)
            connection.commit()
        finally:
            connection.close()
        _publish_seal(legacy, database)


def _connect(database: Path) -> sqlite3.Connection:
    # Never let sqlite3 create an apparently fresh authority after publication.
    if not database.is_file():
        raise sqlite3.DatabaseError("provider accounting database is missing")
    ensure_private_file(database, 0o600)
    seal = database.with_suffix(".sqlite3.seal")
    ensure_private_file(seal, 0o600)
    recorded, _, flag = atomic_read_text(seal).strip().partition(" ")
    if len(recorded) != 64 or flag not in {"", "pending"} or recorded != _digest_file(database):
        raise sqlite3.DatabaseError("provider accounting integrity seal does not match")
    connection = sqlite3.connect(str(database), timeout=15, isolation_level=None)
    connection.execute("PRAGMA busy_timeout=15000")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    if connection.execute("SELECT value FROM meta WHERE key='schema'").fetchone() != ("1",):
        connection.close()
        raise sqlite3.DatabaseError("provider accounting schema is incomplete")
    return connection


def _authority_read(function):
    @wraps(function)
    def guarded(legacy: Path, *args, **kwargs):
        # A writer publishes the database and its seal under this lock. Readers
        # must not observe the brief post-commit, pre-seal interval as damage.
        with cross_process_lock(legacy, strict=True):
            return function(legacy, *args, **kwargs)
    return guarded


def _populate(connection: sqlite3.Connection, data: dict, cap) -> None:
    connection.executescript(_SCHEMA)
    connection.execute("BEGIN IMMEDIATE")
    try:
        metadata = data.get(cap._RECEIPTS, {})
        for period, providers in data.items():
            if period in {cap._RECEIPTS, cap._ATTEMPT_INDEX}:
                continue
            for provider, total in providers.items():
                connection.execute("INSERT INTO totals VALUES(?, ?, ?)", (period, provider, total))
                for request_id, row in metadata.get(period, {}).get(provider, {}).items():
                    connection.execute(
                        "INSERT INTO receipts VALUES(?, ?, ?, ?, ?, ?, ?)",
                        (period, provider, request_id, row.get("work_item_sha256"),
                         row["state"], row["projected"],
                         json.dumps(row, allow_nan=False)),
                    )
        for key, row in cap._complete_attempt_index(data).items():
            connection.execute(
                "INSERT INTO attempts VALUES(?, ?, ?, ?, ?)",
                (key, row["metadata_sha256"], row["provider"], row["period"], row["request_id"]),
            )
        connection.execute("INSERT INTO meta VALUES('schema', '1')")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def _build_staged(legacy: Path, data: dict, cap) -> Path:
    directory = ensure_private_directory(legacy.parent)
    stage = Path(directory) / (".provider_spend-" + uuid.uuid4().hex + ".sqlite3")
    try:
        connection = sqlite3.connect(str(stage), isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            _populate(connection, data, cap)
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise sqlite3.DatabaseError("provider accounting database failed validation")
        finally:
            connection.close()
        os.chmod(stage, 0o600)
        return stage
    except BaseException:
        stage.unlink(missing_ok=True)
        raise


def ensure(legacy: Path, cap) -> Path:
    database = database_path(legacy)
    marker = active_path(legacy)
    if marker.exists():
        ensure_private_file(marker, 0o600)
        if not database.is_file():
            raise sqlite3.DatabaseError("provider accounting database is missing")
        _recover_pending_seal(legacy, database, cap)
        return database
    # The old JSON source and the authority switch share one lock with every
    # local writer. cross_process_lock is re-entrant for read/recovery callers
    # that already hold it. A distinct init lock also serializes first-use
    # work across callers that have not yet opened the legacy sidecar.
    with cross_process_lock(legacy, strict=True):
        with cross_process_lock(database.with_suffix(".sqlite3.init"), strict=True):
            if marker.exists():
                if not database.is_file():
                    raise sqlite3.DatabaseError("provider accounting database is missing")
                return database
            source = cap._load_json(legacy)
            stage = _build_staged(legacy, source, cap)
            try:
                _publish_seal(legacy, stage)
                os.replace(stage, database)
                atomic_create_text(marker, "provider accounting sqlite v1\n")
            finally:
                stage.unlink(missing_ok=True)
    return database


def _bucket(connection: sqlite3.Connection, period: str, provider: str, cap):
    total_row = connection.execute(
        "SELECT dollars FROM totals WHERE period=? AND provider=?", (period, provider),
    ).fetchone()
    rows = connection.execute(
        "SELECT request_id, payload FROM receipts WHERE period=? AND provider=?",
        (period, provider),
    ).fetchall()
    if total_row is None and rows:
        raise cap.ProviderAccountingUnavailable
    total = float(total_row[0]) if total_row is not None else 0.0
    receipts = {request_id: json.loads(payload) for request_id, payload in rows}
    cap._validate_receipts(total, receipts)
    return total, receipts


@_authority_read
def read_bucket(legacy: Path, period: str, provider: str, cap):
    connection = _connect(ensure(legacy, cap))
    try:
        connection.execute("BEGIN")
        result = _bucket(connection, period, provider, cap)
        connection.commit()
        return result
    finally:
        connection.close()


@_authority_read
def read_status(legacy: Path, period: str, provider: str, cap):
    """Read the hot admission counters without decoding historical receipts."""
    connection = _connect(ensure(legacy, cap))
    try:
        connection.execute("BEGIN")
        row = connection.execute(
            "SELECT dollars FROM totals WHERE period=? AND provider=?",
            (period, provider),
        ).fetchone()
        if row is None and connection.execute(
            "SELECT 1 FROM receipts WHERE period=? AND provider=? LIMIT 1",
            (period, provider),
        ).fetchone() is not None:
            raise cap.ProviderAccountingUnavailable
        total = cap._amount(float(row[0])) if row else 0.0
        # The state index can seek straight to live holds. Scanning every
        # settled receipt here made each admission slower as history grew.
        held_row = connection.execute(
            "SELECT COALESCE(SUM(projected), 0) FROM receipts "
            "WHERE period=? AND provider=? AND state IN ('held', 'unknown')",
            (period, provider),
        ).fetchone()
        held = cap._amount(float(held_row[0]))
        if held > total + 1e-8:
            raise cap.ProviderAccountingUnavailable
        unresolved = connection.execute(
            "SELECT 1 FROM receipts WHERE period=? AND provider=? "
            "AND state='unknown' LIMIT 1", (period, provider),
        ).fetchone() is not None or connection.execute(
            "SELECT 1 FROM receipts WHERE period=? AND provider=? "
            "AND state='held' AND projected=0 LIMIT 1", (period, provider),
        ).fetchone() is not None
        connection.commit()
        return total, held, unresolved
    finally:
        connection.close()


@_authority_read
def read_receipt(legacy: Path, period: str, provider: str, request_id: str, cap):
    connection = _connect(ensure(legacy, cap))
    try:
        row = connection.execute(
            "SELECT t.dollars, r.payload FROM receipts AS r LEFT JOIN totals AS t "
            "ON t.period=r.period AND t.provider=r.provider "
            "WHERE r.period=? AND r.provider=? AND r.request_id=?",
            (period, provider, request_id),
        ).fetchone()
        if row is None or row[0] is None:
            raise cap.ProviderAccountingUnavailable
        receipt = json.loads(row[1])
        cap._validate_receipts(float(row[0]), {request_id: receipt})
        return receipt
    finally:
        connection.close()


@_authority_read
def find_receipts(legacy: Path, work_item_sha256: str, *, limit: int,
                  after: tuple[str, str, str] | None, cap):
    """A bounded, coherent page using the tenant-bound work-item index."""
    connection = _connect(ensure(legacy, cap))
    try:
        connection.execute("BEGIN")
        sql = (
            "SELECT r.period, r.provider, r.request_id, t.dollars, r.payload "
            "FROM receipts AS r LEFT JOIN totals AS t "
            "ON t.period=r.period AND t.provider=r.provider "
            "WHERE r.work_item_sha256=?"
        )
        params: list[object] = [work_item_sha256]
        if after is not None:
            sql += " AND (r.period, r.provider, r.request_id) > (?, ?, ?)"
            params.extend(after)
        sql += " ORDER BY r.period, r.provider, r.request_id LIMIT ?"
        params.append(limit)
        result = []
        for period, provider, request_id, total, payload in connection.execute(sql, params):
            if total is None:
                raise cap.ProviderAccountingUnavailable
            receipt = json.loads(payload)
            cap._validate_receipts(float(total), {request_id: receipt})
            if receipt.get("work_item_sha256") != work_item_sha256:
                raise cap.ProviderAccountingUnavailable
            result.append((period, provider, request_id, float(total), receipt))
        connection.commit()
        return result
    finally:
        connection.close()


def mutate(legacy: Path, period: str, provider: str, operation, cap, *,
           attempt_claim=None, new_request_id=None, target_request_id=None,
           numeric_only=False):
    database = ensure(legacy, cap)
    with cross_process_lock(legacy, strict=True):
        connection = _connect(database)
        try:
            connection.execute("BEGIN IMMEDIATE")
            if numeric_only:
                total_row = connection.execute(
                    "SELECT dollars FROM totals WHERE period=? AND provider=?",
                    (period, provider),
                ).fetchone()
                if total_row is None and connection.execute(
                    "SELECT 1 FROM receipts WHERE period=? AND provider=? LIMIT 1",
                    (period, provider),
                ).fetchone() is not None:
                    raise cap.ProviderAccountingUnavailable
                total = float(total_row[0]) if total_row is not None else 0.0
                before = {}
            elif new_request_id is not None:
                row = connection.execute(
                    "SELECT 1 FROM receipts WHERE period=? AND provider=? AND request_id=?",
                    (period, provider, new_request_id),
                ).fetchone()
                if row is not None:
                    raise cap.ProviderAccountingUnavailable
                if connection.execute(
                    "SELECT 1 FROM receipts WHERE period=? AND provider=? "
                    "AND (state='unknown' OR (state='held' AND projected=0)) LIMIT 1",
                    (period, provider),
                ).fetchone() is not None and cap.caps_from_config().get(provider) is not None:
                    raise cap.ProviderAccountingUnavailable
                existing_receipt = connection.execute(
                    "SELECT 1 FROM receipts WHERE period=? AND provider=? LIMIT 1",
                    (period, provider),
                ).fetchone()
                before = {}
                total_row = connection.execute(
                    "SELECT dollars FROM totals WHERE period=? AND provider=?",
                    (period, provider),
                ).fetchone()
                if total_row is None and existing_receipt is not None:
                    raise cap.ProviderAccountingUnavailable
                total = float(total_row[0]) if total_row is not None else 0.0
            elif target_request_id is not None:
                total_row = connection.execute(
                    "SELECT dollars FROM totals WHERE period=? AND provider=?",
                    (period, provider),
                ).fetchone()
                row = connection.execute(
                    "SELECT payload FROM receipts WHERE period=? AND provider=? AND request_id=?",
                    (period, provider, target_request_id),
                ).fetchone()
                if total_row is None or row is None:
                    raise cap.ProviderAccountingUnavailable
                total = float(total_row[0])
                before = {target_request_id: json.loads(row[0])}
                cap._validate_receipts(total, before)
            else:
                total, before = _bucket(connection, period, provider, cap)
            original_receipts = json.dumps(before, allow_nan=False)
            receipts = json.loads(original_receipts)
            if attempt_claim is not None:
                key = cap._operation_attempt_key(
                    str(attempt_claim["scope_sha256"]),
                    str(attempt_claim["operation_id"]), int(attempt_claim["attempt_no"]),
                )
                prior = connection.execute(
                    "SELECT metadata_sha256, provider, period, request_id FROM attempts "
                    "WHERE attempt_key=?", (key,),
                ).fetchone()
                if prior is not None:
                    if prior[0] != attempt_claim["metadata_sha256"]:
                        raise cap.ProviderAccountingUnavailable
                    raise cap.ProviderAttemptAlreadyAdmitted(cap._existing_attempt_reference({
                        "metadata_sha256": prior[0], "provider": prior[1],
                        "period": prior[2], "request_id": prior[3],
                    }))
            new_total, receipts, result = operation(total, receipts)
            cap._validate_receipts(new_total, receipts)
            if numeric_only and receipts:
                raise cap.ProviderAccountingUnavailable
            if set(before) - set(receipts):
                # A normal mutation must never silently discard charge evidence.
                raise cap.ProviderAccountingUnavailable
            if (attempt_claim is None and new_total == total
                    and json.dumps(receipts, allow_nan=False) == original_receipts):
                # Exact replay still verified the whole seal and original rows
                # under the authority lock and native writer reservation. No
                # counter, receipt or attempt changed: keep their durable bytes.
                connection.rollback()
                return result
            _mark_seal_pending(legacy)
            if attempt_claim is not None:
                connection.execute(
                    "INSERT INTO attempts VALUES(?, ?, ?, ?, ?)",
                    (key, attempt_claim["metadata_sha256"], provider, period,
                     attempt_claim["request_id"]),
                )
            connection.execute(
                "INSERT INTO totals VALUES(?, ?, ?) ON CONFLICT(period, provider) "
                "DO UPDATE SET dollars=excluded.dollars", (period, provider, new_total),
            )
            for request_id, row in receipts.items():
                if row == before.get(request_id):
                    continue
                payload = json.dumps(row, allow_nan=False)
                connection.execute(
                    "INSERT INTO receipts VALUES(?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(period, provider, request_id) DO UPDATE SET "
                    "work_item_sha256=excluded.work_item_sha256, state=excluded.state, "
                    "projected=excluded.projected, payload=excluded.payload",
                    (period, provider, request_id, row.get("work_item_sha256"),
                     row["state"], row["projected"], payload),
                )
            connection.commit()
            _publish_seal(legacy, database)
            return result
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


def _read_complete(connection: sqlite3.Connection, cap) -> dict:
    """Read and validate every retained row from the caller's one snapshot."""
    data: dict = {}
    for period, provider, total in connection.execute("SELECT period, provider, dollars FROM totals"):
        data.setdefault(period, {})[provider] = total
    metadata: dict = {}
    for period, provider, request_id, payload in connection.execute(
        "SELECT period, provider, request_id, payload FROM receipts"
    ):
        metadata.setdefault(period, {}).setdefault(provider, {})[request_id] = json.loads(payload)
    if metadata:
        data[cap._RECEIPTS] = metadata
    attempts = {
        key: {"metadata_sha256": digest, "provider": provider,
              "period": period, "request_id": request_id}
        for key, digest, provider, period, request_id in connection.execute(
            "SELECT attempt_key, metadata_sha256, provider, period, request_id FROM attempts"
        )
    }
    if attempts:
        data[cap._ATTEMPT_INDEX] = attempts
    # Export/recovery must fail closed if a row is corrupt or missing.
    cap._validate_ledger(data)
    return data


@_authority_read
def load(legacy: Path, cap) -> dict:
    connection = _connect(ensure(legacy, cap))
    try:
        connection.execute("BEGIN")
        data = _read_complete(connection, cap)
        connection.commit()
        return data
    finally:
        connection.close()


def replace(legacy: Path, data: dict, cap) -> None:
    """Publish a reviewed complete replacement under the caller's JSON lock."""
    cap._validate_ledger(data)
    if not is_active(legacy):
        # A pre-migration repair may need to replace a damaged JSON source.
        # Retain the caller's failed-file evidence, then migrate the repaired
        # source through the ordinary complete-before-active publication.
        cap._save_json(legacy, data)
        ensure(legacy, cap)
        return
    stage = _build_staged(legacy, data, cap)
    try:
        _publish_seal(legacy, stage)
        os.replace(stage, database_path(legacy))
    finally:
        stage.unlink(missing_ok=True)


@_authority_read
def health(legacy: Path, cap) -> dict:
    database = ensure(legacy, cap)
    connection = _connect(database)
    try:
        connection.execute("BEGIN")
        # The same sealed read snapshot supplies both complete recovery data
        # and health counters. Opening a second connection here rehashed all
        # settled history without strengthening that snapshot's custody.
        data = _read_complete(connection, cap)
        # JSON copy size can differ substantially from SQLite page allocation.
        encoded_ledger_bytes = len(json.dumps(data, allow_nan=False).encode("utf-8"))
        integrity = connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
        receipt_count = int(connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
        attempt_count = int(connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
        unresolved = int(connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE state != 'settled'"
        ).fetchone()[0])
        connection.commit()
        return {"format": "indexed", "available": integrity, "receipt_count": receipt_count,
                "attempt_count": attempt_count, "unresolved_count": unresolved,
                "bytes": database.stat().st_size,
                "encoded_ledger_bytes": encoded_ledger_bytes,
                "single_file_copy_available": encoded_ledger_bytes + 2048 <= 12 * 1024 * 1024,
                "message": ("Spending records are healthy." if integrity else
                            "Spending records need recovery; new AI calls are blocked.")}
    finally:
        connection.close()
