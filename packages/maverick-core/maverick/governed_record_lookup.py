"""Maintained, rebuildable exact-key projections over canonical governed rows.

Only digests, source identities and revisions enter the local index. A lookup
always hydrates and revalidates the source; this projection grants no authority.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from .file_lock import (
    atomic_create_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_file,
    prepare_private_directory,
)
from .privacy_ops import _validated_private_directory


class RecordLookupUnavailable(RuntimeError):
    """A partial, ambiguous or stale projection cannot answer authoritatively."""


@dataclass(frozen=True)
class RecordLookupSpec:
    name: str
    extract: Callable[[Mapping[str, Any]], list[str]]
    max_keys: int = 20
    max_records: int = 10_000

    def __post_init__(self):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.name):
            raise ValueError("record lookup name must be versioned and portable")
        if not 1 <= self.max_keys <= 100 or not 1 <= self.max_records <= 10_000:
            raise ValueError("record lookup bounds are invalid")

    def keys(self, row):
        keys = self.extract(row)
        if not isinstance(keys, list) or len(keys) > self.max_keys:
            raise RecordLookupUnavailable("record lookup source exceeds its key bound")
        if any(not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key) for key in keys):
            raise RecordLookupUnavailable("record lookup source has invalid digests")
        return set(keys)


def lookup_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def batch_limit(limit):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("record lookup batch must be between 1 and 100")
    return limit


_SCHEMA = """
CREATE TABLE IF NOT EXISTS state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), cursor TEXT NOT NULL,
 ready INTEGER NOT NULL, scanned INTEGER NOT NULL, signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
 digest TEXT NOT NULL, record_id TEXT NOT NULL, revision INTEGER NOT NULL,
 PRIMARY KEY(digest,record_id)
);
CREATE INDEX IF NOT EXISTS entries_record ON entries(record_id);
CREATE TABLE IF NOT EXISTS dirty (record_id TEXT PRIMARY KEY);
"""


class LocalRecordLookup:
    def __init__(self, store, spec: RecordLookupSpec):
        self.store, self.spec = store, spec

    def _signature(self):
        info = self.store._dir().stat()
        return f"{info.st_dev}:{info.st_ino}:{info.st_mtime_ns}:{info.st_ctime_ns}"

    def _reset(self, connection):
        connection.execute("DELETE FROM entries")
        connection.execute("DELETE FROM dirty")
        empty = next(iter(self.store.iter_record_ids(limit=1)), None) is None
        connection.execute("INSERT OR REPLACE INTO state VALUES (1,'',?,0,?)",
                           (int(empty), self._signature()))

    @contextmanager
    def connection(self, *, rebuild=False):
        root, _ = _validated_private_directory(self.store._dir(), must_exist=False)
        prepare_private_directory(root)
        derived, _ = _validated_private_directory(root / ".record-lookup", must_exist=False)
        prepare_private_directory(derived)
        path = derived / (self.spec.name + ".sqlite3")
        with cross_process_lock(path, strict=True):
            if not path.exists():
                atomic_create_bytes(path, b"")
            ensure_private_file(path)
            connection = sqlite3.connect(str(path), timeout=10)
            try:
                try:
                    if rebuild:
                        connection.executescript("DROP TABLE IF EXISTS entries; DROP TABLE IF EXISTS dirty; DROP TABLE IF EXISTS state;")
                    connection.executescript(_SCHEMA)
                except sqlite3.DatabaseError:
                    if not rebuild:
                        raise RecordLookupUnavailable("record lookup needs an explicit rebuild") from None
                    connection.close()
                    atomic_write_bytes(path, b"")
                    connection = sqlite3.connect(str(path), timeout=10)
                    connection.executescript(_SCHEMA)
                state = connection.execute("SELECT signature FROM state WHERE singleton=1").fetchone()
                marker = root / ".record-lookup-rebuild"
                if rebuild or state is None or state[0] != self._signature() or marker.exists():
                    self._reset(connection)
                    if marker.exists():
                        ensure_private_file(marker)
                        marker.unlink()
                        connection.execute("UPDATE state SET signature=?", (self._signature(),))
                    connection.commit()
                yield connection
            finally:
                connection.close()

    def _replace(self, connection, record_id, row):
        connection.execute("DELETE FROM entries WHERE record_id=?", (record_id,))
        if row is not None:
            connection.executemany("INSERT INTO entries VALUES (?,?,?)",
                                   [(key, record_id, row.get("revision", 0)) for key in self.spec.keys(row)])

    def mutate(self, record_id, operation):
        with self.connection() as connection:
            # A crash before/after the JSON commit always leaves a durable
            # intent, even if the business operation raises a stop exception.
            connection.execute("INSERT OR IGNORE INTO dirty VALUES (?)", (record_id,))
            connection.commit()
            result = operation()
            self._replace(connection, record_id, self.store.load(record_id))
            connection.execute("DELETE FROM dirty WHERE record_id=?", (record_id,))
            connection.execute("UPDATE state SET signature=?", (self._signature(),))
            connection.commit()
            return result

    def _advance(self, connection, limit):
        dirty = connection.execute("SELECT record_id FROM dirty LIMIT ?", (limit,)).fetchall()
        for (record_id,) in dirty:
            self._replace(connection, record_id, self.store.load(record_id))
            connection.execute("DELETE FROM dirty WHERE record_id=?", (record_id,))
        cursor, ready, scanned = connection.execute("SELECT cursor,ready,scanned FROM state").fetchone()
        if (not isinstance(cursor, str) or ready not in (0, 1)
                or not isinstance(scanned, int) or not 0 <= scanned <= self.spec.max_records):
            raise RecordLookupUnavailable("record lookup migration state is invalid")
        remaining = limit - len(dirty)
        if not ready and remaining:
            window = [(key, ident) for key, ident in self.store.iter_record_ids(
                start_after=cursor, limit=remaining + 1) if key > cursor]
            processed, read_bytes = 0, 0
            for key, ident in window[:remaining]:
                source_path = self.store._path(ident)
                size = source_path.stat().st_size
                if processed and read_bytes + size > 16 * 1024 * 1024:
                    break
                row = self.store.load(ident)
                self._replace(connection, ident, row)
                cursor, scanned = key, scanned + 1
                processed, read_bytes = processed + 1, read_bytes + size
                if scanned > self.spec.max_records:
                    raise RecordLookupUnavailable("record lookup source exceeds its record bound")
            ready = len(window) <= processed
        connection.execute("UPDATE state SET cursor=?,ready=?,scanned=?,signature=?",
                           (cursor, int(ready), scanned, self._signature()))
        connection.commit()
        pending = connection.execute("SELECT 1 FROM dirty LIMIT 1").fetchone() is not None
        return {"ready": bool(ready) and not pending, "scanned": scanned, "cursor": cursor}

    def maintain(self, *, limit=100, rebuild=False):
        with self.connection(rebuild=rebuild) as connection:
            return self._advance(connection, batch_limit(limit))

    def lookup(self, digest):
        with self.connection() as connection:
            if not self._advance(connection, 10)["ready"]:
                raise RecordLookupUnavailable("record lookup is rebuilding; retry shortly")
            rows = connection.execute("SELECT record_id,revision FROM entries WHERE digest=? LIMIT 2",
                                      (digest,)).fetchall()
            if len(rows) > 1:
                raise RecordLookupUnavailable("record lookup association is ambiguous")
            if not rows:
                return None
            record_id, revision = rows[0]
            row = self.store.load(record_id)
            if row is None or row.get("revision", 0) != revision or digest not in self.spec.keys(row):
                self._reset(connection)
                connection.commit()
                raise RecordLookupUnavailable("record lookup association needs rebuilding")
            return row
