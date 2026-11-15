"""Documents the ingest screen held back for an administrator's decision.

A document that trips the injection tripwire (or a configured Shield) is not
stored in the vector store. It used to be dropped without a trace; it is now
kept here with the rule that matched and a short excerpt, so a person can see
why it is missing and include it or keep it out. Nothing in this store is
searchable: retrieval reads only the vector store.

The SQLite file is created only when a first document is held; reading a
store that does not exist yet returns nothing.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

HELD = "held"
INCLUDED = "included"
KEPT_OUT = "kept_out"
_DECISIONS = {INCLUDED, KEPT_OUT}
_COLUMNS = ("id", "collection", "doc_sha256", "source", "subject", "rule", "excerpt",
            "text", "args", "state", "held_at", "decided_by", "decided_at")


class HeldDocuments:
    """A small SQLite table of held documents (``:memory:`` by default)."""

    def __init__(self, path: str | Path = ":memory:"):
        self._path = str(path)
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        if self._path == ":memory:":
            self._connect()

    def _connect(self) -> sqlite3.Connection:
        """Open (and on first use create) the store. Caller holds no lock."""
        if self._db is None:
            if self._path != ":memory:":
                Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(self._path, check_same_thread=False)
            with db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS held_documents ("
                    "id TEXT PRIMARY KEY, collection TEXT, doc_sha256 TEXT, source TEXT, "
                    "subject TEXT, rule TEXT, excerpt TEXT, text TEXT, args TEXT, state TEXT, "
                    "held_at REAL, decided_by TEXT, decided_at REAL)"
                )
                db.execute("CREATE INDEX IF NOT EXISTS held_documents_doc "
                           "ON held_documents(collection, doc_sha256, held_at)")
            self._db = db
        return self._db

    def _existing(self) -> sqlite3.Connection | None:
        """The store if it exists (another process may have created it since)."""
        if self._db is None and self._path != ":memory:" and Path(self._path).is_file():
            self._connect()
        return self._db

    def _rows(self, sql: str, params) -> list[tuple]:
        with self._lock:
            db = self._existing()
            return [] if db is None else db.execute(sql, params).fetchall()

    def _write(self, sql: str, params) -> int:
        with self._lock:
            db = self._connect()
            with db:
                return db.execute(sql, params).rowcount

    @staticmethod
    def _row(row) -> dict:
        record = dict(zip(_COLUMNS, row, strict=True))
        record["args"] = json.loads(record["args"] or "{}")
        return record

    def latest(self, collection: str, doc_sha256: str) -> dict | None:
        """The newest record for this document in this collection."""
        rows = self._rows(
            f"SELECT {', '.join(_COLUMNS)} FROM held_documents WHERE collection = ? "
            "AND doc_sha256 = ? ORDER BY held_at DESC, rowid DESC LIMIT 1", (collection, doc_sha256),
        )
        return self._row(rows[0]) if rows else None

    def state(self, collection: str, doc_sha256: str) -> str | None:
        record = self.latest(collection, doc_sha256)
        return record["state"] if record else None

    def hold(self, *, collection: str, doc_sha256: str, source: str, subject: str,
             rule: str, excerpt: str, text: str, args: dict) -> dict:
        """Hold a document. One that is already waiting is not held twice; one
        an administrator kept out earlier is held again as a new upload."""
        current = self.latest(collection, doc_sha256)
        if current is not None and current["state"] == HELD:
            return current
        identifier = uuid.uuid4().hex
        # Metadata that JSON cannot store is kept as text; a hold never fails on it.
        self._write(
            "INSERT INTO held_documents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (identifier, collection, doc_sha256, source, subject, rule, excerpt, text,
             json.dumps(args, sort_keys=True, default=str), HELD, time.time(), "", None),
        )
        record = self.get(identifier)
        if record is None:
            raise RuntimeError("held document was not recorded")
        return record

    def get(self, identifier: str) -> dict | None:
        rows = self._rows(f"SELECT {', '.join(_COLUMNS)} FROM held_documents WHERE id = ?", (identifier,))
        return self._row(rows[0]) if rows else None

    def list(self, state: str = HELD, *, limit: int = 200) -> list[dict]:
        rows = self._rows(
            f"SELECT {', '.join(_COLUMNS)} FROM held_documents WHERE state = ? "
            "ORDER BY held_at DESC LIMIT ?", (state, max(1, int(limit))),
        )
        return [self._row(row) for row in rows]

    def count(self, state: str = HELD) -> int:
        rows = self._rows("SELECT COUNT(*) FROM held_documents WHERE state = ?", (state,))
        return int(rows[0][0]) if rows else 0

    def decide(self, identifier: str, decision: str, *, decided_by: str) -> dict:
        """Record ``included`` or ``kept_out`` for a held document. Either way
        its held copy of the text is discarded: an included document is already
        in the vector store, and a kept-out one is not kept. Call this last."""
        if decision not in _DECISIONS:
            raise ValueError("unknown held-document decision")
        changed = self._write(
            "UPDATE held_documents SET state = ?, decided_by = ?, decided_at = ?, text = '' "
            "WHERE id = ? AND state = ?",
            (decision, decided_by, time.time(), identifier, HELD),
        )
        record = self.get(identifier)
        if record is None:
            raise LookupError("held document not found")
        if not changed:
            raise ValueError("this document was already decided")
        return record

    @staticmethod
    def _where(key: str, value: str, collections) -> tuple[str, list]:
        if key not in {"subject", "source"}:
            raise ValueError("held documents are matched by subject or source")
        clause, params = f"{key} = ?", [value]
        if collections is not None:
            names = list(collections)
            clause += f" AND collection IN ({', '.join('?' for _ in names) or 'NULL'})"
            params.extend(names)
        return clause, params

    def delete_where(self, key: str, value: str, collections=None) -> int:
        """Erase held records by ``subject`` or ``source`` (erasure covers them too)."""
        clause, params = self._where(key, value, collections)
        with self._lock:
            db = self._existing()
            if db is None:
                return 0
            with db:
                return db.execute(f"DELETE FROM held_documents WHERE {clause}", params).rowcount

    def count_where(self, key: str, value: str, collections=None) -> int:
        clause, params = self._where(key, value, collections)
        rows = self._rows(f"SELECT COUNT(*) FROM held_documents WHERE {clause}", params)
        return int(rows[0][0]) if rows else 0

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
