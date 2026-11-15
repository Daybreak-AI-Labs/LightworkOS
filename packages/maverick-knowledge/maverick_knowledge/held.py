"""Documents the ingest screen held back for an administrator's decision.

A document that trips the injection tripwire (or a configured Shield) is not
stored in the vector store. It used to be dropped without a trace; it is now
kept here with the rule that matched and a short excerpt, so a person can see
why it is missing and include it or keep it out. Nothing in this store is
searchable: retrieval reads only the vector store.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

HELD = "held"
INCLUDED = "included"
KEPT_OUT = "kept_out"
_DECISIONS = {INCLUDED, KEPT_OUT}
_COLUMNS = ("id", "collection", "doc_sha256", "source", "subject", "rule", "excerpt",
            "text", "args", "state", "held_at", "decided_by", "decided_at")


def hold_id(collection: str, doc_sha256: str) -> str:
    """One hold per document per collection, so a repeat upload is not a new hold."""
    return hashlib.sha256(f"lightwork:knowledge-hold:v1\0{collection}\0{doc_sha256}".encode()).hexdigest()[:32]


class HeldDocuments:
    """A small SQLite table of held documents (``:memory:`` by default)."""

    def __init__(self, path: str | Path = ":memory:"):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS held_documents ("
                "id TEXT PRIMARY KEY, collection TEXT, doc_sha256 TEXT, source TEXT, "
                "subject TEXT, rule TEXT, excerpt TEXT, text TEXT, args TEXT, state TEXT, "
                "held_at REAL, decided_by TEXT, decided_at REAL)"
            )

    @staticmethod
    def _row(row) -> dict:
        record = dict(zip(_COLUMNS, row, strict=True))
        record["args"] = json.loads(record["args"] or "{}")
        return record

    def hold(self, *, collection: str, doc_sha256: str, source: str, subject: str,
             rule: str, excerpt: str, text: str, args: dict) -> dict:
        """Record a held document. A document already on record keeps its state."""
        identifier = hold_id(collection, doc_sha256)
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO held_documents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (identifier, collection, doc_sha256, source, subject, rule, excerpt, text,
                 json.dumps(args, sort_keys=True), HELD, time.time(), "", None),
            )
        record = self.get(identifier)
        if record is None:
            raise RuntimeError("held document was not recorded")
        return record

    def get(self, identifier: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM held_documents WHERE id = ?", (identifier,),
            ).fetchone()
        return self._row(row) if row else None

    def state(self, collection: str, doc_sha256: str) -> str | None:
        record = self.get(hold_id(collection, doc_sha256))
        return record["state"] if record else None

    def list(self, state: str = HELD, *, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM held_documents WHERE state = ? "
                "ORDER BY held_at DESC LIMIT ?", (state, max(1, int(limit))),
            ).fetchall()
        return [self._row(row) for row in rows]

    def decide(self, identifier: str, decision: str, *, decided_by: str) -> dict:
        """Move a held document to ``included`` or ``kept_out``. Either way its
        held copy of the text is discarded: an included document lives in the
        vector store, and a kept-out one is not kept. The decision record stays."""
        if decision not in _DECISIONS:
            raise ValueError("unknown held-document decision")
        with self._lock, self._db:
            changed = self._db.execute(
                "UPDATE held_documents SET state = ?, decided_by = ?, decided_at = ?, text = '' "
                "WHERE id = ? AND state = ?",
                (decision, decided_by, time.time(), identifier, HELD),
            ).rowcount
        record = self.get(identifier)
        if record is None:
            raise LookupError("held document not found")
        if not changed:
            raise ValueError("this document was already decided")
        return record

    def reopen(self, identifier: str, text: str) -> None:
        """Undo an inclusion whose storage failed, so the document stays held."""
        with self._lock, self._db:
            self._db.execute(
                "UPDATE held_documents SET state = ?, decided_by = '', decided_at = NULL, text = ? "
                "WHERE id = ? AND state = ?", (HELD, text, identifier, INCLUDED),
            )

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
        with self._lock, self._db:
            return self._db.execute(f"DELETE FROM held_documents WHERE {clause}", params).rowcount

    def count_where(self, key: str, value: str, collections=None) -> int:
        clause, params = self._where(key, value, collections)
        with self._lock:
            return int(self._db.execute(
                f"SELECT COUNT(*) FROM held_documents WHERE {clause}", params,
            ).fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._db.close()
