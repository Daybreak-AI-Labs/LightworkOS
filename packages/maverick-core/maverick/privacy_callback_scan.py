"""Bounded persistent queue progress; a cursor never grants callback authority.

Each tenant/source filter shares a keyset cursor across polling processes. A
stable set of N due rows is inspected in at most ceil(N / page_size) + 1 polls
from an arbitrary cursor when no work can be claimed. Claiming advances through
examined rows. Exhaustion resets the cursor, so released holds are revisited.
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections.abc import Sequence

MAX_SCOPES_PER_TENANT = 256


def create_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS rights_callback_scan_progress ("
        "tenant_id TEXT NOT NULL, scope_sha256 TEXT NOT NULL, "
        "next_attempt_at REAL NOT NULL, callback_id TEXT NOT NULL, touched_at REAL NOT NULL, "
        "PRIMARY KEY(tenant_id,scope_sha256))"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS rights_callback_scan_scope_age "
        "ON rights_callback_scan_progress(tenant_id,touched_at,scope_sha256)"
    )


class CallbackScan:
    """Used only inside the caller's immediate claim transaction."""

    def __init__(self, connection: sqlite3.Connection, tenant: str,
                 sources: Sequence[str] | None, now: float, page_size: int):
        self.connection = connection
        self.tenant = tenant
        self.scope = hashlib.sha256(json.dumps(sources, separators=(",", ":")).encode()).hexdigest()
        self.now = now
        self.page_size = page_size
        sql = (
            "SELECT * FROM rights_callbacks WHERE tenant_id=? AND "
            "((state='pending' AND next_attempt_at<=?) OR "
            "(state='leased' AND lease_until<=?)) "
        )
        parameters: list[object] = [tenant, now, now]
        if sources is not None:
            sql += "AND source_id IN (" + ",".join("?" for _ in sources) + ") "
            parameters.extend(sources)
        self._sql = sql
        self._parameters = parameters
        self.rows = self._read_page()
        self.examined = 0
        self.last: sqlite3.Row | None = None

    def _read_page(self) -> list[sqlite3.Row]:
        position = self.connection.execute(
            "SELECT next_attempt_at,callback_id FROM rights_callback_scan_progress "
            "WHERE tenant_id=? AND scope_sha256=?", (self.tenant, self.scope),
        ).fetchone()
        # This is scheduling progress, never evidence or an authorization
        # decision. A malformed hint is safely rebuilt from the queue head.
        valid = position is not None and isinstance(position[0], (int, float)) and math.isfinite(position[0])
        valid = valid and isinstance(position[1], str) and 1 <= len(position[1]) <= 256
        suffix = "ORDER BY next_attempt_at,callback_id LIMIT ?"
        if valid:
            rows = self.connection.execute(
                self._sql + "AND (next_attempt_at,callback_id) > (?,?) " + suffix,
                (*self._parameters, *position, self.page_size),
            ).fetchall()
            if rows:
                return rows
        # Only wrap within this poll when the first range is empty. Total
        # returned/validated candidates remain bounded by one page.
        return self.connection.execute(self._sql + suffix,
                                       (*self._parameters, self.page_size)).fetchall()

    def examined_row(self, row: sqlite3.Row) -> None:
        self.examined += 1
        self.last = row

    def save(self) -> None:
        if self.last is None or (self.examined == len(self.rows) and len(self.rows) < self.page_size):
            self.connection.execute(
                "DELETE FROM rights_callback_scan_progress WHERE tenant_id=? AND scope_sha256=?",
                (self.tenant, self.scope),
            )
            return
        self.connection.execute(
            "INSERT INTO rights_callback_scan_progress VALUES(?,?,?,?,?) "
            "ON CONFLICT(tenant_id,scope_sha256) DO UPDATE SET "
            "next_attempt_at=excluded.next_attempt_at,callback_id=excluded.callback_id,touched_at=excluded.touched_at",
            (self.tenant, self.scope, self.last["next_attempt_at"], self.last["callback_id"], self.now),
        )
        # Bound derived progress under changing worker source filters. Active
        # scopes win ties; eviction only restarts scanning, never drops work.
        self.connection.execute(
            "DELETE FROM rights_callback_scan_progress WHERE tenant_id=? AND scope_sha256 IN ("
            "SELECT scope_sha256 FROM rights_callback_scan_progress WHERE tenant_id=? "
            "ORDER BY touched_at DESC,(scope_sha256=?) DESC,scope_sha256 LIMIT -1 OFFSET ?)",
            (self.tenant, self.tenant, self.scope, MAX_SCOPES_PER_TENANT),
        )
