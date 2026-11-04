"""Pending two-person tracker reviews for the consent scan inventory.

A registry-changing tracker review needs two different people.  Instead of
asking the first reviewer to type a second person's fingerprint, the first
person files a request here and a different signed-in administrator approves
it; only then is the review recorded, with both reviewer fingerprints derived
on the server from the two authenticated sessions.  This store keeps nothing
but the request, its status and the proposer's server-derived fingerprint.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from maverick import consent_storage
from maverick.file_lock import ensure_private_directory, ensure_private_file

_STATUSES = frozenset({"pending", "approved", "withdrawn"})
_MAX_LIST = 500


class ScanReviewRequestError(RuntimeError):
    """The request store is unavailable or its records failed integrity."""


class ScanReviewRequestConflict(ScanReviewRequestError):
    """The request is not pending any more."""


class ScanReviewRequestNotFound(ScanReviewRequestError):
    """No such request in this workspace."""


def _canonical(value: object) -> str:
    return json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


class ScanReviewRequestStore:
    """Tenant-scoped, integrity-checked pending review requests."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        ensure_private_directory(self.path.parent)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS scan_review_requests ("
                "tenant TEXT NOT NULL, request_id TEXT NOT NULL, property_id TEXT NOT NULL, "
                "tracker_key TEXT NOT NULL, payload_json TEXT NOT NULL, "
                "proposer_sha256 TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL, "
                "decided_at REAL, record_sha256 TEXT NOT NULL, "
                "PRIMARY KEY (tenant, request_id))"
            )
        if not consent_storage.shared():
            ensure_private_file(self.path)

    @contextlib.contextmanager
    def _connect(self):
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=10.0)
        else:
            connection = sqlite3.connect(str(self.path), isolation_level=None, timeout=10.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _body(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "tenant": row["tenant"],
            "request_id": row["request_id"],
            "property_id": row["property_id"],
            "tracker_key": row["tracker_key"],
            "payload_json": row["payload_json"],
            "proposer_sha256": row["proposer_sha256"],
            "status": row["status"],
            "created_at": row["created_at"],
            "decided_at": row["decided_at"],
        }

    def _result(self, row: sqlite3.Row) -> dict[str, Any]:
        body = self._body(row)
        if body["status"] not in _STATUSES or _sha256(body) != row["record_sha256"]:
            raise ScanReviewRequestError("stored review request failed integrity")
        payload = json.loads(body["payload_json"])
        if not isinstance(payload, dict):
            raise ScanReviewRequestError("stored review request failed integrity")
        return {
            "request_id": body["request_id"],
            "property_id": body["property_id"],
            "tracker_key": body["tracker_key"],
            "payload": payload,
            "proposer_sha256": body["proposer_sha256"],
            "status": body["status"],
            "created_at": body["created_at"],
            "decided_at": body["decided_at"],
        }

    def create(
        self,
        tenant: str,
        *,
        property_id: str,
        tracker_key: str,
        payload: Mapping[str, Any],
        proposer_sha256: str,
    ) -> dict[str, Any]:
        body = {
            "tenant": tenant,
            "request_id": f"CSRR-{secrets.token_hex(12)}",
            "property_id": property_id,
            "tracker_key": tracker_key,
            "payload_json": _canonical(dict(payload)),
            "proposer_sha256": proposer_sha256,
            "status": "pending",
            "created_at": float(self._clock()),
            "decided_at": None,
        }
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO scan_review_requests VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    body["tenant"],
                    body["request_id"],
                    body["property_id"],
                    body["tracker_key"],
                    body["payload_json"],
                    body["proposer_sha256"],
                    body["status"],
                    body["created_at"],
                    body["decided_at"],
                    _sha256(body),
                ),
            )
        return self.get(tenant, body["request_id"])

    def get(self, tenant: str, request_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scan_review_requests WHERE tenant=? AND request_id=?",
                (tenant, request_id),
            ).fetchone()
        if row is None:
            raise ScanReviewRequestNotFound("review request was not found")
        return self._result(row)

    def list(self, tenant: str, *, limit: int = 200) -> list[dict[str, Any]]:
        bound = max(1, min(int(limit), _MAX_LIST))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scan_review_requests WHERE tenant=? "
                "ORDER BY created_at DESC, request_id LIMIT ?",
                (tenant, bound),
            ).fetchall()
        return [self._result(row) for row in rows]

    def decide(self, tenant: str, request_id: str, status: str) -> dict[str, Any]:
        if status not in {"approved", "withdrawn"}:
            raise ScanReviewRequestError("review request decision is unsupported")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM scan_review_requests WHERE tenant=? AND request_id=?",
                    (tenant, request_id),
                ).fetchone()
                if row is None:
                    raise ScanReviewRequestNotFound("review request was not found")
                current = self._result(row)
                if current["status"] != "pending":
                    raise ScanReviewRequestConflict("review request is no longer pending")
                body = {**self._body(row), "status": status, "decided_at": float(self._clock())}
                connection.execute(
                    "UPDATE scan_review_requests SET status=?, decided_at=?, record_sha256=? "
                    "WHERE tenant=? AND request_id=? AND status='pending'",
                    (status, body["decided_at"], _sha256(body), tenant, request_id),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self.get(tenant, request_id)


__all__ = [
    "ScanReviewRequestConflict",
    "ScanReviewRequestError",
    "ScanReviewRequestNotFound",
    "ScanReviewRequestStore",
]
