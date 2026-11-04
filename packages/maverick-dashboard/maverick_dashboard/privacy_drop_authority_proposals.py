"""Durable four-eyes proposal queue for DROP administration APIs."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from maverick.file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from maverick.paths import canonical_tenant_id
from maverick.privacy_drop_management import (
    DROPManagementConfigError,
    DROPManagementConflict,
    DROPManagementIntegrityError,
    DROPManagementNotFound,
    DROPManagementValidationError,
    DROPPrincipalBinding,
)
from maverick.sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
_KINDS = frozenset(
    {
        "enroll_broker",
        "revoke_broker",
        "import_record",
        "revoke_record",
        "approve_outcome",
        "rotate_key",
        "retire_key",
        "revoke_key",
        "record_key_migration",
    }
)
_STATES = frozenset({"proposed", "applying", "approved", "rejected"})
_DIGEST_RE = __import__("re").compile(r"[0-9a-f]{64}\Z")
_REF_RE = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_MAX_JSON_BYTES = 128 * 1024


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise DROPManagementValidationError("DROP proposal must be finite JSON") from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise DROPManagementValidationError("DROP proposal exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise DROPManagementValidationError(f"{label} is not a closed reference")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DROPManagementValidationError(f"{label} is not a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or not 0 < result < 100_000_000_000.0:
        raise DROPManagementValidationError(f"{label} is not a finite timestamp")
    return result


@dataclass(frozen=True, slots=True)
class DROPAuthorityProposal:
    proposal_id: str
    kind: str
    state: str
    revision: int
    payload_sha256: str
    proposer_key_revision: int
    result_sha256: str
    created_at: float
    updated_at: float
    retained_until: float
    integrity_sha256: str


class DROPAuthorityProposalStore:
    """Tenant-bound CAS queue; only the server-resolved proposer is durable."""

    def __init__(  # noqa: PLR0913
        self,
        path: str | Path,
        *,
        tenant_id: str,
        principal_binding_resolver: Callable[[str, str], DROPPrincipalBinding],
        principal_binding_verifier: Callable[[str, str, int, str], bool],
        retention_seconds: int = 30 * 24 * 3_600,
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = lambda: None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not all(
            callable(value)
            for value in (
                principal_binding_resolver,
                principal_binding_verifier,
                maintenance_authorizer,
                config_gate,
                clock,
            )
        ):
            raise DROPManagementConfigError("DROP proposal dependencies are incomplete")
        if (
            isinstance(retention_seconds, bool)
            or not isinstance(retention_seconds, int)
            or not 3_600 <= retention_seconds <= 365 * 24 * 3_600
        ):
            raise DROPManagementValidationError("DROP proposal retention is invalid")
        self.path = Path(path)
        self.tenant_id = canonical_tenant_id(tenant_id)
        self._bind = principal_binding_resolver
        self._verify = principal_binding_verifier
        self._retention_seconds = retention_seconds
        self._maintenance_authorizer = maintenance_authorizer
        self._gate = config_gate
        self._clock = clock
        self._maintenance = threading.local()
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.create_function(
            "drop_proposal_maintenance_authorized",
            0,
            lambda: 1 if bool(getattr(self._maintenance, "authorized", False)) else 0,
        )
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS drop_authority_proposals(
                    tenant_id TEXT NOT NULL,proposal_id TEXT NOT NULL,kind TEXT NOT NULL,
                    state TEXT NOT NULL,revision INTEGER NOT NULL,proposer_ref TEXT NOT NULL,
                    proposer_binding_sha256 TEXT NOT NULL,proposer_key_revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,payload_sha256 TEXT NOT NULL,
                    result_sha256 TEXT NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,
                    retained_until REAL NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,proposal_id)
                );
                CREATE TABLE IF NOT EXISTS drop_authority_proposal_operations(
                    tenant_id TEXT NOT NULL,action TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,proposal_id TEXT NOT NULL,result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,action,key_sha256)
                );
                CREATE TRIGGER IF NOT EXISTS drop_authority_proposal_operations_no_update
                    BEFORE UPDATE ON drop_authority_proposal_operations
                    BEGIN SELECT RAISE(ABORT,'immutable DROP proposal operation'); END;
                DROP TRIGGER IF EXISTS drop_authority_proposal_operations_no_delete;
                CREATE TRIGGER drop_authority_proposal_operations_no_delete
                    BEFORE DELETE ON drop_authority_proposal_operations
                    WHEN drop_proposal_maintenance_authorized()=0
                    BEGIN SELECT RAISE(ABORT,'immutable DROP proposal operation'); END;
                DROP TRIGGER IF EXISTS drop_authority_proposals_no_delete;
                CREATE TRIGGER drop_authority_proposals_no_delete
                    BEFORE DELETE ON drop_authority_proposals
                    WHEN drop_proposal_maintenance_authorized()=0
                    BEGIN SELECT RAISE(ABORT,'immutable DROP proposal'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise DROPManagementConfigError(
                    f"unsupported DROP proposal schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            foreign = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM drop_authority_proposals WHERE tenant_id<>?) "
                "OR EXISTS(SELECT 1 FROM drop_authority_proposal_operations WHERE tenant_id<>?)",
                (self.tenant_id, self.tenant_id),
            ).fetchone()
            if foreign is None or int(foreign[0]) != 0:
                raise DROPManagementIntegrityError("DROP proposal store contains another tenant")
        ensure_private_file(self.path)

    def _now(self) -> float:
        return _timestamp(self._clock(), "current time")

    @staticmethod
    def _body(row: sqlite3.Row, *, integrity: bool = True) -> dict[str, object]:
        body = {
            "tenant_id": str(row["tenant_id"]),
            "proposal_id": str(row["proposal_id"]),
            "kind": str(row["kind"]),
            "state": str(row["state"]),
            "revision": int(row["revision"]),
            "proposer_ref": str(row["proposer_ref"]),
            "proposer_binding_sha256": str(row["proposer_binding_sha256"]),
            "proposer_key_revision": int(row["proposer_key_revision"]),
            "payload_json": str(row["payload_json"]),
            "payload_sha256": str(row["payload_sha256"]),
            "result_sha256": str(row["result_sha256"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "retained_until": float(row["retained_until"]),
        }
        if integrity and not _same(_sha256(body), row["integrity_sha256"]):
            raise DROPManagementIntegrityError("stored DROP proposal changed")
        return body

    def _public(self, body: Mapping[str, object]) -> DROPAuthorityProposal:
        return DROPAuthorityProposal(
            proposal_id=str(body["proposal_id"]),
            kind=str(body["kind"]),
            state=str(body["state"]),
            revision=int(body["revision"]),
            payload_sha256=str(body["payload_sha256"]),
            proposer_key_revision=int(body["proposer_key_revision"]),
            result_sha256=str(body["result_sha256"]),
            created_at=float(body["created_at"]),
            updated_at=float(body["updated_at"]),
            retained_until=float(body["retained_until"]),
            integrity_sha256=_sha256(dict(body)),
        )

    @staticmethod
    def _operation_body(row: sqlite3.Row) -> dict[str, object]:
        body = {
            "tenant_id": str(row["tenant_id"]),
            "action": str(row["action"]),
            "key_sha256": str(row["key_sha256"]),
            "request_sha256": str(row["request_sha256"]),
            "proposal_id": str(row["proposal_id"]),
            "result_json": str(row["result_json"]),
            "created_at": float(row["created_at"]),
        }
        if not _same(_sha256(body), row["integrity_sha256"]):
            raise DROPManagementIntegrityError("stored DROP proposal operation changed")
        return body

    def propose(
        self,
        *,
        kind: str,
        payload: Mapping[str, object],
        proposer_ref: str,
        idempotency_key: str,
    ) -> DROPAuthorityProposal:
        self._gate()
        if kind not in _KINDS:
            raise DROPManagementValidationError("DROP proposal kind is invalid")
        proposer = _ref(proposer_ref, "proposer_ref")
        binding = self._bind(self.tenant_id, proposer).normalized()
        payload_json = _canonical(dict(payload)).decode("ascii")
        payload_sha256 = _sha256(dict(payload))
        key_sha256 = _text_sha256(_ref(idempotency_key, "idempotency_key"))
        request = {
            "kind": kind,
            "payload_sha256": payload_sha256,
            "proposer_binding_sha256": binding.binding_sha256,
            "proposer_key_revision": binding.key_revision,
        }
        request_sha256 = _sha256(request)
        now = self._now()
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM drop_authority_proposal_operations WHERE tenant_id=? "
                "AND action='propose' AND key_sha256=?",
                (self.tenant_id, key_sha256),
            ).fetchone()
            if replay is not None:
                if not _same(replay["request_sha256"], request_sha256):
                    raise DROPManagementConflict("idempotency key is bound to another proposal")
                stored = json.loads(str(replay["result_json"]))
                connection.rollback()
                return self._public(stored)
            proposal_id = str(uuid.uuid4())
            body = {
                "tenant_id": self.tenant_id,
                "proposal_id": proposal_id,
                "kind": kind,
                "state": "proposed",
                "revision": 1,
                "proposer_ref": proposer,
                "proposer_binding_sha256": binding.binding_sha256,
                "proposer_key_revision": binding.key_revision,
                "payload_json": payload_json,
                "payload_sha256": payload_sha256,
                "result_sha256": "",
                "created_at": now,
                "updated_at": now,
                "retained_until": now + self._retention_seconds,
            }
            connection.execute(
                "INSERT INTO drop_authority_proposals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (*body.values(), _sha256(body)),
            )
            operation = {
                "tenant_id": self.tenant_id,
                "action": "propose",
                "key_sha256": key_sha256,
                "request_sha256": request_sha256,
                "proposal_id": proposal_id,
                "result_json": _canonical(body).decode("ascii"),
                "created_at": now,
            }
            connection.execute(
                "INSERT INTO drop_authority_proposal_operations VALUES(?,?,?,?,?,?,?,?)",
                (*operation.values(), _sha256(operation)),
            )
            connection.commit()
        return self._public(body)

    def claim_approval(
        self,
        proposal_id: str,
        *,
        expected_revision: int,
        reviewer_ref: str,
        idempotency_key: str,
    ) -> tuple[DROPAuthorityProposal, Mapping[str, object], str]:
        """Claim apply authority; stale/replayed claims return only the same proposal."""

        self._gate()
        proposal = str(uuid.UUID(str(proposal_id)))
        if expected_revision != 1:
            raise DROPManagementConflict("DROP proposal revision changed")
        reviewer = _ref(reviewer_ref, "reviewer_ref")
        approval_key_sha256 = _text_sha256(_ref(idempotency_key, "idempotency_key"))
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM drop_authority_proposals WHERE tenant_id=? AND proposal_id=?",
                (self.tenant_id, proposal),
            ).fetchone()
            if row is None:
                raise DROPManagementNotFound("DROP proposal was not found")
            body = self._body(row)
            if body["retained_until"] <= self._now():
                raise DROPManagementNotFound("DROP proposal was not found")
            if not self._verify(
                self.tenant_id,
                str(body["proposer_ref"]),
                int(body["proposer_key_revision"]),
                str(body["proposer_binding_sha256"]),
            ):
                raise DROPManagementConflict("DROP proposal principal key changed")
            reviewer_binding = self._bind(self.tenant_id, reviewer).normalized()
            if _same(reviewer_binding.binding_sha256, body["proposer_binding_sha256"]):
                raise DROPManagementConflict("independent DROP proposal approval is required")
            approval_request = {
                "proposal_id": proposal,
                "expected_revision": expected_revision,
                "reviewer_binding_sha256": reviewer_binding.binding_sha256,
                "reviewer_key_revision": reviewer_binding.key_revision,
            }
            approval_request_sha256 = _sha256(approval_request)
            operation = connection.execute(
                "SELECT * FROM drop_authority_proposal_operations WHERE tenant_id=? "
                "AND action='approve' AND key_sha256=?",
                (self.tenant_id, approval_key_sha256),
            ).fetchone()
            operation_inserted = False
            if operation is not None:
                if not _same(operation["request_sha256"], approval_request_sha256):
                    raise DROPManagementConflict("approval idempotency key changed")
            else:
                operation_body = {
                    "tenant_id": self.tenant_id,
                    "action": "approve",
                    "key_sha256": approval_key_sha256,
                    "request_sha256": approval_request_sha256,
                    "proposal_id": proposal,
                    "result_json": _canonical(approval_request).decode("ascii"),
                    "created_at": self._now(),
                }
                connection.execute(
                    "INSERT INTO drop_authority_proposal_operations VALUES(?,?,?,?,?,?,?,?)",
                    (*operation_body.values(), _sha256(operation_body)),
                )
                operation_inserted = True
            if body["state"] == "approved":
                payload = json.loads(str(body["payload_json"]))
                if operation_inserted:
                    connection.commit()
                else:
                    connection.rollback()
                return self._public(body), payload, str(body["proposer_ref"])
            if body["state"] not in {"proposed", "applying"} or body["revision"] != 1:
                raise DROPManagementConflict("DROP proposal state changed")
            if body["state"] == "proposed":
                body.update({"state": "applying", "updated_at": self._now()})
                updated = connection.execute(
                    "UPDATE drop_authority_proposals SET state='applying',updated_at=?,"
                    "integrity_sha256=? WHERE tenant_id=? AND proposal_id=? "
                    "AND state='proposed' AND revision=1",
                    (
                        body["updated_at"],
                        _sha256(body),
                        self.tenant_id,
                        proposal,
                    ),
                )
                if updated.rowcount != 1:
                    raise DROPManagementConflict("DROP proposal changed concurrently")
                connection.commit()
            else:
                if operation_inserted:
                    connection.commit()
                else:
                    connection.rollback()
        payload = json.loads(str(body["payload_json"]))
        if not isinstance(payload, Mapping) or not _same(_sha256(payload), body["payload_sha256"]):
            raise DROPManagementIntegrityError("stored DROP proposal payload changed")
        return self._public(body), payload, str(body["proposer_ref"])

    def complete_approval(
        self,
        proposal_id: str,
        *,
        result: Mapping[str, object],
    ) -> DROPAuthorityProposal:
        proposal = str(uuid.UUID(str(proposal_id)))
        result_sha256 = _sha256(dict(result))
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM drop_authority_proposals WHERE tenant_id=? AND proposal_id=?",
                (self.tenant_id, proposal),
            ).fetchone()
            if row is None:
                raise DROPManagementNotFound("DROP proposal was not found")
            body = self._body(row)
            if body["state"] == "approved":
                if not _same(body["result_sha256"], result_sha256):
                    raise DROPManagementConflict("DROP proposal result changed")
                connection.rollback()
                return self._public(body)
            if body["state"] != "applying" or body["revision"] != 1:
                raise DROPManagementConflict("DROP proposal state changed")
            body.update(
                {
                    "state": "approved",
                    "revision": 2,
                    "result_sha256": result_sha256,
                    "updated_at": self._now(),
                }
            )
            updated = connection.execute(
                "UPDATE drop_authority_proposals SET state='approved',revision=2,"
                "result_sha256=?,updated_at=?,integrity_sha256=? WHERE tenant_id=? "
                "AND proposal_id=? AND state='applying' AND revision=1",
                (
                    result_sha256,
                    body["updated_at"],
                    _sha256(body),
                    self.tenant_id,
                    proposal,
                ),
            )
            if updated.rowcount != 1:
                raise DROPManagementConflict("DROP proposal changed concurrently")
            connection.commit()
        return self._public(body)

    def list_proposals(self, *, limit: int = 100) -> tuple[DROPAuthorityProposal, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 250:
            raise DROPManagementValidationError("DROP proposal limit is invalid")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_authority_proposals WHERE tenant_id=? "
                "ORDER BY created_at DESC,proposal_id LIMIT ?",
                (self.tenant_id, limit),
            ).fetchall()
        return tuple(self._public(self._body(row)) for row in rows)

    def list_open_summaries(
        self, *, proposer_ref: str, limit: int = 100
    ) -> tuple[Mapping[str, object], ...]:
        """Proposals still waiting for a second administrator, with a short,
        digest-free description of what each one would change."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 250:
            raise DROPManagementValidationError("DROP proposal limit is invalid")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_authority_proposals WHERE tenant_id=? "
                "AND state IN ('proposed','applying') "
                "ORDER BY created_at DESC,proposal_id LIMIT ?",
                (self.tenant_id, limit),
            ).fetchall()
        summaries: list[Mapping[str, object]] = []
        for row in rows:
            body = self._body(row)
            payload = json.loads(str(body["payload_json"]))
            summary = {
                field: payload[field]
                for field in (
                    "drop_id",
                    "broker_ref",
                    "status",
                    "request_type",
                    "language",
                    "valid_until",
                    "key_revision",
                )
                if isinstance(payload, Mapping) and field in payload
            }
            summaries.append(
                {
                    "proposal_id": body["proposal_id"],
                    "kind": body["kind"],
                    "state": body["state"],
                    "revision": body["revision"],
                    "created_at": body["created_at"],
                    "proposed_by_you": hmac.compare_digest(
                        str(body["proposer_ref"]), str(proposer_ref)
                    ),
                    "summary": summary,
                }
            )
        return tuple(summaries)

    def retained_key_revision_counts(self) -> Mapping[int, int]:
        now = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT proposer_key_revision,COUNT(*) AS count "
                "FROM drop_authority_proposals WHERE tenant_id=? AND retained_until>? "
                "GROUP BY proposer_key_revision",
                (self.tenant_id, now),
            ).fetchall()
        return {int(row["proposer_key_revision"]): int(row["count"]) for row in rows}

    def purge_expired(self, *, before: float | None = None, limit: int = 100) -> int:
        """Purge expired proposals and their replay records under maintenance authority."""

        self._gate()
        try:
            authorized = self._maintenance_authorizer()
        except Exception as exc:
            raise DROPManagementConfigError("DROP proposal maintenance is unavailable") from exc
        if authorized is not True:
            raise DROPManagementConfigError("DROP proposal maintenance is unavailable")
        if not self.verify_integrity():
            raise DROPManagementIntegrityError("DROP proposal integrity must pass before purge")
        now = self._now()
        cutoff = now if before is None else min(now, _timestamp(before, "before"))
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise DROPManagementValidationError("DROP proposal purge limit is invalid")
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT proposal_id FROM drop_authority_proposals WHERE tenant_id=? "
                "AND retained_until<=? ORDER BY retained_until,proposal_id LIMIT ?",
                (self.tenant_id, cutoff, limit),
            ).fetchall()
            proposal_ids = tuple(str(row["proposal_id"]) for row in rows)
            self._maintenance.authorized = True
            try:
                for proposal_id in proposal_ids:
                    connection.execute(
                        "DELETE FROM drop_authority_proposal_operations "
                        "WHERE tenant_id=? AND proposal_id=?",
                        (self.tenant_id, proposal_id),
                    )
                    connection.execute(
                        "DELETE FROM drop_authority_proposals "
                        "WHERE tenant_id=? AND proposal_id=? AND retained_until<=?",
                        (self.tenant_id, proposal_id, cutoff),
                    )
                connection.commit()
            finally:
                self._maintenance.authorized = False
        return len(proposal_ids)

    def verify_integrity(self) -> bool:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM drop_authority_proposals WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchall()
                operation_rows = connection.execute(
                    "SELECT * FROM drop_authority_proposal_operations WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchall()
            proposal_ids = {str(row["proposal_id"]) for row in rows}
            for row in rows:
                body = self._body(row)
                if body["kind"] not in _KINDS or body["state"] not in _STATES:
                    return False
                payload = json.loads(str(body["payload_json"]))
                if not isinstance(payload, Mapping) or not _same(
                    _sha256(payload), body["payload_sha256"]
                ):
                    return False
                if not self._verify(
                    self.tenant_id,
                    str(body["proposer_ref"]),
                    int(body["proposer_key_revision"]),
                    str(body["proposer_binding_sha256"]),
                ):
                    return False
            for row in operation_rows:
                operation = self._operation_body(row)
                if (
                    operation["action"] not in {"propose", "approve"}
                    or operation["proposal_id"] not in proposal_ids
                ):
                    return False
                result = json.loads(str(operation["result_json"]))
                if not isinstance(result, Mapping):
                    return False
            return True
        except Exception:
            return False


__all__ = ["DROPAuthorityProposal", "DROPAuthorityProposalStore"]
