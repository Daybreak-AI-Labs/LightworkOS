"""Built-in digest-only data-map target for approved discovery remediation.

``privacy_data_discovery_remediation`` intentionally stops at a callback and
reconciler seam.  This module supplies a production local target for that seam.
It records one independently approved classification observation (or an
explicit false-positive no-change tombstone) using only the opaque identifiers
and digests carried by ``RemediationClaim``.  It never receives source values,
locations, object names, documents, credentials, provider URLs or tenant ids.

The target is idempotent by the callback digest, transactionally durable,
integrity checked, retention bounded, and retains a digest tombstone after
payload purge so an old ambiguous callback cannot be replayed optimistically.
It is a privacy-safe input to an evergreen data map; it does not infer purpose,
controller, data subjects, recipients, transfers, legal basis or estate
completeness, and therefore is not by itself a complete Article 30 RoPA.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

from .file_lock import ensure_private_directory, ensure_private_file
from .privacy_data_discovery import require_enabled
from .privacy_data_discovery_remediation import (
    RemediationAmbiguousError,
    RemediationCallbackResult,
    RemediationClaim,
    RemediationReconciliationProbe,
    RemediationReconciliationResult,
)
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
OBSERVATION_SCHEMA = "lightwork.privacy-discovery-data-map-observation.v1"
TOMBSTONE_SCHEMA = "lightwork.privacy-discovery-data-map-tombstone.v1"

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_JSON_BYTES = 128 * 1024
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_MAX_LIST = 1_000
_OUTCOMES = frozenset({"applied", "no_change"})


class PrivacyDiscoveryDataMapError(RuntimeError):
    """Base local data-map target error."""


class PrivacyDiscoveryDataMapConfigError(PrivacyDiscoveryDataMapError):
    """The target is disabled or lacks a required authority."""


class PrivacyDiscoveryDataMapValidationError(PrivacyDiscoveryDataMapError, ValueError):
    """Input is outside the closed target contract."""


class PrivacyDiscoveryDataMapIntegrityError(PrivacyDiscoveryDataMapError):
    """A durable target record failed integrity verification."""


@dataclass(frozen=True, slots=True)
class DataMapObservation:
    observation_id: str
    tenant_sha256: str
    callback_idempotency_sha256: str
    source_id: str
    report_id: str
    finding_id: str
    review_id: str
    review_version: int
    decision: str
    category: str | None
    evidence_sha256: str
    authority_sha256: str
    report_completeness_sha256: str
    outcome: str
    observed_at: float
    retained_until: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class DataMapTombstone:
    callback_idempotency_sha256: str
    tenant_sha256: str
    authority_sha256: str
    outcome: str
    receipt_sha256: str
    purged_at: float
    previous_integrity_sha256: str
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class DataMapIntegrityVerification:
    observations: int
    tombstones: int


def _canonical(value: object) -> bytes:
    try:
        result = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise PrivacyDiscoveryDataMapValidationError(
            "data-map value is not finite canonical JSON"
        ) from None
    if not 1 <= len(result) <= _MAX_JSON_BYTES:
        raise PrivacyDiscoveryDataMapValidationError(
            "data-map value exceeds its byte bound"
        )
    return result


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _same(left: object, right: object) -> bool:
    return (
        isinstance(left, str)
        and isinstance(right, str)
        and hmac.compare_digest(left, right)
    )


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise PrivacyDiscoveryDataMapValidationError(f"{label} is invalid")
    return value


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise PrivacyDiscoveryDataMapValidationError(f"{label} is invalid")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise PrivacyDiscoveryDataMapValidationError(f"{label} is invalid")
    return float(value)


def _retention(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not _MIN_RETENTION_SECONDS <= value <= _MAX_RETENTION_SECONDS
    ):
        raise PrivacyDiscoveryDataMapConfigError("target retention is invalid")
    return value


def _observation_payload(observation: DataMapObservation) -> dict[str, object]:
    result = asdict(observation)
    result.pop("integrity_sha256", None)
    return {"schema": OBSERVATION_SCHEMA, **result}


def _tombstone_payload(tombstone: DataMapTombstone) -> dict[str, object]:
    result = asdict(tombstone)
    result.pop("integrity_sha256", None)
    return {"schema": TOMBSTONE_SCHEMA, **result}


def _validate_claim(claim: RemediationClaim) -> None:
    if type(claim) is not RemediationClaim:
        raise PrivacyDiscoveryDataMapValidationError("claim type is invalid")
    for value, label in (
        (claim.tenant_sha256, "tenant_sha256"),
        (claim.callback_idempotency_sha256, "callback_idempotency_sha256"),
        (claim.evidence_sha256, "evidence_sha256"),
        (claim.authority_sha256, "authority_sha256"),
        (claim.report_completeness_sha256, "report_completeness_sha256"),
    ):
        _digest(value, label)
    for value, label in (
        (claim.source_id, "source_id"),
        (claim.report_id, "report_id"),
        (claim.finding_id, "finding_id"),
        (claim.review_id, "review_id"),
    ):
        _ref(value, label)
    if claim.decision not in {"confirmed", "reclassified", "false_positive"}:
        raise PrivacyDiscoveryDataMapValidationError("claim decision is invalid")
    if claim.decision == "false_positive":
        if claim.category is not None:
            raise PrivacyDiscoveryDataMapValidationError(
                "false-positive claim cannot carry a category"
            )
    else:
        _ref(claim.category, "category")
    if (
        isinstance(claim.review_version, bool)
        or not isinstance(claim.review_version, int)
        or claim.review_version < 1
    ):
        raise PrivacyDiscoveryDataMapValidationError("review_version is invalid")


def _validate_probe(probe: RemediationReconciliationProbe) -> None:
    if type(probe) is not RemediationReconciliationProbe:
        raise PrivacyDiscoveryDataMapValidationError("reconciliation probe is invalid")
    _digest(probe.callback_idempotency_sha256, "callback_idempotency_sha256")
    _digest(probe.tenant_sha256, "tenant_sha256")
    _digest(probe.authority_sha256, "authority_sha256")


class PrivacyDiscoveryDataMapTarget:
    """Durable callback and reconciler for the approved-remediation outbox."""

    def __init__(
        self,
        path: str | Path,
        *,
        retention_seconds: int = 365 * 24 * 60 * 60,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(config_gate) or not callable(clock):
            raise PrivacyDiscoveryDataMapConfigError("target authority is invalid")
        try:
            config_gate()
        except Exception as exc:
            raise PrivacyDiscoveryDataMapConfigError(
                "privacy discovery data-map target is disabled"
            ) from exc
        self.path = Path(path)
        self._retention_seconds = _retention(retention_seconds)
        self._gate = config_gate
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()
        ensure_private_file(self.path)

    def __repr__(self) -> str:
        return (
            f"PrivacyDiscoveryDataMapTarget(path={str(self.path)!r}, "
            f"retention_seconds={self._retention_seconds!r})"
        )

    def _check_gate(self) -> None:
        try:
            self._gate()
        except Exception as exc:
            raise PrivacyDiscoveryDataMapConfigError(
                "privacy discovery data-map target is disabled"
            ) from exc

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "target clock")
        except PrivacyDiscoveryDataMapValidationError:
            raise
        except Exception as exc:
            raise PrivacyDiscoveryDataMapConfigError(
                "data-map target clock is unavailable"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA secure_delete=ON")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise PrivacyDiscoveryDataMapConfigError(
                    "unsupported data-map target schema"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS observations(
                    callback_idempotency_sha256 TEXT PRIMARY KEY,
                    tenant_sha256 TEXT NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS observations_tenant_retention
                    ON observations(tenant_sha256, retained_until);
                CREATE TABLE IF NOT EXISTS tombstones(
                    callback_idempotency_sha256 TEXT PRIMARY KEY,
                    tenant_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL
                );
                PRAGMA user_version=1;
                """
            )

    @staticmethod
    def _observation(row: sqlite3.Row) -> DataMapObservation:
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError):
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map observation is unreadable"
            ) from None
        if not isinstance(payload, Mapping) or payload.get("schema") != OBSERVATION_SCHEMA:
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map observation schema is invalid"
            )
        claimed = row["integrity_sha256"]
        if not _same(_sha256(payload), claimed):
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map observation integrity failed"
            )
        values = dict(payload)
        values.pop("schema", None)
        result = DataMapObservation(**values, integrity_sha256=claimed)
        if (
            row["callback_idempotency_sha256"]
            != result.callback_idempotency_sha256
            or row["tenant_sha256"] != result.tenant_sha256
            or float(row["retained_until"]) != result.retained_until
        ):
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map observation indexes drifted"
            )
        return result

    @staticmethod
    def _tombstone(row: sqlite3.Row) -> DataMapTombstone:
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError):
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map tombstone is unreadable"
            ) from None
        if not isinstance(payload, Mapping) or payload.get("schema") != TOMBSTONE_SCHEMA:
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map tombstone schema is invalid"
            )
        claimed = row["integrity_sha256"]
        if not _same(_sha256(payload), claimed):
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map tombstone integrity failed"
            )
        values = dict(payload)
        values.pop("schema", None)
        result = DataMapTombstone(**values, integrity_sha256=claimed)
        if (
            row["callback_idempotency_sha256"]
            != result.callback_idempotency_sha256
            or row["tenant_sha256"] != result.tenant_sha256
        ):
            raise PrivacyDiscoveryDataMapIntegrityError(
                "data-map tombstone indexes drifted"
            )
        return result

    def __call__(self, claim: RemediationClaim) -> RemediationCallbackResult:
        """Apply one exact claim; a SQLite commit failure is ambiguous."""

        self._check_gate()
        _validate_claim(claim)
        now = self._now()
        outcome = "no_change" if claim.decision == "false_positive" else "applied"
        observation_id = "PDM-" + claim.callback_idempotency_sha256[:32]
        unsigned = DataMapObservation(
            observation_id=observation_id,
            tenant_sha256=claim.tenant_sha256,
            callback_idempotency_sha256=claim.callback_idempotency_sha256,
            source_id=claim.source_id,
            report_id=claim.report_id,
            finding_id=claim.finding_id,
            review_id=claim.review_id,
            review_version=claim.review_version,
            decision=claim.decision,
            category=claim.category,
            evidence_sha256=claim.evidence_sha256,
            authority_sha256=claim.authority_sha256,
            report_completeness_sha256=claim.report_completeness_sha256,
            outcome=outcome,
            observed_at=now,
            retained_until=now + self._retention_seconds,
            integrity_sha256="",
        )
        payload = _observation_payload(unsigned)
        integrity = _sha256(payload)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM observations WHERE callback_idempotency_sha256=?",
                    (claim.callback_idempotency_sha256,),
                ).fetchone()
                tombstone = connection.execute(
                    "SELECT * FROM tombstones WHERE callback_idempotency_sha256=?",
                    (claim.callback_idempotency_sha256,),
                ).fetchone()
                if existing is not None:
                    current = self._observation(existing)
                    if not _same(current.authority_sha256, claim.authority_sha256):
                        raise PrivacyDiscoveryDataMapIntegrityError(
                            "data-map idempotency authority drifted"
                        )
                    connection.commit()
                    return RemediationCallbackResult(
                        outcome=current.outcome,
                        receipt_sha256=current.integrity_sha256,
                        authority_sha256=current.authority_sha256,
                    )
                if tombstone is not None:
                    removed = self._tombstone(tombstone)
                    if not _same(removed.authority_sha256, claim.authority_sha256):
                        raise PrivacyDiscoveryDataMapIntegrityError(
                            "data-map tombstone authority drifted"
                        )
                    connection.commit()
                    return RemediationCallbackResult(
                        outcome=removed.outcome,
                        receipt_sha256=removed.receipt_sha256,
                        authority_sha256=removed.authority_sha256,
                    )
                connection.execute(
                    "INSERT INTO observations VALUES(?,?,?,?,?)",
                    (
                        claim.callback_idempotency_sha256,
                        claim.tenant_sha256,
                        unsigned.retained_until,
                        _canonical(payload).decode("ascii"),
                        integrity,
                    ),
                )
                connection.commit()
        except (KeyboardInterrupt, SystemExit):
            raise
        except (PrivacyDiscoveryDataMapValidationError, PrivacyDiscoveryDataMapIntegrityError):
            raise
        except sqlite3.Error:
            raise RemediationAmbiguousError("data_map_outcome_unknown") from None
        return RemediationCallbackResult(
            outcome=outcome,
            receipt_sha256=integrity,
            authority_sha256=claim.authority_sha256,
        )

    def reconcile(
        self,
        probe: RemediationReconciliationProbe,
    ) -> RemediationReconciliationResult:
        """Prove applied/no-change/absent without attempting a write."""

        self._check_gate()
        _validate_probe(probe)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM observations WHERE callback_idempotency_sha256=?",
                (probe.callback_idempotency_sha256,),
            ).fetchone()
            if row is not None:
                observation = self._observation(row)
                if (
                    observation.tenant_sha256 != probe.tenant_sha256
                    or not _same(observation.authority_sha256, probe.authority_sha256)
                ):
                    return RemediationReconciliationResult(
                        outcome="unknown",
                        authority_sha256=probe.authority_sha256,
                    )
                return RemediationReconciliationResult(
                    outcome=observation.outcome,
                    authority_sha256=observation.authority_sha256,
                    receipt_sha256=observation.integrity_sha256,
                )
            row = connection.execute(
                "SELECT * FROM tombstones WHERE callback_idempotency_sha256=?",
                (probe.callback_idempotency_sha256,),
            ).fetchone()
            if row is None:
                return RemediationReconciliationResult(
                    outcome="absent",
                    authority_sha256=probe.authority_sha256,
                )
            tombstone = self._tombstone(row)
            if (
                tombstone.tenant_sha256 != probe.tenant_sha256
                or not _same(tombstone.authority_sha256, probe.authority_sha256)
            ):
                return RemediationReconciliationResult(
                    outcome="unknown",
                    authority_sha256=probe.authority_sha256,
                )
            return RemediationReconciliationResult(
                outcome=tombstone.outcome,
                authority_sha256=tombstone.authority_sha256,
                receipt_sha256=tombstone.receipt_sha256,
            )

    def list_observations(
        self,
        tenant_sha256: str,
        *,
        limit: int = 100,
    ) -> tuple[DataMapObservation, ...]:
        self._check_gate()
        tenant = _digest(tenant_sha256, "tenant_sha256")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
            raise PrivacyDiscoveryDataMapValidationError("list limit is invalid")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM observations WHERE tenant_sha256=? "
                "ORDER BY retained_until, callback_idempotency_sha256 LIMIT ?",
                (tenant, limit),
            ).fetchall()
        return tuple(self._observation(row) for row in rows)

    def purge_expired(self, *, now: float | None = None, limit: int = 500) -> int:
        """Purge bounded observations while preserving idempotency tombstones."""

        self._check_gate()
        moment = self._now() if now is None else _timestamp(now, "purge time")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise PrivacyDiscoveryDataMapValidationError("purge limit is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM observations WHERE retained_until<=? "
                "ORDER BY retained_until, callback_idempotency_sha256 LIMIT ?",
                (moment, limit),
            ).fetchall()
            for row in rows:
                observation = self._observation(row)
                unsigned = DataMapTombstone(
                    callback_idempotency_sha256=(
                        observation.callback_idempotency_sha256
                    ),
                    tenant_sha256=observation.tenant_sha256,
                    authority_sha256=observation.authority_sha256,
                    outcome=observation.outcome,
                    receipt_sha256=observation.integrity_sha256,
                    purged_at=moment,
                    previous_integrity_sha256=observation.integrity_sha256,
                    integrity_sha256="",
                )
                payload = _tombstone_payload(unsigned)
                digest = _sha256(payload)
                connection.execute(
                    "INSERT INTO tombstones VALUES(?,?,?,?) "
                    "ON CONFLICT(callback_idempotency_sha256) DO NOTHING",
                    (
                        observation.callback_idempotency_sha256,
                        observation.tenant_sha256,
                        _canonical(payload).decode("ascii"),
                        digest,
                    ),
                )
                connection.execute(
                    "DELETE FROM observations WHERE callback_idempotency_sha256=?",
                    (observation.callback_idempotency_sha256,),
                )
            connection.commit()
        return len(rows)

    def verify_integrity(self) -> DataMapIntegrityVerification:
        self._check_gate()
        with self._connect() as connection:
            observations = connection.execute("SELECT * FROM observations").fetchall()
            tombstones = connection.execute("SELECT * FROM tombstones").fetchall()
        for row in observations:
            self._observation(row)
        for row in tombstones:
            self._tombstone(row)
        return DataMapIntegrityVerification(len(observations), len(tombstones))

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "target": "local_digest_only_data_map",
            "approved_remediation_claims_only": True,
            "raw_values_persisted": False,
            "raw_locations_persisted": False,
            "document_content_persisted": False,
            "credentials_persisted": False,
            "provider_network_io": False,
            "provider_writes": False,
            "idempotency_tombstones_retained": True,
            "purpose_inferred": False,
            "transfers_inferred": False,
            "article_30_ropa_completeness_claimed": False,
            "estate_completeness_claimed": False,
            "live_provider_acceptance_verified": False,
        }


__all__ = [
    "OBSERVATION_SCHEMA",
    "SCHEMA_VERSION",
    "TOMBSTONE_SCHEMA",
    "DataMapIntegrityVerification",
    "DataMapObservation",
    "DataMapTombstone",
    "PrivacyDiscoveryDataMapConfigError",
    "PrivacyDiscoveryDataMapError",
    "PrivacyDiscoveryDataMapIntegrityError",
    "PrivacyDiscoveryDataMapTarget",
    "PrivacyDiscoveryDataMapValidationError",
]
