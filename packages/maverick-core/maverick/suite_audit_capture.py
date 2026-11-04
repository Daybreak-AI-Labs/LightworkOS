"""Reusable, tenant-exact capture contract for governance-suite histories.

The contract is intentionally smaller than any source store.  A producer may
expose only the fixed unified-audit action vocabulary and SHA-256 commitments;
raw actors, resource identifiers, payloads, documents, credentials and tenant
data stay in the owning suite.  Consumers such as unified audit and the shared
governance inventory can independently re-read the same capture and compare an
exact revision/digest/head/count tuple.

``complete`` means the producer covered the whole named suite, not merely one
canonical store.  ``retention_complete`` is a separate assertion and must not
be inferred from an immutable SQLite trigger or a locally signed transport.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import asdict, dataclass
from typing import Protocol, runtime_checkable

from .paths import InvalidTenantError, canonical_tenant_id
from .unified_audit import (
    GENESIS_SHA256,
    REQUIRED_SUITES,
    SOURCE_LIMITATION_CODES,
    SourceRecord,
)

CAPTURE_SCHEMA = "lightwork.suite-audit-capture.v1"
CAPTURE_PROVIDER_SCHEMA = "lightwork.suite-audit-capture-provider.v1"
_SOURCE_IDS = frozenset(REQUIRED_SUITES)
_DIGESTS = frozenset(SOURCE_LIMITATION_CODES)


class SuiteAuditCaptureError(RuntimeError):
    """A suite capture is unavailable, ambiguous, or failed validation."""

    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise SuiteAuditCaptureError("source_integrity_unverified") from exc


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (InvalidTenantError, TypeError, ValueError) as exc:
        raise SuiteAuditCaptureError("source_authority_invalid") from exc


def _source(value: object) -> str:
    if not isinstance(value, str) or value not in _SOURCE_IDS:
        raise SuiteAuditCaptureError("source_authority_invalid")
    return value


def _positive_integer(value: object, error_code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 2**31 - 1
    ):
        raise SuiteAuditCaptureError(error_code)
    return value


def _timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SuiteAuditCaptureError("source_head_unavailable")
    selected = float(value)
    if not math.isfinite(selected) or not 0 < selected < 100_000_000_000.0:
        raise SuiteAuditCaptureError("source_head_unavailable")
    return selected


def _digest(value: object, error_code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
    ):
        raise SuiteAuditCaptureError(error_code)
    try:
        int(value, 16)
    except ValueError as exc:
        raise SuiteAuditCaptureError(error_code) from exc
    return value


def _limitations(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise SuiteAuditCaptureError("source_history_incomplete")
    if (
        len(value) > len(_DIGESTS)
        or tuple(sorted(set(value))) != value
        or any(item not in _DIGESTS for item in value)
    ):
        raise SuiteAuditCaptureError("source_history_incomplete")
    return value


@dataclass(frozen=True, slots=True)
class SuiteAuditCapture:
    """One immutable, digest-only snapshot of a suite-owned audit history."""

    tenant_id: str
    source_id: str
    source_revision: int
    source_schema_version: int
    observed_at: float
    records: tuple[SourceRecord, ...]
    record_count: int
    head_sha256: str
    complete: bool
    retention_complete: bool
    integrity_verified: bool
    limitations: tuple[str, ...]
    capture_sha256: str

    def __post_init__(self) -> None:
        tenant = _tenant(self.tenant_id)
        source = _source(self.source_id)
        revision = _positive_integer(
            self.source_revision,
            "source_authority_invalid",
        )
        schema_version = _positive_integer(
            self.source_schema_version,
            "source_authority_invalid",
        )
        observed = _timestamp(self.observed_at)
        if not isinstance(self.records, tuple) or any(
            type(record) is not SourceRecord for record in self.records
        ):
            raise SuiteAuditCaptureError("source_history_unavailable")
        if (
            isinstance(self.record_count, bool)
            or not isinstance(self.record_count, int)
            or self.record_count < 0
            or self.record_count != len(self.records)
        ):
            raise SuiteAuditCaptureError("source_history_unavailable")
        previous = GENESIS_SHA256
        for sequence, record in enumerate(self.records, start=1):
            if (
                record.sequence != sequence
                or record.occurred_at > observed
                or not hmac.compare_digest(record.previous_sha256, previous)
            ):
                raise SuiteAuditCaptureError("source_integrity_unverified")
            previous = record.record_sha256
        head = _digest(self.head_sha256, "source_head_unavailable")
        if not hmac.compare_digest(head, previous):
            raise SuiteAuditCaptureError("source_integrity_unverified")
        if any(
            type(flag) is not bool
            for flag in (
                self.complete,
                self.retention_complete,
                self.integrity_verified,
            )
        ):
            raise SuiteAuditCaptureError("source_history_incomplete")
        limits = _limitations(self.limitations)
        if self.complete and (
            not self.retention_complete
            or not self.integrity_verified
            or limits
        ):
            raise SuiteAuditCaptureError("source_history_incomplete")
        if not self.complete and not limits:
            raise SuiteAuditCaptureError("source_history_incomplete")
        supplied = _digest(self.capture_sha256, "source_integrity_unverified")
        material = {
            "schema": CAPTURE_SCHEMA,
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "source_id": source,
            "source_revision": revision,
            "source_schema_version": schema_version,
            "observed_at": observed,
            "record_count": self.record_count,
            "head_sha256": head,
            "complete": self.complete,
            "retention_complete": self.retention_complete,
            "integrity_verified": self.integrity_verified,
            "limitations": list(limits),
            "record_sha256s": [record.record_sha256 for record in self.records],
        }
        expected = hashlib.sha256(_canonical(material)).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise SuiteAuditCaptureError("source_integrity_unverified")
        object.__setattr__(self, "tenant_id", tenant)
        object.__setattr__(self, "source_id", source)
        object.__setattr__(self, "source_revision", revision)
        object.__setattr__(self, "source_schema_version", schema_version)
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "head_sha256", head)
        object.__setattr__(self, "limitations", limits)

    def public_metadata(self) -> dict[str, object]:
        """Return reusable metadata without the tenant id or source records."""

        value = asdict(self)
        value.pop("tenant_id")
        value.pop("records")
        return value


def build_suite_audit_capture(
    *,
    tenant_id: str,
    source_id: str,
    source_revision: int,
    source_schema_version: int,
    observed_at: float,
    records: tuple[SourceRecord, ...],
    complete: bool,
    retention_complete: bool,
    integrity_verified: bool,
    limitations: tuple[str, ...],
) -> SuiteAuditCapture:
    """Build and self-validate a canonical capture commitment."""

    tenant = _tenant(tenant_id)
    source = _source(source_id)
    previous = records[-1].record_sha256 if records else GENESIS_SHA256
    material = {
        "schema": CAPTURE_SCHEMA,
        "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
        "source_id": source,
        "source_revision": source_revision,
        "source_schema_version": source_schema_version,
        "observed_at": float(observed_at),
        "record_count": len(records),
        "head_sha256": previous,
        "complete": complete,
        "retention_complete": retention_complete,
        "integrity_verified": integrity_verified,
        "limitations": list(limitations),
        "record_sha256s": [record.record_sha256 for record in records],
    }
    return SuiteAuditCapture(
        tenant_id=tenant,
        source_id=source,
        source_revision=source_revision,
        source_schema_version=source_schema_version,
        observed_at=observed_at,
        records=records,
        record_count=len(records),
        head_sha256=previous,
        complete=complete,
        retention_complete=retention_complete,
        integrity_verified=integrity_verified,
        limitations=limitations,
        capture_sha256=hashlib.sha256(_canonical(material)).hexdigest(),
    )


@runtime_checkable
class SuiteAuditCaptureProvider(Protocol):
    """Read-only provider used independently by projections and verifiers."""

    @property
    def provider_identity_sha256(self) -> str: ...

    def capture(self, *, tenant_id: str, source_id: str) -> SuiteAuditCapture: ...


__all__ = [
    "CAPTURE_PROVIDER_SCHEMA",
    "CAPTURE_SCHEMA",
    "SuiteAuditCapture",
    "SuiteAuditCaptureError",
    "SuiteAuditCaptureProvider",
    "build_suite_audit_capture",
]
