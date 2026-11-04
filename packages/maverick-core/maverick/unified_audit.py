"""Tenant-bound, digest-only projection of the six governance audit domains.

This module does not replace any domain system of record.  It verifies a
closed page contract supplied by a server-injected domain adapter, appends a
normalized commitment to a strictly signed audit sink, and advances its local
cursor only after every append succeeds.  No raw domain payload, actor,
resource identifier, credential, or tenant identifier is persisted here.

The fixed six-source coverage floor is deliberately not configurable.  A
missing, unavailable, revoked, truncated, stale, or failed source keeps the
overall projection incomplete.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 2
GENESIS_SHA256 = "0" * 64
REQUIRED_SUITES = (
    "ai_governance",
    "consent_preferences",
    "data_use_governance",
    "privacy_automation",
    "tech_risk_compliance",
    "third_party_management",
)
SOURCE_SPECS = {suite: suite for suite in REQUIRED_SUITES}

_TOKEN = re.compile(r"^[a-z][a-z0-9_.:-]{0,95}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_HISTORY_LIMIT = 1_000
_MAX_LIMITATIONS = 32
_STATE_SCHEMA = "lightwork.unified-audit-source-state.v1"
_HISTORY_SCHEMA = "lightwork.unified-audit-history.v1"
_PROJECTION_SCHEMA = "lightwork.unified-audit-projection.v1"
_STATUS_SCHEMA = "lightwork.unified-audit-status.v1"
_PAGE_SCHEMA = "lightwork.unified-audit-source-page.v1"
_RECORD_SCHEMA = "lightwork.unified-audit-source-record.v1"
_RECEIPT_SCHEMA = "lightwork.unified-audit-projection-receipt.v1"
_VERIFICATION_SCHEMA = "lightwork.unified-audit-source-verification.v1"
_MAX_FUTURE_SKEW_SECONDS = 300.0

# These are the only non-digest values a source is allowed to project.  They
# are deliberately broad enough for all six suites, but closed so a source
# cannot smuggle a customer, patient, employee, or document name into an
# ``action`` or ``limitations`` field.
SOURCE_ACTION_CODES = frozenset(
    {
        "access_recorded",
        "approval_denied",
        "approval_granted",
        "consent_recorded",
        "consent_revoked",
        "control_evaluated",
        "decision_recorded",
        "evidence_recorded",
        "export_recorded",
        "incident_recorded",
        "integrity_verified",
        "observation_recorded",
        "policy_changed",
        "record_changed",
        "record_created",
        "record_deleted",
        "record_updated",
        "relationship_changed",
        "request_submitted",
        "retention_action",
        "risk_changed",
        "status_changed",
    }
)
SOURCE_LIMITATION_CODES = frozenset(
    {
        "authoritative_history_reader_unavailable",
        "more_records_available",
        "page_limit_reached",
        "source_authority_changed",
        "source_authority_invalid",
        "source_authority_revoked",
        "source_head_unavailable",
        "source_history_incomplete",
        "source_history_unavailable",
        "source_integrity_unverified",
        "source_page_incomplete",
        "source_page_invalid",
        "source_retention_unverified",
        "source_watermark_unaccepted",
    }
)
STATE_LIMITATION_CODES = SOURCE_LIMITATION_CODES | frozenset(
    {
        "authority_rotated_pending_reconciliation",
        "operator_replay_pending",
        "source_configuration_unavailable",
        "source_conflict",
        "source_contract_invalid",
        "source_dependency_unavailable",
        "source_integrity_failed",
        "source_lease_lost",
        "source_not_reconciled",
        "source_not_registered",
        "source_retry_exhausted",
        "source_revoked",
    }
)
ASSURANCE_LEVELS = frozenset({"self_asserted", "signed_anchored"})


class UnifiedAuditError(RuntimeError):
    """Base error for the unified-audit control plane."""


class UnifiedAuditConfigError(UnifiedAuditError):
    """Deployment configuration or injected authority is unavailable."""


class UnifiedAuditValidationError(UnifiedAuditError, ValueError):
    """An input or source page violates the closed contract."""


class UnifiedAuditConflict(UnifiedAuditError):
    """A cursor, authority, revision, retry, or lease precondition changed."""


class UnifiedAuditIntegrityError(UnifiedAuditError):
    """Persisted or supplied digest/chain material failed verification."""


class UnifiedAuditNotFound(UnifiedAuditError):
    """A fixed source is not registered in the server-owned registry."""


class UnifiedAuditLeaseLost(UnifiedAuditConflict):
    """The caller no longer owns the exact source projection lease."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise UnifiedAuditValidationError("material is not canonical JSON") from exc


def canonical_sha256(value: object) -> str:
    """Return the canonical SHA-256 commitment used by adapter contracts."""

    return hashlib.sha256(_canonical(value)).hexdigest()


def _loads(raw: str, label: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite number {value}")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate key {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw, parse_constant=reject_constant, object_pairs_hook=pairs)
    except (TypeError, ValueError) as exc:
        raise UnifiedAuditIntegrityError(f"stored {label} is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise UnifiedAuditValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise UnifiedAuditValidationError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise UnifiedAuditValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str, *, allow_zero: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UnifiedAuditValidationError(f"{label} must be a timestamp")
    result = float(value)
    minimum = 0.0 if allow_zero else 0.0 + float.fromhex("0x0.0000000000001p-1022")
    if not math.isfinite(result) or result < minimum or result >= 100_000_000_000.0:
        raise UnifiedAuditValidationError(f"{label} is outside its bound")
    return result


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), "clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except UnifiedAuditValidationError as exc:
        raise UnifiedAuditConfigError("unified-audit clock is invalid") from exc
    except Exception as exc:
        raise UnifiedAuditConfigError("unified-audit clock is unavailable") from exc


def _source_id(value: object) -> str:
    selected = _token(value, "source_id")
    if selected not in SOURCE_SPECS:
        raise UnifiedAuditValidationError("source_id is outside the fixed suite registry")
    return selected


def _tenant(value: object) -> str:
    if not isinstance(value, str):
        raise UnifiedAuditValidationError("tenant_id is invalid")
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise UnifiedAuditValidationError("tenant_id is invalid") from exc


def _tenant_sha256(tenant_id: str) -> str:
    return hashlib.sha256(f"lightwork.unified-audit.tenant.v1:{tenant_id}".encode()).hexdigest()


def _worker_sha256(tenant_sha256: str, worker_id: object) -> str:
    if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 512:
        raise UnifiedAuditValidationError("worker_id is invalid")
    return hashlib.sha256(
        f"lightwork.unified-audit.worker.v1:{tenant_sha256}:{worker_id}".encode()
    ).hexdigest()


def _limitation_codes(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > _MAX_LIMITATIONS:
        raise UnifiedAuditValidationError("limitations are invalid")
    result = tuple(_token(value, "limitation") for value in values)
    if len(set(result)) != len(result) or tuple(sorted(result)) != result:
        raise UnifiedAuditValidationError("limitations must be unique and sorted")
    return result


def _source_limitation_codes(values: Sequence[str]) -> tuple[str, ...]:
    result = _limitation_codes(values)
    if any(value not in SOURCE_LIMITATION_CODES for value in result):
        raise UnifiedAuditValidationError("source limitations are outside the closed vocabulary")
    return result


def _state_limitation_codes(values: Sequence[str]) -> tuple[str, ...]:
    result = _limitation_codes(values)
    if any(value not in STATE_LIMITATION_CODES for value in result):
        raise UnifiedAuditValidationError("state limitations are outside the closed vocabulary")
    return result


@dataclass(frozen=True, slots=True)
class UnifiedAuditConfig:
    enable: bool = False
    page_size: int = 100
    lease_seconds: int = 120
    max_lag_seconds: int = 300
    max_attempts: int = 5
    retry_backoff_seconds: int = 30
    poll_seconds: int = 60

    def __post_init__(self) -> None:
        if not isinstance(self.enable, bool):
            raise UnifiedAuditConfigError("audit.unified.enable must be true or false")
        bounds = (
            (self.page_size, "page_size", 1, 500),
            (self.lease_seconds, "lease_seconds", 30, 86_400),
            (self.max_lag_seconds, "max_lag_seconds", 1, 31_536_000),
            (self.max_attempts, "max_attempts", 1, 20),
            (self.retry_backoff_seconds, "retry_backoff_seconds", 0, 86_400),
            (self.poll_seconds, "poll_seconds", 5, 3_600),
        )
        try:
            for value, label, minimum, maximum in bounds:
                _integer(value, label, minimum, maximum)
        except UnifiedAuditValidationError as exc:
            raise UnifiedAuditConfigError(str(exc)) from exc

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> UnifiedAuditConfig:
        if not isinstance(config, Mapping):
            raise UnifiedAuditConfigError("unified-audit configuration is unavailable")
        audit = config.get("audit") or {}
        if not isinstance(audit, Mapping):
            raise UnifiedAuditConfigError("[audit] must be a table")
        section = audit.get("unified") or {}
        if not isinstance(section, Mapping):
            raise UnifiedAuditConfigError("[audit.unified] must be a table")
        allowed = {
            "enable",
            "page_size",
            "lease_seconds",
            "max_lag_seconds",
            "max_attempts",
            "retry_backoff_seconds",
            "poll_seconds",
            # Parsed by unified_audit_custody.  Keep the projection dataclass
            # independent from the optional custody composition while allowing
            # the nested table in the same signed feature authority.
            "custody",
        }
        unknown = sorted(str(key) for key in section if key not in allowed)
        if unknown:
            raise UnifiedAuditConfigError("unknown [audit.unified] key: " + ", ".join(unknown))
        values = {
            key: section[key]
            for key in allowed - {"custody"}
            if key in section
        }
        return cls(**values)


def _load_config() -> Mapping[str, Any]:
    try:
        from .config import config_source_errors, load_config

        config = load_config()
        if config_source_errors():
            raise UnifiedAuditConfigError("unified-audit configuration source is invalid")
    except UnifiedAuditConfigError:
        raise
    except Exception as exc:
        raise UnifiedAuditConfigError("unified-audit configuration is unavailable") from exc
    if not isinstance(config, Mapping):
        raise UnifiedAuditConfigError("unified-audit configuration is unavailable")
    return config


def config_from(config: Mapping[str, Any] | None = None) -> UnifiedAuditConfig:
    return UnifiedAuditConfig.from_mapping(_load_config() if config is None else config)


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Side-effect-free feature probe; invalid policy is never treated as enabled."""

    try:
        selected = _load_config() if config is None else config
        parsed = UnifiedAuditConfig.from_mapping(selected)
        audit = selected.get("audit") if isinstance(selected, Mapping) else None
        return bool(parsed.enable and isinstance(audit, Mapping) and audit.get("sign") is True)
    except (UnifiedAuditError, TypeError, ValueError):
        return False


def require_enabled(config: Mapping[str, Any] | None = None) -> UnifiedAuditConfig:
    selected = _load_config() if config is None else config
    parsed = UnifiedAuditConfig.from_mapping(selected)
    audit = selected.get("audit") if isinstance(selected, Mapping) else None
    if not parsed.enable:
        raise UnifiedAuditConfigError("unified_audit_disabled")
    if not isinstance(audit, Mapping) or audit.get("sign") is not True:
        raise UnifiedAuditConfigError("unified_audit_requires_signed_audit")
    return parsed


@dataclass(frozen=True, slots=True)
class SourceAuthority:
    tenant_id: str
    source_id: str
    suite_id: str
    authority_revision: int
    authority_sha256: str
    source_schema_version: int = 1

    def __post_init__(self) -> None:
        tenant = _tenant(self.tenant_id)
        source = _source_id(self.source_id)
        suite = _source_id(self.suite_id)
        if source != suite or SOURCE_SPECS[source] != suite:
            raise UnifiedAuditValidationError("source and suite authority do not match")
        _integer(self.authority_revision, "authority_revision", 1, 2**31 - 1)
        if _digest(self.authority_sha256, "authority_sha256") == GENESIS_SHA256:
            raise UnifiedAuditValidationError("authority_sha256 cannot be genesis")
        _integer(self.source_schema_version, "source_schema_version", 1, 2**31 - 1)
        object.__setattr__(self, "tenant_id", tenant)


@dataclass(frozen=True, slots=True)
class SourceRecord:
    sequence: int
    occurred_at: float
    action: str
    actor_sha256: str
    resource_sha256: str
    payload_sha256: str
    previous_sha256: str
    record_sha256: str

    def __post_init__(self) -> None:
        _integer(self.sequence, "sequence", 1, 2**63 - 1)
        _timestamp(self.occurred_at, "occurred_at")
        if self.action not in SOURCE_ACTION_CODES:
            raise UnifiedAuditValidationError("action is outside the closed source vocabulary")
        for field in (
            "actor_sha256",
            "resource_sha256",
            "payload_sha256",
            "previous_sha256",
            "record_sha256",
        ):
            _digest(getattr(self, field), field)
        expected = _source_record_digest(self)
        if not hmac.compare_digest(expected, self.record_sha256):
            raise UnifiedAuditIntegrityError("source record digest is invalid")


def _source_record_digest(record: SourceRecord) -> str:
    return canonical_sha256(
        {
            "schema": _RECORD_SCHEMA,
            "sequence": record.sequence,
            "occurred_at": float(record.occurred_at),
            "action": record.action,
            "actor_sha256": record.actor_sha256,
            "resource_sha256": record.resource_sha256,
            "payload_sha256": record.payload_sha256,
            "previous_sha256": record.previous_sha256,
        }
    )


def build_source_record(
    *,
    sequence: int,
    occurred_at: float,
    action: str,
    actor_sha256: str,
    resource_sha256: str,
    payload_sha256: str,
    previous_sha256: str,
) -> SourceRecord:
    material = {
        "schema": _RECORD_SCHEMA,
        "sequence": sequence,
        "occurred_at": float(occurred_at),
        "action": action,
        "actor_sha256": actor_sha256,
        "resource_sha256": resource_sha256,
        "payload_sha256": payload_sha256,
        "previous_sha256": previous_sha256,
    }
    return SourceRecord(
        record_sha256=canonical_sha256(material),
        **{k: v for k, v in material.items() if k != "schema"},
    )


@dataclass(frozen=True, slots=True)
class SourcePage:
    tenant_id: str
    source_id: str
    suite_id: str
    authority_revision: int
    authority_sha256: str
    source_schema_version: int
    after_sequence: int
    first_sequence: int
    last_sequence: int
    record_count: int
    prior_sha256: str
    head_sha256: str
    previous_page_sha256: str
    page_sha256: str
    terminal: bool
    complete: bool
    truncated: bool
    watermark: float
    limitations: tuple[str, ...]
    records: tuple[SourceRecord, ...]

    def __post_init__(self) -> None:
        authority = SourceAuthority(
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            suite_id=self.suite_id,
            authority_revision=self.authority_revision,
            authority_sha256=self.authority_sha256,
            source_schema_version=self.source_schema_version,
        )
        object.__setattr__(self, "tenant_id", authority.tenant_id)
        for field in ("after_sequence", "first_sequence", "last_sequence", "record_count"):
            _integer(getattr(self, field), field, 0, 2**63 - 1)
        for field in ("prior_sha256", "head_sha256", "previous_page_sha256", "page_sha256"):
            _digest(getattr(self, field), field)
        for field in ("terminal", "complete", "truncated"):
            if not isinstance(getattr(self, field), bool):
                raise UnifiedAuditValidationError(f"{field} must be true or false")
        _timestamp(self.watermark, "watermark")
        limitations = _source_limitation_codes(self.limitations)
        object.__setattr__(self, "limitations", limitations)
        if not isinstance(self.records, tuple) or any(
            not isinstance(item, SourceRecord) for item in self.records
        ):
            raise UnifiedAuditValidationError("records must be SourceRecord values")
        if len(self.records) > 500:
            raise UnifiedAuditValidationError("source page exceeds the absolute record bound")
        _validate_source_page(self)


def _page_material(page: SourcePage) -> dict[str, Any]:
    return {
        "schema": _PAGE_SCHEMA,
        "tenant_sha256": _tenant_sha256(page.tenant_id),
        "source_id": page.source_id,
        "suite_id": page.suite_id,
        "authority_revision": page.authority_revision,
        "authority_sha256": page.authority_sha256,
        "source_schema_version": page.source_schema_version,
        "after_sequence": page.after_sequence,
        "first_sequence": page.first_sequence,
        "last_sequence": page.last_sequence,
        "record_count": page.record_count,
        "prior_sha256": page.prior_sha256,
        "head_sha256": page.head_sha256,
        "previous_page_sha256": page.previous_page_sha256,
        "terminal": page.terminal,
        "complete": page.complete,
        "truncated": page.truncated,
        "watermark": float(page.watermark),
        "limitations": list(page.limitations),
        "record_sha256s": [record.record_sha256 for record in page.records],
    }


def _validate_source_page(page: SourcePage) -> None:
    records = page.records
    if page.record_count != len(records):
        raise UnifiedAuditIntegrityError("source page count does not match records")
    if page.complete and (not page.terminal or page.truncated or page.limitations):
        raise UnifiedAuditValidationError("complete source page has limitations")
    if (page.truncated or not page.complete) and not page.limitations:
        raise UnifiedAuditValidationError("incomplete source page must disclose limitations")
    expected_sequence = page.after_sequence + 1
    previous = page.prior_sha256
    if records:
        if page.first_sequence != expected_sequence:
            raise UnifiedAuditIntegrityError("source page first sequence is discontinuous")
        for record in records:
            if not hmac.compare_digest(_source_record_digest(record), record.record_sha256):
                raise UnifiedAuditIntegrityError("source record digest is invalid")
            if record.sequence != expected_sequence:
                raise UnifiedAuditIntegrityError("source page sequence is discontinuous")
            if not hmac.compare_digest(record.previous_sha256, previous):
                raise UnifiedAuditIntegrityError("source record chain is discontinuous")
            previous = record.record_sha256
            expected_sequence += 1
        if page.last_sequence != records[-1].sequence:
            raise UnifiedAuditIntegrityError("source page last sequence is invalid")
    elif page.first_sequence != page.after_sequence or page.last_sequence != page.after_sequence:
        raise UnifiedAuditIntegrityError("empty source page cursor is invalid")
    if page.last_sequence != page.after_sequence + page.record_count:
        raise UnifiedAuditIntegrityError("source page cursor count is invalid")
    if any(record.occurred_at > page.watermark for record in records):
        raise UnifiedAuditIntegrityError("source record occurs after the page watermark")
    if not hmac.compare_digest(page.head_sha256, previous):
        raise UnifiedAuditIntegrityError("source page head digest is invalid")
    expected_page = canonical_sha256(_page_material(page))
    if not hmac.compare_digest(expected_page, page.page_sha256):
        raise UnifiedAuditIntegrityError("source page digest is invalid")


def build_source_page(
    authority: SourceAuthority,
    *,
    after_sequence: int,
    prior_sha256: str,
    previous_page_sha256: str,
    records: Sequence[SourceRecord],
    terminal: bool,
    complete: bool,
    truncated: bool,
    watermark: float,
    limitations: Sequence[str] = (),
) -> SourcePage:
    if isinstance(records, (str, bytes)) or len(records) > 500:
        raise UnifiedAuditValidationError("source page exceeds the absolute record bound")
    selected = tuple(records)
    first = selected[0].sequence if selected else after_sequence
    last = selected[-1].sequence if selected else after_sequence
    head = selected[-1].record_sha256 if selected else prior_sha256
    values: dict[str, Any] = {
        **asdict(authority),
        "after_sequence": after_sequence,
        "first_sequence": first,
        "last_sequence": last,
        "record_count": len(selected),
        "prior_sha256": prior_sha256,
        "head_sha256": head,
        "previous_page_sha256": previous_page_sha256,
        "page_sha256": GENESIS_SHA256,
        "terminal": terminal,
        "complete": complete,
        "truncated": truncated,
        "watermark": watermark,
        "limitations": tuple(limitations),
        "records": selected,
    }
    provisional = SourcePage.__new__(SourcePage)
    for key, value in values.items():
        object.__setattr__(provisional, key, value)
    values["page_sha256"] = canonical_sha256(_page_material(provisional))
    return SourcePage(**values)


@runtime_checkable
class DomainAuditSource(Protocol):
    def authority(self) -> SourceAuthority: ...

    def read_page(
        self,
        *,
        after_sequence: int,
        prior_sha256: str,
        previous_page_sha256: str,
        limit: int,
    ) -> SourcePage: ...


@dataclass(frozen=True, slots=True)
class SourceVerification:
    """Independent verification result for one immutable source snapshot.

    A digest-chain adapter by itself is only self-asserted.  Overall coverage
    can become current only when a separately injected verifier reports a
    signed, anchored snapshot with an accepted retention boundary.
    """

    tenant_id: str
    source_id: str
    authority_revision: int
    authority_sha256: str
    source_schema_version: int
    page_sha256: str
    verified_at: float
    assurance_level: str
    verifier_identity_sha256: str
    trust_root_revision: int
    key_id_sha256: str
    anchor_sha256: str
    snapshot_head_sha256: str
    snapshot_record_count: int
    retention_complete: bool
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _tenant(self.tenant_id))
        object.__setattr__(self, "source_id", _source_id(self.source_id))
        _integer(self.authority_revision, "authority_revision", 1, 2**31 - 1)
        _integer(self.source_schema_version, "source_schema_version", 1, 2**31 - 1)
        _integer(self.trust_root_revision, "trust_root_revision", 0, 2**31 - 1)
        _integer(self.snapshot_record_count, "snapshot_record_count", 0, 2**63 - 1)
        _timestamp(self.verified_at, "verified_at")
        for field in (
            "authority_sha256",
            "page_sha256",
            "verifier_identity_sha256",
            "key_id_sha256",
            "anchor_sha256",
            "snapshot_head_sha256",
        ):
            _digest(getattr(self, field), field)
        if self.assurance_level not in ASSURANCE_LEVELS:
            raise UnifiedAuditValidationError("source assurance level is invalid")
        if not isinstance(self.retention_complete, bool):
            raise UnifiedAuditValidationError("retention_complete must be true or false")
        limitations = _source_limitation_codes(self.limitations)
        object.__setattr__(self, "limitations", limitations)
        if self.assurance_level == "signed_anchored" and (
            self.trust_root_revision < 1
            or self.key_id_sha256 == GENESIS_SHA256
            or self.anchor_sha256 == GENESIS_SHA256
            or self.verifier_identity_sha256 == GENESIS_SHA256
            or not self.retention_complete
            or limitations
        ):
            raise UnifiedAuditValidationError(
                "signed_anchored assurance requires a trusted complete snapshot"
            )

    @property
    def verification_sha256(self) -> str:
        return canonical_sha256({"schema": _VERIFICATION_SCHEMA, **asdict(self)})


@runtime_checkable
class SourceVerifier(Protocol):
    @property
    def verifier_identity_sha256(self) -> str: ...

    def verify_page(
        self,
        *,
        authority: SourceAuthority,
        page: SourcePage,
    ) -> SourceVerification: ...


@dataclass(frozen=True, slots=True)
class ProjectionReceipt:
    """Durable signed-sink acknowledgement bound to one exact event."""

    projection_event_id: str
    event_sha256: str
    tenant_sha256: str
    sink_identity_sha256: str
    key_id_sha256: str
    chain_sha256: str
    signature_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "projection_event_id",
            "event_sha256",
            "tenant_sha256",
            "sink_identity_sha256",
            "key_id_sha256",
            "chain_sha256",
            "signature_sha256",
        ):
            if _digest(getattr(self, field), field) == GENESIS_SHA256:
                raise UnifiedAuditValidationError(f"{field} cannot be genesis")

    @property
    def receipt_sha256(self) -> str:
        return canonical_sha256({"schema": _RECEIPT_SCHEMA, **asdict(self)})


@runtime_checkable
class ProjectionSink(Protocol):
    @property
    def tenant_sha256(self) -> str: ...

    @property
    def sink_identity_sha256(self) -> str: ...

    @property
    def signing_ready(self) -> bool: ...

    def append(self, event: Mapping[str, Any]) -> ProjectionReceipt: ...


class StrictAuditProjectionSink:
    """Adapter for the central audit writer's cryptographically strict append."""

    def __init__(
        self,
        *,
        tenant_id: str,
        audit_log: Any | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        tenant = _tenant(tenant_id)
        from .paths import data_dir

        expected_audit_dir = data_dir("audit", tenant=tenant).resolve()
        if audit_log is None:
            from .audit.writer import AuditLog

            audit_log = AuditLog(expected_audit_dir)
        if not callable(getattr(audit_log, "record_strict_signed", None)):
            raise UnifiedAuditConfigError("strict signed audit writer is unavailable")
        audit_dir = getattr(audit_log, "audit_dir", None)
        if not isinstance(audit_dir, Path):
            raise UnifiedAuditConfigError("strict signed audit writer identity is unavailable")
        resolved_audit_dir = audit_dir.resolve()
        if resolved_audit_dir != expected_audit_dir:
            raise UnifiedAuditConfigError(
                "strict signed audit writer is outside the tenant audit authority"
            )
        if not callable(clock):
            raise UnifiedAuditConfigError("unified-audit sink clock is unavailable")
        self._audit_log = audit_log
        self._clock = clock
        self._tenant_sha256 = _tenant_sha256(tenant)
        self._sink_identity_sha256 = canonical_sha256(
            {
                "schema": "lightwork.unified-audit-sink-identity.v1",
                "tenant_sha256": self._tenant_sha256,
                "audit_dir_sha256": hashlib.sha256(
                    str(resolved_audit_dir).encode("utf-8")
                ).hexdigest(),
            }
        )

    @property
    def tenant_sha256(self) -> str:
        return self._tenant_sha256

    @property
    def sink_identity_sha256(self) -> str:
        return self._sink_identity_sha256

    @property
    def signing_ready(self) -> bool:
        value = getattr(self._audit_log, "signing_enabled", False)
        return value if type(value) is bool else False

    def append(self, event: Mapping[str, Any]) -> ProjectionReceipt:
        if not isinstance(event, Mapping):
            raise UnifiedAuditValidationError("projection event is invalid")
        from .audit.events import AuditEvent, EventKind

        audit_event = AuditEvent(
            ts=_clock_value(self._clock),
            kind=EventKind.UNIFIED_AUDIT_PROJECTION,
            agent="unified-audit-projector",
            payload=dict(event),
        )
        result = self._audit_log.record_strict_signed(audit_event)
        if result is not True:
            raise UnifiedAuditError("strict signed audit writer refused an append")

        # Return evidence from the row the central writer just verified or
        # appended.  This second read is intentional: a bare boolean cannot
        # bind the cursor commit to a tenant, key, chain position, or exact
        # event.  The central writer has already serialized this operation
        # under its strict rewrite lock; we verify the containing chain again
        # before issuing the receipt.
        identity = event.get("projection_event_id")
        identity = _digest(identity, "projection_event_id")
        from .audit.sealing import SegmentReadError, segment_text
        from .audit.signing import verify_chain

        matches: list[dict[str, Any]] = []
        for path in sorted(self._audit_log.audit_dir.glob("*.ndjson")):
            try:
                segment = segment_text(path, fail_soft=False)
                rows = segment.splitlines()
            except (OSError, SegmentReadError) as exc:
                raise UnifiedAuditIntegrityError(
                    "strict signed audit receipt is unavailable"
                ) from exc
            for raw in rows:
                try:
                    row = json.loads(raw)
                except (TypeError, ValueError) as exc:
                    raise UnifiedAuditIntegrityError(
                        "strict signed audit receipt row is invalid"
                    ) from exc
                if (
                    isinstance(row, dict)
                    and row.get("kind") == EventKind.UNIFIED_AUDIT_PROJECTION
                    and row.get("projection_event_id") == identity
                ):
                    if verify_chain(path, segment=segment):
                        raise UnifiedAuditIntegrityError(
                            "strict signed audit receipt chain is invalid"
                        )
                    matches.append(row)
        if len(matches) != 1:
            raise UnifiedAuditIntegrityError("strict signed audit receipt identity is not unique")
        row = matches[0]
        if any(row.get(key) != value for key, value in event.items()):
            raise UnifiedAuditIntegrityError(
                "strict signed audit receipt does not match the projection"
            )
        if row.get("tenant_sha256") != self._tenant_sha256:
            raise UnifiedAuditIntegrityError("strict signed audit receipt tenant changed")
        key_id = row.get("key_id")
        chain_hash = row.get("hash")
        signature = row.get("sig")
        if not all(isinstance(value, str) and value for value in (key_id, chain_hash, signature)):
            raise UnifiedAuditIntegrityError("strict signed audit receipt is unsigned")
        return ProjectionReceipt(
            projection_event_id=identity,
            event_sha256=canonical_sha256(dict(event)),
            tenant_sha256=self._tenant_sha256,
            sink_identity_sha256=self._sink_identity_sha256,
            key_id_sha256=hashlib.sha256(key_id.encode("ascii")).hexdigest(),
            chain_sha256=_digest(chain_hash, "chain_sha256"),
            signature_sha256=hashlib.sha256(signature.encode("ascii")).hexdigest(),
        )


class UnifiedAuditRegistry:
    """Exact in-memory server registry; there is no caller-facing registration API."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = _tenant(tenant_id)
        self._sources: dict[str, DomainAuditSource] = {}
        self._verifiers: dict[str, SourceVerifier] = {}

    def register(
        self,
        source: DomainAuditSource,
        *,
        verifier: SourceVerifier | None = None,
    ) -> None:
        if not isinstance(source, DomainAuditSource):
            raise UnifiedAuditConfigError("domain audit source does not implement the contract")
        try:
            authority = source.authority()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise UnifiedAuditConfigError("domain audit source authority is unavailable") from exc
        if not isinstance(authority, SourceAuthority):
            raise UnifiedAuditConfigError("domain audit source authority is invalid")
        try:
            authority = SourceAuthority(**asdict(authority))
        except (UnifiedAuditError, TypeError, ValueError) as exc:
            raise UnifiedAuditConfigError("domain audit source authority is invalid") from exc
        if authority.tenant_id != self.tenant_id:
            raise UnifiedAuditConfigError("domain audit source tenant binding is invalid")
        if authority.source_id in self._sources:
            raise UnifiedAuditConflict("domain audit source is already registered")
        if verifier is not None:
            if not isinstance(verifier, SourceVerifier):
                raise UnifiedAuditConfigError("domain audit source verifier is invalid")
            try:
                verifier_identity = verifier.verifier_identity_sha256
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise UnifiedAuditConfigError(
                    "domain audit source verifier identity is unavailable"
                ) from exc
            if _digest(verifier_identity, "verifier_identity_sha256") == GENESIS_SHA256:
                raise UnifiedAuditConfigError("domain audit source verifier identity is invalid")
            self._verifiers[authority.source_id] = verifier
        self._sources[authority.source_id] = source

    def get(self, source_id: str) -> DomainAuditSource:
        selected = _source_id(source_id)
        source = self._sources.get(selected)
        if source is None:
            raise UnifiedAuditNotFound("required unified-audit source is unavailable")
        return source

    def available_source_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._sources))

    def verifier(self, source_id: str) -> SourceVerifier:
        selected = _source_id(source_id)
        verifier = self._verifiers.get(selected)
        if verifier is None:
            raise UnifiedAuditConfigError("required source verifier is unavailable")
        return verifier

    def verified_source_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self._sources) & set(self._verifiers)))


@dataclass(frozen=True, slots=True)
class ProjectionClaim:
    source_id: str
    state_revision: int
    cursor_sequence: int
    source_head_sha256: str
    previous_page_sha256: str
    worker_sha256: str
    lease_until: float


@dataclass(frozen=True, slots=True)
class ProjectionRunResult:
    source_id: str
    outcome: str
    projected: int
    cursor_sequence: int
    complete: bool
    page_sha256: str
    error_code: str = ""


def _initial_state(source_id: str, now: float) -> dict[str, Any]:
    return {
        "schema": _STATE_SCHEMA,
        "source_id": source_id,
        "suite_id": SOURCE_SPECS[source_id],
        "registered": False,
        "revoked": False,
        "authority_revision": 0,
        "authority_sha256": GENESIS_SHA256,
        "source_schema_version": 0,
        "pending_authority_revision": 0,
        "pending_authority_sha256": GENESIS_SHA256,
        "pending_source_schema_version": 0,
        "pending_verifier_identity_sha256": GENESIS_SHA256,
        "pending_trust_root_revision": 0,
        "pending_source_key_id_sha256": GENESIS_SHA256,
        "cursor_sequence": 0,
        "source_head_sha256": GENESIS_SHA256,
        "previous_page_sha256": GENESIS_SHA256,
        "complete": False,
        "truncated": False,
        "limitations": ["source_not_registered"],
        "watermark": 0.0,
        "last_success_at": 0.0,
        "last_attempt_at": 0.0,
        "error_code": "source_not_registered",
        "assurance_level": "self_asserted",
        "verifier_identity_sha256": GENESIS_SHA256,
        "trust_root_revision": 0,
        "source_key_id_sha256": GENESIS_SHA256,
        "source_anchor_sha256": GENESIS_SHA256,
        "snapshot_head_sha256": GENESIS_SHA256,
        "snapshot_record_count": 0,
        "retention_complete": False,
        "verification_sha256": GENESIS_SHA256,
        "sink_identity_sha256": GENESIS_SHA256,
        "sink_key_id_sha256": GENESIS_SHA256,
        "projection_receipt_sha256": GENESIS_SHA256,
        "success_generation": 0,
        "attempts": 0,
        "next_attempt_at": 0.0,
        "lease_owner_sha256": GENESIS_SHA256,
        "lease_until": 0.0,
        "revision": 1,
        "updated_at": now,
    }


def _validate_state(state: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(state, Mapping) or state.get("schema") != _STATE_SCHEMA:
        raise UnifiedAuditIntegrityError("stored source state schema is invalid")
    expected_keys = set(_initial_state("ai_governance", 1.0))
    if set(state) != expected_keys:
        raise UnifiedAuditIntegrityError("stored source state shape is invalid")
    source = _source_id(state.get("source_id"))
    suite = _source_id(state.get("suite_id"))
    if source != suite:
        raise UnifiedAuditIntegrityError("stored source suite binding is invalid")
    for key in ("registered", "revoked", "complete", "truncated", "retention_complete"):
        if not isinstance(state.get(key), bool):
            raise UnifiedAuditIntegrityError(f"stored {key} flag is invalid")
    for key, minimum, maximum in (
        ("authority_revision", 0, 2**31 - 1),
        ("source_schema_version", 0, 2**31 - 1),
        ("pending_authority_revision", 0, 2**31 - 1),
        ("pending_source_schema_version", 0, 2**31 - 1),
        ("pending_trust_root_revision", 0, 2**31 - 1),
        ("cursor_sequence", 0, 2**63 - 1),
        ("trust_root_revision", 0, 2**31 - 1),
        ("snapshot_record_count", 0, 2**63 - 1),
        ("success_generation", 0, 2**63 - 1),
        ("attempts", 0, 20),
        ("revision", 1, 2**63 - 1),
    ):
        try:
            _integer(state.get(key), key, minimum, maximum)
        except UnifiedAuditValidationError as exc:
            raise UnifiedAuditIntegrityError(str(exc)) from exc
    for key in (
        "authority_sha256",
        "pending_authority_sha256",
        "pending_verifier_identity_sha256",
        "pending_source_key_id_sha256",
        "source_head_sha256",
        "previous_page_sha256",
        "lease_owner_sha256",
        "verifier_identity_sha256",
        "source_key_id_sha256",
        "source_anchor_sha256",
        "snapshot_head_sha256",
        "verification_sha256",
        "sink_identity_sha256",
        "sink_key_id_sha256",
        "projection_receipt_sha256",
    ):
        try:
            _digest(state.get(key), key)
        except UnifiedAuditValidationError as exc:
            raise UnifiedAuditIntegrityError(str(exc)) from exc
    for key in (
        "watermark",
        "last_success_at",
        "last_attempt_at",
        "next_attempt_at",
        "lease_until",
    ):
        try:
            _timestamp(state.get(key), key, allow_zero=True)
        except UnifiedAuditValidationError as exc:
            raise UnifiedAuditIntegrityError(str(exc)) from exc
    try:
        _state_limitation_codes(tuple(state.get("limitations") or ()))
    except UnifiedAuditValidationError as exc:
        raise UnifiedAuditIntegrityError(str(exc)) from exc
    error = state.get("error_code")
    if error and (
        not isinstance(error, str)
        or _TOKEN.fullmatch(error) is None
        or error not in STATE_LIMITATION_CODES
    ):
        raise UnifiedAuditIntegrityError("stored source error code is invalid")
    if state.get("assurance_level") not in ASSURANCE_LEVELS:
        raise UnifiedAuditIntegrityError("stored source assurance level is invalid")
    if state["registered"] and state["authority_revision"] < 1:
        raise UnifiedAuditIntegrityError("registered source has no authority")
    if state["complete"] and (
        state["revoked"] or state["truncated"] or state["limitations"] or state["error_code"]
    ):
        raise UnifiedAuditIntegrityError("stored source completeness is contradictory")
    if state["complete"] and (
        state["assurance_level"] != "signed_anchored"
        or not state["retention_complete"]
        or state["verification_sha256"] == GENESIS_SHA256
        or state["projection_receipt_sha256"] == GENESIS_SHA256
    ):
        raise UnifiedAuditIntegrityError("stored source completeness lacks trusted evidence")
    return dict(state)


class UnifiedAuditStore:
    """SQLite cursor/lease authority with digest-protected state and immutable history."""

    def __init__(
        self,
        path: Path | str,
        *,
        tenant_id: str,
        clock: Callable[[], float] = time.time,
        existing_only: bool = False,
    ) -> None:
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        self.tenant_sha256 = _tenant_sha256(self.tenant_id)
        if not callable(clock):
            raise UnifiedAuditConfigError("unified-audit clock is unavailable")
        self._clock = clock
        if existing_only and not self.path.is_file():
            raise UnifiedAuditConfigError("unified-audit authority does not exist")
        try:
            ensure_private_directory(self.path.parent)
            if not self.path.exists():
                if existing_only:
                    raise UnifiedAuditConfigError("unified-audit authority does not exist")
                self.path.touch(mode=0o600)
            ensure_private_file(self.path, 0o600)
            self._initialize(existing_only=existing_only)
        except UnifiedAuditError:
            raise
        except (OSError, sqlite3.DatabaseError) as exc:
            raise UnifiedAuditConfigError("unified-audit authority is unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self, *, existing_only: bool) -> None:
        with self._connect() as connection:
            if existing_only:
                present = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='unified_meta'"
                ).fetchone()
                if present is None:
                    raise UnifiedAuditConfigError("unified-audit authority is uninitialized")
            connection.executescript(
                """
                    CREATE TABLE IF NOT EXISTS unified_meta(
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS unified_source_state(
                        source_id TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        integrity_sha256 TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS unified_history(
                        sequence INTEGER PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        previous_sha256 TEXT NOT NULL,
                        integrity_sha256 TEXT NOT NULL
                    );
                    CREATE TRIGGER IF NOT EXISTS unified_history_no_update
                    BEFORE UPDATE ON unified_history
                    BEGIN SELECT RAISE(ABORT,'unified audit history is immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS unified_history_no_delete
                    BEFORE DELETE ON unified_history
                    BEGIN SELECT RAISE(ABORT,'unified audit history is immutable'); END;
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            try:
                metadata = dict(connection.execute("SELECT key,value FROM unified_meta"))
                expected = {
                    "schema_version": str(SCHEMA_VERSION),
                    "tenant_sha256": self.tenant_sha256,
                    "history_event_count": "0",
                    "history_tip_sha256": GENESIS_SHA256,
                    "sweep_generation": "0",
                }
                if metadata and metadata != expected:
                    raise UnifiedAuditIntegrityError("unified-audit authority metadata is invalid")
                if not metadata:
                    connection.executemany(
                        "INSERT INTO unified_meta(key,value) VALUES(?,?)",
                        tuple(expected.items()),
                    )
                now = _clock_value(self._clock)
                for source_id in REQUIRED_SUITES:
                    state = _initial_state(source_id, now)
                    encoded = _canonical(state).decode("ascii")
                    digest = self._state_digest(state)
                    connection.execute(
                        "INSERT OR IGNORE INTO unified_source_state VALUES(?,?,?)",
                        (source_id, encoded, digest),
                    )
                rows = connection.execute(
                    "SELECT source_id FROM unified_source_state ORDER BY source_id"
                ).fetchall()
                if tuple(str(row["source_id"]) for row in rows) != tuple(sorted(REQUIRED_SUITES)):
                    raise UnifiedAuditIntegrityError("unified-audit source registry is invalid")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _state_digest(self, state: Mapping[str, Any]) -> str:
        return canonical_sha256(
            {
                "schema": "lightwork.unified-audit-state-envelope.v1",
                "tenant_sha256": self.tenant_sha256,
                "state": state,
            }
        )

    def _read_state_on(self, connection: sqlite3.Connection, source_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT payload_json,integrity_sha256 FROM unified_source_state WHERE source_id=?",
            (source_id,),
        ).fetchone()
        if row is None:
            raise UnifiedAuditIntegrityError("required source state is missing")
        payload = _loads(str(row["payload_json"]), "source state")
        state = _validate_state(payload if isinstance(payload, Mapping) else {})
        expected = self._state_digest(state)
        if not hmac.compare_digest(expected, str(row["integrity_sha256"])):
            raise UnifiedAuditIntegrityError("stored source state digest is invalid")
        return state

    def _write_state_on(
        self,
        connection: sqlite3.Connection,
        previous: Mapping[str, Any],
        current: Mapping[str, Any],
    ) -> dict[str, Any]:
        validated = _validate_state(current)
        previous_digest = self._state_digest(previous)
        current_digest = self._state_digest(validated)
        cursor = connection.execute(
            "UPDATE unified_source_state SET payload_json=?,integrity_sha256=? "
            "WHERE source_id=? AND integrity_sha256=?",
            (
                _canonical(validated).decode("ascii"),
                current_digest,
                validated["source_id"],
                previous_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise UnifiedAuditConflict("unified-audit source state changed")
        return validated

    def _append_history_on(
        self,
        connection: sqlite3.Connection,
        *,
        source_id: str,
        action: str,
        state: Mapping[str, Any],
        detail_sha256: str,
        now: float,
    ) -> None:
        row = connection.execute(
            "SELECT sequence,integrity_sha256 FROM unified_history ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if row is None else int(row["sequence"]) + 1
        previous = GENESIS_SHA256 if row is None else str(row["integrity_sha256"])
        metadata = dict(
            connection.execute(
                "SELECT key,value FROM unified_meta "
                "WHERE key IN ('history_event_count','history_tip_sha256')"
            )
        )
        if metadata != {
            "history_event_count": str(sequence - 1),
            "history_tip_sha256": previous,
        }:
            raise UnifiedAuditIntegrityError(
                "unified-audit history anchor does not match the append position"
            )
        payload = {
            "schema": _HISTORY_SCHEMA,
            "sequence": sequence,
            "source_id": source_id,
            "action": _token(action, "history action"),
            "state_revision": int(state["revision"]),
            "cursor_sequence": int(state["cursor_sequence"]),
            "state_sha256": self._state_digest(state),
            "detail_sha256": _digest(detail_sha256, "detail_sha256"),
            "occurred_at": now,
            "previous_sha256": previous,
        }
        digest = canonical_sha256(
            {
                "schema": "lightwork.unified-audit-history-envelope.v1",
                "tenant_sha256": self.tenant_sha256,
                "payload": payload,
            }
        )
        connection.execute(
            "INSERT INTO unified_history VALUES(?,?,?,?)",
            (sequence, _canonical(payload).decode("ascii"), previous, digest),
        )
        connection.execute(
            "UPDATE unified_meta SET value=? WHERE key='history_event_count'",
            (str(sequence),),
        )
        connection.execute(
            "UPDATE unified_meta SET value=? WHERE key='history_tip_sha256'",
            (digest,),
        )

    def bind_source(self, authority: SourceAuthority) -> dict[str, Any]:
        if authority.tenant_id != self.tenant_id:
            raise UnifiedAuditConfigError("source authority tenant does not match store")
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, authority.source_id)
                if state["revoked"]:
                    raise UnifiedAuditConflict("unified-audit source is revoked")
                current = dict(state)
                if not state["registered"]:
                    current.update(
                        registered=True,
                        authority_revision=authority.authority_revision,
                        authority_sha256=authority.authority_sha256,
                        source_schema_version=authority.source_schema_version,
                        limitations=["source_not_reconciled"],
                        error_code="",
                    )
                    action = "source_bound"
                elif (
                    state["authority_revision"] == authority.authority_revision
                    and hmac.compare_digest(state["authority_sha256"], authority.authority_sha256)
                    and state["source_schema_version"] == authority.source_schema_version
                ):
                    connection.execute("COMMIT")
                    return state
                elif (
                    state["pending_authority_revision"] == authority.authority_revision
                    and hmac.compare_digest(
                        state["pending_authority_sha256"], authority.authority_sha256
                    )
                    and state["pending_source_schema_version"] == authority.source_schema_version
                    and authority.authority_revision > state["authority_revision"]
                ):
                    current.update(
                        authority_revision=authority.authority_revision,
                        authority_sha256=authority.authority_sha256,
                        source_schema_version=authority.source_schema_version,
                        pending_authority_revision=0,
                        pending_authority_sha256=GENESIS_SHA256,
                        pending_source_schema_version=0,
                        complete=False,
                        limitations=["authority_rotated_pending_reconciliation"],
                        assurance_level="self_asserted",
                        retention_complete=False,
                        verification_sha256=GENESIS_SHA256,
                        projection_receipt_sha256=GENESIS_SHA256,
                        success_generation=0,
                    )
                    action = "authority_rotated"
                else:
                    raise UnifiedAuditConflict("source authority changed without authorization")
                current["revision"] += 1
                current["updated_at"] = now
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=authority.source_id,
                    action=action,
                    state=saved,
                    detail_sha256=authority.authority_sha256,
                    now=now,
                )
                connection.execute("COMMIT")
                return saved
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def authorize_rotation(
        self,
        source_id: str,
        *,
        expected_state_revision: int,
        expected_authority_revision: int,
        expected_authority_sha256: str,
        new_authority_revision: int,
        new_authority_sha256: str,
        new_source_schema_version: int,
        new_verifier_identity_sha256: str,
        new_trust_root_revision: int,
        new_source_key_id_sha256: str,
        reason_sha256: str,
    ) -> dict[str, Any]:
        source = _source_id(source_id)
        expected_state = _integer(expected_state_revision, "expected_state_revision", 1, 2**63 - 1)
        expected_revision = _integer(
            expected_authority_revision, "expected_authority_revision", 1, 2**31 - 1
        )
        new_revision = _integer(new_authority_revision, "new_authority_revision", 1, 2**31 - 1)
        new_schema = _integer(new_source_schema_version, "new_source_schema_version", 1, 2**31 - 1)
        new_verifier = _digest(new_verifier_identity_sha256, "new_verifier_identity_sha256")
        new_trust_root = _integer(new_trust_root_revision, "new_trust_root_revision", 1, 2**31 - 1)
        new_source_key = _digest(new_source_key_id_sha256, "new_source_key_id_sha256")
        expected_digest = _digest(expected_authority_sha256, "expected_authority_sha256")
        new_digest = _digest(new_authority_sha256, "new_authority_sha256")
        reason = _digest(reason_sha256, "reason_sha256")
        if new_revision <= expected_revision or hmac.compare_digest(new_digest, expected_digest):
            raise UnifiedAuditValidationError("authority rotation must advance revision and key")
        if new_verifier == GENESIS_SHA256 or new_source_key == GENESIS_SHA256:
            raise UnifiedAuditValidationError(
                "authority rotation requires a pinned verifier and source key"
            )
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, source)
                if (
                    state["revision"] != expected_state
                    or state["authority_revision"] != expected_revision
                    or not hmac.compare_digest(state["authority_sha256"], expected_digest)
                    or not state["registered"]
                    or state["revoked"]
                ):
                    raise UnifiedAuditConflict("source rotation authority changed")
                current = dict(state)
                current.update(
                    pending_authority_revision=new_revision,
                    pending_authority_sha256=new_digest,
                    pending_source_schema_version=new_schema,
                    pending_verifier_identity_sha256=new_verifier,
                    pending_trust_root_revision=new_trust_root,
                    pending_source_key_id_sha256=new_source_key,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=source,
                    action="rotation_authorized",
                    state=saved,
                    detail_sha256=canonical_sha256(
                        {
                            "new_authority_sha256": new_digest,
                            "new_source_schema_version": new_schema,
                            "new_verifier_identity_sha256": new_verifier,
                            "new_trust_root_revision": new_trust_root,
                            "new_source_key_id_sha256": new_source_key,
                            "reason_sha256": reason,
                        }
                    ),
                    now=now,
                )
                connection.execute("COMMIT")
                return saved
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def revoke_source(
        self,
        source_id: str,
        *,
        expected_state_revision: int,
        reason_sha256: str,
    ) -> dict[str, Any]:
        source = _source_id(source_id)
        expected = _integer(expected_state_revision, "expected_state_revision", 1, 2**63 - 1)
        reason = _digest(reason_sha256, "reason_sha256")
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, source)
                if state["revision"] != expected:
                    raise UnifiedAuditConflict("source state revision changed")
                current = dict(state)
                current.update(
                    revoked=True,
                    complete=False,
                    limitations=["source_revoked"],
                    error_code="source_revoked",
                    success_generation=0,
                    lease_owner_sha256=GENESIS_SHA256,
                    lease_until=0.0,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=source,
                    action="source_revoked",
                    state=saved,
                    detail_sha256=reason,
                    now=now,
                )
                connection.execute("COMMIT")
                return saved
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def begin_sweep(self) -> int:
        """Start one fixed-six reconciliation generation."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT value FROM unified_meta WHERE key='sweep_generation'"
                ).fetchone()
                if row is None:
                    raise UnifiedAuditIntegrityError("sweep generation metadata is missing")
                current = _integer(int(row["value"]), "sweep_generation", 0, 2**63 - 2)
                generation = current + 1
                connection.execute(
                    "UPDATE unified_meta SET value=? WHERE key='sweep_generation'",
                    (str(generation),),
                )
                connection.execute("COMMIT")
                return generation
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def mark_unavailable(
        self,
        source_id: str,
        *,
        error_code: str,
        sweep_generation: int,
    ) -> dict[str, Any]:
        """Persist a pre-claim or registry failure so stale green state is lost."""

        source = _source_id(source_id)
        code = _token(error_code, "error_code")
        if code not in STATE_LIMITATION_CODES:
            raise UnifiedAuditValidationError("error_code is outside the closed vocabulary")
        _integer(sweep_generation, "sweep_generation", 1, 2**63 - 1)
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, source)
                if state["lease_until"] > now and state["lease_owner_sha256"] != GENESIS_SHA256:
                    raise UnifiedAuditLeaseLost(
                        "unified-audit source has an active reconciliation lease"
                    )
                current = dict(state)
                current.update(
                    complete=False,
                    limitations=[code],
                    error_code=code,
                    success_generation=0,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=source,
                    action="source_unavailable",
                    state=saved,
                    detail_sha256=canonical_sha256(
                        {"error_code": code, "sweep_generation": sweep_generation}
                    ),
                    now=now,
                )
                connection.execute("COMMIT")
                return saved
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def claim(
        self,
        source_id: str,
        *,
        worker_id: str,
        lease_seconds: int,
        max_attempts: int,
    ) -> ProjectionClaim:
        source = _source_id(source_id)
        lease = _integer(lease_seconds, "lease_seconds", 30, 86_400)
        attempts = _integer(max_attempts, "max_attempts", 1, 20)
        worker = _worker_sha256(self.tenant_sha256, worker_id)
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, source)
                if not state["registered"]:
                    raise UnifiedAuditNotFound("unified-audit source is not registered")
                if state["revoked"]:
                    raise UnifiedAuditConflict("unified-audit source is revoked")
                if state["attempts"] >= attempts:
                    raise UnifiedAuditConflict("unified-audit source retry limit is exhausted")
                if state["next_attempt_at"] > now:
                    raise UnifiedAuditConflict("unified-audit source retry is not due")
                if state["lease_until"] > now:
                    raise UnifiedAuditLeaseLost("unified-audit source is already leased")
                reclaimed = (
                    state["lease_until"] > 0 and state["lease_owner_sha256"] != GENESIS_SHA256
                )
                reclaimed_attempts = state["attempts"] + (1 if reclaimed else 0)
                if reclaimed and reclaimed_attempts >= attempts:
                    current = dict(state)
                    current.update(
                        complete=False,
                        limitations=["source_retry_exhausted"],
                        error_code="source_retry_exhausted",
                        attempts=reclaimed_attempts,
                        success_generation=0,
                        lease_owner_sha256=GENESIS_SHA256,
                        lease_until=0.0,
                        revision=state["revision"] + 1,
                        updated_at=now,
                    )
                    saved = self._write_state_on(connection, state, current)
                    self._append_history_on(
                        connection,
                        source_id=source,
                        action="lease_retry_exhausted",
                        state=saved,
                        detail_sha256=worker,
                        now=now,
                    )
                    connection.execute("COMMIT")
                    raise UnifiedAuditConflict("unified-audit source retry limit is exhausted")
                current = dict(state)
                current.update(
                    attempts=reclaimed_attempts,
                    lease_owner_sha256=worker,
                    lease_until=now + lease,
                    last_attempt_at=now,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=source,
                    action="lease_reclaimed" if reclaimed else "source_claimed",
                    state=saved,
                    detail_sha256=worker,
                    now=now,
                )
                connection.execute("COMMIT")
                return ProjectionClaim(
                    source_id=source,
                    state_revision=int(saved["revision"]),
                    cursor_sequence=int(saved["cursor_sequence"]),
                    source_head_sha256=str(saved["source_head_sha256"]),
                    previous_page_sha256=str(saved["previous_page_sha256"]),
                    worker_sha256=worker,
                    lease_until=float(saved["lease_until"]),
                )
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def renew_claim(
        self,
        claim: ProjectionClaim,
        *,
        lease_seconds: int,
    ) -> ProjectionClaim:
        """Renew an active lease and return the replacement CAS claim."""

        lease = _integer(lease_seconds, "lease_seconds", 30, 86_400)
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, claim.source_id)
                if (
                    state["revision"] != claim.state_revision
                    or not hmac.compare_digest(state["lease_owner_sha256"], claim.worker_sha256)
                    or state["lease_until"] <= now
                ):
                    raise UnifiedAuditLeaseLost("unified-audit source lease cannot be renewed")
                current = dict(state)
                current.update(
                    lease_until=now + lease,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=claim.source_id,
                    action="source_lease_renewed",
                    state=saved,
                    detail_sha256=claim.worker_sha256,
                    now=now,
                )
                connection.execute("COMMIT")
                return ProjectionClaim(
                    source_id=claim.source_id,
                    state_revision=int(saved["revision"]),
                    cursor_sequence=claim.cursor_sequence,
                    source_head_sha256=claim.source_head_sha256,
                    previous_page_sha256=claim.previous_page_sha256,
                    worker_sha256=claim.worker_sha256,
                    lease_until=float(saved["lease_until"]),
                )
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def finish_page(
        self,
        claim: ProjectionClaim,
        page: SourcePage,
        *,
        projected: int,
        verification: SourceVerification,
        receipt: ProjectionReceipt,
        sweep_generation: int,
    ) -> dict[str, Any]:
        if claim.source_id != page.source_id:
            raise UnifiedAuditValidationError("claim and source page do not match")
        count = _integer(projected, "projected", 0, 500)
        if count != page.record_count:
            raise UnifiedAuditConflict("not every source record was appended")
        generation = _integer(sweep_generation, "sweep_generation", 1, 2**63 - 1)
        if not isinstance(verification, SourceVerification):
            raise UnifiedAuditValidationError("source verification is invalid")
        if not isinstance(receipt, ProjectionReceipt):
            raise UnifiedAuditValidationError("signed projection receipt is invalid")
        if (
            verification.tenant_id != page.tenant_id
            or verification.source_id != page.source_id
            or verification.authority_revision != page.authority_revision
            or verification.source_schema_version != page.source_schema_version
            or not hmac.compare_digest(verification.authority_sha256, page.authority_sha256)
            or not hmac.compare_digest(verification.page_sha256, page.page_sha256)
            or verification.snapshot_record_count < page.last_sequence
            or (
                page.terminal
                and (
                    verification.snapshot_record_count != page.last_sequence
                    or not hmac.compare_digest(verification.snapshot_head_sha256, page.head_sha256)
                )
            )
        ):
            raise UnifiedAuditIntegrityError(
                "source verification does not bind the committed snapshot"
            )
        trusted_complete = bool(
            page.complete
            and verification.assurance_level == "signed_anchored"
            and verification.retention_complete
            and not verification.limitations
        )
        stored_limitations = list(page.limitations)
        if page.complete and not trusted_complete:
            stored_limitations = ["source_integrity_unverified"]
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, claim.source_id)
                if (
                    state["revision"] != claim.state_revision
                    or not hmac.compare_digest(state["lease_owner_sha256"], claim.worker_sha256)
                    or state["lease_until"] <= now
                    or state["cursor_sequence"] != claim.cursor_sequence
                    or not hmac.compare_digest(
                        state["source_head_sha256"], claim.source_head_sha256
                    )
                    or not hmac.compare_digest(
                        state["previous_page_sha256"], claim.previous_page_sha256
                    )
                ):
                    raise UnifiedAuditLeaseLost("unified-audit source lease or cursor changed")
                if (
                    page.authority_revision != state["authority_revision"]
                    or not hmac.compare_digest(page.authority_sha256, state["authority_sha256"])
                    or page.source_schema_version != state["source_schema_version"]
                ):
                    raise UnifiedAuditConflict("source authority changed before cursor commit")
                if state["pending_verifier_identity_sha256"] != GENESIS_SHA256:
                    if (
                        not hmac.compare_digest(
                            verification.verifier_identity_sha256,
                            state["pending_verifier_identity_sha256"],
                        )
                        or verification.trust_root_revision != state["pending_trust_root_revision"]
                        or not hmac.compare_digest(
                            verification.key_id_sha256,
                            state["pending_source_key_id_sha256"],
                        )
                    ):
                        raise UnifiedAuditConflict(
                            "source verifier or trust root changed without authorization"
                        )
                elif state["verifier_identity_sha256"] != GENESIS_SHA256 and (
                    not hmac.compare_digest(
                        verification.verifier_identity_sha256,
                        state["verifier_identity_sha256"],
                    )
                    or verification.trust_root_revision != state["trust_root_revision"]
                    or not hmac.compare_digest(
                        verification.key_id_sha256,
                        state["source_key_id_sha256"],
                    )
                ):
                    raise UnifiedAuditConflict(
                        "source verifier or trust root changed without authorization"
                    )
                current = dict(state)
                current.update(
                    cursor_sequence=page.last_sequence,
                    source_head_sha256=page.head_sha256,
                    previous_page_sha256=page.page_sha256,
                    complete=trusted_complete,
                    truncated=page.truncated,
                    limitations=stored_limitations,
                    watermark=float(page.watermark),
                    last_success_at=now,
                    error_code="",
                    assurance_level=verification.assurance_level,
                    verifier_identity_sha256=verification.verifier_identity_sha256,
                    trust_root_revision=verification.trust_root_revision,
                    source_key_id_sha256=verification.key_id_sha256,
                    source_anchor_sha256=verification.anchor_sha256,
                    snapshot_head_sha256=verification.snapshot_head_sha256,
                    snapshot_record_count=verification.snapshot_record_count,
                    retention_complete=verification.retention_complete,
                    verification_sha256=verification.verification_sha256,
                    sink_identity_sha256=receipt.sink_identity_sha256,
                    sink_key_id_sha256=receipt.key_id_sha256,
                    projection_receipt_sha256=receipt.receipt_sha256,
                    success_generation=generation,
                    pending_verifier_identity_sha256=GENESIS_SHA256,
                    pending_trust_root_revision=0,
                    pending_source_key_id_sha256=GENESIS_SHA256,
                    attempts=0,
                    next_attempt_at=0.0,
                    lease_owner_sha256=GENESIS_SHA256,
                    lease_until=0.0,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=claim.source_id,
                    action="page_committed",
                    state=saved,
                    detail_sha256=page.page_sha256,
                    now=now,
                )
                connection.execute("COMMIT")
                return saved
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def fail_claim(
        self,
        claim: ProjectionClaim,
        *,
        error_code: str,
        retry_backoff_seconds: int,
    ) -> dict[str, Any]:
        code = _token(error_code, "error_code")
        if code not in STATE_LIMITATION_CODES:
            raise UnifiedAuditValidationError("error_code is outside the closed vocabulary")
        backoff = _integer(retry_backoff_seconds, "retry_backoff_seconds", 0, 86_400)
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, claim.source_id)
                if (
                    state["revision"] != claim.state_revision
                    or not hmac.compare_digest(state["lease_owner_sha256"], claim.worker_sha256)
                    or state["lease_until"] <= now
                ):
                    raise UnifiedAuditLeaseLost("unified-audit source failure lease changed")
                current = dict(state)
                current.update(
                    complete=False,
                    limitations=[code],
                    error_code=code,
                    attempts=state["attempts"] + 1,
                    next_attempt_at=now + backoff,
                    lease_owner_sha256=GENESIS_SHA256,
                    lease_until=0.0,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=claim.source_id,
                    action="source_failed",
                    state=saved,
                    detail_sha256=canonical_sha256({"error_code": code}),
                    now=now,
                )
                connection.execute("COMMIT")
                return saved
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def replay_source(
        self,
        source_id: str,
        *,
        expected_state_revision: int,
        reason_sha256: str,
    ) -> dict[str, Any]:
        source = _source_id(source_id)
        expected = _integer(expected_state_revision, "expected_state_revision", 1, 2**63 - 1)
        reason = _digest(reason_sha256, "reason_sha256")
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._read_state_on(connection, source)
                if state["revision"] != expected or state["revoked"]:
                    raise UnifiedAuditConflict("source replay authority changed")
                current = dict(state)
                current.update(
                    attempts=0,
                    next_attempt_at=0.0,
                    error_code="",
                    complete=False,
                    limitations=["operator_replay_pending"],
                    success_generation=0,
                    revision=state["revision"] + 1,
                    updated_at=now,
                )
                saved = self._write_state_on(connection, state, current)
                self._append_history_on(
                    connection,
                    source_id=source,
                    action="source_replayed",
                    state=saved,
                    detail_sha256=reason,
                    now=now,
                )
                connection.execute("COMMIT")
                return saved
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def source_states(self) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            return tuple(
                self._read_state_on(connection, source_id) for source_id in REQUIRED_SUITES
            )

    def status(self, *, max_lag_seconds: int) -> dict[str, Any]:
        max_lag = _integer(max_lag_seconds, "max_lag_seconds", 1, 31_536_000)
        integrity, source_states = self._verified_snapshot()
        sweep_generation = int(integrity["sweep_generation"])
        now = float(integrity["snapshot_at"])
        sources: list[dict[str, Any]] = []
        for state in source_states:
            lag = (
                None
                if state["watermark"] <= 0 or state["watermark"] > now + _MAX_FUTURE_SKEW_SECONDS
                else max(0.0, now - state["watermark"])
            )
            current = bool(
                state["registered"]
                and not state["revoked"]
                and state["complete"]
                and not state["truncated"]
                and not state["limitations"]
                and not state["error_code"]
                and lag is not None
                and lag <= max_lag
                and state["assurance_level"] == "signed_anchored"
                and state["retention_complete"]
                and state["success_generation"] == sweep_generation
                and state["verification_sha256"] != GENESIS_SHA256
                and state["projection_receipt_sha256"] != GENESIS_SHA256
            )
            sources.append(
                {
                    "source_id": state["source_id"],
                    "suite_id": state["suite_id"],
                    "registered": state["registered"],
                    "revoked": state["revoked"],
                    "cursor_sequence": state["cursor_sequence"],
                    "authority_revision": state["authority_revision"],
                    "authority_sha256": state["authority_sha256"],
                    "source_schema_version": state["source_schema_version"],
                    "complete": state["complete"],
                    "truncated": state["truncated"],
                    "limitations": list(state["limitations"]),
                    "error_code": state["error_code"],
                    "attempts": state["attempts"],
                    "watermark": state["watermark"],
                    "lag_seconds": lag,
                    "current": current,
                    "revision": state["revision"],
                    "assurance_level": state["assurance_level"],
                    "verifier_identity_sha256": state["verifier_identity_sha256"],
                    "trust_root_revision": state["trust_root_revision"],
                    "source_key_id_sha256": state["source_key_id_sha256"],
                    "source_anchor_sha256": state["source_anchor_sha256"],
                    "snapshot_head_sha256": state["snapshot_head_sha256"],
                    "snapshot_record_count": state["snapshot_record_count"],
                    "retention_complete": state["retention_complete"],
                    "verification_sha256": state["verification_sha256"],
                    "sink_identity_sha256": state["sink_identity_sha256"],
                    "sink_key_id_sha256": state["sink_key_id_sha256"],
                    "projection_receipt_sha256": state["projection_receipt_sha256"],
                    "success_generation": state["success_generation"],
                }
            )
        coverage = canonical_sha256(
            {
                "schema": _STATUS_SCHEMA,
                "tenant_sha256": self.tenant_sha256,
                "sources": sources,
                "max_lag_seconds": max_lag,
                "sweep_generation": sweep_generation,
            }
        )
        return {
            "schema": _STATUS_SCHEMA,
            "tenant_sha256": self.tenant_sha256,
            "required_sources": list(REQUIRED_SUITES),
            "sources": sources,
            "complete": all(item["current"] for item in sources),
            "coverage_sha256": coverage,
            "sweep_generation": sweep_generation,
            "checked_at": now,
            "limits": {
                "raw_source_payloads_persisted": False,
                "raw_actor_or_resource_ids_persisted": False,
                "domain_systems_of_record_replaced": False,
                "live_provider_completeness_inferred": False,
                "unkeyed_source_hashes_treated_as_verified": False,
                "local_sqlite_is_external_worm_anchor": False,
                "deterministic_hashes_are_anonymization": False,
                "cross_day_anchor_and_deletion_verified_here": False,
                "offhost_signing_key_custody_verified_here": False,
                "live_scale_or_recovery_accepted": False,
            },
        }

    def list_history(self, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        bounded = _integer(limit, "limit", 1, _MAX_HISTORY_LIMIT)
        self.verify_integrity()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM unified_history ORDER BY sequence DESC LIMIT ?",
                (bounded,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            payload = _loads(str(row["payload_json"]), "history event")
            if not isinstance(payload, Mapping):
                raise UnifiedAuditIntegrityError("stored history event is invalid")
            result.append({**dict(payload), "integrity_sha256": str(row["integrity_sha256"])})
        return tuple(result)

    def _verified_snapshot(self) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
        with self._connect() as connection:
            # Pin state, metadata, and history to one SQLite read snapshot.  A
            # valid writer commit between separate connections must not look
            # like an integrity break to a concurrent status request.
            connection.execute("BEGIN")
            try:
                states = tuple(
                    self._read_state_on(connection, source_id) for source_id in REQUIRED_SUITES
                )
                metadata = dict(connection.execute("SELECT key,value FROM unified_meta"))
                if (
                    set(metadata)
                    != {
                        "schema_version",
                        "tenant_sha256",
                        "history_event_count",
                        "history_tip_sha256",
                        "sweep_generation",
                    }
                    or metadata["schema_version"] != str(SCHEMA_VERSION)
                    or not hmac.compare_digest(metadata["tenant_sha256"], self.tenant_sha256)
                ):
                    raise UnifiedAuditIntegrityError("unified-audit metadata changed")
                try:
                    history_count = _integer(
                        int(metadata["history_event_count"]),
                        "history_event_count",
                        0,
                        2**63 - 1,
                    )
                    sweep_generation = _integer(
                        int(metadata["sweep_generation"]),
                        "sweep_generation",
                        0,
                        2**63 - 1,
                    )
                    history_tip = _digest(metadata["history_tip_sha256"], "history_tip_sha256")
                except (TypeError, ValueError, UnifiedAuditValidationError) as exc:
                    raise UnifiedAuditIntegrityError(
                        "unified-audit metadata counters are invalid"
                    ) from exc
                rows = connection.execute(
                    "SELECT * FROM unified_history ORDER BY sequence"
                ).fetchall()
                snapshot_at = _clock_value(self._clock)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        previous = GENESIS_SHA256
        expected_sequence = 1
        latest_by_source: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            if int(row["sequence"]) != expected_sequence or not hmac.compare_digest(
                str(row["previous_sha256"]), previous
            ):
                raise UnifiedAuditIntegrityError("unified-audit history is discontinuous")
            payload = _loads(str(row["payload_json"]), "history event")
            if (
                not isinstance(payload, Mapping)
                or payload.get("sequence") != expected_sequence
                or payload.get("source_id") not in REQUIRED_SUITES
            ):
                raise UnifiedAuditIntegrityError("unified-audit history payload is invalid")
            expected = canonical_sha256(
                {
                    "schema": "lightwork.unified-audit-history-envelope.v1",
                    "tenant_sha256": self.tenant_sha256,
                    "payload": payload,
                }
            )
            if not hmac.compare_digest(expected, str(row["integrity_sha256"])):
                raise UnifiedAuditIntegrityError("unified-audit history digest is invalid")
            previous = expected
            latest_by_source[str(payload["source_id"])] = payload
            expected_sequence += 1
        if history_count != len(rows) or not hmac.compare_digest(history_tip, previous):
            raise UnifiedAuditIntegrityError("unified-audit history anchor changed")
        for state in states:
            latest = latest_by_source.get(str(state["source_id"]))
            if state["revision"] == 1 and latest is None:
                continue
            if (
                latest is None
                or latest.get("state_revision") != state["revision"]
                or latest.get("cursor_sequence") != state["cursor_sequence"]
                or not hmac.compare_digest(
                    str(latest.get("state_sha256", "")), self._state_digest(state)
                )
            ):
                raise UnifiedAuditIntegrityError(
                    "unified-audit current state is not linked to history"
                )
        report = {
            "schema": "lightwork.unified-audit-integrity.v1",
            "tenant_sha256": self.tenant_sha256,
            "source_states": len(states),
            "history_events": len(rows),
            "terminal_history_sha256": previous,
            "sweep_generation": sweep_generation,
            "snapshot_at": snapshot_at,
            "anchor_scope": "local_sqlite_consistency_only",
            "valid": True,
        }
        return report, states

    def verify_integrity(self) -> dict[str, Any]:
        report, _states = self._verified_snapshot()
        return report


def _projection_record_event(
    tenant_sha256: str,
    authority: SourceAuthority,
    record: SourceRecord,
) -> dict[str, Any]:
    event_id = canonical_sha256(
        {
            "schema": _PROJECTION_SCHEMA,
            "tenant_sha256": tenant_sha256,
            "source_id": authority.source_id,
            "authority_revision": authority.authority_revision,
            "authority_sha256": authority.authority_sha256,
            "source_schema_version": authority.source_schema_version,
            "source_sequence": record.sequence,
            "source_record_sha256": record.record_sha256,
        }
    )
    return {
        "projection_event_id": event_id,
        "projection_schema": _PROJECTION_SCHEMA,
        "projection_type": "source_record",
        "tenant_sha256": tenant_sha256,
        "source_id": authority.source_id,
        "suite_id": authority.suite_id,
        "source_schema_version": authority.source_schema_version,
        "source_authority_revision": authority.authority_revision,
        "source_authority_sha256": authority.authority_sha256,
        "source_sequence": record.sequence,
        "source_occurred_at": record.occurred_at,
        "source_action": record.action,
        "source_actor_sha256": record.actor_sha256,
        "source_resource_sha256": record.resource_sha256,
        "source_payload_sha256": record.payload_sha256,
        "source_previous_sha256": record.previous_sha256,
        "source_record_sha256": record.record_sha256,
        "raw_source_payload_persisted": False,
    }


def _projection_page_event(
    tenant_sha256: str,
    authority: SourceAuthority,
    page: SourcePage,
    verification: SourceVerification,
) -> dict[str, Any]:
    event_id = canonical_sha256(
        {
            "schema": _PROJECTION_SCHEMA,
            "projection_type": "source_page_receipt",
            "tenant_sha256": tenant_sha256,
            "source_id": authority.source_id,
            "authority_revision": authority.authority_revision,
            "authority_sha256": authority.authority_sha256,
            "source_schema_version": authority.source_schema_version,
            "source_page_sha256": page.page_sha256,
            "verification_sha256": verification.verification_sha256,
        }
    )
    return {
        "projection_event_id": event_id,
        "projection_schema": _PROJECTION_SCHEMA,
        "projection_type": "source_page_receipt",
        "tenant_sha256": tenant_sha256,
        "source_id": authority.source_id,
        "suite_id": authority.suite_id,
        "source_schema_version": authority.source_schema_version,
        "source_authority_revision": authority.authority_revision,
        "source_authority_sha256": authority.authority_sha256,
        "source_sequence": page.last_sequence,
        "source_page_sha256": page.page_sha256,
        "source_head_sha256": page.head_sha256,
        "source_record_count": page.record_count,
        "source_terminal": page.terminal,
        "source_complete": page.complete,
        "source_truncated": page.truncated,
        "source_watermark": page.watermark,
        "source_limitations": list(page.limitations),
        "source_assurance_level": verification.assurance_level,
        "source_verifier_identity_sha256": verification.verifier_identity_sha256,
        "source_trust_root_revision": verification.trust_root_revision,
        "source_key_id_sha256": verification.key_id_sha256,
        "source_anchor_sha256": verification.anchor_sha256,
        "source_snapshot_head_sha256": verification.snapshot_head_sha256,
        "source_snapshot_record_count": verification.snapshot_record_count,
        "source_retention_complete": verification.retention_complete,
        "source_verification_sha256": verification.verification_sha256,
        "raw_source_payload_persisted": False,
    }


def _authority_equal(left: SourceAuthority, right: SourceAuthority) -> bool:
    return (
        left.tenant_id == right.tenant_id
        and left.source_id == right.source_id
        and left.suite_id == right.suite_id
        and left.authority_revision == right.authority_revision
        and left.source_schema_version == right.source_schema_version
        and hmac.compare_digest(left.authority_sha256, right.authority_sha256)
    )


def _error_code(error: BaseException) -> str:
    if isinstance(error, UnifiedAuditIntegrityError):
        return "source_integrity_failed"
    if isinstance(error, UnifiedAuditLeaseLost):
        return "source_lease_lost"
    if isinstance(error, UnifiedAuditConflict):
        return "source_conflict"
    if isinstance(error, UnifiedAuditValidationError):
        return "source_contract_invalid"
    if isinstance(error, UnifiedAuditConfigError):
        return "source_configuration_unavailable"
    return "source_dependency_unavailable"


class UnifiedAuditProjector:
    """One-page-per-source reconciler with append-before-cursor ordering."""

    def __init__(
        self,
        *,
        registry: UnifiedAuditRegistry,
        store: UnifiedAuditStore,
        sink: ProjectionSink,
        config: UnifiedAuditConfig,
    ) -> None:
        if not isinstance(registry, UnifiedAuditRegistry):
            raise UnifiedAuditConfigError("unified-audit registry is unavailable")
        if not isinstance(store, UnifiedAuditStore):
            raise UnifiedAuditConfigError("unified-audit store is unavailable")
        if registry.tenant_id != store.tenant_id:
            raise UnifiedAuditConfigError("unified-audit tenant authorities do not match")
        if not isinstance(sink, ProjectionSink):
            raise UnifiedAuditConfigError("unified-audit signed sink is unavailable")
        try:
            sink_tenant = _digest(sink.tenant_sha256, "sink tenant_sha256")
            sink_identity = _digest(sink.sink_identity_sha256, "sink_identity_sha256")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise UnifiedAuditConfigError(
                "unified-audit signed sink identity is unavailable"
            ) from exc
        if (
            not hmac.compare_digest(sink_tenant, store.tenant_sha256)
            or sink_identity == GENESIS_SHA256
        ):
            raise UnifiedAuditConfigError("unified-audit signed sink tenant binding does not match")
        if not isinstance(config, UnifiedAuditConfig) or not config.enable:
            raise UnifiedAuditConfigError("unified_audit_disabled")
        self.registry = registry
        self.store = store
        self.sink = sink
        self.config = config
        self._sink_identity_sha256 = sink_identity

    def _signing_ready(self) -> bool:
        try:
            value = self.sink.signing_ready
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise UnifiedAuditConfigError("unified-audit signed sink is unavailable") from exc
        if type(value) is not bool:
            raise UnifiedAuditConfigError("unified-audit signed sink readiness is invalid")
        return value

    def _append(self, event: Mapping[str, Any]) -> ProjectionReceipt:
        receipt = self.sink.append(event)
        if not isinstance(receipt, ProjectionReceipt):
            raise UnifiedAuditIntegrityError(
                "unified-audit signed sink returned no verifiable receipt"
            )
        receipt = ProjectionReceipt(**asdict(receipt))
        if (
            not hmac.compare_digest(
                receipt.projection_event_id,
                _digest(event.get("projection_event_id"), "projection_event_id"),
            )
            or not hmac.compare_digest(receipt.event_sha256, canonical_sha256(dict(event)))
            or not hmac.compare_digest(receipt.tenant_sha256, self.store.tenant_sha256)
            or not hmac.compare_digest(receipt.sink_identity_sha256, self._sink_identity_sha256)
        ):
            raise UnifiedAuditIntegrityError(
                "unified-audit signed sink receipt does not bind the exact event"
            )
        if not self._signing_ready():
            raise UnifiedAuditConfigError("unified-audit signed sink lost readiness")
        return receipt

    def _mark_preclaim_failure(
        self,
        source_id: str,
        error: BaseException,
        generation: int,
    ) -> None:
        try:
            self.store.mark_unavailable(
                source_id,
                error_code=_error_code(error),
                sweep_generation=generation,
            )
        except (UnifiedAuditConflict, UnifiedAuditLeaseLost):
            pass

    def run_source(
        self,
        source_id: str,
        *,
        worker_id: str,
        sweep_generation: int | None = None,
    ) -> ProjectionRunResult:
        source_name = _source_id(source_id)
        generation = (
            self.store.begin_sweep()
            if sweep_generation is None
            else _integer(sweep_generation, "sweep_generation", 1, 2**63 - 1)
        )
        try:
            source = self.registry.get(source_name)
            verifier = self.registry.verifier(source_name)
            authority = source.authority()
            if not isinstance(authority, SourceAuthority) or authority.source_id != source_name:
                raise UnifiedAuditConfigError("domain audit source authority is invalid")
            authority = SourceAuthority(**asdict(authority))
            if authority.tenant_id != self.store.tenant_id:
                raise UnifiedAuditConfigError("domain audit source tenant changed")
            self.store.bind_source(authority)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            self._mark_preclaim_failure(source_name, exc, generation)
            raise
        claim = self.store.claim(
            source_name,
            worker_id=worker_id,
            lease_seconds=self.config.lease_seconds,
            max_attempts=self.config.max_attempts,
        )
        try:
            page = source.read_page(
                after_sequence=claim.cursor_sequence,
                prior_sha256=claim.source_head_sha256,
                previous_page_sha256=claim.previous_page_sha256,
                limit=self.config.page_size,
            )
            if not isinstance(page, SourcePage):
                raise UnifiedAuditValidationError("domain audit source returned an invalid page")
            _validate_source_page(page)
            observed_at = _clock_value(self.store._clock)
            if (
                page.tenant_id != authority.tenant_id
                or page.source_id != authority.source_id
                or page.suite_id != authority.suite_id
                or page.authority_revision != authority.authority_revision
                or page.source_schema_version != authority.source_schema_version
                or not hmac.compare_digest(page.authority_sha256, authority.authority_sha256)
                or page.after_sequence != claim.cursor_sequence
                or not hmac.compare_digest(page.prior_sha256, claim.source_head_sha256)
                or not hmac.compare_digest(page.previous_page_sha256, claim.previous_page_sha256)
                or page.record_count > self.config.page_size
                or page.watermark > observed_at + _MAX_FUTURE_SKEW_SECONDS
            ):
                raise UnifiedAuditIntegrityError("source page authority or cursor is invalid")
            verification = verifier.verify_page(authority=authority, page=page)
            if not isinstance(verification, SourceVerification):
                raise UnifiedAuditValidationError("source verifier returned an invalid result")
            # Reconstruct the frozen value at the trust boundary so a hostile
            # verifier cannot mutate a dataclass instance after construction.
            verification = SourceVerification(**asdict(verification))
            if (
                not hmac.compare_digest(
                    verifier.verifier_identity_sha256,
                    verification.verifier_identity_sha256,
                )
                or verification.verified_at < page.watermark
                or verification.verified_at > observed_at + _MAX_FUTURE_SKEW_SECONDS
            ):
                raise UnifiedAuditIntegrityError(
                    "source verification timing or identity is invalid"
                )
            if not self._signing_ready():
                raise UnifiedAuditConfigError("unified-audit signed sink is not ready")
            appended = 0
            for record in page.records:
                event = _projection_record_event(self.store.tenant_sha256, authority, record)
                self._append(event)
                appended += 1
            page_event = _projection_page_event(
                self.store.tenant_sha256, authority, page, verification
            )
            page_receipt = self._append(page_event)
            current_authority = source.authority()
            if not isinstance(current_authority, SourceAuthority):
                raise UnifiedAuditConflict("source authority changed during reconciliation")
            current_authority = SourceAuthority(**asdict(current_authority))
            if not _authority_equal(authority, current_authority):
                raise UnifiedAuditConflict("source authority changed during reconciliation")
            state = self.store.finish_page(
                claim,
                page,
                projected=appended,
                verification=verification,
                receipt=page_receipt,
                sweep_generation=generation,
            )
            return ProjectionRunResult(
                source_id=source_name,
                outcome="committed",
                projected=appended,
                cursor_sequence=int(state["cursor_sequence"]),
                complete=bool(state["complete"]),
                page_sha256=page.page_sha256,
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            try:
                self.store.fail_claim(
                    claim,
                    error_code=_error_code(exc),
                    retry_backoff_seconds=self.config.retry_backoff_seconds,
                )
            except UnifiedAuditLeaseLost:
                pass
            raise

    def run_all(self, *, worker_id: str) -> tuple[ProjectionRunResult, ...]:
        results: list[ProjectionRunResult] = []
        generation = self.store.begin_sweep()
        available = set(self.registry.available_source_ids())
        verified = set(self.registry.verified_source_ids())
        for source_id in REQUIRED_SUITES:
            if source_id not in available or source_id not in verified:
                error_code = (
                    "source_not_registered"
                    if source_id not in available
                    else "source_configuration_unavailable"
                )
                try:
                    self.store.mark_unavailable(
                        source_id,
                        error_code=error_code,
                        sweep_generation=generation,
                    )
                except UnifiedAuditLeaseLost:
                    pass
                results.append(
                    ProjectionRunResult(
                        source_id=source_id,
                        outcome="unavailable",
                        projected=0,
                        cursor_sequence=0,
                        complete=False,
                        page_sha256=GENESIS_SHA256,
                        error_code=error_code,
                    )
                )
                continue
            try:
                results.append(
                    self.run_source(
                        source_id,
                        worker_id=worker_id,
                        sweep_generation=generation,
                    )
                )
            except Exception as exc:
                states = {state["source_id"]: state for state in self.store.source_states()}
                state = states[source_id]
                results.append(
                    ProjectionRunResult(
                        source_id=source_id,
                        outcome="failed",
                        projected=0,
                        cursor_sequence=int(state["cursor_sequence"]),
                        complete=False,
                        page_sha256=str(state["previous_page_sha256"]),
                        error_code=_error_code(exc),
                    )
                )
        return tuple(results)

    def status(self) -> dict[str, Any]:
        result = self.store.status(max_lag_seconds=self.config.max_lag_seconds)
        registered = set(self.registry.available_source_ids())
        verified = set(self.registry.verified_source_ids())
        try:
            sink_ready = self._signing_ready()
        except UnifiedAuditError:
            sink_ready = False
        for source in result["sources"]:
            runtime_available = source["source_id"] in registered
            verifier_available = source["source_id"] in verified
            source["runtime_available"] = runtime_available
            source["verifier_available"] = verifier_available
            source["current"] = bool(
                source["current"] and runtime_available and verifier_available and sink_ready
            )
        result["complete"] = all(source["current"] for source in result["sources"])
        result["registered_sources"] = sorted(registered)
        result["verified_sources"] = sorted(verified)
        result["sink_ready"] = sink_ready
        result["coverage_sha256"] = canonical_sha256(
            {
                "schema": _STATUS_SCHEMA,
                "tenant_sha256": self.store.tenant_sha256,
                "sources": result["sources"],
                "sweep_generation": result["sweep_generation"],
                "sink_ready": sink_ready,
            }
        )
        result["enabled"] = True
        return result


__all__ = [
    "build_source_page",
    "build_source_record",
    "canonical_sha256",
    "config_from",
    "DomainAuditSource",
    "enabled",
    "GENESIS_SHA256",
    "ProjectionClaim",
    "ProjectionReceipt",
    "ProjectionRunResult",
    "ProjectionSink",
    "REQUIRED_SUITES",
    "require_enabled",
    "SOURCE_SPECS",
    "SOURCE_ACTION_CODES",
    "SOURCE_LIMITATION_CODES",
    "SourceAuthority",
    "SourcePage",
    "SourceRecord",
    "SourceVerification",
    "SourceVerifier",
    "StrictAuditProjectionSink",
    "UnifiedAuditConfig",
    "UnifiedAuditConfigError",
    "UnifiedAuditConflict",
    "UnifiedAuditError",
    "UnifiedAuditIntegrityError",
    "UnifiedAuditLeaseLost",
    "UnifiedAuditNotFound",
    "UnifiedAuditProjector",
    "UnifiedAuditRegistry",
    "UnifiedAuditStore",
    "UnifiedAuditValidationError",
]
