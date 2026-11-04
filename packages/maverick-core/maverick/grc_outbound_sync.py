"""Tenant-bound semantic synchronization into external GRC systems.

The ordinary enterprise connector surface intentionally exposes broad REST
operations.  That is useful for interactive work, but it is not a safe
contract for durable governance writeback: a caller-selected table or path can
silently change the meaning of a record between retries.  This module instead
defines three typed Lightwork source records and two fixed semantic dialects.
Callers select only a supported target; the dialect owns the operation and
field mapping.

The transport seam is deliberately narrower than HTTP.  It receives a
credential-free :class:`OutboundRequest` containing a semantic operation, not
a URL or table name, and must return an echoed source binding plus the external
record identity.  A production transport can resolve credentials and vendor
endpoints outside this persistence boundary.

Delivery is at-least-once.  A crash after the remote side effect but before the
local receipt may repeat the call, so every source version has a deterministic
idempotency key and the transport contract requires that key to be honored.
CAS-governed state, receipts, and secret-free failure/conflict events make
recovery inspectable without persisting provider exception messages.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol
from urllib.parse import urlsplit

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

SYNC_STATE_SCHEMA = "lightwork.grc-outbound-sync-state.v1"
SYNC_EVENT_SCHEMA = "lightwork.grc-outbound-sync-event.v1"
OUTBOUND_REQUEST_SCHEMA = "lightwork.grc-outbound-request.v1"
OUTBOUND_RECEIPT_SCHEMA = "lightwork.grc-outbound-receipt.v1"

_SYNC_STATES = GovernedRecordStore(
    "grc_outbound_sync_states",
    "GOS",
    "grc_outbound_sync_state",
)
_SYNC_EVENTS = GovernedRecordStore(
    "grc_outbound_sync_events",
    "GOE",
    "grc_outbound_sync_event",
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")
_TOKEN_RE = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_EXTERNAL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_-])(?:authorization|credential|password|passwd|private[_-]?key|"
    r"api[_-]?key|client[_-]?secret|refresh[_-]?token|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_INCIDENT_STATES = frozenset({"open", "contained", "resolved", "dismissed"})
_ACCEPTANCE_STATES = frozenset({"accepted", "expired", "revoked"})
_MAX_HISTORY = 32
_MAX_RECORDS = 10_000
_MAX_LIST_LIMIT = 500


class GRCOutboundSyncError(RuntimeError):
    """Base error for governed GRC writeback."""


class GRCOutboundConfigError(GRCOutboundSyncError):
    """The core is disabled or a target has not been admitted."""


class GRCOutboundStateError(GRCOutboundSyncError):
    """Persisted state or a transport response violates the contract."""


class GRCOutboundConflict(GRCOutboundSyncError):
    """A source revision or external identity conflicts with durable state."""


class GRCOutboundDeliveryError(GRCOutboundSyncError):
    """A retry-safe failure was persisted for operator-visible recovery."""


class GRCTransportFailure(RuntimeError):
    """Safe transport classification; provider error text is never persisted."""

    def __init__(self, category: str = "transport_failure", *, retryable: bool = True):
        self.category = _token(category, "transport failure category")
        self.retryable = bool(retryable)
        super().__init__(self.category)


class GRCTransportConflict(GRCTransportFailure):
    """The remote record rejected the supplied source/external revision."""

    def __init__(self, category: str = "external_revision_conflict"):
        super().__init__(category, retryable=False)


class GRCSystem(str, Enum):
    """Supported semantic GRC targets."""

    SERVICENOW_IRM = "servicenow_irm"
    ARCHER = "archer"


class SourceKind(str, Enum):
    """Lightwork source records admitted for outbound synchronization."""

    FINDING = "finding"
    RISK_ACCEPTANCE = "risk_acceptance"
    AI_INCIDENT = "ai_incident"


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("GRC outbound value is not canonical JSON") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _stable_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{_sha256([str(part) for part in parts])[:32]}"


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not _ID_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _token(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip().lower()
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip().lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text


def _revision(value: object, label: str = "source_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a timestamp")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{label} must be a finite non-negative timestamp")
    return parsed


def _safe_text(value: object, label: str, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = re.sub(r"[\t\r\n]+", " ", value).strip()
    if required and not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit or _CONTROL_RE.search(text):
        raise ValueError(f"{label} is invalid")
    try:
        from .safety.secret_detector import redact

        safe, _matches = redact(text)
    except Exception as exc:
        raise GRCOutboundStateError("secret redaction is unavailable") from exc
    return safe


def _safe_actor(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("actor must be a string")
    text = re.sub(r"[\t\r\n]+", " ", value).strip()
    if not text or len(text) > 256 or _CONTROL_RE.search(text):
        raise ValueError("actor is invalid")
    try:
        from .safety.secret_detector import scan

        if scan(text):
            raise ValueError("actor contains secret material")
    except ValueError:
        raise
    except Exception as exc:
        raise GRCOutboundStateError("secret detection is unavailable") from exc
    return text


def _external_id(value: object, label: str = "external_id") -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not _EXTERNAL_ID_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _external_revision(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("external_revision must be a string")
    text = value.strip()
    if not text or len(text) > 256 or _CONTROL_RE.search(text):
        raise ValueError("external_revision is invalid")
    safe = _safe_text(text, "external_revision", 256)
    if safe != text:
        raise ValueError("external_revision contains secret material")
    return text


def _external_url(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("external_url must be a string")
    text = value.strip()
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("external_url must be a credential-free HTTPS record URL")
    safe = _safe_text(text, "external_url", 2_000)
    if safe != text:
        raise ValueError("external_url contains secret material")
    return text


def _safe_json(value: object, *, depth: int = 0) -> object:
    """Copy a bounded JSON value while rejecting credential-shaped keys."""

    if depth > 12:
        raise ValueError("GRC outbound projection exceeds the nesting limit")
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("GRC outbound projection contains a non-finite number")
        return value
    if isinstance(value, str):
        return _safe_text(value, "GRC outbound projection text", 8_000, required=False)
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise ValueError("GRC outbound projection has too many fields")
        out: dict[str, object] = {}
        for raw_key in sorted(value, key=str):
            key = str(raw_key)
            if not key or len(key) > 128 or _CONTROL_RE.search(key):
                raise ValueError("GRC outbound projection key is invalid")
            if _SENSITIVE_KEY_RE.search(key):
                raise ValueError("GRC outbound projection contains a sensitive field")
            out[key] = _safe_json(value[raw_key], depth=depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ValueError("GRC outbound projection list is too large")
        return [_safe_json(item, depth=depth + 1) for item in value]
    raise ValueError("GRC outbound projection contains a non-JSON value")


def _tenant_binding() -> tuple[str, str]:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise GRCOutboundStateError(
            "GRC outbound synchronization requires an explicit tenant authority"
        )
    return tenant, hashlib.sha256(tenant.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FindingSource:
    """One exact model-risk finding revision."""

    finding_id: str
    asset_id: str
    finding_type: str
    severity: str
    summary: str
    source_revision: int
    source_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", _identity(self.finding_id, "finding_id"))
        object.__setattr__(self, "asset_id", _identity(self.asset_id, "asset_id"))
        object.__setattr__(
            self, "finding_type", _token(self.finding_type, "finding_type")
        )
        object.__setattr__(self, "severity", _token(self.severity, "severity"))
        if self.severity not in _SEVERITIES:
            raise ValueError("finding severity is invalid")
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("finding summary is required")
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        object.__setattr__(
            self, "source_digest", _digest(self.source_digest, "source_digest")
        )

    @property
    def kind(self) -> SourceKind:
        return SourceKind.FINDING

    @property
    def source_id(self) -> str:
        return self.finding_id


@dataclass(frozen=True)
class RiskAcceptanceSource:
    """One exact, human-owned model-risk acceptance revision."""

    acceptance_id: str
    finding_id: str
    asset_id: str
    severity: str
    rationale: str
    reviewer: str
    decided_at: float
    expires_at: float
    status: str
    source_revision: int
    source_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "acceptance_id", _identity(self.acceptance_id, "acceptance_id")
        )
        object.__setattr__(self, "finding_id", _identity(self.finding_id, "finding_id"))
        object.__setattr__(self, "asset_id", _identity(self.asset_id, "asset_id"))
        object.__setattr__(self, "severity", _token(self.severity, "severity"))
        if self.severity not in _SEVERITIES:
            raise ValueError("risk acceptance severity is invalid")
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ValueError("risk acceptance rationale is required")
        if not isinstance(self.reviewer, str) or not self.reviewer.strip():
            raise ValueError("risk acceptance reviewer is required")
        decided = _timestamp(self.decided_at, "decided_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= decided:
            raise ValueError("risk acceptance expires_at must follow decided_at")
        object.__setattr__(self, "decided_at", decided)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(self, "status", _token(self.status, "status"))
        if self.status not in _ACCEPTANCE_STATES:
            raise ValueError("risk acceptance status is invalid")
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        object.__setattr__(
            self, "source_digest", _digest(self.source_digest, "source_digest")
        )

    @property
    def kind(self) -> SourceKind:
        return SourceKind.RISK_ACCEPTANCE

    @property
    def source_id(self) -> str:
        return self.acceptance_id


@dataclass(frozen=True)
class AIIncidentSource:
    """One exact governed model-risk incident revision."""

    incident_id: str
    asset_id: str
    incident_source_id: str
    severity: str
    summary: str
    status: str
    occurred_at: float
    resolution: str
    source_revision: int
    source_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "incident_id", _identity(self.incident_id, "incident_id"))
        object.__setattr__(self, "asset_id", _identity(self.asset_id, "asset_id"))
        object.__setattr__(
            self,
            "incident_source_id",
            _identity(self.incident_source_id, "incident_source_id"),
        )
        object.__setattr__(self, "severity", _token(self.severity, "severity"))
        if self.severity not in _SEVERITIES:
            raise ValueError("AI incident severity is invalid")
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("AI incident summary is required")
        object.__setattr__(self, "status", _token(self.status, "status"))
        if self.status not in _INCIDENT_STATES:
            raise ValueError("AI incident status is invalid")
        object.__setattr__(
            self, "occurred_at", _timestamp(self.occurred_at, "occurred_at")
        )
        if not isinstance(self.resolution, str):
            raise ValueError("AI incident resolution must be a string")
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        object.__setattr__(
            self, "source_digest", _digest(self.source_digest, "source_digest")
        )

    @property
    def kind(self) -> SourceKind:
        return SourceKind.AI_INCIDENT

    @property
    def source_id(self) -> str:
        return self.incident_id


GRCSource = FindingSource | RiskAcceptanceSource | AIIncidentSource


@dataclass(frozen=True)
class ExternalReference:
    """Previously acknowledged external record used for update semantics."""

    external_id: str
    external_revision: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "external_id", _external_id(self.external_id))
        object.__setattr__(
            self, "external_revision", _external_revision(self.external_revision)
        )


@dataclass(frozen=True)
class OutboundRequest:
    """Credential-free semantic request passed to an injected transport."""

    target: GRCSystem
    operation: str
    source_kind: SourceKind
    source_id: str
    source_revision: int
    source_digest: str
    tenant_sha256: str
    idempotency_key: str
    payload_sha256: str
    payload: Mapping[str, object]
    external_reference: ExternalReference | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, GRCSystem):
            raise TypeError("target must be a GRCSystem")
        if not isinstance(self.source_kind, SourceKind):
            raise TypeError("source_kind must be a SourceKind")
        object.__setattr__(self, "operation", _token(self.operation, "operation"))
        object.__setattr__(self, "source_id", _identity(self.source_id, "source_id"))
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        object.__setattr__(
            self, "source_digest", _digest(self.source_digest, "source_digest")
        )
        object.__setattr__(
            self, "tenant_sha256", _digest(self.tenant_sha256, "tenant_sha256")
        )
        object.__setattr__(
            self, "idempotency_key", _identity(self.idempotency_key, "idempotency_key")
        )
        object.__setattr__(
            self, "payload_sha256", _digest(self.payload_sha256, "payload_sha256")
        )
        safe_payload = _safe_json(self.payload)
        if not isinstance(safe_payload, dict):
            raise ValueError("GRC outbound payload must be an object")
        if _sha256(safe_payload) != self.payload_sha256:
            raise ValueError("GRC outbound payload digest does not match payload")
        object.__setattr__(self, "payload", safe_payload)
        if self.external_reference is not None and not isinstance(
            self.external_reference, ExternalReference
        ):
            raise TypeError("external_reference must be an ExternalReference")

    def safe_projection(self) -> dict[str, object]:
        """Return the exact secret-free payload eligible for persistence/send."""

        external = None
        if self.external_reference is not None:
            external = {
                "external_id": self.external_reference.external_id,
                "external_revision": self.external_reference.external_revision,
            }
        return {
            "schema": OUTBOUND_REQUEST_SCHEMA,
            "target": self.target.value,
            "operation": self.operation,
            "source_kind": self.source_kind.value,
            "source_id": self.source_id,
            "source_revision": self.source_revision,
            "source_digest": self.source_digest,
            "tenant_sha256": self.tenant_sha256,
            "idempotency_key": self.idempotency_key,
            "payload_sha256": self.payload_sha256,
            "payload": dict(self.payload),
            "external_reference": external,
        }


@dataclass(frozen=True)
class OutboundResponse:
    """Typed acknowledgement returned by a target-specific transport."""

    idempotency_key: str
    source_revision: int
    source_digest: str
    external_id: str
    external_url: str
    external_revision: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "idempotency_key", _identity(self.idempotency_key, "idempotency_key")
        )
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        object.__setattr__(
            self, "source_digest", _digest(self.source_digest, "source_digest")
        )
        object.__setattr__(self, "external_id", _external_id(self.external_id))
        object.__setattr__(self, "external_url", _external_url(self.external_url))
        object.__setattr__(
            self, "external_revision", _external_revision(self.external_revision)
        )


class OutboundTransport(Protocol):
    """Narrow vendor transport. Credentials and URLs stay behind this seam."""

    def send(self, request: OutboundRequest) -> OutboundResponse: ...


@dataclass(frozen=True)
class GRCOutboundPolicy:
    """Explicit default-off admission policy for the unwired core."""

    enabled: bool = False
    allowed_targets: frozenset[GRCSystem] = frozenset()
    max_attempts_per_revision: int = 8

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("GRC outbound enabled must be a boolean")
        if not isinstance(self.allowed_targets, frozenset) or any(
            not isinstance(target, GRCSystem) for target in self.allowed_targets
        ):
            raise ValueError("allowed_targets must be a frozenset of GRCSystem values")
        if (
            isinstance(self.max_attempts_per_revision, bool)
            or not isinstance(self.max_attempts_per_revision, int)
            or not 1 <= self.max_attempts_per_revision <= 100
        ):
            raise ValueError("max_attempts_per_revision must be between 1 and 100")

    def require(self, target: GRCSystem) -> None:
        if not self.enabled:
            raise GRCOutboundConfigError("GRC outbound synchronization is disabled")
        if target not in self.allowed_targets:
            raise GRCOutboundConfigError(
                f"GRC outbound target {target.value} is not admitted"
            )


def policy_from_config() -> GRCOutboundPolicy:
    """Load the tenant's strict, default-off semantic writeback policy."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            raise GRCOutboundConfigError("GRC outbound configuration is unreadable")
        config = load_config()
    except GRCOutboundConfigError:
        raise
    except Exception as exc:
        raise GRCOutboundConfigError(
            "GRC outbound configuration is unavailable"
        ) from exc
    if not isinstance(config, Mapping):
        raise GRCOutboundConfigError("configuration root must be a table")
    raw = config.get("grc_outbound_sync")
    if raw is None:
        return GRCOutboundPolicy()
    if not isinstance(raw, Mapping):
        raise GRCOutboundConfigError("grc_outbound_sync must be a table")
    gate = raw.get("enable", False)
    if not isinstance(gate, bool):
        raise GRCOutboundConfigError("grc_outbound_sync.enable must be boolean")
    targets = raw.get("targets", [])
    if not isinstance(targets, list) or len(targets) > len(GRCSystem):
        raise GRCOutboundConfigError(
            "grc_outbound_sync.targets must be a bounded list"
        )
    parsed: set[GRCSystem] = set()
    for value in targets:
        try:
            parsed.add(GRCSystem(value))
        except (TypeError, ValueError) as exc:
            raise GRCOutboundConfigError(
                "grc_outbound_sync.targets contains an unsupported target"
            ) from exc
    attempts = raw.get("max_attempts_per_revision", 8)
    try:
        return GRCOutboundPolicy(
            enabled=gate,
            allowed_targets=frozenset(parsed),
            max_attempts_per_revision=attempts,
        )
    except (TypeError, ValueError) as exc:
        raise GRCOutboundConfigError(
            "grc_outbound_sync policy is invalid"
        ) from exc


def enabled() -> bool:
    try:
        return policy_from_config().enabled
    except GRCOutboundConfigError:
        return False


def configured_sync() -> GRCOutboundSync:
    return GRCOutboundSync(policy=policy_from_config())


class _SemanticAdapter(Protocol):
    target: GRCSystem

    def operation(self, source: GRCSource) -> str: ...

    def payload(self, source: GRCSource, *, tenant_sha256: str) -> dict[str, object]: ...


_SERVICENOW_PRIORITY = {"low": "4", "medium": "3", "high": "2", "critical": "1"}
_ARCHER_RATING = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}


def _common_payload(source: GRCSource, tenant_sha256: str) -> dict[str, object]:
    return {
        "lightwork_source_kind": source.kind.value,
        "lightwork_source_id": source.source_id,
        "lightwork_source_revision": source.source_revision,
        "lightwork_source_digest": source.source_digest,
        "lightwork_tenant_sha256": tenant_sha256,
        "asset_id": source.asset_id,
    }


class ServiceNowIRMAdapter:
    """Fixed logical mapping for ServiceNow Integrated Risk Management."""

    target = GRCSystem.SERVICENOW_IRM

    def operation(self, source: GRCSource) -> str:
        return {
            SourceKind.FINDING: "servicenow_irm.upsert_issue",
            SourceKind.RISK_ACCEPTANCE: "servicenow_irm.upsert_risk_response",
            SourceKind.AI_INCIDENT: "servicenow_irm.upsert_risk_event",
        }[source.kind]

    def payload(self, source: GRCSource, *, tenant_sha256: str) -> dict[str, object]:
        body = _common_payload(source, tenant_sha256)
        body["source"] = "Lightwork"
        body["risk_rating"] = source.severity
        body["priority"] = _SERVICENOW_PRIORITY[source.severity]
        if isinstance(source, FindingSource):
            body.update({
                "short_description": _safe_text(source.summary, "summary", 4_000)[:160],
                "description": _safe_text(source.summary, "summary", 4_000),
                "finding_type": source.finding_type,
                "state": "open",
            })
        elif isinstance(source, RiskAcceptanceSource):
            body.update({
                "short_description": f"AI risk acceptance for {source.finding_id}",
                "description": _safe_text(source.rationale, "rationale", 4_000),
                "finding_id": source.finding_id,
                "reviewer": _safe_text(source.reviewer, "reviewer", 256),
                "decided_at": source.decided_at,
                "valid_to": source.expires_at,
                "state": source.status,
                "response_type": "accept",
            })
        else:
            body.update({
                "short_description": _safe_text(source.summary, "summary", 4_000)[:160],
                "description": _safe_text(source.summary, "summary", 4_000),
                "incident_source_id": source.incident_source_id,
                "state": source.status,
                "occurred_at": source.occurred_at,
                "close_notes": _safe_text(
                    source.resolution, "resolution", 4_000, required=False
                ),
            })
        return body


class ArcherAdapter:
    """Fixed logical mapping for an Archer-style GRC content transport."""

    target = GRCSystem.ARCHER

    def operation(self, source: GRCSource) -> str:
        return {
            SourceKind.FINDING: "archer.upsert_finding",
            SourceKind.RISK_ACCEPTANCE: "archer.upsert_risk_acceptance",
            SourceKind.AI_INCIDENT: "archer.upsert_ai_incident",
        }[source.kind]

    def payload(self, source: GRCSource, *, tenant_sha256: str) -> dict[str, object]:
        body = _common_payload(source, tenant_sha256)
        body["record_name"] = f"Lightwork {source.kind.value}: {source.source_id}"
        body["risk_rating"] = _ARCHER_RATING[source.severity]
        body["source_system"] = "Lightwork"
        if isinstance(source, FindingSource):
            body.update({
                "description": _safe_text(source.summary, "summary", 4_000),
                "finding_type": source.finding_type,
                "workflow_status": "Open",
            })
        elif isinstance(source, RiskAcceptanceSource):
            body.update({
                "description": _safe_text(source.rationale, "rationale", 4_000),
                "related_finding_id": source.finding_id,
                "approved_by": _safe_text(source.reviewer, "reviewer", 256),
                "decision_date": source.decided_at,
                "expiration_date": source.expires_at,
                "workflow_status": source.status.title(),
                "response_strategy": "Accept",
            })
        else:
            body.update({
                "description": _safe_text(source.summary, "summary", 4_000),
                "source_event_id": source.incident_source_id,
                "workflow_status": source.status.title(),
                "occurrence_date": source.occurred_at,
                "resolution_notes": _safe_text(
                    source.resolution, "resolution", 4_000, required=False
                ),
            })
        return body


_ADAPTERS: dict[GRCSystem, _SemanticAdapter] = {
    GRCSystem.SERVICENOW_IRM: ServiceNowIRMAdapter(),
    GRCSystem.ARCHER: ArcherAdapter(),
}


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in record.items()
        if key != "_audit_pending"
    }


def _source_snapshot(source: GRCSource) -> dict[str, object]:
    return {
        "kind": source.kind.value,
        "id": source.source_id,
        "revision": source.source_revision,
        "digest": source.source_digest,
    }


def _state_external_reference(state: Mapping[str, Any]) -> ExternalReference | None:
    external = state.get("external")
    if external is None:
        return None
    if not isinstance(external, Mapping):
        raise GRCOutboundStateError("GRC outbound external reference is malformed")
    try:
        return ExternalReference(
            external_id=external.get("id"),
            external_revision=external.get("revision"),
        )
    except (TypeError, ValueError) as exc:
        raise GRCOutboundStateError(
            "GRC outbound external reference is malformed"
        ) from exc


class GRCOutboundSync:
    """CAS-governed, retry-safe semantic GRC synchronization core."""

    def __init__(
        self,
        *,
        policy: GRCOutboundPolicy | None = None,
        state_store: GovernedRecordStore | None = None,
        event_store: GovernedRecordStore | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._policy = policy or GRCOutboundPolicy()
        self._states = state_store or _SYNC_STATES
        self._events = event_store or _SYNC_EVENTS
        self._clock = clock or time.time

    @staticmethod
    def _source(source: object) -> GRCSource:
        if not isinstance(source, (FindingSource, RiskAcceptanceSource, AIIncidentSource)):
            raise TypeError("source must be a typed GRC outbound source")
        return source

    @staticmethod
    def _target(target: object) -> GRCSystem:
        if not isinstance(target, GRCSystem):
            raise TypeError("target must be a GRCSystem")
        return target

    def _request(
        self,
        source: GRCSource,
        *,
        target: GRCSystem,
        tenant_sha256: str,
        external_reference: ExternalReference | None,
    ) -> OutboundRequest:
        adapter = _ADAPTERS[target]
        idempotency_key = _stable_id(
            "GRC",
            tenant_sha256,
            target.value,
            source.kind.value,
            source.source_id,
            source.source_revision,
            source.source_digest,
        )
        payload = adapter.payload(source, tenant_sha256=tenant_sha256)
        safe_payload = _safe_json(payload)
        if not isinstance(safe_payload, dict):
            raise GRCOutboundStateError("semantic GRC adapter returned no payload")
        return OutboundRequest(
            target=target,
            operation=adapter.operation(source),
            source_kind=source.kind,
            source_id=source.source_id,
            source_revision=source.source_revision,
            source_digest=source.source_digest,
            tenant_sha256=tenant_sha256,
            idempotency_key=idempotency_key,
            payload_sha256=_sha256(safe_payload),
            payload=safe_payload,
            external_reference=external_reference,
        )

    def preview(self, source: GRCSource, *, target: GRCSystem) -> dict[str, object]:
        """Build the persisted/sendable projection without causing a side effect."""

        item = self._source(source)
        system = self._target(target)
        self._policy.require(system)
        _tenant, tenant_sha256 = _tenant_binding()
        state = self._states.get(
            _stable_id("GOS", tenant_sha256, system.value, item.kind.value, item.source_id)
        )
        external = None if state is None else _state_external_reference(state)
        return self._request(
            item,
            target=system,
            tenant_sha256=tenant_sha256,
            external_reference=external,
        ).safe_projection()

    def _event(
        self,
        *,
        event_kind: str,
        reason: str,
        target: GRCSystem,
        tenant_sha256: str,
        source: GRCSource,
        actor: str,
        fingerprint: object,
        details: Mapping[str, object],
    ) -> dict[str, Any]:
        kind = _token(event_kind, "event_kind")
        code = _token(reason, "event reason")
        safe_details = _safe_json(details)
        if not isinstance(safe_details, dict):
            raise GRCOutboundStateError("GRC outbound event details are malformed")
        event_id = _stable_id(
            "GOE",
            tenant_sha256,
            target.value,
            source.kind.value,
            source.source_id,
            kind,
            code,
            fingerprint,
        )
        existing = self._events.get(event_id)
        if existing is not None:
            return _public(existing)
        body = {
            "id": event_id,
            "schema": SYNC_EVENT_SCHEMA,
            "tenant_sha256": tenant_sha256,
            "target": target.value,
            "event_kind": kind,
            "reason": code,
            "source": _source_snapshot(source),
            "details": safe_details,
            "observed_at": _timestamp(self._clock(), "clock"),
        }
        try:
            saved = self._events.create(
                body,
                action=f"grc_outbound_{kind}",
                actor=actor,
                max_records=_MAX_RECORDS,
            )
        except RecordConflict:
            saved = self._events.get(event_id)
            if saved is None:
                raise
        return _public(saved)

    def _record_source_conflict(
        self,
        *,
        state: Mapping[str, Any],
        source: GRCSource,
        target: GRCSystem,
        tenant_sha256: str,
        reason: str,
        actor: str,
        incoming_payload_sha256: str | None = None,
    ) -> None:
        stored = state.get("source")
        if not isinstance(stored, Mapping):
            raise GRCOutboundStateError("GRC outbound source binding is malformed")
        details: dict[str, object] = {
            "state_id": str(state.get("id") or ""),
            "stored_revision": int(stored.get("revision") or 0),
            "stored_digest": str(stored.get("digest") or ""),
            "incoming_revision": source.source_revision,
            "incoming_digest": source.source_digest,
            "stored_payload_sha256": str(state.get("payload_sha256") or ""),
        }
        if incoming_payload_sha256 is not None:
            details["incoming_payload_sha256"] = incoming_payload_sha256
        self._event(
            event_kind="conflict",
            reason=reason,
            target=target,
            tenant_sha256=tenant_sha256,
            source=source,
            actor=actor,
            fingerprint=details,
            details=details,
        )

    @staticmethod
    def _prior_version(state: Mapping[str, Any]) -> dict[str, object]:
        return {
            "source": dict(state.get("source") or {}),
            "idempotency_key": state.get("idempotency_key"),
            "payload_sha256": state.get("payload_sha256"),
            "status": state.get("status"),
            "attempts": state.get("attempts"),
            "external": state.get("external"),
            "receipt": state.get("receipt"),
            "failure": state.get("failure"),
        }

    def _admit(
        self,
        source: GRCSource,
        *,
        target: GRCSystem,
        tenant_sha256: str,
        actor: str,
    ) -> tuple[dict[str, Any], OutboundRequest]:
        state_id = _stable_id(
            "GOS", tenant_sha256, target.value, source.kind.value, source.source_id
        )
        for _ in range(12):
            current = self._states.get(state_id)
            external = None if current is None else _state_external_reference(current)
            request = self._request(
                source,
                target=target,
                tenant_sha256=tenant_sha256,
                external_reference=external,
            )
            if current is None:
                body = {
                    "id": state_id,
                    "schema": SYNC_STATE_SCHEMA,
                    "tenant_sha256": tenant_sha256,
                    "target": target.value,
                    "source": _source_snapshot(source),
                    "operation": request.operation,
                    "idempotency_key": request.idempotency_key,
                    "payload_sha256": request.payload_sha256,
                    "request": request.safe_projection(),
                    "status": "pending",
                    "attempts": 0,
                    "external": None,
                    "receipt": None,
                    "failure": None,
                    "history": [],
                    "queued_at": _timestamp(self._clock(), "clock"),
                }
                try:
                    saved = self._states.create(
                        body,
                        action="grc_outbound_queued",
                        actor=actor,
                        max_records=_MAX_RECORDS,
                    )
                    return _public(saved), request
                except RecordConflict:
                    continue

            if (
                current.get("schema") != SYNC_STATE_SCHEMA
                or current.get("tenant_sha256") != tenant_sha256
                or current.get("target") != target.value
            ):
                raise GRCOutboundStateError("GRC outbound state authority is malformed")
            stored = current.get("source")
            if not isinstance(stored, Mapping):
                raise GRCOutboundStateError("GRC outbound source binding is malformed")
            if stored.get("kind") != source.kind.value or stored.get("id") != source.source_id:
                raise GRCOutboundStateError("GRC outbound source identity is malformed")
            stored_revision = stored.get("revision")
            if isinstance(stored_revision, bool) or not isinstance(stored_revision, int):
                raise GRCOutboundStateError("GRC outbound source revision is malformed")
            stored_digest = str(stored.get("digest") or "")
            if source.source_revision < stored_revision:
                self._record_source_conflict(
                    state=current,
                    source=source,
                    target=target,
                    tenant_sha256=tenant_sha256,
                    reason="stale_source_revision",
                    actor=actor,
                )
                raise GRCOutboundConflict("source revision is older than outbound state")
            if source.source_revision == stored_revision:
                if source.source_digest != stored_digest:
                    self._record_source_conflict(
                        state=current,
                        source=source,
                        target=target,
                        tenant_sha256=tenant_sha256,
                        reason="source_revision_digest_mismatch",
                        actor=actor,
                    )
                    raise GRCOutboundConflict(
                        "source revision is already bound to another digest"
                    )
                if (
                    current.get("operation") != request.operation
                    or current.get("idempotency_key") != request.idempotency_key
                    or current.get("payload_sha256") != request.payload_sha256
                ):
                    self._record_source_conflict(
                        state=current,
                        source=source,
                        target=target,
                        tenant_sha256=tenant_sha256,
                        reason="adapter_contract_changed",
                        actor=actor,
                        incoming_payload_sha256=request.payload_sha256,
                    )
                    raise GRCOutboundConflict(
                        "semantic adapter changed without a source revision"
                    )
                return _public(current), request

            history = list(current.get("history") or [])
            if len(history) > _MAX_HISTORY:
                raise GRCOutboundStateError("GRC outbound history is malformed")
            history.append(self._prior_version(current))
            history = history[-_MAX_HISTORY:]
            expected = int(current.get("revision") or 0)

            queued_at = _timestamp(self._clock(), "clock")

            def advance(
                row: dict[str, Any],
                current_request: OutboundRequest = request,
                current_history: list[dict[str, object]] = history,
                current_queued_at: float = queued_at,
            ) -> None:
                row["source"] = _source_snapshot(source)
                row["operation"] = current_request.operation
                row["idempotency_key"] = current_request.idempotency_key
                row["payload_sha256"] = current_request.payload_sha256
                row["request"] = current_request.safe_projection()
                row["status"] = "pending"
                row["attempts"] = 0
                row["receipt"] = None
                row["failure"] = None
                row["history"] = current_history
                row["queued_at"] = current_queued_at

            try:
                saved = self._states.update(
                    state_id,
                    advance,
                    expected_revision=expected,
                    action="grc_outbound_revision_queued",
                    actor=actor,
                )
            except RecordConflict:
                continue
            if saved is None:
                continue
            return _public(saved), request
        raise GRCOutboundStateError("GRC outbound admission did not converge")

    @staticmethod
    def _response_contract(request: OutboundRequest, response: object) -> OutboundResponse:
        if not isinstance(response, OutboundResponse):
            raise GRCOutboundStateError("transport returned an untyped response")
        if (
            response.idempotency_key != request.idempotency_key
            or response.source_revision != request.source_revision
            or response.source_digest != request.source_digest
        ):
            raise GRCOutboundConflict("transport response source binding does not match")
        if (
            request.external_reference is not None
            and response.external_id != request.external_reference.external_id
        ):
            raise GRCOutboundConflict("transport changed the external record identity")
        return response

    def _commit_failure(
        self,
        *,
        state: Mapping[str, Any],
        request: OutboundRequest,
        source: GRCSource,
        target: GRCSystem,
        tenant_sha256: str,
        actor: str,
        error_type: str,
        category: str,
        retryable: bool,
        conflict: bool,
    ) -> dict[str, Any]:
        state_id = str(state.get("id") or "")
        current = self._states.get(state_id)
        if current is None:
            raise GRCOutboundStateError("GRC outbound state disappeared")
        if current.get("idempotency_key") != request.idempotency_key:
            return _public(current)
        if current.get("status") == "delivered":
            return _public(current)
        attempts = current.get("attempts")
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
            raise GRCOutboundStateError("GRC outbound attempts are malformed")
        observed_at = _timestamp(self._clock(), "clock")
        event_kind = "conflict" if conflict else "failure"
        safe_type = (
            error_type
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", error_type)
            else "TransportError"
        )
        safe_category = _token(category, "failure category")
        expected = int(current.get("revision") or 0)
        event_fingerprint = {
            "idempotency_key": request.idempotency_key,
            "attempt": attempts + 1,
            "category": safe_category,
            "error_type": safe_type,
        }
        event_id = _stable_id(
            "GOE",
            tenant_sha256,
            target.value,
            source.kind.value,
            source.source_id,
            event_kind,
            safe_category,
            event_fingerprint,
        )

        def mutate(row: dict[str, Any]) -> None:
            if row.get("idempotency_key") != request.idempotency_key:
                raise RecordConflict("GRC outbound source advanced during delivery")
            row["status"] = "conflict" if conflict else "failed"
            row["attempts"] = attempts + 1
            row["failure"] = {
                "event_id": event_id,
                "event_kind": event_kind,
                "category": safe_category,
                "error_type": safe_type,
                "retryable": bool(retryable),
                "failed_at": observed_at,
            }

        try:
            saved = self._states.update(
                state_id,
                mutate,
                expected_revision=expected,
                action=f"grc_outbound_{event_kind}",
                actor=actor,
            )
        except RecordConflict:
            recovered = self._states.get(state_id)
            if recovered is None:
                raise GRCOutboundStateError("GRC outbound state disappeared") from None
            if recovered.get("status") == "delivered":
                return _public(recovered)
            if recovered.get("idempotency_key") != request.idempotency_key:
                return _public(recovered)
            raise
        if saved is None:
            raise GRCOutboundStateError("GRC outbound state disappeared")
        self._event(
            event_kind=event_kind,
            reason=safe_category,
            target=target,
            tenant_sha256=tenant_sha256,
            source=source,
            actor=actor,
            fingerprint=event_fingerprint,
            details={
                "state_id": state_id,
                "idempotency_key": request.idempotency_key,
                "payload_sha256": request.payload_sha256,
                "attempt": attempts + 1,
                "error_type": safe_type,
                "retryable": bool(retryable),
            },
        )
        return _public(saved)

    def _commit_receipt(
        self,
        *,
        state: Mapping[str, Any],
        request: OutboundRequest,
        response: OutboundResponse,
        actor: str,
    ) -> dict[str, Any]:
        state_id = str(state.get("id") or "")
        for _ in range(8):
            current = self._states.get(state_id)
            if current is None:
                raise GRCOutboundStateError("GRC outbound state disappeared")
            if current.get("idempotency_key") != request.idempotency_key:
                raise GRCOutboundConflict(
                    "source advanced before the outbound receipt was committed"
                )
            if current.get("status") == "delivered":
                external = current.get("external") or {}
                if (
                    external.get("id") != response.external_id
                    or external.get("url") != response.external_url
                    or external.get("revision") != response.external_revision
                ):
                    raise GRCOutboundConflict(
                        "idempotent retry returned another external receipt"
                    )
                return _public(current)
            attempts = current.get("attempts")
            if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
                raise GRCOutboundStateError("GRC outbound attempts are malformed")
            delivered_at = _timestamp(self._clock(), "clock")
            receipt = {
                "schema": OUTBOUND_RECEIPT_SCHEMA,
                "receipt_id": _stable_id(
                    "GOR",
                    request.idempotency_key,
                    response.external_id,
                    response.external_revision,
                ),
                "target": request.target.value,
                "operation": request.operation,
                "source_kind": request.source_kind.value,
                "source_id": request.source_id,
                "source_revision": request.source_revision,
                "source_digest": request.source_digest,
                "idempotency_key": request.idempotency_key,
                "payload_sha256": request.payload_sha256,
                "external_id": response.external_id,
                "external_url": response.external_url,
                "external_revision": response.external_revision,
                "attempt": attempts + 1,
                "delivered_at": delivered_at,
            }
            expected = int(current.get("revision") or 0)

            attempt_number = attempts + 1

            def mutate(
                row: dict[str, Any],
                current_receipt: dict[str, object] = receipt,
                current_attempt: int = attempt_number,
            ) -> None:
                if row.get("idempotency_key") != request.idempotency_key:
                    raise RecordConflict("GRC outbound source advanced during delivery")
                row["status"] = "delivered"
                row["attempts"] = current_attempt
                row["external"] = {
                    "id": response.external_id,
                    "url": response.external_url,
                    "revision": response.external_revision,
                }
                row["receipt"] = current_receipt
                row["failure"] = None

            try:
                saved = self._states.update(
                    state_id,
                    mutate,
                    expected_revision=expected,
                    action="grc_outbound_delivered",
                    actor=actor,
                )
            except RecordConflict:
                continue
            if saved is not None:
                return _public(saved)
        raise GRCOutboundStateError("GRC outbound receipt commit did not converge")

    def sync(
        self,
        source: GRCSource,
        *,
        target: GRCSystem,
        transport: OutboundTransport,
        actor: str,
    ) -> dict[str, Any]:
        """Synchronize one exact source revision and return its durable state."""

        item = self._source(source)
        system = self._target(target)
        self._policy.require(system)
        operator = _safe_actor(actor)
        _tenant, tenant_sha256 = _tenant_binding()
        state, request = self._admit(
            item,
            target=system,
            tenant_sha256=tenant_sha256,
            actor=operator,
        )
        if state.get("status") == "delivered":
            return state
        failure = state.get("failure") or {}
        if state.get("status") == "conflict" or failure.get("retryable") is False:
            raise GRCOutboundConflict(
                "GRC outbound state requires operator resolution or a new source revision"
            )
        attempts = state.get("attempts")
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
            raise GRCOutboundStateError("GRC outbound attempts are malformed")
        if attempts >= self._policy.max_attempts_per_revision:
            raise GRCOutboundDeliveryError(
                "GRC outbound retry limit reached for this source revision"
            )
        if not hasattr(transport, "send") or not callable(transport.send):
            raise TypeError("transport must implement send(request)")

        try:
            raw_response = transport.send(request)
            response = self._response_contract(request, raw_response)
        except (KeyboardInterrupt, SystemExit):
            raise
        except GRCTransportConflict as exc:
            saved = self._commit_failure(
                state=state,
                request=request,
                source=item,
                target=system,
                tenant_sha256=tenant_sha256,
                actor=operator,
                error_type=type(exc).__name__,
                category=exc.category,
                retryable=False,
                conflict=True,
            )
            if saved.get("status") == "delivered":
                return saved
            raise GRCOutboundConflict("external GRC record rejected the update") from None
        except GRCTransportFailure as exc:
            saved = self._commit_failure(
                state=state,
                request=request,
                source=item,
                target=system,
                tenant_sha256=tenant_sha256,
                actor=operator,
                error_type=type(exc).__name__,
                category=exc.category,
                retryable=exc.retryable,
                conflict=False,
            )
            if saved.get("status") == "delivered":
                return saved
            raise GRCOutboundDeliveryError(
                "external GRC delivery failed; retry-safe state was recorded"
            ) from None
        except GRCOutboundConflict as exc:
            saved = self._commit_failure(
                state=state,
                request=request,
                source=item,
                target=system,
                tenant_sha256=tenant_sha256,
                actor=operator,
                error_type=type(exc).__name__,
                category="response_binding_conflict",
                retryable=False,
                conflict=True,
            )
            if saved.get("status") == "delivered":
                return saved
            raise GRCOutboundConflict("external GRC receipt conflicts with the request") from None
        except GRCOutboundStateError as exc:
            saved = self._commit_failure(
                state=state,
                request=request,
                source=item,
                target=system,
                tenant_sha256=tenant_sha256,
                actor=operator,
                error_type=type(exc).__name__,
                category="invalid_transport_response",
                retryable=False,
                conflict=False,
            )
            if saved.get("status") == "delivered":
                return saved
            raise GRCOutboundDeliveryError(
                "external GRC transport returned an invalid response"
            ) from None
        except Exception as exc:  # failure-policy: retryable, message never retained
            saved = self._commit_failure(
                state=state,
                request=request,
                source=item,
                target=system,
                tenant_sha256=tenant_sha256,
                actor=operator,
                error_type=type(exc).__name__,
                category="transport_exception",
                retryable=True,
                conflict=False,
            )
            if saved.get("status") == "delivered":
                return saved
            raise GRCOutboundDeliveryError(
                "external GRC delivery failed; retry-safe state was recorded"
            ) from None
        return self._commit_receipt(
            state=state,
            request=request,
            response=response,
            actor=operator,
        )

    def get_state(
        self,
        *,
        target: GRCSystem,
        source_kind: SourceKind,
        source_id: str,
    ) -> dict[str, Any] | None:
        """Return one tenant's durable safe state by semantic identity."""

        system = self._target(target)
        self._policy.require(system)
        if not isinstance(source_kind, SourceKind):
            raise TypeError("source_kind must be a SourceKind")
        identifier = _identity(source_id, "source_id")
        _tenant, tenant_sha256 = _tenant_binding()
        row = self._states.get(
            _stable_id("GOS", tenant_sha256, system.value, source_kind.value, identifier)
        )
        if row is None:
            return None
        if row.get("tenant_sha256") != tenant_sha256:
            raise GRCOutboundStateError("GRC outbound tenant binding failed")
        return _public(row)

    def list_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """List bounded failure/conflict records for the active tenant."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST_LIMIT}")
        _tenant, tenant_sha256 = _tenant_binding()
        rows = self._events.list(limit=limit)
        out: list[dict[str, Any]] = []
        for row in rows:
            if row.get("tenant_sha256") != tenant_sha256:
                raise GRCOutboundStateError("GRC outbound event tenant binding failed")
            out.append(_public(row))
        return sorted(out, key=lambda row: str(row.get("id") or ""))


__all__ = [
    "AIIncidentSource",
    "ArcherAdapter",
    "ExternalReference",
    "FindingSource",
    "GRCOutboundConfigError",
    "GRCOutboundConflict",
    "GRCOutboundDeliveryError",
    "GRCOutboundPolicy",
    "GRCOutboundStateError",
    "GRCOutboundSync",
    "GRCOutboundSyncError",
    "GRCSystem",
    "GRCTransportConflict",
    "GRCTransportFailure",
    "OutboundRequest",
    "OutboundResponse",
    "OutboundTransport",
    "RiskAcceptanceSource",
    "ServiceNowIRMAdapter",
    "SourceKind",
    "configured_sync",
    "enabled",
    "policy_from_config",
]
