"""Closed, read-only contracts for continuous technology-control evidence.

Collectors are deliberately injected.  This module does not resolve secrets,
make arbitrary network requests, accept provider URLs, or persist provider
payloads.  A collector returns bounded, normalized observations whose evidence
is represented only by SHA-256 digests and enumerated reason codes.

The built-in ``local_soc2_v1`` collector wraps Lightwork's local posture probe.
It is useful for exercising the governed runtime, but it is not a certification
or a live cloud-provider assessment.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Protocol

COLLECTOR_SCHEMA = "lightwork.trc-evidence-collector.v1"
PAGE_SCHEMA = "lightwork.trc-evidence-page.v1"

NETWORK_IO = False
RAW_PROVIDER_PAYLOAD_PERSISTED = False
COMPLIANCE_INFERRED = False
CERTIFICATION_ASSERTED = False

_ID_RE = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
_CONTROL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CURSOR_RE = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_STATUSES = frozenset({"observed", "failed", "unknown"})
_INCOMPLETE_REASONS = frozenset(
    {
        "access_denied",
        "collector_error",
        "coverage_unknown",
        "provider_truncated",
        "scope_unavailable",
        "source_unavailable",
        "timeout",
    }
)
_MAX_ITEMS_PER_PAGE = 250
_MAX_BYTES_PER_PAGE = 1024 * 1024


class EvidenceCollectorError(RuntimeError):
    """Base collector-boundary error."""


class EvidenceCollectorValidationError(EvidenceCollectorError, ValueError):
    """A request or normalized provider result is outside the closed contract."""


class EvidenceCollectorUnavailable(EvidenceCollectorError):
    """A configured collector is not installed in the trusted registry."""


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EvidenceCollectorValidationError(
            "collector value must be finite canonical JSON"
        ) from exc
    if len(encoded) > _MAX_BYTES_PER_PAGE:
        raise EvidenceCollectorValidationError("collector value exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise EvidenceCollectorValidationError(f"{label} is invalid")
    return value


def _control(value: object) -> str:
    if not isinstance(value, str) or not _CONTROL_RE.fullmatch(value):
        raise EvidenceCollectorValidationError("control_ref is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise EvidenceCollectorValidationError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise EvidenceCollectorValidationError(f"{label} is outside its bound")
    return value


@dataclass(frozen=True, slots=True)
class CollectionRequest:
    """Exact authority pinned before a collector performs read-only I/O."""

    tenant_sha256: str
    definition_id: str
    definition_version: int
    definition_integrity_sha256: str
    collector_id: str
    collector_schema_version: int
    collector_key_id: str
    capability_revision: int
    enrollment_id: str
    enrollment_revision: int
    enrollment_integrity_sha256: str
    asset_scope_sha256: str
    control_refs: tuple[str, ...]
    window_started_at: float
    window_ended_at: float
    credential_handle: object | None = None


@dataclass(frozen=True, slots=True)
class ControlEvidence:
    """One digest-only, non-conclusive technical control observation."""

    control_ref: str
    status: str
    reason_code: str
    evidence_sha256: str
    source_revision_sha256: str


@dataclass(frozen=True, slots=True)
class EvidencePage:
    """One normalized bounded provider page."""

    items: tuple[ControlEvidence, ...]
    next_cursor: str | None
    terminal: bool
    complete: bool
    incomplete_reason: str | None
    source_revision_sha256: str
    artifact_sha256: str
    bytes_read: int
    provider_request_sha256: str


class EvidenceCollector(Protocol):
    """Trusted, read-only adapter installed by deployment code."""

    collector_id: str

    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage: ...


def validate_request(request: CollectionRequest) -> CollectionRequest:
    if not isinstance(request, CollectionRequest):
        raise EvidenceCollectorValidationError("collection request has the wrong type")
    _digest(request.tenant_sha256, "tenant_sha256")
    _id(request.definition_id, "definition_id")
    _positive_int(request.definition_version, "definition_version", 2**31 - 1)
    if request.definition_version < 1:
        raise EvidenceCollectorValidationError("definition_version is outside its bound")
    _digest(request.definition_integrity_sha256, "definition_integrity_sha256")
    _id(request.collector_id, "collector_id")
    _positive_int(
        request.collector_schema_version,
        "collector_schema_version",
        2**31 - 1,
    )
    if request.collector_schema_version < 1:
        raise EvidenceCollectorValidationError("collector_schema_version is outside its bound")
    _id(request.collector_key_id, "collector_key_id")
    _positive_int(request.capability_revision, "capability_revision", 2**31 - 1)
    if request.capability_revision < 1:
        raise EvidenceCollectorValidationError("capability_revision is outside its bound")
    _id(request.enrollment_id, "enrollment_id")
    _positive_int(request.enrollment_revision, "enrollment_revision", 2**31 - 1)
    if request.enrollment_revision < 1:
        raise EvidenceCollectorValidationError("enrollment_revision is outside its bound")
    _digest(request.enrollment_integrity_sha256, "enrollment_integrity_sha256")
    _digest(request.asset_scope_sha256, "asset_scope_sha256")
    if not 1 <= len(request.control_refs) <= _MAX_ITEMS_PER_PAGE:
        raise EvidenceCollectorValidationError("control_refs is outside its bound")
    controls = tuple(_control(item) for item in request.control_refs)
    if len(set(controls)) != len(controls) or controls != tuple(sorted(controls)):
        raise EvidenceCollectorValidationError("control_refs must be unique and sorted")
    for value, label in (
        (request.window_started_at, "window_started_at"),
        (request.window_ended_at, "window_ended_at"),
    ):
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise EvidenceCollectorValidationError(f"{label} is invalid")
    if request.window_started_at > request.window_ended_at:
        raise EvidenceCollectorValidationError("collection window is reversed")
    return request


def validate_page(
    page: EvidencePage,
    *,
    expected_controls: tuple[str, ...],
) -> EvidencePage:
    """Validate untrusted adapter output before any value is persisted."""

    if not isinstance(page, EvidencePage):
        raise EvidenceCollectorValidationError("collector page has the wrong type")
    if not isinstance(page.terminal, bool) or not isinstance(page.complete, bool):
        raise EvidenceCollectorValidationError("collector completion flags are invalid")
    if page.complete and not page.terminal:
        raise EvidenceCollectorValidationError("a non-terminal page cannot be complete")
    if page.complete != (page.incomplete_reason is None):
        raise EvidenceCollectorValidationError("collector completeness and reason do not agree")
    if page.incomplete_reason is not None and page.incomplete_reason not in _INCOMPLETE_REASONS:
        raise EvidenceCollectorValidationError("incomplete_reason is invalid")
    if page.terminal and page.next_cursor is not None:
        raise EvidenceCollectorValidationError("terminal page cannot have a cursor")
    if not page.terminal:
        if not isinstance(page.next_cursor, str) or not _CURSOR_RE.fullmatch(page.next_cursor):
            raise EvidenceCollectorValidationError("next_cursor is invalid")
    if not isinstance(page.items, tuple) or len(page.items) > _MAX_ITEMS_PER_PAGE:
        raise EvidenceCollectorValidationError("collector items exceed their bound")

    allowed = set(expected_controls)
    seen: set[str] = set()
    for item in page.items:
        if not isinstance(item, ControlEvidence):
            raise EvidenceCollectorValidationError("collector item has the wrong type")
        control_ref = _control(item.control_ref)
        if control_ref not in allowed or control_ref in seen:
            raise EvidenceCollectorValidationError(
                "collector returned an unexpected or duplicate control"
            )
        seen.add(control_ref)
        if item.status not in _STATUSES:
            raise EvidenceCollectorValidationError("collector status is invalid")
        if not isinstance(item.reason_code, str) or not _REASON_RE.fullmatch(item.reason_code):
            raise EvidenceCollectorValidationError("collector reason_code is invalid")
        _digest(item.evidence_sha256, "evidence_sha256")
        _digest(item.source_revision_sha256, "source_revision_sha256")
    _digest(page.source_revision_sha256, "source_revision_sha256")
    _digest(page.artifact_sha256, "artifact_sha256")
    _digest(page.provider_request_sha256, "provider_request_sha256")
    _positive_int(page.bytes_read, "bytes_read", _MAX_BYTES_PER_PAGE)
    _canonical(
        {
            "schema": PAGE_SCHEMA,
            "items": [asdict(item) for item in page.items],
            "next_cursor": page.next_cursor,
            "terminal": page.terminal,
            "complete": page.complete,
            "incomplete_reason": page.incomplete_reason,
            "source_revision_sha256": page.source_revision_sha256,
            "artifact_sha256": page.artifact_sha256,
            "bytes_read": page.bytes_read,
            "provider_request_sha256": page.provider_request_sha256,
        }
    )
    return page


class CollectorRegistry:
    """Immutable registry of deployment-installed collector instances."""

    def __init__(self, collectors: Mapping[str, EvidenceCollector]) -> None:
        if not isinstance(collectors, Mapping) or not collectors:
            raise EvidenceCollectorValidationError("collector registry cannot be empty")
        normalized: dict[str, EvidenceCollector] = {}
        for key, collector in collectors.items():
            collector_id = _id(key, "collector_id")
            if getattr(collector, "collector_id", None) != collector_id:
                raise EvidenceCollectorValidationError(
                    "collector registry key does not match its adapter"
                )
            if not callable(getattr(collector, "fetch", None)):
                raise EvidenceCollectorValidationError("collector has no fetch method")
            normalized[collector_id] = collector
        self._collectors = normalized

    def resolve(self, collector_id: str) -> EvidenceCollector:
        candidate = self._collectors.get(_id(collector_id, "collector_id"))
        if candidate is None:
            raise EvidenceCollectorUnavailable("collector is not installed")
        return candidate

    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._collectors))


class LocalSoc2Collector:
    """Digest-only adapter for Lightwork's local SOC 2 posture probe."""

    collector_id = "local_soc2_v1"

    _LOCAL_CONTROLS = frozenset(
        {
            "audit_log",
            "audit_signing_key",
            "capability_enforcement",
            "data_subject_export",
            "encryption_at_rest",
            "oidc_auth",
            "tenant_isolation",
            "usage_quotas",
        }
    )

    @staticmethod
    def _observation(control_ref: str, value: object) -> ControlEvidence:
        safe_value = value if isinstance(value, Mapping) else {"status": "unknown"}
        raw_status = safe_value.get("status")
        if raw_status in {"enabled", "ok"}:
            status = "observed"
            reason = "technical_probe_observed"
        elif raw_status in {"absent", "broken", "disabled"}:
            status = "failed"
            reason = "technical_probe_failed"
        else:
            status = "unknown"
            reason = "technical_probe_unknown"
        evidence = {
            "schema": "lightwork.local-soc2-control-evidence.v1",
            "control_ref": control_ref,
            "status": raw_status if isinstance(raw_status, str) else "unknown",
            "enabled": safe_value.get("enabled")
            if isinstance(safe_value.get("enabled"), bool)
            else None,
        }
        source_revision = _sha256(
            {
                "schema": "lightwork.local-soc2-source-revision.v1",
                "collector_id": LocalSoc2Collector.collector_id,
                "control_ref": control_ref,
            }
        )
        return ControlEvidence(
            control_ref=control_ref,
            status=status,
            reason_code=reason,
            evidence_sha256=_sha256(evidence),
            source_revision_sha256=source_revision,
        )

    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage:
        validate_request(request)
        if request.collector_id != self.collector_id:
            raise EvidenceCollectorValidationError("collector request id is invalid")
        if cursor is not None:
            raise EvidenceCollectorValidationError("local collector is single-page")
        if not set(request.control_refs).issubset(self._LOCAL_CONTROLS):
            raise EvidenceCollectorValidationError(
                "local collector received an unsupported control"
            )

        from .soc2 import collect_soc2_evidence

        snapshot = collect_soc2_evidence()
        controls = snapshot.get("controls")
        controls = controls if isinstance(controls, Mapping) else {}
        values: dict[str, object] = dict(controls)
        values["audit_log"] = snapshot.get("audit_log")
        values["audit_signing_key"] = snapshot.get("audit_signing_key")
        items = tuple(
            self._observation(control_ref, values.get(control_ref))
            for control_ref in request.control_refs
        )
        source_revision = _sha256(
            {
                "schema": "lightwork.local-soc2-snapshot-revision.v1",
                "version": snapshot.get("version")
                if isinstance(snapshot.get("version"), str)
                else "unknown",
                "collector_id": self.collector_id,
            }
        )
        artifact = _sha256(
            {
                "schema": "lightwork.local-soc2-artifact.v1",
                "items": [
                    {
                        "control_ref": item.control_ref,
                        "status": item.status,
                        "reason_code": item.reason_code,
                        "evidence_sha256": item.evidence_sha256,
                    }
                    for item in items
                ],
            }
        )
        provider_request = _sha256(
            {
                "schema": "lightwork.local-soc2-request.v1",
                "enrollment_id": request.enrollment_id,
                "enrollment_revision": request.enrollment_revision,
                "asset_scope_sha256": request.asset_scope_sha256,
                "window_started_at": request.window_started_at,
                "window_ended_at": request.window_ended_at,
            }
        )
        return EvidencePage(
            items=items,
            next_cursor=None,
            terminal=True,
            complete=True,
            incomplete_reason=None,
            source_revision_sha256=source_revision,
            artifact_sha256=artifact,
            bytes_read=len(_canonical([asdict(item) for item in items])),
            provider_request_sha256=provider_request,
        )


__all__ = [
    "CERTIFICATION_ASSERTED",
    "COLLECTOR_SCHEMA",
    "COMPLIANCE_INFERRED",
    "CollectionRequest",
    "CollectorRegistry",
    "ControlEvidence",
    "EvidenceCollector",
    "EvidenceCollectorError",
    "EvidenceCollectorUnavailable",
    "EvidenceCollectorValidationError",
    "EvidencePage",
    "LocalSoc2Collector",
    "NETWORK_IO",
    "PAGE_SCHEMA",
    "RAW_PROVIDER_PAYLOAD_PERSISTED",
    "validate_page",
    "validate_request",
]
