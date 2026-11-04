"""Governed, deterministic executive PDF reports for third-party records.

The module deliberately owns only the report artifact and its immutable source
manifest.  A deployment composition must resolve live third-party records and
derive the tenant, principal and RBAC role; callers cannot author any of those
authorities.  PDF rendering uses a tiny deterministic PDF 1.4 writer rather
than an HTML renderer, so arbitrary markup, CSS, URLs and network fetches never
enter the reporting boundary. Optional brand-asset reference/digest fields are
provenance metadata only: this module does not resolve, fetch or embed logo
bytes.

Local integrity verification is not live portfolio, customer, or OneTrust
acceptance.  ``LIVE_PORTFOLIO_ACCEPTANCE_VERIFIED`` therefore remains false.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 3
REPORT_SCHEMA = "lightwork.third-party-executive-report.v1"
TOMBSTONE_SCHEMA = "lightwork.third-party-executive-report-tombstone.v1"
SNAPSHOT_SCHEMA = "lightwork.third-party-executive-report-snapshot.v1"
SOURCE_SCHEMA = "lightwork.third-party-executive-report-source.v1"
BRAND_SCHEMA = "lightwork.third-party-executive-report-brand.v1"
CONTROL_SCHEMA = "lightwork.third-party-executive-report-control.v1"
AUDIT_SCHEMA = "lightwork.third-party-executive-report-audit.v1"
GRANT_SCHEMA = "lightwork.third-party-executive-report-download-grant.v1"
OPERATION_SCHEMA = "lightwork.third-party-executive-report-operation.v1"
AUDIT_CHECKPOINT_SCHEMA = (
    "lightwork.third-party-executive-report-audit-checkpoint.v1"
)
LIVE_PORTFOLIO_ACCEPTANCE_VERIFIED = False

GENESIS_SHA256 = "0" * 64
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_COLOR_RE = re.compile(r"#[0-9A-Fa-f]{6}\Z")
_TOKEN_RE = re.compile(r"tpr_[A-Za-z0-9_-]{32,128}\Z")
_MAX_JSON_BYTES = 512 * 1024
_MAX_TOMBSTONE_BYTES = 4 * 1024
_MAX_TEXT = 180
_MAX_METRICS = 64
_MAX_AUDIT = 2_000
_GRANTS_PER_REPORT_CAPACITY = 4
_MAX_GRANT_CAPACITY = 100_000
_OPERATIONS_PER_REPORT_CAPACITY = 32
_MAX_OPERATION_CAPACITY = 250_000
_AUDIT_EVENTS_PER_REPORT_CAPACITY = 32

ROLE_VIEWS = frozenset({"admin", "operator", "auditor", "viewer"})
SOURCE_KINDS = frozenset(
    {
        "intelligence_vendor",
        "intelligence_finding",
        "lifecycle_assessment",
        "lifecycle_record",
        "contract_record",
        "collaboration_invitation",
    }
)
SOURCE_STATES = frozenset({"available", "empty", "unavailable"})
SOURCE_REASONS = frozenset(
    {
        "none",
        "not_selected",
        "not_found",
        "source_disabled",
        "source_not_configured",
        "source_unavailable",
    }
)
METRIC_IDS = frozenset(
    {
        "selected_record_count",
        "available_record_count",
        "unavailable_record_count",
        "active_vendor_count",
        "critical_vendor_count",
        "high_risk_vendor_count",
        "open_finding_count",
        "critical_finding_count",
        "active_lifecycle_count",
        "offboarding_lifecycle_count",
        "open_assessment_count",
        "high_risk_assessment_count",
        "contract_count",
        "active_contract_count",
        "engagement_count",
        "active_engagement_count",
        "open_collaboration_count",
        "completed_collaboration_count",
    }
)


class ThirdPartyExecutiveReportError(RuntimeError):
    """Base error carrying only a closed, non-sensitive code."""

    def __init__(self, error_code: str) -> None:
        if not isinstance(error_code, str) or re.fullmatch(
            r"[a-z][a-z0-9_]{0,95}", error_code
        ) is None:
            raise ValueError("executive report error code is invalid")
        self.error_code = error_code
        super().__init__(error_code)


class ThirdPartyExecutiveReportConfigError(ThirdPartyExecutiveReportError):
    """A deployment-owned authority or feature policy is unavailable."""


class ThirdPartyExecutiveReportValidationError(ThirdPartyExecutiveReportError, ValueError):
    """A value falls outside the closed report contract."""


class ThirdPartyExecutiveReportConflict(ThirdPartyExecutiveReportError):
    """An idempotency, CAS or state precondition changed."""


class ThirdPartyExecutiveReportNotFound(ThirdPartyExecutiveReportError):
    """A tenant-scoped report or grant is absent."""


class ThirdPartyExecutiveReportPermissionDenied(ThirdPartyExecutiveReportError):
    """The server-derived principal or role lacks authority."""


class ThirdPartyExecutiveReportIntegrityError(ThirdPartyExecutiveReportError):
    """Persisted report state cannot be trusted."""


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_material_invalid"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_material_oversized"
        )
    return encoded


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    if not isinstance(value, str):
        raise ThirdPartyExecutiveReportValidationError("executive_report_tenant_invalid")
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_tenant_invalid"
        ) from exc


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ThirdPartyExecutiveReportValidationError(f"executive_report_{label}_invalid")
    return value


def _digest(value: object, label: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ThirdPartyExecutiveReportValidationError(f"executive_report_{label}_invalid")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ThirdPartyExecutiveReportValidationError(f"executive_report_{label}_invalid")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ThirdPartyExecutiveReportValidationError(f"executive_report_{label}_invalid")
    selected = float(value)
    if not math.isfinite(selected) or not 0 < selected < 100_000_000_000.0:
        raise ThirdPartyExecutiveReportValidationError(f"executive_report_{label}_invalid")
    return selected


def _plain_text(value: object, label: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= maximum:
        raise ThirdPartyExecutiveReportValidationError(f"executive_report_{label}_invalid")
    if any(ord(character) < 32 for character in value) or any(
        marker in value for marker in ("<", ">", "{", "}", "://")
    ):
        raise ThirdPartyExecutiveReportValidationError(f"executive_report_{label}_invalid")
    return value


def _role(value: object) -> str:
    if not isinstance(value, str) or value not in ROLE_VIEWS:
        raise ThirdPartyExecutiveReportValidationError("executive_report_role_invalid")
    return value


def _idempotency_sha256(value: object) -> str:
    if not isinstance(value, str) or _OP_RE.fullmatch(value) is None:
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_idempotency_key_invalid"
        )
    return hashlib.sha256(
        ("lightwork.third-party-executive-report.idempotency.v1:" + value).encode()
    ).hexdigest()


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), "clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except ThirdPartyExecutiveReportError:
        raise
    except Exception as exc:
        raise ThirdPartyExecutiveReportConfigError(
            "executive_report_clock_unavailable"
        ) from exc


@dataclass(frozen=True, slots=True)
class ThirdPartyExecutiveReportConfig:
    enable: bool = False
    max_reports: int = 10_000
    max_sources: int = 100
    max_pdf_bytes: int = 512 * 1024
    retention_seconds: int = 365 * 24 * 60 * 60
    download_token_seconds: int = 300

    def __post_init__(self) -> None:
        if type(self.enable) is not bool:
            raise ThirdPartyExecutiveReportConfigError("executive_report_enable_invalid")
        try:
            _integer(self.max_reports, "max_reports", 1, 1_000_000)
            _integer(self.max_sources, "max_sources", 1, 500)
            _integer(self.max_pdf_bytes, "max_pdf_bytes", 16_384, 4 * 1024 * 1024)
            _integer(self.retention_seconds, "retention_seconds", 86_400, 315_360_000)
            _integer(self.download_token_seconds, "download_token_seconds", 30, 86_400)
        except ThirdPartyExecutiveReportValidationError as exc:
            raise ThirdPartyExecutiveReportConfigError(exc.error_code) from exc

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> ThirdPartyExecutiveReportConfig:
        if not isinstance(config, Mapping):
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_configuration_unavailable"
            )
        parent = config.get("third_party_management")
        if parent is None:
            return cls()
        if not isinstance(parent, Mapping):
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_configuration_invalid"
            )
        parent_enabled = parent.get("enable", False)
        if type(parent_enabled) is not bool:
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_configuration_invalid"
            )
        section = parent.get("executive_reports")
        if section is None:
            return cls()
        if not isinstance(section, Mapping):
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_configuration_invalid"
            )
        allowed = {
            "enable",
            "max_reports",
            "max_sources",
            "max_pdf_bytes",
            "retention_seconds",
            "download_token_seconds",
        }
        if any(key not in allowed for key in section):
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_configuration_unknown_key"
            )
        if parent_enabled is not True:
            return cls()
        return cls(**dict(section))


@dataclass(frozen=True, slots=True)
class SourceSelector:
    source_kind: str
    source_id: str

    def normalized(self) -> SourceSelector:
        if self.source_kind not in SOURCE_KINDS:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_source_kind_invalid"
            )
        return SourceSelector(self.source_kind, _id(self.source_id, "source_id"))


@dataclass(frozen=True, slots=True)
class SourceManifestEntry:
    schema: str
    source_kind: str
    source_id: str
    state: str
    revision: int
    integrity_sha256: str | None
    record_count: int
    reason_code: str

    def normalized(self) -> SourceManifestEntry:
        if self.schema != SOURCE_SCHEMA or self.source_kind not in SOURCE_KINDS:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_source_invalid"
            )
        source_id = _id(self.source_id, "source_id")
        if self.state not in SOURCE_STATES or self.reason_code not in SOURCE_REASONS:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_source_state_invalid"
            )
        revision = _integer(self.revision, "source_revision", 0, 2_147_483_647)
        count = _integer(self.record_count, "source_record_count", 0, 2_147_483_647)
        digest = _digest(self.integrity_sha256, "source_digest", optional=True)
        if self.state == "available":
            if revision < 1 or digest is None or count < 1 or self.reason_code != "none":
                raise ThirdPartyExecutiveReportValidationError(
                    "executive_report_source_available_invalid"
                )
        elif revision != 0 or digest is not None or count != 0 or self.reason_code == "none":
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_source_unavailable_invalid"
            )
        return SourceManifestEntry(
            SOURCE_SCHEMA,
            self.source_kind,
            source_id,
            self.state,
            revision,
            digest,
            count,
            self.reason_code,
        )


@dataclass(frozen=True, slots=True)
class ReportMetric:
    metric_id: str
    value: int

    def normalized(self) -> ReportMetric:
        if self.metric_id not in METRIC_IDS:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_metric_invalid"
            )
        return ReportMetric(
            self.metric_id,
            _integer(self.value, "metric_value", 0, 2_147_483_647),
        )


@dataclass(frozen=True, slots=True)
class ReportSnapshot:
    schema: str
    tenant_id: str
    role_view: str
    sources: tuple[SourceManifestEntry, ...]
    metrics: tuple[ReportMetric, ...]
    captured_at: float
    live_portfolio_acceptance_verified: bool = False

    def normalized(self, *, max_sources: int) -> ReportSnapshot:
        if self.schema != SNAPSHOT_SCHEMA:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_snapshot_schema_invalid"
            )
        tenant = _tenant(self.tenant_id)
        role = _role(self.role_view)
        if type(self.live_portfolio_acceptance_verified) is not bool:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_acceptance_flag_invalid"
            )
        if self.live_portfolio_acceptance_verified:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_live_acceptance_unverified"
            )
        if not isinstance(self.sources, tuple) or len(self.sources) > max_sources:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_sources_oversized"
            )
        sources = tuple(item.normalized() for item in self.sources)
        keys = [(item.source_kind, item.source_id) for item in sources]
        if len(set(keys)) != len(keys) or keys != sorted(keys):
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_sources_not_canonical"
            )
        if not isinstance(self.metrics, tuple) or len(self.metrics) > _MAX_METRICS:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_metrics_oversized"
            )
        metrics = tuple(item.normalized() for item in self.metrics)
        metric_ids = [item.metric_id for item in metrics]
        if len(set(metric_ids)) != len(metric_ids) or metric_ids != sorted(metric_ids):
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_metrics_not_canonical"
            )
        return ReportSnapshot(
            SNAPSHOT_SCHEMA,
            tenant,
            role,
            sources,
            metrics,
            _timestamp(self.captured_at, "captured_at"),
            False,
        )


@dataclass(frozen=True, slots=True)
class BrandTokens:
    schema: str
    organization_name: str
    report_title: str
    footer_text: str
    primary_color: str
    accent_color: str
    text_color: str
    brand_asset_metadata_ref: str | None = None
    brand_asset_metadata_sha256: str | None = None

    def normalized(self) -> BrandTokens:
        if self.schema != BRAND_SCHEMA:
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_brand_schema_invalid"
            )
        colors: list[str] = []
        for label, value in (
            ("primary_color", self.primary_color),
            ("accent_color", self.accent_color),
            ("text_color", self.text_color),
        ):
            if not isinstance(value, str) or _COLOR_RE.fullmatch(value) is None:
                raise ThirdPartyExecutiveReportValidationError(
                    f"executive_report_{label}_invalid"
                )
            colors.append(value.upper())
        asset = (
            None
            if self.brand_asset_metadata_ref is None
            else _id(self.brand_asset_metadata_ref, "brand_asset_metadata_ref")
        )
        digest = _digest(
            self.brand_asset_metadata_sha256,
            "brand_asset_metadata_digest",
            optional=True,
        )
        if (asset is None) is not (digest is None):
            raise ThirdPartyExecutiveReportValidationError(
                "executive_report_brand_asset_metadata_binding_invalid"
            )
        return BrandTokens(
            BRAND_SCHEMA,
            _plain_text(self.organization_name, "organization_name", 120),
            _plain_text(self.report_title, "report_title", 160),
            _plain_text(self.footer_text, "footer_text", 160),
            colors[0],
            colors[1],
            colors[2],
            asset,
            digest,
        )


@dataclass(frozen=True, slots=True)
class ExecutiveReportRecord:
    schema: str
    tenant_id: str
    report_id: str
    role_view: str
    brand: BrandTokens
    snapshot: ReportSnapshot
    created_by_ref: str
    created_at: float
    retained_until: float
    pdf_sha256: str
    pdf_bytes: int
    content_sha256: str
    state: str
    control_revision: int
    revoked_at: float | None
    revocation_reason: str | None
    control_sha256: str
    artifact_available: bool
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class ExecutiveReportTombstone:
    """Bounded terminal marker with no source, brand, or principal content."""

    schema: str
    tenant_sha256: str
    report_id: str
    role_view: str
    created_at: float
    retained_until: float
    purged_at: float
    pdf_sha256: str
    pdf_bytes: int
    original_content_sha256: str
    terminal_control_sha256: str
    state: str
    control_revision: int
    artifact_available: bool
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class DownloadGrant:
    schema: str
    grant_id: str
    report_id: str
    report_control_revision: int
    expires_at: float
    token: str | None
    token_disclosed: bool
    idempotent_replay: bool


@dataclass(frozen=True, slots=True)
class DownloadArtifact:
    report_id: str
    pdf_sha256: str
    pdf_bytes: bytes


@dataclass(frozen=True, slots=True)
class IntegrityVerification:
    reports: int
    tombstones: int
    artifacts: int
    grants: int
    operations: int
    audit_events: int
    audit_checkpoint_sequence: int
    audit_checkpoint_sha256: str
    terminal_audit_sha256: str


def _content_body(
    *,
    tenant_id: str,
    report_id: str,
    role_view: str,
    brand: BrandTokens,
    snapshot: ReportSnapshot,
    created_by_ref: str,
    created_at: float,
    retained_until: float,
    pdf_sha256: str,
    pdf_bytes: int,
) -> dict[str, object]:
    return {
        "schema": REPORT_SCHEMA,
        "tenant_id": tenant_id,
        "report_id": report_id,
        "role_view": role_view,
        "brand": asdict(brand),
        "snapshot": asdict(snapshot),
        "created_by_ref": created_by_ref,
        "created_at": created_at,
        "retained_until": retained_until,
        "pdf_sha256": pdf_sha256,
        "pdf_bytes": pdf_bytes,
    }


def _control_body(
    report_id: str,
    state: str,
    revision: int,
    revoked_at: float | None,
    revocation_reason: str | None,
) -> dict[str, object]:
    return {
        "schema": CONTROL_SCHEMA,
        "report_id": report_id,
        "state": state,
        "control_revision": revision,
        "revoked_at": revoked_at,
        "revocation_reason": revocation_reason,
    }


def _privacy_tombstone_body(
    *,
    tenant_id: str,
    report_id: str,
    role_view: str,
    created_at: float,
    retained_until: float,
    purged_at: float,
    pdf_sha256: str,
    pdf_bytes: int,
    original_content_sha256: str,
    terminal_control_sha256: str,
    control_revision: int,
) -> dict[str, object]:
    body = {
        "schema": TOMBSTONE_SCHEMA,
        "tenant_sha256": hashlib.sha256(_tenant(tenant_id).encode()).hexdigest(),
        "report_id": _id(report_id, "report_id"),
        "role_view": _role(role_view),
        "created_at": _timestamp(created_at, "created_at"),
        "retained_until": _timestamp(retained_until, "retained_until"),
        "purged_at": _timestamp(purged_at, "purged_at"),
        "pdf_sha256": _digest(pdf_sha256, "pdf_sha256"),
        "pdf_bytes": _integer(pdf_bytes, "pdf_bytes", 1, 4 * 1024 * 1024),
        "original_content_sha256": _digest(
            original_content_sha256,
            "original_content_sha256",
        ),
        "terminal_control_sha256": _digest(
            terminal_control_sha256,
            "terminal_control_sha256",
        ),
        "state": "expired",
        "control_revision": _integer(
            control_revision,
            "control_revision",
            1,
            2_147_483_647,
        ),
        "artifact_available": False,
    }
    _canonical(body, maximum=_MAX_TOMBSTONE_BYTES)
    return body


def _audit_checkpoint_body(
    *,
    sequence: int,
    terminal_sha256: str,
    compacted_at: float,
) -> dict[str, object]:
    selected_sequence = _integer(
        sequence,
        "audit_checkpoint_sequence",
        0,
        9_223_372_036_854_775_807,
    )
    terminal = _digest(terminal_sha256, "audit_checkpoint_sha256")
    if isinstance(compacted_at, bool) or not isinstance(compacted_at, (int, float)):
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_audit_checkpoint_time_invalid"
        )
    selected_time = float(compacted_at)
    if not math.isfinite(selected_time) or not 0 <= selected_time < 100_000_000_000.0:
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_audit_checkpoint_time_invalid"
        )
    if selected_sequence == 0 and (
        terminal != GENESIS_SHA256 or selected_time != 0.0
    ):
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_audit_checkpoint_invalid"
        )
    if selected_sequence > 0 and selected_time <= 0:
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_audit_checkpoint_invalid"
        )
    return {
        "schema": AUDIT_CHECKPOINT_SCHEMA,
        "compacted_through_sequence": selected_sequence,
        "terminal_audit_sha256": terminal,
        "compacted_at": selected_time,
    }


def _operation_body(
    *,
    idempotency_sha256: object,
    request_sha256: object,
    operation_type: object,
    report_id: object,
    result: object,
    created_at: object,
) -> dict[str, object]:
    idem = _digest(idempotency_sha256, "idempotency_sha256")
    request = _digest(request_sha256, "request_sha256")
    operation = _id(operation_type, "operation_type")
    report = None if report_id is None else _id(report_id, "report_id")
    if not isinstance(result, Mapping):
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_operation_result_invalid"
        )
    selected_result = dict(result)
    _canonical(selected_result)
    return {
        "schema": OPERATION_SCHEMA,
        "idempotency_sha256": idem,
        "request_sha256": request,
        "operation_type": operation,
        "report_id": report,
        "result": selected_result,
        "created_at": _timestamp(created_at, "operation_created_at"),
    }


def _grant_capacity(config: ThirdPartyExecutiveReportConfig) -> int:
    return min(
        config.max_reports * _GRANTS_PER_REPORT_CAPACITY,
        _MAX_GRANT_CAPACITY,
    )


def _operation_capacity(config: ThirdPartyExecutiveReportConfig) -> int:
    return min(
        max(_OPERATIONS_PER_REPORT_CAPACITY, config.max_reports * 8),
        _MAX_OPERATION_CAPACITY,
    )


def _audit_capacity(config: ThirdPartyExecutiveReportConfig) -> int:
    return min(
        max(_AUDIT_EVENTS_PER_REPORT_CAPACITY, config.max_reports * 4),
        _MAX_AUDIT,
    )


def _hex_rgb(value: str) -> tuple[float, float, float]:
    return tuple(int(value[index : index + 2], 16) / 255 for index in (1, 3, 5))  # type: ignore[return-value]


def _pdf_text(value: object, maximum: int = 160) -> str:
    normalized = unicodedata.normalize("NFKD", str(value))
    ascii_value = normalized.encode("ascii", "replace").decode("ascii")[:maximum]
    return ascii_value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _metric_label(metric_id: str) -> str:
    return metric_id.replace("_", " ").title()


# Body text starts here on every page (below the 72pt brand band) and never
# runs past the floor: the footer sits at y=34, so the floor keeps one clear
# line between the last body baseline and the footer text.
_PDF_FIRST_BASELINE = 690
_PDF_BODY_FLOOR = 60


def _pdf_line_style(
    kind: str,
    accent: tuple[float, float, float],
    text_color: tuple[float, float, float],
) -> tuple[str, int, tuple[float, float, float], int]:
    """``(font, size, color, baseline step)`` for one rendered line kind."""

    if kind == "title":
        return "F2", 20, (1.0, 1.0, 1.0), 31
    if kind == "subtitle":
        return "F1", 12, (1.0, 1.0, 1.0), 28
    if kind == "heading":
        return "F2", 13, accent, 25
    if kind == "metric":
        return "F2", 10, text_color, 18
    if kind == "digest":
        return "F1", 7, text_color, 15
    return "F1", 9, text_color, 18


def render_deterministic_pdf(
    *,
    report_id: str,
    brand: BrandTokens,
    snapshot: ReportSnapshot,
    created_at: float,
    maximum_bytes: int,
) -> bytes:
    """Render bounded PDF bytes without HTML, CSS, URLs, scripts or fetches."""

    report = _id(report_id, "report_id")
    selected_brand = brand.normalized()
    selected_snapshot = snapshot.normalized(max_sources=max(1, len(snapshot.sources)))
    limit = _integer(maximum_bytes, "max_pdf_bytes", 16_384, 4 * 1024 * 1024)
    primary = _hex_rgb(selected_brand.primary_color)
    accent = _hex_rgb(selected_brand.accent_color)
    text_color = _hex_rgb(selected_brand.text_color)

    lines: list[tuple[str, str]] = [
        ("title", selected_brand.report_title),
        ("subtitle", selected_brand.organization_name),
        ("body", f"Report reference: {report}"),
        ("body", f"Role view: {selected_snapshot.role_view}"),
        ("body", f"Captured timestamp: {selected_snapshot.captured_at:.6f}"),
        ("body", f"Artifact timestamp: {_timestamp(created_at, 'created_at'):.6f}"),
        ("heading", "Portfolio metrics"),
    ]
    if selected_snapshot.metrics:
        lines.extend(
            ("metric", f"{_metric_label(metric.metric_id)}: {metric.value}")
            for metric in selected_snapshot.metrics
        )
    else:
        lines.append(("body", "No metrics are available for the selected records."))
    lines.append(("heading", "Exact source manifest"))
    if selected_snapshot.sources:
        for source in selected_snapshot.sources:
            lines.append(
                (
                    "source",
                    f"{source.source_kind} / {source.source_id}: {source.state}; "
                    f"revision {source.revision}; records {source.record_count}",
                )
            )
            digest = source.integrity_sha256 or "not-available"
            lines.append(("digest", f"digest {digest}; reason {source.reason_code}"))
    else:
        lines.append(("body", "No source records were selected. This report is intentionally empty."))
    if selected_brand.brand_asset_metadata_ref is not None:
        lines.extend(
            (
                ("heading", "Non-rendered brand asset metadata"),
                (
                    "body",
                    "Metadata reference: "
                    f"{selected_brand.brand_asset_metadata_ref}",
                ),
                (
                    "digest",
                    "Metadata digest: "
                    f"{selected_brand.brand_asset_metadata_sha256}",
                ),
                ("body", "No brand asset bytes were resolved or embedded."),
            )
        )
    lines.extend(
        (
            ("heading", "Evidence boundary"),
            (
                "body",
                "Unavailable sources are shown explicitly and are never counted as available.",
            ),
            (
                "body",
                "This artifact does not establish live portfolio or customer acceptance.",
            ),
        )
    )

    # Paginate by the vertical space the lines actually consume: a
    # fixed line count overflowed the page once a report carried every
    # metric plus several sources, drawing body lines below the y=34 footer
    # and off the paper edge -- silently clipping the source digests that
    # are the report's evidence. A line starts a new page when its baseline
    # would cross the body floor above the footer band.
    chunks: list[list[tuple[str, str]]] = [[]]
    y = _PDF_FIRST_BASELINE
    for line in lines:
        y_step = _pdf_line_style(line[0], accent, text_color)[3]
        if chunks[-1] and y - y_step < _PDF_BODY_FLOOR:
            chunks.append([])
            y = _PDF_FIRST_BASELINE
        chunks[-1].append(line)
        y -= y_step
    if not chunks[0]:
        chunks = [[("body", "No report content is available.")]]
    page_streams: list[bytes] = []
    for page_index, chunk in enumerate(chunks, 1):
        operations = [
            "q",
            f"{primary[0]:.4f} {primary[1]:.4f} {primary[2]:.4f} rg",
            "0 720 612 72 re f",
            f"{accent[0]:.4f} {accent[1]:.4f} {accent[2]:.4f} rg",
            "0 714 612 6 re f",
            "Q",
        ]
        y = _PDF_FIRST_BASELINE
        for kind, value in chunk:
            font, size, color, y_step = _pdf_line_style(kind, accent, text_color)
            operations.extend(
                (
                    "BT",
                    f"/{font} {size} Tf",
                    f"{color[0]:.4f} {color[1]:.4f} {color[2]:.4f} rg",
                    f"54 {y} Td",
                    f"({_pdf_text(value, 118)}) Tj",
                    "ET",
                )
            )
            y -= y_step
        operations.extend(
            (
                "BT",
                "/F1 8 Tf",
                f"{text_color[0]:.4f} {text_color[1]:.4f} {text_color[2]:.4f} rg",
                "54 34 Td",
                f"({_pdf_text(selected_brand.footer_text, 92)} - Page {page_index} of {len(chunks)}) Tj",
                "ET",
            )
        )
        page_streams.append(("\n".join(operations) + "\n").encode("ascii"))

    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    }
    kids: list[str] = []
    for index, stream in enumerate(page_streams):
        page_object = 5 + index * 2
        stream_object = page_object + 1
        kids.append(f"{page_object} 0 R")
        objects[page_object] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {stream_object} 0 R >>"
        ).encode("ascii")
        objects[stream_object] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"endstream"
        )
    objects[2] = (
        f"<< /Type /Pages /Count {len(page_streams)} /Kids [{' '.join(kids)}] >>"
    ).encode("ascii")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_number in range(1, max(objects) + 1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(objects[object_number])
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode("ascii")
    )
    result = bytes(output)
    if len(result) > limit:
        raise ThirdPartyExecutiveReportValidationError(
            "executive_report_pdf_oversized"
        )
    return result


class ThirdPartyExecutiveReportStore:
    """Private tenant store for immutable report artifacts and mutable controls."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        principal_resolver: Callable[[], str],
        audit_authorizer: Callable[[], bool],
        maintenance_authorizer: Callable[[], bool],
        config_gate: Callable[[], None],
        config: ThirdPartyExecutiveReportConfig,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(config, ThirdPartyExecutiveReportConfig) or config.enable is not True:
            raise ThirdPartyExecutiveReportConfigError("executive_report_disabled")
        for dependency in (
            principal_resolver,
            audit_authorizer,
            maintenance_authorizer,
            config_gate,
            clock,
        ):
            if not callable(dependency):
                raise ThirdPartyExecutiveReportConfigError(
                    "executive_report_authority_unavailable"
                )
        self._path = Path(path)
        self._tenant = _tenant(tenant_id)
        self._principal_resolver = principal_resolver
        self._audit_authorizer = audit_authorizer
        self._maintenance_authorizer = maintenance_authorizer
        self._config_gate = config_gate
        self._config = config
        self._clock = clock
        self._id_factory = id_factory or (lambda: f"report_{secrets.token_hex(16)}")
        self._token_factory = token_factory or (lambda: f"tpr_{secrets.token_urlsafe(32)}")
        ensure_private_directory(self._path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS executive_report_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executive_reports(
                    report_id TEXT PRIMARY KEY,
                    content_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    pdf_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    tombstoned_at REAL
                );
                CREATE TABLE IF NOT EXISTS executive_report_artifacts(
                    report_id TEXT PRIMARY KEY REFERENCES executive_reports(report_id),
                    pdf_blob BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executive_report_controls(
                    report_id TEXT PRIMARY KEY REFERENCES executive_reports(report_id),
                    control_json TEXT NOT NULL,
                    control_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executive_report_operations(
                    idempotency_sha256 TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    report_id TEXT,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    integrity_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executive_report_download_grants(
                    grant_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL REFERENCES executive_reports(report_id),
                    token_sha256 TEXT UNIQUE NOT NULL,
                    principal_ref TEXT NOT NULL,
                    report_control_revision INTEGER NOT NULL,
                    expires_at REAL NOT NULL,
                    redeemed_at REAL,
                    grant_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executive_report_audit(
                    sequence INTEGER PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    occurred_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executive_report_audit_checkpoint(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    checkpoint_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL
                );
                """
            )
            row = connection.execute(
                "SELECT value FROM executive_report_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO executive_report_meta(key,value) VALUES('schema_version',?)",
                    (str(SCHEMA_VERSION),),
                )
            else:
                version = str(row["value"])
                if version == "1":
                    self._migrate_operations_v1(connection)
                    version = "2"
                if version == "2":
                    self._migrate_v2_to_v3(connection)
                    version = "3"
                if version != str(SCHEMA_VERSION):
                    raise ThirdPartyExecutiveReportConfigError(
                        "executive_report_schema_unsupported"
                    )
                connection.execute(
                    "UPDATE executive_report_meta SET value=? WHERE key='schema_version'",
                    (str(SCHEMA_VERSION),),
                )
            self._ensure_audit_checkpoint(connection)
            columns = {
                str(item["name"])
                for item in connection.execute(
                    "PRAGMA table_info(executive_report_operations)"
                ).fetchall()
            }
            if "integrity_sha256" not in columns:
                raise ThirdPartyExecutiveReportConfigError(
                    "executive_report_schema_unsupported"
                )
            report_columns = {
                str(item["name"])
                for item in connection.execute(
                    "PRAGMA table_info(executive_reports)"
                ).fetchall()
            }
            audit_columns = {
                str(item["name"])
                for item in connection.execute(
                    "PRAGMA table_info(executive_report_audit)"
                ).fetchall()
            }
            if "tombstoned_at" not in report_columns or "occurred_at" not in audit_columns:
                raise ThirdPartyExecutiveReportConfigError(
                    "executive_report_schema_unsupported"
                )
            now = _clock_value(self._clock)
            self._retire_operations(connection, now=now)
            self._compact_audit(connection, now=now)
            self._retire_tombstones(connection, now=now)
            connection.commit()
        ensure_private_file(self._path)

    @staticmethod
    def _migrate_operations_v1(connection: sqlite3.Connection) -> None:
        columns = {
            str(item["name"])
            for item in connection.execute(
                "PRAGMA table_info(executive_report_operations)"
            ).fetchall()
        }
        if "integrity_sha256" not in columns:
            connection.execute(
                "ALTER TABLE executive_report_operations "
                "ADD COLUMN integrity_sha256 TEXT"
            )
        try:
            rows = connection.execute(
                "SELECT * FROM executive_report_operations"
            ).fetchall()
            for item in rows:
                raw_result = str(item["result_json"])
                result = json.loads(raw_result)
                if (
                    not isinstance(result, Mapping)
                    or _canonical(dict(result)).decode("ascii") != raw_result
                ):
                    raise ValueError("legacy operation result is not canonical")
                body = _operation_body(
                    idempotency_sha256=item["idempotency_sha256"],
                    request_sha256=item["request_sha256"],
                    operation_type=item["operation_type"],
                    report_id=item["report_id"],
                    result=result,
                    created_at=item["created_at"],
                )
                connection.execute(
                    "UPDATE executive_report_operations SET integrity_sha256=? "
                    "WHERE idempotency_sha256=?",
                    (
                        canonical_sha256(body),
                        str(item["idempotency_sha256"]),
                    ),
                )
        except (ThirdPartyExecutiveReportError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_schema_migration_failed"
            ) from exc

    @staticmethod
    def _ensure_audit_checkpoint(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT checkpoint_json,integrity_sha256 "
            "FROM executive_report_audit_checkpoint WHERE singleton=1"
        ).fetchone()
        if row is None:
            body = _audit_checkpoint_body(
                sequence=0,
                terminal_sha256=GENESIS_SHA256,
                compacted_at=0.0,
            )
            connection.execute(
                "INSERT INTO executive_report_audit_checkpoint VALUES(1,?,?)",
                (_canonical(body).decode("ascii"), canonical_sha256(body)),
            )
            return
        ThirdPartyExecutiveReportStore._audit_checkpoint_from_row(row)

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        """Deterministically add bounded-history indexes and minimize old tombstones."""

        try:
            report_columns = {
                str(item["name"])
                for item in connection.execute(
                    "PRAGMA table_info(executive_reports)"
                ).fetchall()
            }
            if "tombstoned_at" not in report_columns:
                connection.execute(
                    "ALTER TABLE executive_reports ADD COLUMN tombstoned_at REAL"
                )
            audit_columns = {
                str(item["name"])
                for item in connection.execute(
                    "PRAGMA table_info(executive_report_audit)"
                ).fetchall()
            }
            if "occurred_at" not in audit_columns:
                connection.execute(
                    "ALTER TABLE executive_report_audit ADD COLUMN occurred_at REAL"
                )
            audit_rows = connection.execute(
                "SELECT * FROM executive_report_audit ORDER BY sequence"
            ).fetchall()
            previous = GENESIS_SHA256
            for expected, item in enumerate(audit_rows, 1):
                event = json.loads(str(item["event_json"]))
                if (
                    not isinstance(event, Mapping)
                    or int(item["sequence"]) != expected
                    or str(item["previous_sha256"]) != previous
                    or event.get("previous_sha256") != previous
                    or event.get("sequence") != expected
                    or not hmac.compare_digest(
                        str(item["integrity_sha256"]), canonical_sha256(event)
                    )
                ):
                    raise ValueError("legacy audit chain is invalid")
                occurred_at = _timestamp(event.get("occurred_at"), "occurred_at")
                connection.execute(
                    "UPDATE executive_report_audit SET occurred_at=? WHERE sequence=?",
                    (occurred_at, expected),
                )
                previous = str(item["integrity_sha256"])
            self._ensure_audit_checkpoint(connection)
            expired_rows = connection.execute(
                "SELECT r.*,c.control_json,c.control_sha256 "
                "FROM executive_reports r JOIN executive_report_controls c USING(report_id) "
                "LEFT JOIN executive_report_artifacts a USING(report_id) "
                "WHERE a.report_id IS NULL"
            ).fetchall()
            for row in expired_rows:
                content = json.loads(str(row["content_json"]))
                control = json.loads(str(row["control_json"]))
                if not isinstance(content, Mapping) or not isinstance(control, Mapping):
                    raise ValueError("legacy report material is invalid")
                original_content_sha = str(row["content_sha256"])
                terminal_control_sha = str(row["control_sha256"])
                if not hmac.compare_digest(
                    original_content_sha,
                    canonical_sha256(content),
                ) or not hmac.compare_digest(
                    terminal_control_sha,
                    canonical_sha256(control),
                ):
                    raise ValueError("legacy report material digest differs")
                if content.get("schema") != REPORT_SCHEMA or control.get("state") != "expired":
                    raise ValueError("legacy artifact is unexpectedly absent")
                report_id = _id(content.get("report_id"), "report_id")
                retained_until = _timestamp(
                    content.get("retained_until"),
                    "retained_until",
                )
                tombstone = _privacy_tombstone_body(
                    tenant_id=_tenant(content.get("tenant_id")),
                    report_id=report_id,
                    role_view=_role(content.get("role_view")),
                    created_at=_timestamp(content.get("created_at"), "created_at"),
                    retained_until=retained_until,
                    purged_at=retained_until,
                    pdf_sha256=str(_digest(content.get("pdf_sha256"), "pdf_sha256")),
                    pdf_bytes=_integer(
                        content.get("pdf_bytes"),
                        "pdf_bytes",
                        1,
                        self._config.max_pdf_bytes,
                    ),
                    original_content_sha256=original_content_sha,
                    terminal_control_sha256=terminal_control_sha,
                    control_revision=_integer(
                        control.get("control_revision"),
                        "control_revision",
                        1,
                        2_147_483_647,
                    ),
                )
                encoded = _canonical(
                    tombstone,
                    maximum=_MAX_TOMBSTONE_BYTES,
                ).decode("ascii")
                connection.execute(
                    "DELETE FROM executive_report_download_grants WHERE report_id=?",
                    (report_id,),
                )
                connection.execute(
                    "DELETE FROM executive_report_operations WHERE report_id=?",
                    (report_id,),
                )
                connection.execute(
                    "DELETE FROM executive_report_controls WHERE report_id=?",
                    (report_id,),
                )
                connection.execute(
                    "UPDATE executive_reports SET content_json=?,content_sha256=?,"
                    "tombstoned_at=? WHERE report_id=?",
                    (
                        encoded,
                        canonical_sha256(tombstone),
                        retained_until,
                        report_id,
                    ),
                )
        except (ThirdPartyExecutiveReportError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_schema_migration_failed"
            ) from exc

    def _gate(self) -> None:
        try:
            self._config_gate()
        except (KeyboardInterrupt, SystemExit):
            raise
        except ThirdPartyExecutiveReportError:
            raise
        except Exception as exc:
            raise ThirdPartyExecutiveReportConfigError(
                "executive_report_configuration_changed"
            ) from exc

    def _principal(self) -> str:
        self._gate()
        try:
            principal = self._principal_resolver()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_principal_unavailable"
            ) from exc
        return _id(principal, "principal_ref")

    @staticmethod
    def _access_allowed(report_role: str, caller_role: str) -> bool:
        allowed = {
            "admin": ROLE_VIEWS,
            "operator": frozenset({"operator", "viewer"}),
            "auditor": frozenset({"auditor", "viewer"}),
            "viewer": frozenset({"viewer"}),
        }
        return report_role in allowed[_role(caller_role)]

    @staticmethod
    def _audit_checkpoint_from_row(
        row: sqlite3.Row,
    ) -> tuple[Mapping[str, object], str]:
        try:
            raw = str(row["checkpoint_json"])
            value = json.loads(raw)
            if (
                not isinstance(value, Mapping)
                or value.get("schema") != AUDIT_CHECKPOINT_SCHEMA
                or _canonical(dict(value)).decode("ascii") != raw
            ):
                raise ValueError("audit checkpoint is not canonical")
            body = _audit_checkpoint_body(
                sequence=value.get("compacted_through_sequence"),  # type: ignore[arg-type]
                terminal_sha256=value.get("terminal_audit_sha256"),  # type: ignore[arg-type]
                compacted_at=value.get("compacted_at"),  # type: ignore[arg-type]
            )
            digest = str(row["integrity_sha256"])
            if _DIGEST_RE.fullmatch(digest) is None or not hmac.compare_digest(
                digest,
                canonical_sha256(body),
            ):
                raise ValueError("audit checkpoint digest differs")
            return body, digest
        except ThirdPartyExecutiveReportError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_audit_checkpoint_integrity_failed"
            ) from exc

    @staticmethod
    def _audit_event_from_row(
        row: sqlite3.Row,
        *,
        expected_sequence: int,
        previous_sha256: str,
    ) -> tuple[Mapping[str, object], str]:
        try:
            raw = str(row["event_json"])
            event = json.loads(raw)
            occurred_at = _timestamp(row["occurred_at"], "occurred_at")
            digest = str(row["integrity_sha256"])
            if (
                not isinstance(event, Mapping)
                or _canonical(dict(event)).decode("ascii") != raw
                or int(row["sequence"]) != expected_sequence
                or str(row["previous_sha256"]) != previous_sha256
                or event.get("previous_sha256") != previous_sha256
                or event.get("sequence") != expected_sequence
                or event.get("occurred_at") != occurred_at
                or _DIGEST_RE.fullmatch(digest) is None
                or not hmac.compare_digest(digest, canonical_sha256(event))
            ):
                raise ValueError("audit event differs from its chain projection")
            return event, digest
        except ThirdPartyExecutiveReportError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_audit_integrity_failed"
            ) from exc

    def _audit_checkpoint(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[Mapping[str, object], str]:
        row = connection.execute(
            "SELECT checkpoint_json,integrity_sha256 "
            "FROM executive_report_audit_checkpoint WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_audit_checkpoint_missing"
            )
        return self._audit_checkpoint_from_row(row)

    def _compact_audit(
        self,
        connection: sqlite3.Connection,
        *,
        now: float,
        reserve: int = 0,
    ) -> int:
        checkpoint, _checkpoint_digest = self._audit_checkpoint(connection)
        checkpoint_sequence = int(checkpoint["compacted_through_sequence"])
        previous = str(checkpoint["terminal_audit_sha256"])
        rows = connection.execute(
            "SELECT * FROM executive_report_audit ORDER BY sequence"
        ).fetchall()
        validated: list[tuple[sqlite3.Row, str]] = []
        for offset, row in enumerate(rows, 1):
            _event, digest = self._audit_event_from_row(
                row,
                expected_sequence=checkpoint_sequence + offset,
                previous_sha256=previous,
            )
            validated.append((row, digest))
            previous = digest
        retention_cutoff = now - self._config.retention_seconds
        retention_count = 0
        for row, _digest_value in validated:
            if float(row["occurred_at"]) > retention_cutoff:
                break
            retention_count += 1
        capacity = _audit_capacity(self._config)
        overflow_count = max(0, len(validated) + reserve - capacity)
        remove_count = max(retention_count, overflow_count)
        if remove_count == 0:
            return 0
        terminal_row, terminal = validated[remove_count - 1]
        terminal_sequence = int(terminal_row["sequence"])
        body = _audit_checkpoint_body(
            sequence=terminal_sequence,
            terminal_sha256=terminal,
            compacted_at=now,
        )
        connection.execute(
            "UPDATE executive_report_audit_checkpoint SET "
            "checkpoint_json=?,integrity_sha256=? WHERE singleton=1",
            (_canonical(body).decode("ascii"), canonical_sha256(body)),
        )
        connection.execute(
            "DELETE FROM executive_report_audit WHERE sequence<=?",
            (terminal_sequence,),
        )
        return remove_count

    def _audit_event(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        report_id: str | None,
        actor_ref: str,
        details: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        self._compact_audit(connection, now=occurred_at, reserve=1)
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM executive_report_audit "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if previous is None:
            checkpoint, _checkpoint_digest = self._audit_checkpoint(connection)
            sequence = int(checkpoint["compacted_through_sequence"]) + 1
            previous_sha = str(checkpoint["terminal_audit_sha256"])
        else:
            sequence = int(previous["sequence"]) + 1
            previous_sha = str(previous["integrity_sha256"])
        event = {
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "action": _id(action, "audit_action"),
            "report_id": report_id,
            "actor_ref": actor_ref,
            "details": dict(details),
            "occurred_at": occurred_at,
            "previous_sha256": previous_sha,
        }
        digest = canonical_sha256(event)
        connection.execute(
            "INSERT INTO executive_report_audit VALUES(?,?,?,?,?)",
            (
                sequence,
                _canonical(event).decode("ascii"),
                previous_sha,
                digest,
                occurred_at,
            ),
        )

    @staticmethod
    def _operation_from_row(row: sqlite3.Row) -> Mapping[str, object]:
        try:
            raw_result = str(row["result_json"])
            result = json.loads(raw_result)
            if (
                not isinstance(result, Mapping)
                or _canonical(dict(result)).decode("ascii") != raw_result
            ):
                raise ValueError("operation result is not canonical")
            body = _operation_body(
                idempotency_sha256=row["idempotency_sha256"],
                request_sha256=row["request_sha256"],
                operation_type=row["operation_type"],
                report_id=row["report_id"],
                result=result,
                created_at=row["created_at"],
            )
            digest = str(row["integrity_sha256"])
            if _DIGEST_RE.fullmatch(digest) is None or not hmac.compare_digest(
                digest,
                canonical_sha256(body),
            ):
                raise ValueError("operation digest differs")
        except ThirdPartyExecutiveReportIntegrityError:
            raise
        except (ThirdPartyExecutiveReportError, KeyError, TypeError, ValueError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_operation_integrity_failed"
            ) from exc
        return body

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        idem: str,
        request_sha: str,
    ) -> Mapping[str, object] | None:
        row = connection.execute(
            "SELECT * FROM executive_report_operations "
            "WHERE idempotency_sha256=?",
            (idem,),
        ).fetchone()
        if row is None:
            return None
        body = ThirdPartyExecutiveReportStore._operation_from_row(row)
        if not hmac.compare_digest(str(body["request_sha256"]), request_sha):
            raise ThirdPartyExecutiveReportConflict(
                "executive_report_idempotency_conflict"
            )
        result = body["result"]
        if not isinstance(result, Mapping):
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_operation_corrupt"
            )
        return result

    def _retire_operations(
        self,
        connection: sqlite3.Connection,
        *,
        now: float,
        reserve: int = 0,
        report_ids: tuple[str, ...] = (),
    ) -> int:
        capacity = _operation_capacity(self._config)
        rows = connection.execute(
            "SELECT * FROM executive_report_operations ORDER BY created_at,idempotency_sha256"
        ).fetchall()
        for row in rows:
            self._operation_from_row(row)
        selected_report_ids = frozenset(
            _id(value, "report_id") for value in report_ids
        )
        cutoff = now - self._config.retention_seconds
        delete_ids = {
            str(row["idempotency_sha256"])
            for row in rows
            if float(row["created_at"]) <= cutoff
            or (
                row["report_id"] is not None
                and str(row["report_id"]) in selected_report_ids
            )
        }
        remaining = [
            row
            for row in rows
            if str(row["idempotency_sha256"]) not in delete_ids
        ]
        overflow = max(0, len(remaining) + reserve - capacity)
        delete_ids.update(
            str(row["idempotency_sha256"]) for row in remaining[:overflow]
        )
        for identifier in sorted(delete_ids):
            connection.execute(
                "DELETE FROM executive_report_operations WHERE idempotency_sha256=?",
                (identifier,),
            )
        return len(delete_ids)

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        *,
        idem: str,
        request_sha: str,
        operation_type: str,
        report_id: str | None,
        result: Mapping[str, object],
        created_at: float,
    ) -> None:
        self._retire_operations(connection, now=created_at, reserve=1)
        result_json = _canonical(dict(result)).decode("ascii")
        body = _operation_body(
            idempotency_sha256=idem,
            request_sha256=request_sha,
            operation_type=operation_type,
            report_id=report_id,
            result=result,
            created_at=created_at,
        )
        connection.execute(
            "INSERT INTO executive_report_operations VALUES(?,?,?,?,?,?,?)",
            (
                idem,
                request_sha,
                operation_type,
                report_id,
                result_json,
                created_at,
                canonical_sha256(body),
            ),
        )

    @staticmethod
    def _control_from_row(row: sqlite3.Row) -> tuple[Mapping[str, object], str]:
        try:
            value = json.loads(str(row["control_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_control_corrupt"
            ) from exc
        if not isinstance(value, Mapping):
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_control_corrupt"
            )
        digest = str(row["control_sha256"])
        if _DIGEST_RE.fullmatch(digest) is None or not hmac.compare_digest(
            digest, canonical_sha256(value)
        ):
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_control_integrity_failed"
            )
        return value, digest

    @staticmethod
    def _grant_from_row(row: sqlite3.Row) -> Mapping[str, object]:
        try:
            value = json.loads(str(row["grant_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_download_grant_corrupt"
            ) from exc
        if not isinstance(value, Mapping) or value.get("schema") != GRANT_SCHEMA:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_download_grant_corrupt"
            )
        digest = str(row["integrity_sha256"])
        if _DIGEST_RE.fullmatch(digest) is None or not hmac.compare_digest(
            digest, canonical_sha256(value)
        ):
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_download_grant_integrity_failed"
            )
        try:
            token_sha = str(_digest(value["token_sha256"], "token_sha256"))
            principal = _id(value["principal_ref"], "principal_ref")
            revision = _integer(
                value["report_control_revision"],
                "report_control_revision",
                1,
                2_147_483_647,
            )
            expires_at = _timestamp(value["expires_at"], "expires_at")
            _timestamp(value["created_at"], "created_at")
            redeemed = value.get("redeemed_at")
            if redeemed is not None:
                redeemed = _timestamp(redeemed, "redeemed_at")
            row_redeemed = row["redeemed_at"]
            if row_redeemed is not None:
                row_redeemed = float(row_redeemed)
            if (
                _id(value["grant_id"], "grant_id") != str(row["grant_id"])
                or _id(value["report_id"], "report_id") != str(row["report_id"])
                or token_sha != str(row["token_sha256"])
                or principal != str(row["principal_ref"])
                or revision != int(row["report_control_revision"])
                or expires_at != float(row["expires_at"])
                or redeemed != row_redeemed
            ):
                raise ValueError("grant columns differ from immutable projection")
        except ThirdPartyExecutiveReportError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_download_grant_corrupt"
            ) from exc
        return value

    @staticmethod
    def _retire_stale_grants(
        connection: sqlite3.Connection,
        *,
        now: float,
        limit: int,
    ) -> tuple[str, ...]:
        bounded = _integer(limit, "grant_cleanup_limit", 1, _MAX_GRANT_CAPACITY)
        rows = connection.execute(
            "SELECT * FROM executive_report_download_grants "
            "WHERE redeemed_at IS NOT NULL OR expires_at<=? "
            "ORDER BY expires_at,grant_id LIMIT ?",
            (now, bounded),
        ).fetchall()
        identifiers: list[str] = []
        for row in rows:
            ThirdPartyExecutiveReportStore._grant_from_row(row)
            identifier = _id(row["grant_id"], "grant_id")
            connection.execute(
                "DELETE FROM executive_report_download_grants WHERE grant_id=?",
                (identifier,),
            )
            identifiers.append(identifier)
        return tuple(identifiers)

    def _retire_tombstones(
        self,
        connection: sqlite3.Connection,
        *,
        now: float,
        reserve: int = 0,
    ) -> tuple[str, ...]:
        rows = connection.execute(
            "SELECT report_id,tombstoned_at FROM executive_reports "
            "WHERE tombstoned_at IS NOT NULL ORDER BY tombstoned_at,report_id"
        ).fetchall()
        for row in rows:
            record = self._row_record(connection, str(row["report_id"]))
            if not isinstance(record, ExecutiveReportTombstone):
                raise ThirdPartyExecutiveReportIntegrityError(
                    "executive_report_tombstone_projection_invalid"
                )
        cutoff = now - self._config.retention_seconds
        selected = {
            str(row["report_id"])
            for row in rows
            if float(row["tombstoned_at"]) <= cutoff
        }
        remaining = [row for row in rows if str(row["report_id"]) not in selected]
        overflow = max(0, len(remaining) + reserve - self._config.max_reports)
        selected.update(str(row["report_id"]) for row in remaining[:overflow])
        for identifier in sorted(selected):
            connection.execute(
                "DELETE FROM executive_report_download_grants WHERE report_id=?",
                (identifier,),
            )
            connection.execute(
                "DELETE FROM executive_report_operations WHERE report_id=?",
                (identifier,),
            )
            connection.execute(
                "DELETE FROM executive_report_controls WHERE report_id=?",
                (identifier,),
            )
            connection.execute(
                "DELETE FROM executive_reports WHERE report_id=?",
                (identifier,),
            )
        return tuple(sorted(selected))

    def _row_record(
        self,
        connection: sqlite3.Connection,
        report_id: str,
    ) -> ExecutiveReportRecord | ExecutiveReportTombstone:
        row = connection.execute(
            "SELECT r.*,c.control_json,c.control_sha256,"
            "CASE WHEN a.report_id IS NULL THEN 0 ELSE 1 END AS artifact_available "
            "FROM executive_reports r LEFT JOIN executive_report_controls c USING(report_id) "
            "LEFT JOIN executive_report_artifacts a USING(report_id) WHERE r.report_id=?",
            (report_id,),
        ).fetchone()
        if row is None:
            raise ThirdPartyExecutiveReportNotFound("executive_report_not_found")
        try:
            content = json.loads(str(row["content_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_content_corrupt"
            ) from exc
        if not isinstance(content, Mapping):
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_content_corrupt"
            )
        content_digest = str(row["content_sha256"])
        if _DIGEST_RE.fullmatch(content_digest) is None or not hmac.compare_digest(
            content_digest, canonical_sha256(content)
        ):
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_content_integrity_failed"
            )
        try:
            if content.get("schema") == TOMBSTONE_SCHEMA:
                if (
                    row["control_json"] is not None
                    or row["control_sha256"] is not None
                    or bool(row["artifact_available"])
                ):
                    raise ValueError("tombstone retains control or artifact material")
                identifier = _id(content["report_id"], "report_id")
                created_at = _timestamp(content["created_at"], "created_at")
                retained_until = _timestamp(
                    content["retained_until"],
                    "retained_until",
                )
                purged_at = _timestamp(content["purged_at"], "purged_at")
                tenant_sha = str(_digest(content["tenant_sha256"], "tenant_sha256"))
                pdf_sha = str(_digest(content["pdf_sha256"], "pdf_sha256"))
                if (
                    tenant_sha != hashlib.sha256(self._tenant.encode()).hexdigest()
                    or identifier != str(row["report_id"])
                    or created_at != float(row["created_at"])
                    or retained_until != float(row["retained_until"])
                    or purged_at != float(row["tombstoned_at"])
                    or pdf_sha != str(row["pdf_sha256"])
                    or content.get("state") != "expired"
                    or content.get("artifact_available") is not False
                    or purged_at < retained_until
                ):
                    raise ValueError("tombstone columns differ from its projection")
                expected = _privacy_tombstone_body(
                    tenant_id=self._tenant,
                    report_id=identifier,
                    role_view=_role(content["role_view"]),
                    created_at=created_at,
                    retained_until=retained_until,
                    purged_at=purged_at,
                    pdf_sha256=pdf_sha,
                    pdf_bytes=_integer(
                        content["pdf_bytes"],
                        "pdf_bytes",
                        1,
                        self._config.max_pdf_bytes,
                    ),
                    original_content_sha256=str(
                        _digest(
                            content["original_content_sha256"],
                            "original_content_sha256",
                        )
                    ),
                    terminal_control_sha256=str(
                        _digest(
                            content["terminal_control_sha256"],
                            "terminal_control_sha256",
                        )
                    ),
                    control_revision=_integer(
                        content["control_revision"],
                        "control_revision",
                        1,
                        2_147_483_647,
                    ),
                )
                if dict(content) != expected:
                    raise ValueError("tombstone contains unrecognized material")
                return ExecutiveReportTombstone(
                    schema=TOMBSTONE_SCHEMA,
                    tenant_sha256=tenant_sha,
                    report_id=identifier,
                    role_view=_role(content["role_view"]),
                    created_at=created_at,
                    retained_until=retained_until,
                    purged_at=purged_at,
                    pdf_sha256=pdf_sha,
                    pdf_bytes=int(content["pdf_bytes"]),
                    original_content_sha256=str(content["original_content_sha256"]),
                    terminal_control_sha256=str(content["terminal_control_sha256"]),
                    state="expired",
                    control_revision=int(content["control_revision"]),
                    artifact_available=False,
                    integrity_sha256=content_digest,
                )
            if content.get("schema") != REPORT_SCHEMA or row["tombstoned_at"] is not None:
                raise ValueError("report schema is invalid")
            if row["control_json"] is None or row["control_sha256"] is None:
                raise ValueError("retained report control is missing")
            control, control_digest = self._control_from_row(row)
            brand = BrandTokens(**dict(content["brand"])).normalized()  # type: ignore[arg-type]
            snapshot_raw = dict(content["snapshot"])  # type: ignore[arg-type]
            snapshot_raw["sources"] = tuple(
                SourceManifestEntry(**dict(item)) for item in snapshot_raw["sources"]
            )
            snapshot_raw["metrics"] = tuple(
                ReportMetric(**dict(item)) for item in snapshot_raw["metrics"]
            )
            snapshot = ReportSnapshot(**snapshot_raw).normalized(
                max_sources=self._config.max_sources
            )
            state = str(control["state"])
            revision = int(control["control_revision"])
            revoked_at = control["revoked_at"]
            reason = control["revocation_reason"]
            if state not in {"active", "revoked"}:
                raise ValueError("invalid state")
            if state == "revoked":
                revoked_at = _timestamp(revoked_at, "revoked_at")
                reason = _id(reason, "revocation_reason")
            elif revoked_at is not None or reason is not None:
                raise ValueError("invalid revocation")
            artifact_available = bool(row["artifact_available"])
            tenant = _tenant(content["tenant_id"])
            identifier = _id(content["report_id"], "report_id")
            created_at = _timestamp(content["created_at"], "created_at")
            retained_until = _timestamp(content["retained_until"], "retained_until")
            pdf_sha256 = str(_digest(content["pdf_sha256"], "pdf_sha256"))
            if (
                tenant != self._tenant
                or identifier != str(row["report_id"])
                or control.get("report_id") != identifier
                or pdf_sha256 != str(row["pdf_sha256"])
                or created_at != float(row["created_at"])
                or retained_until != float(row["retained_until"])
            ):
                raise ValueError("indexed report columns differ from immutable content")
            if not artifact_available:
                raise ValueError("retained report artifact is missing")
            combined = canonical_sha256(
                {"content_sha256": content_digest, "control_sha256": control_digest}
            )
            return ExecutiveReportRecord(
                schema=REPORT_SCHEMA,
                tenant_id=tenant,
                report_id=identifier,
                role_view=_role(content["role_view"]),
                brand=brand,
                snapshot=snapshot,
                created_by_ref=_id(content["created_by_ref"], "created_by_ref"),
                created_at=created_at,
                retained_until=retained_until,
                pdf_sha256=pdf_sha256,
                pdf_bytes=_integer(content["pdf_bytes"], "pdf_bytes", 1, self._config.max_pdf_bytes),
                content_sha256=content_digest,
                state=state,
                control_revision=_integer(revision, "control_revision", 1, 2_147_483_647),
                revoked_at=revoked_at,
                revocation_reason=reason,
                control_sha256=control_digest,
                artifact_available=artifact_available,
                integrity_sha256=combined,
            )
        except ThirdPartyExecutiveReportError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ThirdPartyExecutiveReportIntegrityError(
                "executive_report_record_corrupt"
            ) from exc

    def create_report(
        self,
        *,
        snapshot: ReportSnapshot,
        brand: BrandTokens,
        idempotency_key: str,
        expected_absent_revision: int = 0,
        report_id: str | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> ExecutiveReportRecord | ExecutiveReportTombstone:
        actor = self._principal()
        selected_snapshot = snapshot.normalized(max_sources=self._config.max_sources)
        if selected_snapshot.tenant_id != self._tenant:
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_tenant_mismatch"
            )
        if selected_snapshot.role_view == "viewer":
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_viewer_cannot_create"
            )
        selected_brand = brand.normalized()
        _integer(expected_absent_revision, "expected_absent_revision", 0, 0)
        selected_report_id = None if report_id is None else _id(report_id, "report_id")
        now = _clock_value(self._clock)
        retained_until = now + self._config.retention_seconds
        request = {
            "operation": "create_report",
            "snapshot": asdict(selected_snapshot),
            "brand": asdict(selected_brand),
            "expected_absent_revision": expected_absent_revision,
            "report_id": selected_report_id,
        }
        request_sha = canonical_sha256(request)
        idem = _idempotency_sha256(idempotency_key)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if effect_guard is not None:
                effect_guard()
            replay = self._operation(connection, idem, request_sha)
            if replay is not None:
                report = self._row_record(connection, _id(replay["report_id"], "report_id"))
                connection.commit()
                return report
            self._retire_tombstones(connection, now=now)
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM executive_report_artifacts"
                ).fetchone()[0]
            )
            if count >= self._config.max_reports:
                raise ThirdPartyExecutiveReportConflict(
                    "executive_report_capacity_exceeded"
                )
            identifier = _id(selected_report_id or self._id_factory(), "report_id")
            if connection.execute(
                "SELECT 1 FROM executive_reports WHERE report_id=?", (identifier,)
            ).fetchone() is not None:
                raise ThirdPartyExecutiveReportConflict("executive_report_already_exists")
            pdf = render_deterministic_pdf(
                report_id=identifier,
                brand=selected_brand,
                snapshot=selected_snapshot,
                created_at=now,
                maximum_bytes=self._config.max_pdf_bytes,
            )
            pdf_sha = hashlib.sha256(pdf).hexdigest()
            content = _content_body(
                tenant_id=self._tenant,
                report_id=identifier,
                role_view=selected_snapshot.role_view,
                brand=selected_brand,
                snapshot=selected_snapshot,
                created_by_ref=actor,
                created_at=now,
                retained_until=retained_until,
                pdf_sha256=pdf_sha,
                pdf_bytes=len(pdf),
            )
            content_sha = canonical_sha256(content)
            control = _control_body(identifier, "active", 1, None, None)
            control_sha = canonical_sha256(control)
            connection.execute(
                "INSERT INTO executive_reports("
                "report_id,content_json,content_sha256,pdf_sha256,created_at,"
                "retained_until,tombstoned_at) VALUES(?,?,?,?,?,?,NULL)",
                (
                    identifier,
                    _canonical(content).decode("ascii"),
                    content_sha,
                    pdf_sha,
                    now,
                    retained_until,
                ),
            )
            connection.execute(
                "INSERT INTO executive_report_artifacts VALUES(?,?)",
                (identifier, sqlite3.Binary(pdf)),
            )
            connection.execute(
                "INSERT INTO executive_report_controls VALUES(?,?,?)",
                (identifier, _canonical(control).decode("ascii"), control_sha),
            )
            self._record_operation(
                connection,
                idem=idem,
                request_sha=request_sha,
                operation_type="create_report",
                report_id=identifier,
                result={"report_id": identifier},
                created_at=now,
            )
            self._audit_event(
                connection,
                action="report_created",
                report_id=identifier,
                actor_ref=actor,
                details={
                    "role_view": selected_snapshot.role_view,
                    "content_sha256": content_sha,
                    "pdf_sha256": pdf_sha,
                    "source_count": len(selected_snapshot.sources),
                },
                occurred_at=now,
            )
            result = self._row_record(connection, identifier)
            if effect_guard is not None:
                effect_guard()
            connection.commit()
            return result

    def creation_original(self, *, idempotency_key: str, report_id: str,
                         caller_role: str) -> Mapping[str, object] | None:
        """Read one native creation operation, without collecting or writing again."""
        actor = self._principal()
        identifier = _id(report_id, "report_id")
        idem = _idempotency_sha256(idempotency_key)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM executive_report_operations WHERE idempotency_sha256=?", (idem,)
            ).fetchone()
            if row is None:
                return None
            operation = self._operation_from_row(row)
            if operation["operation_type"] != "create_report" or operation["report_id"] != identifier:
                raise ThirdPartyExecutiveReportConflict("executive_report_idempotency_conflict")
            record = self._row_record(connection, identifier)
            if not self._access_allowed(record.role_view, caller_role):
                raise ThirdPartyExecutiveReportPermissionDenied("executive_report_role_mismatch")
            if isinstance(record, ExecutiveReportRecord) and record.created_by_ref != actor:
                raise ThirdPartyExecutiveReportPermissionDenied("executive_report_principal_changed")
            return {"report_id": identifier, "state": record.state,
                    "artifact_available": record.artifact_available}

    def get_report(
        self,
        report_id: str,
        *,
        caller_role: str,
    ) -> ExecutiveReportRecord | ExecutiveReportTombstone:
        self._principal()
        identifier = _id(report_id, "report_id")
        with self._connect() as connection:
            report = self._row_record(connection, identifier)
        if not self._access_allowed(report.role_view, caller_role):
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_role_mismatch"
            )
        return report

    def list_reports(
        self,
        *,
        caller_role: str,
        limit: int = 100,
    ) -> tuple[ExecutiveReportRecord | ExecutiveReportTombstone, ...]:
        self._principal()
        role = _role(caller_role)
        bounded = _integer(limit, "limit", 1, 500)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT report_id FROM executive_reports ORDER BY created_at DESC,report_id LIMIT ?",
                (min(self._config.max_reports, 2_000),),
            ).fetchall()
            reports = [self._row_record(connection, str(row["report_id"])) for row in rows]
        return tuple(
            report
            for report in reports
            if self._access_allowed(report.role_view, role)
        )[:bounded]

    def history_window(self, *, caller_role, offset=0, after=None, before=None, oldest=False):
        """Current role-scoped metadata windows without the recent-list cap."""
        from .metadata_history import sql_window
        self._principal()
        role = _role(caller_role)
        allowed = sorted(value for value in ROLE_VIEWS if self._access_allowed(value, role))
        where = ["json_extract(r.content_json,'$.role_view') IN (" + ",".join("?" for _ in allowed) + ")"]
        params = list(allowed)
        for value, operator in ((after, ">="), (before, "<")):
            if value is not None:
                where.append("r.created_at" + operator + "?")
                params.append(value)
        with self._connect() as connection:
            connection.execute("BEGIN")
            result = sql_window(connection.execute,
                table="executive_reports r LEFT JOIN executive_report_controls c USING(report_id)",
                columns="r.report_id", stamp="r.report_id,r.content_sha256,c.control_sha256",
                where=" AND ".join(where), params=tuple(params),
                order="r.created_at " + ("ASC" if oldest else "DESC") + ",r.report_id", offset=offset)
            reports = [self._row_record(connection, str(row[0])) for row in result.rows]
            result.rows = [row for row in reports if self._access_allowed(row.role_view, role)]
            return result

    def issue_download_grant(
        self,
        report_id: str,
        *,
        caller_role: str,
        expected_control_revision: int,
        idempotency_key: str,
    ) -> DownloadGrant:
        actor = self._principal()
        identifier = _id(report_id, "report_id")
        role = _role(caller_role)
        expected = _integer(
            expected_control_revision, "expected_control_revision", 1, 2_147_483_647
        )
        now = _clock_value(self._clock)
        request = {
            "operation": "issue_download_grant",
            "report_id": identifier,
            "caller_role": role,
            "expected_control_revision": expected,
            "principal_ref": actor,
        }
        request_sha = canonical_sha256(request)
        idem = _idempotency_sha256(idempotency_key)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._operation(connection, idem, request_sha)
            if replay is not None:
                connection.commit()
                return DownloadGrant(
                    GRANT_SCHEMA,
                    _id(replay["grant_id"], "grant_id"),
                    identifier,
                    expected,
                    _timestamp(replay["expires_at"], "expires_at"),
                    None,
                    False,
                    True,
                )
            report = self._row_record(connection, identifier)
            if not self._access_allowed(report.role_view, role):
                raise ThirdPartyExecutiveReportPermissionDenied(
                    "executive_report_role_mismatch"
                )
            if report.state != "active" or report.control_revision != expected:
                raise ThirdPartyExecutiveReportConflict(
                    "executive_report_control_changed"
                )
            if now >= report.retained_until or not report.artifact_available:
                raise ThirdPartyExecutiveReportConflict(
                    "executive_report_artifact_unavailable"
                )
            grant_capacity = _grant_capacity(self._config)
            self._retire_stale_grants(
                connection,
                now=now,
                limit=grant_capacity,
            )
            grant_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM executive_report_download_grants"
                ).fetchone()[0]
            )
            if grant_count >= grant_capacity:
                raise ThirdPartyExecutiveReportConflict(
                    "executive_report_download_grant_capacity_exceeded"
                )
            token = ""
            token_sha = ""
            for _attempt in range(3):
                candidate = self._token_factory()
                if not isinstance(candidate, str) or _TOKEN_RE.fullmatch(candidate) is None:
                    raise ThirdPartyExecutiveReportConfigError(
                        "executive_report_token_factory_invalid"
                    )
                candidate_sha = hashlib.sha256(candidate.encode("ascii")).hexdigest()
                if connection.execute(
                    "SELECT 1 FROM executive_report_download_grants WHERE token_sha256=?",
                    (candidate_sha,),
                ).fetchone() is None:
                    token = candidate
                    token_sha = candidate_sha
                    break
            if not token:
                raise ThirdPartyExecutiveReportConfigError(
                    "executive_report_token_factory_collision"
                )
            grant_id = _id(f"grant_{token_sha[:32]}", "grant_id")
            expires_at = min(
                report.retained_until,
                now + self._config.download_token_seconds,
            )
            grant_body = {
                "schema": GRANT_SCHEMA,
                "grant_id": grant_id,
                "report_id": identifier,
                "token_sha256": token_sha,
                "principal_ref": actor,
                "report_control_revision": expected,
                "expires_at": expires_at,
                "created_at": now,
                "redeemed_at": None,
            }
            grant_sha = canonical_sha256(grant_body)
            connection.execute(
                "INSERT INTO executive_report_download_grants VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    grant_id,
                    identifier,
                    token_sha,
                    actor,
                    expected,
                    expires_at,
                    None,
                    _canonical(grant_body).decode("ascii"),
                    grant_sha,
                ),
            )
            result = {"grant_id": grant_id, "expires_at": expires_at}
            self._record_operation(
                connection,
                idem=idem,
                request_sha=request_sha,
                operation_type="issue_download_grant",
                report_id=identifier,
                result=result,
                created_at=now,
            )
            self._audit_event(
                connection,
                action="download_grant_issued",
                report_id=identifier,
                actor_ref=actor,
                details={
                    "grant_id": grant_id,
                    "token_sha256": token_sha,
                    "expires_at": expires_at,
                },
                occurred_at=now,
            )
            connection.commit()
            return DownloadGrant(
                GRANT_SCHEMA,
                grant_id,
                identifier,
                expected,
                expires_at,
                token,
                True,
                False,
            )

    def redeem_download_token(self, token: str, *, caller_role: str) -> DownloadArtifact:
        actor = self._principal()
        role = _role(caller_role)
        if not isinstance(token, str) or _TOKEN_RE.fullmatch(token) is None:
            raise ThirdPartyExecutiveReportNotFound(
                "executive_report_download_grant_not_found"
            )
        token_sha = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = _clock_value(self._clock)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            grant = connection.execute(
                "SELECT * FROM executive_report_download_grants WHERE token_sha256=?",
                (token_sha,),
            ).fetchone()
            if grant is None:
                raise ThirdPartyExecutiveReportNotFound(
                    "executive_report_download_grant_not_found"
                )
            grant_body = self._grant_from_row(grant)
            report = self._row_record(connection, str(grant["report_id"]))
            if (
                str(grant["principal_ref"]) != actor
                or not self._access_allowed(report.role_view, role)
            ):
                raise ThirdPartyExecutiveReportNotFound(
                    "executive_report_download_grant_not_found"
                )
            if (
                grant["redeemed_at"] is not None
                or now >= float(grant["expires_at"])
                or now >= report.retained_until
                or report.state != "active"
                or int(grant["report_control_revision"]) != report.control_revision
            ):
                raise ThirdPartyExecutiveReportConflict(
                    "executive_report_download_grant_inactive"
                )
            artifact = connection.execute(
                "SELECT pdf_blob FROM executive_report_artifacts WHERE report_id=?",
                (report.report_id,),
            ).fetchone()
            if artifact is None:
                raise ThirdPartyExecutiveReportConflict(
                    "executive_report_artifact_unavailable"
                )
            pdf = bytes(artifact["pdf_blob"])
            if len(pdf) != report.pdf_bytes or not hmac.compare_digest(
                hashlib.sha256(pdf).hexdigest(), report.pdf_sha256
            ):
                raise ThirdPartyExecutiveReportIntegrityError(
                    "executive_report_pdf_integrity_failed"
                )
            updated_grant = {**dict(grant_body), "redeemed_at": now}
            connection.execute(
                "UPDATE executive_report_download_grants SET "
                "redeemed_at=?,grant_json=?,integrity_sha256=? WHERE grant_id=?",
                (
                    now,
                    _canonical(updated_grant).decode("ascii"),
                    canonical_sha256(updated_grant),
                    str(grant["grant_id"]),
                ),
            )
            self._audit_event(
                connection,
                action="download_grant_redeemed",
                report_id=report.report_id,
                actor_ref=actor,
                details={"grant_id": str(grant["grant_id"]), "pdf_sha256": report.pdf_sha256},
                occurred_at=now,
            )
            connection.commit()
            return DownloadArtifact(report.report_id, report.pdf_sha256, pdf)

    def revoke_report(
        self,
        report_id: str,
        *,
        expected_control_revision: int,
        reason_code: str,
        idempotency_key: str,
    ) -> ExecutiveReportRecord:
        actor = self._principal()
        if self._maintenance_authorizer() is not True:
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_maintenance_denied"
            )
        identifier = _id(report_id, "report_id")
        expected = _integer(
            expected_control_revision, "expected_control_revision", 1, 2_147_483_647
        )
        reason = _id(reason_code, "revocation_reason")
        now = _clock_value(self._clock)
        request = {
            "operation": "revoke_report",
            "report_id": identifier,
            "expected_control_revision": expected,
            "reason_code": reason,
        }
        request_sha = canonical_sha256(request)
        idem = _idempotency_sha256(idempotency_key)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._operation(connection, idem, request_sha)
            if replay is not None:
                report = self._row_record(connection, identifier)
                connection.commit()
                return report
            report = self._row_record(connection, identifier)
            if report.state != "active" or report.control_revision != expected:
                raise ThirdPartyExecutiveReportConflict(
                    "executive_report_control_changed"
                )
            control = _control_body(identifier, "revoked", expected + 1, now, reason)
            control_sha = canonical_sha256(control)
            connection.execute(
                "UPDATE executive_report_controls SET control_json=?,control_sha256=? "
                "WHERE report_id=?",
                (_canonical(control).decode("ascii"), control_sha, identifier),
            )
            self._record_operation(
                connection,
                idem=idem,
                request_sha=request_sha,
                operation_type="revoke_report",
                report_id=identifier,
                result={"report_id": identifier, "control_revision": expected + 1},
                created_at=now,
            )
            self._audit_event(
                connection,
                action="report_revoked",
                report_id=identifier,
                actor_ref=actor,
                details={"control_revision": expected + 1, "reason_code": reason},
                occurred_at=now,
            )
            connection.commit()
            return self._row_record(connection, identifier)

    def purge_expired(
        self,
        *,
        limit: int,
        idempotency_key: str,
    ) -> tuple[str, ...]:
        actor = self._principal()
        if self._maintenance_authorizer() is not True:
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_maintenance_denied"
            )
        bounded = _integer(limit, "limit", 1, 1_000)
        now = _clock_value(self._clock)
        request = {"operation": "purge_expired", "limit": bounded}
        request_sha = canonical_sha256(request)
        idem = _idempotency_sha256(idempotency_key)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._operation(connection, idem, request_sha)
            if replay is not None:
                values = replay.get("report_ids")
                if not isinstance(values, list):
                    raise ThirdPartyExecutiveReportIntegrityError(
                        "executive_report_operation_corrupt"
                    )
                connection.commit()
                return tuple(_id(item, "report_id") for item in values)
            retired_grants = self._retire_stale_grants(
                connection,
                now=now,
                limit=_grant_capacity(self._config),
            )
            retired_tombstones = list(
                self._retire_tombstones(connection, now=now)
            )
            rows = connection.execute(
                "SELECT report_id FROM executive_reports WHERE retained_until<=? "
                "AND report_id IN (SELECT report_id FROM executive_report_artifacts) "
                "ORDER BY retained_until,report_id LIMIT ?",
                (now, bounded),
            ).fetchall()
            report_ids: list[str] = []
            for row in rows:
                identifier = _id(row["report_id"], "report_id")
                report = self._row_record(connection, identifier)
                if not isinstance(report, ExecutiveReportRecord):
                    raise ThirdPartyExecutiveReportIntegrityError(
                        "executive_report_retained_record_invalid"
                    )
                control = _control_body(
                    identifier,
                    "expired",
                    report.control_revision + 1,
                    None,
                    None,
                )
                control_sha = canonical_sha256(control)
                retired_tombstones.extend(
                    self._retire_tombstones(connection, now=now, reserve=1)
                )
                tombstone = _privacy_tombstone_body(
                    tenant_id=self._tenant,
                    report_id=identifier,
                    role_view=report.role_view,
                    created_at=report.created_at,
                    retained_until=report.retained_until,
                    purged_at=now,
                    pdf_sha256=report.pdf_sha256,
                    pdf_bytes=report.pdf_bytes,
                    original_content_sha256=report.content_sha256,
                    terminal_control_sha256=control_sha,
                    control_revision=report.control_revision + 1,
                )
                connection.execute(
                    "DELETE FROM executive_report_download_grants WHERE report_id=?",
                    (identifier,),
                )
                connection.execute(
                    "DELETE FROM executive_report_artifacts WHERE report_id=?",
                    (identifier,),
                )
                connection.execute(
                    "DELETE FROM executive_report_controls WHERE report_id=?",
                    (identifier,),
                )
                connection.execute(
                    "UPDATE executive_reports SET content_json=?,content_sha256=?,"
                    "tombstoned_at=? WHERE report_id=?",
                    (
                        _canonical(
                            tombstone,
                            maximum=_MAX_TOMBSTONE_BYTES,
                        ).decode("ascii"),
                        canonical_sha256(tombstone),
                        now,
                        identifier,
                    ),
                )
                self._retire_operations(
                    connection,
                    now=now,
                    report_ids=(identifier,),
                )
                self._audit_event(
                    connection,
                    action="report_content_expired",
                    report_id=identifier,
                    actor_ref=actor,
                    details={"pdf_sha256": report.pdf_sha256},
                    occurred_at=now,
                )
                report_ids.append(identifier)
            result = {
                "report_ids": report_ids,
                "retired_grant_count": len(retired_grants),
                "retired_tombstone_count": len(retired_tombstones),
            }
            self._record_operation(
                connection,
                idem=idem,
                request_sha=request_sha,
                operation_type="purge_expired",
                report_id=None,
                result=result,
                created_at=now,
            )
            connection.commit()
            return tuple(report_ids)

    def audit_history(self, *, limit: int = 100) -> tuple[Mapping[str, object], ...]:
        self._principal()
        if self._audit_authorizer() is not True:
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_audit_denied"
            )
        bounded = _integer(limit, "limit", 1, _MAX_AUDIT)
        with self._connect() as connection:
            checkpoint, _checkpoint_digest = self._audit_checkpoint(connection)
            rows = connection.execute(
                "SELECT * FROM executive_report_audit ORDER BY sequence",
            ).fetchall()
            previous = str(checkpoint["terminal_audit_sha256"])
            sequence = int(checkpoint["compacted_through_sequence"])
            events: list[Mapping[str, object]] = []
            for offset, row in enumerate(rows, 1):
                event, previous = self._audit_event_from_row(
                    row,
                    expected_sequence=sequence + offset,
                    previous_sha256=previous,
                )
                events.append(event)
            return tuple(reversed(events[-bounded:]))

    def verify_integrity(self) -> IntegrityVerification:
        self._principal()
        if self._audit_authorizer() is not True:
            raise ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_audit_denied"
            )
        with self._connect() as connection:
            report_rows = connection.execute(
                "SELECT report_id FROM executive_reports ORDER BY report_id"
            ).fetchall()
            reports = [self._row_record(connection, str(row["report_id"])) for row in report_rows]
            artifacts = connection.execute(
                "SELECT report_id,pdf_blob FROM executive_report_artifacts ORDER BY report_id"
            ).fetchall()
            report_map = {report.report_id: report for report in reports}
            for artifact in artifacts:
                identifier = str(artifact["report_id"])
                report = report_map.get(identifier)
                pdf = bytes(artifact["pdf_blob"])
                if report is None or len(pdf) != report.pdf_bytes or not hmac.compare_digest(
                    hashlib.sha256(pdf).hexdigest(), report.pdf_sha256
                ):
                    raise ThirdPartyExecutiveReportIntegrityError(
                        "executive_report_pdf_integrity_failed"
                    )
            grant_rows = connection.execute(
                "SELECT * FROM executive_report_download_grants ORDER BY grant_id"
            ).fetchall()
            for row in grant_rows:
                self._grant_from_row(row)
            operation_rows = connection.execute(
                "SELECT * FROM executive_report_operations "
                "ORDER BY idempotency_sha256"
            ).fetchall()
            if len(operation_rows) > _operation_capacity(self._config):
                raise ThirdPartyExecutiveReportIntegrityError(
                    "executive_report_operation_capacity_exceeded"
                )
            for row in operation_rows:
                self._operation_from_row(row)
            audit_rows = connection.execute(
                "SELECT * FROM executive_report_audit ORDER BY sequence"
            ).fetchall()
            if len(audit_rows) > _audit_capacity(self._config):
                raise ThirdPartyExecutiveReportIntegrityError(
                    "executive_report_audit_capacity_exceeded"
                )
            checkpoint, _checkpoint_digest = self._audit_checkpoint(connection)
            checkpoint_sequence = int(checkpoint["compacted_through_sequence"])
            checkpoint_terminal = str(checkpoint["terminal_audit_sha256"])
            previous = checkpoint_terminal
            for offset, row in enumerate(audit_rows, 1):
                _event, previous = self._audit_event_from_row(
                    row,
                    expected_sequence=checkpoint_sequence + offset,
                    previous_sha256=previous,
                )
            tombstone_count = sum(
                isinstance(report, ExecutiveReportTombstone) for report in reports
            )
            if tombstone_count > self._config.max_reports:
                raise ThirdPartyExecutiveReportIntegrityError(
                    "executive_report_tombstone_capacity_exceeded"
                )
            return IntegrityVerification(
                reports=len(reports),
                tombstones=tombstone_count,
                artifacts=len(artifacts),
                grants=len(grant_rows),
                operations=len(operation_rows),
                audit_events=len(audit_rows),
                audit_checkpoint_sequence=checkpoint_sequence,
                audit_checkpoint_sha256=checkpoint_terminal,
                terminal_audit_sha256=previous,
            )


__all__ = [
    "AUDIT_SCHEMA",
    "AUDIT_CHECKPOINT_SCHEMA",
    "BRAND_SCHEMA",
    "CONTROL_SCHEMA",
    "DownloadArtifact",
    "DownloadGrant",
    "ExecutiveReportRecord",
    "ExecutiveReportTombstone",
    "GRANT_SCHEMA",
    "IntegrityVerification",
    "LIVE_PORTFOLIO_ACCEPTANCE_VERIFIED",
    "METRIC_IDS",
    "OPERATION_SCHEMA",
    "REPORT_SCHEMA",
    "ROLE_VIEWS",
    "ReportMetric",
    "ReportSnapshot",
    "SNAPSHOT_SCHEMA",
    "SOURCE_KINDS",
    "SOURCE_REASONS",
    "SOURCE_SCHEMA",
    "TOMBSTONE_SCHEMA",
    "SourceManifestEntry",
    "SourceSelector",
    "ThirdPartyExecutiveReportConfig",
    "ThirdPartyExecutiveReportConfigError",
    "ThirdPartyExecutiveReportConflict",
    "ThirdPartyExecutiveReportError",
    "ThirdPartyExecutiveReportIntegrityError",
    "ThirdPartyExecutiveReportNotFound",
    "ThirdPartyExecutiveReportPermissionDenied",
    "ThirdPartyExecutiveReportStore",
    "ThirdPartyExecutiveReportValidationError",
    "BrandTokens",
    "canonical_sha256",
    "render_deterministic_pdf",
]
