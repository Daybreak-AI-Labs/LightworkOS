"""Governed customer sandbox tenant-copy lifecycle.

This is a managed *tenant copy* control plane, not a code-execution sandbox.
Only an explicitly allowlisted, recursively sanitized configuration snapshot may
cross from a production tenant into a separately named sandbox workspace.  The
source resolver, authenticated principal resolver, feature gate, and local
provisioner are injected authorities; callers never supply configuration data,
credentials, paths, or registry records.

The bundled provisioner is deliberately local and bounded.  It writes an
isolated sandbox registry plus immutable snapshot files below an exact injected
root and performs no network I/O.  Live hosted operations, customer acceptance,
and production-scale recovery remain external acceptance work.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import shutil
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    require_private_directory,
)
from .paths import canonical_tenant_id

SNAPSHOT_SCHEMA = "lightwork.customer-sandbox-snapshot.v1"
RECORD_SCHEMA = "lightwork.customer-sandbox-lifecycle.v1"
RECEIPT_SCHEMA = "lightwork.customer-sandbox-provisioning-receipt.v1"
TARGET_AUTHORITY_SCHEMA = "lightwork.customer-sandbox-target-authority.v1"
AUDIT_SCHEMA = "lightwork.customer-sandbox-audit-event.v1"
TOMBSTONE_SCHEMA = "lightwork.customer-sandbox-tombstone.v1"

SUPPORTED_SANDBOX_MODULES = frozenset(
    {
        "ai_governance",
        "consent_preferences",
        "data_use_governance",
        "privacy_automation",
        "tech_risk_compliance",
        "third_party_management",
    }
)

_STATES = frozenset(
    {
        "requested",
        "approved",
        "resync_requested",
        "resync_approved",
        "provisioning",
        "active",
        "suspended",
        "expired",
        "failed",
        "abandon_requested",
        "abandon_approved",
        "destroy_requested",
        "destroy_approved",
        "destroyed",
    }
)
_ACTIVE_TARGET_STATES = frozenset({"active", "suspended", "expired"})
_ACTIONS = frozenset(
    {
        "request_sandbox",
        "approve_sandbox",
        "provision_sandbox",
        "retry_provision",
        "suspend_sandbox",
        "resume_sandbox",
        "expire_sandbox",
        "request_resync",
        "approve_resync",
        "request_destroy",
        "approve_destroy",
        "destroy_sandbox",
        "request_abandon",
        "approve_abandon",
    }
)
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_VALUE_RE = re.compile(
    r"(?:\A\s*(?:\$\{?[A-Z][A-Z0-9_]*\}?|env:|vault:|secret:|bearer\s+|sk-[A-Za-z0-9])"
    r"|-----BEGIN [A-Z ]+PRIVATE KEY-----|https?://)",
    re.IGNORECASE,
)
_PROHIBITED_KEY_RE = re.compile(
    r"(?:secret|credential|password|passphrase|token|api[_-]?key|private[_-]?key|"
    r"authorization|cookie|provider|origin|endpoint|url|uri|connection|principal|"
    r"database|db[_-]?path|world|audit|raw|document|record|event|user[_-]?data|"
    r"file[_-]?path|storage[_-]?path)",
    re.IGNORECASE,
)

_SAFE_STRING_VALUES = frozenset(
    {
        "allow",
        "approve",
        "automatic",
        "block",
        "ccpa",
        "consent",
        "contract",
        "critical",
        "delete",
        "disabled",
        "enabled",
        "enforce",
        "eu",
        "gdpr",
        "global",
        "high",
        "legal_obligation",
        "legitimate_interest",
        "low",
        "manual",
        "medium",
        "monitor",
        "none",
        "notify",
        "off",
        "on",
        "reject",
        "retain",
        "review",
        "strict-review",
        "us",
        "warn",
    }
)
_EXPORT_LEAF = "__leaf__"
_EXPORT_DROP = "__drop__"
_ENABLE_ONLY = {"enable": _EXPORT_LEAF}
_GENERIC_SAFE = {
    "enable": _EXPORT_LEAF,
    "enabled": _EXPORT_LEAF,
    "mode": _EXPORT_LEAF,
    "require_approval": _EXPORT_LEAF,
    "review_required": _EXPORT_LEAF,
    "retention_days": _EXPORT_LEAF,
    "review_days": _EXPORT_LEAF,
    "threshold": _EXPORT_LEAF,
    "severity": _EXPORT_LEAF,
}
_LIMITS = {
    "items": _EXPORT_LEAF,
    "maximum": _EXPORT_LEAF,
    "minimum": _EXPORT_LEAF,
    "max_assets": _EXPORT_LEAF,
    "max_fields": _EXPORT_LEAF,
    "max_lineage_edges": _EXPORT_LEAF,
    "max_context_age_seconds": _EXPORT_LEAF,
}
_SCHEDULER = {
    "enable": _EXPORT_LEAF,
    "poll_seconds": _EXPORT_LEAF,
    "enqueue_limit": _EXPORT_LEAF,
    "claim_limit": _EXPORT_LEAF,
    "tenant_limit": _EXPORT_LEAF,
    "lease_seconds": _EXPORT_LEAF,
    "event_limit": _EXPORT_LEAF,
    "retry_backoff_seconds": _EXPORT_LEAF,
    "purge_limit": _EXPORT_LEAF,
    "history_limit": _EXPORT_LEAF,
}
_EXPORT_SCHEMAS: Mapping[str, Mapping[str, object]] = {
    "ai_governance": {
        **_GENERIC_SAFE,
        "limits": _LIMITS,
        "thresholds": _LIMITS,
        "risk_levels": _EXPORT_LEAF,
        "controls": _EXPORT_LEAF,
        "frameworks": _EXPORT_LEAF,
        "ai_business_intake": _ENABLE_ONLY,
        "ai_inventory": {
            "enable": _EXPORT_LEAF,
            "page_cap": _EXPORT_LEAF,
            "record_cap": _EXPORT_LEAF,
            "retry_attempts": _EXPORT_LEAF,
            "timeout_seconds": _EXPORT_LEAF,
            "missing_grace_runs": _EXPORT_LEAF,
            "poll_seconds": _EXPORT_LEAF,
        },
        "ai_vendor_risk": {"enable": _EXPORT_LEAF, "portal_enable": _EXPORT_LEAF},
        "ai_regulatory_feed": _ENABLE_ONLY,
        "ai_cost_roi": {
            "enable": _EXPORT_LEAF,
            "collector_poll_seconds": _EXPORT_LEAF,
            "collector_lookback_days": _EXPORT_LEAF,
        },
        "ai_bank_mrm": _ENABLE_ONLY,
        "ai_benchmark_exchange": _ENABLE_ONLY,
        "ai_conformity_workflow": _ENABLE_ONLY,
        "ai_discovery_sensors": _ENABLE_ONLY,
        "ai_dynamic_risk": _ENABLE_ONLY,
        "ai_explainability": _ENABLE_ONLY,
        "ai_identity_governance_connectors": _ENABLE_ONLY,
        "ai_insurability": _ENABLE_ONLY,
        "ai_literacy": _ENABLE_ONLY,
        "ai_media_provenance": _ENABLE_ONLY,
        "ai_policy_management": _ENABLE_ONLY,
        "ai_runtime_guardrails": _ENABLE_ONLY,
        "ai_regulated_verticals": _ENABLE_ONLY,
        "policy_packs": _ENABLE_ONLY,
        "portfolio_risk": _ENABLE_ONLY,
        "drift_monitoring": {
            "enable": _EXPORT_LEAF,
            "bins": _EXPORT_LEAF,
            "min_samples": _EXPORT_LEAF,
            "psi_threshold": _EXPORT_LEAF,
            "kl_threshold": _EXPORT_LEAF,
            "embedding_cosine_threshold": _EXPORT_LEAF,
            "performance_decay_threshold": _EXPORT_LEAF,
            "evidence_validity_seconds": _EXPORT_LEAF,
        },
        "agent_topology": _ENABLE_ONLY,
        "red_team_assurance": {
            "enable": _EXPORT_LEAF,
            "max_cases": _EXPORT_LEAF,
            "max_response_bytes": _EXPORT_LEAF,
            "campaign_ttl_seconds": _EXPORT_LEAF,
            "evidence_validity_seconds": _EXPORT_LEAF,
            "scheduler_poll_seconds": _EXPORT_LEAF,
        },
        "eu_ai_incidents": _ENABLE_ONLY,
        "grc_outbound_sync": {
            "enable": _EXPORT_LEAF,
            "max_attempts_per_revision": _EXPORT_LEAF,
        },
    },
    "consent_preferences": {
        "enable": _EXPORT_LEAF,
        "publishing": {"enable": _EXPORT_LEAF, "require_signed_publications": _EXPORT_LEAF},
        "public_api": {
            "enable": _EXPORT_LEAF,
            "token_ttl_seconds": _EXPORT_LEAF,
            "max_request_bytes": _EXPORT_LEAF,
            "max_response_bytes": _EXPORT_LEAF,
            "requests_per_minute": _EXPORT_LEAF,
        },
        "scanner": {
            "enable": _EXPORT_LEAF,
            "notice_proposals": _ENABLE_ONLY,
            "scheduler": _SCHEDULER,
            "interval_seconds": _EXPORT_LEAF,
            "max_pages": _EXPORT_LEAF,
            "max_depth": _EXPORT_LEAF,
            "page_timeout_seconds": _EXPORT_LEAF,
            "max_network_events": _EXPORT_LEAF,
            "allow_authenticated_scans": _EXPORT_LEAF,
        },
        "standards": {
            "gpc": _EXPORT_LEAF,
            "dnt": _EXPORT_LEAF,
            "gpp": _EXPORT_LEAF,
            "tcf": _EXPORT_LEAF,
            "google_consent_mode": _EXPORT_LEAF,
        },
        "identity": _EXPORT_DROP,
        "delivery": {
            "enable": _EXPORT_LEAF,
            "max_attempts": _EXPORT_LEAF,
            "retry_base_seconds": _EXPORT_LEAF,
            "retry_max_seconds": _EXPORT_LEAF,
        },
        "analytics": {
            "enable": _EXPORT_LEAF,
            "min_cohort_size": _EXPORT_LEAF,
            "retention_days": _EXPORT_LEAF,
        },
        "experiments": _ENABLE_ONLY,
        "profile_data": _ENABLE_ONLY,
        "trust_center": _ENABLE_ONLY,
        "storage": _EXPORT_DROP,
        "edge_cache": {
            "enable": _EXPORT_LEAF,
            "max_age_seconds": _EXPORT_LEAF,
            "stale_if_error_seconds": _EXPORT_LEAF,
        },
        "limits": {
            **_LIMITS,
            "profile_page_size": _EXPORT_LEAF,
            "receipt_page_size": _EXPORT_LEAF,
            "request_body_bytes": _EXPORT_LEAF,
        },
    },
    "data_use_governance": {
        "enable": _EXPORT_LEAF,
        "compiler": {
            "enable": _EXPORT_LEAF,
            "max_operations": _EXPORT_LEAF,
            "max_row_filter_nodes": _EXPORT_LEAF,
        },
        "enforcement": {
            "enable": _EXPORT_LEAF,
            "require_four_eyes": _EXPORT_LEAF,
            "max_attempts": _EXPORT_LEAF,
            "retry_base_seconds": _EXPORT_LEAF,
            "retry_max_seconds": _EXPORT_LEAF,
        },
        "provider_audit": {
            "enable": _EXPORT_LEAF,
            "audit_window_seconds": _EXPORT_LEAF,
            "retention_seconds": _EXPORT_LEAF,
            "max_attempts": _EXPORT_LEAF,
            "snowflake_latency_watermark_seconds": _EXPORT_LEAF,
            "cursor_overlap_seconds": _EXPORT_LEAF,
            "max_pages_per_read": _EXPORT_LEAF,
            "scheduler": _SCHEDULER,
        },
        "scheduler": _SCHEDULER,
        "snowflake": _EXPORT_DROP,
        "databricks": _EXPORT_DROP,
        "limits": _LIMITS,
    },
    "privacy_automation": {
        "enable": _EXPORT_LEAF,
        "data_discovery": _ENABLE_ONLY,
        "regulatory_intelligence": _ENABLE_ONLY,
        "rights_orchestration": _ENABLE_ONLY,
        "rights_consumer_delivery": _ENABLE_ONLY,
        "ott_ctv_rights": _ENABLE_ONLY,
        "drop_management": {
            "enable": _EXPORT_LEAF,
            "principal_binding_key_ref": _EXPORT_DROP,
            "retention_seconds": _EXPORT_LEAF,
            "scheduler_enable": _EXPORT_LEAF,
            "scheduler_interval_seconds": _EXPORT_LEAF,
            "scheduler_jitter_seconds": _EXPORT_LEAF,
            "scheduler_retry_max_seconds": _EXPORT_LEAF,
        },
        "notice_governance": _ENABLE_ONLY,
    },
    "tech_risk_compliance": {
        "enable": _EXPORT_LEAF,
        "continuous_evidence": {
            **_ENABLE_ONLY,
            # Collector names select live provider/runtime material and are
            # intentionally not portable sandbox configuration.
            "enabled_collectors": _EXPORT_DROP,
            "scheduler": _SCHEDULER,
        },
        "policy_publication_links": _ENABLE_ONLY,
        "scoping": _ENABLE_ONLY,
        "scope_actions": _ENABLE_ONLY,
    },
    "third_party_management": {
        "enable": _EXPORT_LEAF,
        "intelligence": {
            "enable": _EXPORT_LEAF,
            # Provider enrollment is target-specific live authority.
            "providers": _EXPORT_DROP,
        },
        "lifecycle": _ENABLE_ONLY,
    },
}
AI_GOVERNANCE_SOURCE_SECTIONS = frozenset(
    set(_EXPORT_SCHEMAS["ai_governance"])
    - {
        "controls",
        "enable",
        "enabled",
        "frameworks",
        "limits",
        "mode",
        "require_approval",
        "retention_days",
        "review_days",
        "review_required",
        "risk_levels",
        "severity",
        "threshold",
        "thresholds",
    }
)

_MAX_SNAPSHOT_BYTES = 256 * 1024
_MAX_MODULES = 6
_MAX_DEPTH = 10
_MAX_NODES = 8_192
_MAX_SEQUENCE = 512
_MAX_MAPPING = 512
_MAX_STRING = 2_048
_MAX_SNAPSHOTS_PER_SANDBOX = 20
_MAX_QUOTA_BYTES = 50 * 1024 * 1024
_MAX_RETENTION_SECONDS = 366 * 24 * 60 * 60
_MAX_EXPIRY_SECONDS = 90 * 24 * 60 * 60


class CustomerSandboxError(RuntimeError):
    """Base error with a closed, persistable code."""

    def __init__(self, error_code: str) -> None:
        self.error_code = _error_code(error_code)
        super().__init__(self.error_code)


class CustomerSandboxConfigError(CustomerSandboxError):
    """The feature gate or injected authority is unavailable."""


class CustomerSandboxValidationError(CustomerSandboxError):
    """A bounded request or sanitized snapshot is invalid."""


class CustomerSandboxConflict(CustomerSandboxError):
    """CAS, idempotency, authority, or lifecycle state changed."""


class CustomerSandboxPermissionDenied(CustomerSandboxError):
    """Four-eyes separation or authenticated authority is insufficient."""


class CustomerSandboxNotFound(CustomerSandboxError):
    """A lifecycle record does not exist."""


class CustomerSandboxIntegrityError(CustomerSandboxError):
    """Persisted lifecycle or workspace authority cannot be trusted."""


class CustomerSandboxProvisioningError(CustomerSandboxError):
    """A bounded local provisioning operation needs retry/recovery."""


@dataclass(frozen=True, slots=True, repr=False)
class SourceTenantConfiguration:
    """Trusted source authority; raw configuration is never persisted directly."""

    tenant_id: str
    revision: int
    config_sha256: str
    config: Mapping[str, Any]


@dataclass(frozen=True, slots=True, repr=False)
class SanitizedSandboxSnapshot:
    schema: str
    sandbox_id: str
    source_tenant_id: str
    source_revision: int
    source_config_sha256: str
    target_sandbox_id: str
    snapshot_revision: int
    module_allowlist: tuple[str, ...]
    modules: Mapping[str, Any]
    expires_at: float
    retained_until: float
    plan: str
    quota_bytes: int
    created_at: float
    snapshot_sha256: str


@dataclass(frozen=True, slots=True)
class CustomerSandboxRecord:
    schema: str
    sandbox_id: str
    source_tenant_id: str
    source_revision: int
    source_config_sha256: str
    target_sandbox_id: str
    snapshot_revision: int
    snapshot_sha256: str
    module_allowlist: tuple[str, ...]
    expires_at: float
    retained_until: float
    plan: str
    quota_bytes: int
    state: str
    operation_kind: str
    revision: int
    attempts: int
    max_attempts: int
    requested_by_sha256: str
    approved_by_sha256: str | None
    destroy_requested_by_sha256: str | None
    destroy_approved_by_sha256: str | None
    workspace_sha256: str | None
    last_error_code: str | None
    created_at: float
    updated_at: float
    destroyed_at: float | None
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class SandboxTargetAuthority:
    schema: str
    sandbox_id: str
    target_sandbox_id: str
    snapshot_sha256: str
    workspace_sha256: str
    status: str
    plan: str
    quota_bytes: int
    expires_at: float


@dataclass(frozen=True, slots=True)
class SandboxProvisioningReceipt:
    schema: str
    sandbox_id: str
    target_sandbox_id: str
    snapshot_sha256: str
    workspace_sha256: str | None
    status: str
    no_change: bool
    files_written: int
    bytes_written: int


@dataclass(frozen=True, slots=True)
class CustomerSandboxAuditEvent:
    schema: str
    sequence: int
    sandbox_id: str
    action: str
    detail_sha256: str
    principal_sha256: str
    occurred_at: float
    previous_sha256: str
    event_sha256: str


@dataclass(frozen=True, slots=True)
class CustomerSandboxTombstone:
    schema: str
    sandbox_id: str
    source_tenant_sha256: str
    target_sandbox_sha256: str
    final_record_sha256: str
    destroyed_at: float
    retained_until: float
    purged_at: float
    purged_by_sha256: str
    idempotency_key_sha256: str
    request_sha256: str
    tombstone_sha256: str


SourceConfigurationResolver = Callable[[str], SourceTenantConfiguration]
PrincipalResolver = Callable[[], str]
ConfigGate = Callable[[], None]
TargetCollisionResolver = Callable[[str], bool]


def _canonical(value: object, *, maximum: int = _MAX_SNAPSHOT_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise CustomerSandboxValidationError("sandbox_payload_invalid") from exc
    if not 1 <= len(encoded) <= maximum:
        raise CustomerSandboxValidationError("sandbox_payload_oversized")
    return encoded


def _sha256(value: object, *, maximum: int = _MAX_SNAPSHOT_BYTES) -> str:
    return hashlib.sha256(_canonical(value, maximum=maximum)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise CustomerSandboxValidationError("sandbox_digest_invalid")
    return value


def _opaque_id(value: object, *, label: str = "sandbox identifier") -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None or _CONTROL_RE.search(value):
        raise CustomerSandboxValidationError(f"{label.replace(' ', '_')}_invalid")
    return value


def _sandbox_tenant_id(value: object) -> str:
    """Require a portable slug even though generic tenant paths can percent-encode."""

    return canonical_tenant_id(_opaque_id(value, label="sandbox tenant identifier"))


def _operation_key(value: object) -> str:
    if not isinstance(value, str) or _OP_RE.fullmatch(value) is None:
        raise CustomerSandboxValidationError("sandbox_idempotency_key_invalid")
    return _text_sha256("lightwork.customer-sandbox.idempotency.v1:" + value)


def _error_code(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", value):
        raise ValueError("customer sandbox error code is invalid")
    return value


def _timestamp(value: object, *, label: str = "timestamp") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CustomerSandboxValidationError(f"sandbox_{label}_invalid")
    selected = float(value)
    if not math.isfinite(selected) or selected <= 0:
        raise CustomerSandboxValidationError(f"sandbox_{label}_invalid")
    return selected


def _integer(value: object, *, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CustomerSandboxValidationError(f"sandbox_{label}_invalid")
    return value


def _principal_sha256(resolver: PrincipalResolver) -> str:
    try:
        principal = resolver()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise CustomerSandboxConfigError("sandbox_principal_authority_unavailable") from exc
    if not isinstance(principal, str) or _ID_RE.fullmatch(principal) is None:
        raise CustomerSandboxPermissionDenied("sandbox_principal_invalid")
    return _text_sha256("lightwork.customer-sandbox.principal.v1:" + principal)


def _module_allowlist(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= _MAX_MODULES:
        raise CustomerSandboxValidationError("sandbox_module_allowlist_invalid")
    selected = tuple(sorted(value))
    if (
        any(not isinstance(item, str) for item in selected)
        or len(set(selected)) != len(selected)
        or not set(selected) <= SUPPORTED_SANDBOX_MODULES
    ):
        raise CustomerSandboxValidationError("sandbox_module_allowlist_invalid")
    return selected


def _sanitize_export_leaf(value: object) -> object:
    if isinstance(value, bool) or value is None:
        return value
    if type(value) is int:
        if not -(2**53) <= value <= 2**53:
            raise CustomerSandboxValidationError("sandbox_configuration_number_invalid")
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, str) and value in _SAFE_STRING_VALUES:
        return value
    if isinstance(value, (list, tuple)) and len(value) <= _MAX_SEQUENCE:
        if any(isinstance(item, (list, tuple, Mapping)) for item in value):
            raise CustomerSandboxValidationError("sandbox_configuration_too_complex")
        return [_sanitize_export_leaf(item) for item in value]
    raise CustomerSandboxValidationError("sandbox_prohibited_material")


def _sanitize_value(value: object, *, schema: Mapping[str, object]) -> object:
    nodes = 0

    def visit(item: object, selected_schema: Mapping[str, object], depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if depth > _MAX_DEPTH or nodes > _MAX_NODES:
            raise CustomerSandboxValidationError("sandbox_configuration_too_complex")
        if not isinstance(item, Mapping) or len(item) > _MAX_MAPPING:
            raise CustomerSandboxValidationError("sandbox_configuration_value_invalid")
        result: dict[str, object] = {}
        for raw_key in sorted(item):
            if not isinstance(raw_key, str) or _KEY_RE.fullmatch(raw_key) is None:
                raise CustomerSandboxValidationError("sandbox_configuration_key_invalid")
            projection = selected_schema.get(raw_key)
            if projection is None:
                raise CustomerSandboxValidationError("sandbox_prohibited_material")
            if projection == _EXPORT_DROP:
                continue
            if projection == _EXPORT_LEAF:
                result[raw_key] = _sanitize_export_leaf(item[raw_key])
                continue
            if not isinstance(projection, Mapping):
                raise CustomerSandboxIntegrityError("sandbox_export_schema_invalid")
            result[raw_key] = visit(item[raw_key], projection, depth + 1)
        return result

    return visit(value, schema, 0)


def _snapshot_material(snapshot: SanitizedSandboxSnapshot) -> dict[str, Any]:
    result = asdict(snapshot)
    result.pop("snapshot_sha256", None)
    return result


def _snapshot_from_source(
    *,
    sandbox_id: str,
    source: SourceTenantConfiguration,
    target_sandbox_id: str,
    snapshot_revision: int,
    module_allowlist: Sequence[str],
    expires_at: float,
    retained_until: float,
    plan: str,
    quota_bytes: int,
    created_at: float,
) -> SanitizedSandboxSnapshot:
    if type(source) is not SourceTenantConfiguration or not isinstance(source.config, Mapping):
        raise CustomerSandboxConfigError("sandbox_source_authority_invalid")
    source_tenant = _sandbox_tenant_id(source.tenant_id)
    revision = _integer(source.revision, minimum=1, maximum=2**31 - 1, label="source_revision")
    source_digest = _digest(source.config_sha256)
    if not hmac.compare_digest(_sha256(source.config), source_digest):
        raise CustomerSandboxIntegrityError("sandbox_source_digest_mismatch")
    allowlist = _module_allowlist(tuple(module_allowlist))
    modules: dict[str, object] = {}
    for module in allowlist:
        if module not in source.config or not isinstance(source.config[module], Mapping):
            raise CustomerSandboxValidationError("sandbox_source_module_missing")
        modules[module] = _sanitize_value(
            source.config[module],
            schema=_EXPORT_SCHEMAS[module],
        )
    candidate = SanitizedSandboxSnapshot(
        schema=SNAPSHOT_SCHEMA,
        sandbox_id=_opaque_id(sandbox_id),
        source_tenant_id=source_tenant,
        source_revision=revision,
        source_config_sha256=source_digest,
        target_sandbox_id=_sandbox_tenant_id(target_sandbox_id),
        snapshot_revision=_integer(
            snapshot_revision,
            minimum=1,
            maximum=_MAX_SNAPSHOTS_PER_SANDBOX,
            label="snapshot_revision",
        ),
        module_allowlist=allowlist,
        modules=modules,
        expires_at=_timestamp(expires_at, label="expires_at"),
        retained_until=_timestamp(retained_until, label="retained_until"),
        plan=_opaque_id(plan, label="plan"),
        quota_bytes=_integer(
            quota_bytes,
            minimum=4_096,
            maximum=_MAX_QUOTA_BYTES,
            label="quota_bytes",
        ),
        created_at=_timestamp(created_at, label="created_at"),
        snapshot_sha256="0" * 64,
    )
    encoded = _canonical(_snapshot_material(candidate))
    if len(encoded) > candidate.quota_bytes:
        raise CustomerSandboxValidationError("sandbox_snapshot_exceeds_quota")
    return replace(candidate, snapshot_sha256=hashlib.sha256(encoded).hexdigest())


def _validated_source(resolver: SourceConfigurationResolver, tenant_id: str) -> SourceTenantConfiguration:
    try:
        source = resolver(_sandbox_tenant_id(tenant_id))
    except (KeyboardInterrupt, SystemExit):
        raise
    except CustomerSandboxError:
        raise
    except Exception as exc:
        raise CustomerSandboxConfigError("sandbox_source_authority_unavailable") from exc
    if type(source) is not SourceTenantConfiguration:
        raise CustomerSandboxConfigError("sandbox_source_authority_invalid")
    return source


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Default-off feature gate for managed customer sandbox creation."""

    if config is None:
        try:
            from .config import config_source_errors, load_config

            loaded = load_config()
            if config_source_errors():
                return False
        except Exception:
            return False
        config = loaded if isinstance(loaded, Mapping) else None
    if not isinstance(config, Mapping):
        return False
    section = config.get("customer_sandbox_lifecycle")
    return bool(isinstance(section, Mapping) and section.get("enable") is True)


def require_enabled(config: Mapping[str, Any] | None = None) -> None:
    if not enabled(config):
        raise CustomerSandboxConfigError("customer_sandbox_lifecycle_disabled")


class LocalCustomerSandboxProvisioner:
    """Path-confined local sandbox tenant registry and immutable snapshot store."""

    _lock = threading.RLock()

    def __init__(self, root: str | Path, *, existing_only: bool = False) -> None:
        candidate = Path(root).expanduser().resolve()
        if candidate == Path(candidate.anchor) or len(candidate.parts) < 2:
            raise CustomerSandboxConfigError("sandbox_workspace_root_unsafe")
        self._root = candidate
        self._tenants = candidate / "tenants"
        self._registry = candidate / "sandbox-tenant-registry.json"
        try:
            if existing_only:
                require_private_directory(self._root)
                require_private_directory(self._tenants)
            else:
                ensure_private_directory(self._root)
                ensure_private_directory(self._tenants)
        except PermissionError as exc:
            raise CustomerSandboxConfigError("sandbox_existing_authority_invalid") from exc

    @property
    def root(self) -> Path:
        return self._root

    def _target_path(self, tenant_id: str) -> Path:
        canonical = _sandbox_tenant_id(tenant_id)
        # The owner/manifest retain the exact target identity; the directory
        # name is a bounded 128-bit address so a valid 128-character tenant id
        # cannot exceed legacy Win32 path limits under a deep MAVERICK_HOME.
        segment = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
        candidate = self._tenants / f"t-{segment}"
        if candidate.exists() and self._is_reparse(candidate):
            raise CustomerSandboxIntegrityError("sandbox_target_path_escape")
        target = candidate.resolve()
        try:
            target.relative_to(self._tenants.resolve())
        except ValueError as exc:
            raise CustomerSandboxIntegrityError("sandbox_target_path_escape") from exc
        if target == self._tenants.resolve():
            raise CustomerSandboxIntegrityError("sandbox_target_path_escape")
        return target

    @staticmethod
    def _is_reparse(path: Path) -> bool:
        try:
            details = path.lstat()
        except OSError as exc:
            raise CustomerSandboxIntegrityError("sandbox_target_authority_changed") from exc
        return bool(
            path.is_symlink()
            or getattr(path, "is_junction", lambda: False)()
            or getattr(details, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )

    def _assert_plain_confined_tree(self, root: Path) -> None:
        tenants = self._tenants.resolve()
        if self._is_reparse(root):
            raise CustomerSandboxIntegrityError("sandbox_target_path_escape")
        root.resolve().relative_to(tenants)
        for path in root.rglob("*"):
            if self._is_reparse(path):
                raise CustomerSandboxIntegrityError("sandbox_target_path_escape")
            path.resolve().relative_to(root.resolve())

    def _quarantine_path(self, target_sandbox_id: str) -> Path:
        digest = hashlib.sha256(_sandbox_tenant_id(target_sandbox_id).encode()).hexdigest()
        # A 128-bit collision-resistant suffix keeps worst-case Windows paths
        # well below the source tenant segment's 200-character bound.
        quarantine = self._tenants / f".d-{digest[:32]}"
        quarantine.resolve(strict=False).parent.relative_to(self._tenants.resolve())
        return quarantine

    def _abandon_marker_path(self, target_sandbox_id: str) -> Path:
        digest = hashlib.sha256(_sandbox_tenant_id(target_sandbox_id).encode()).hexdigest()
        return self._root / f".a-{digest[:32]}.json"

    def _destroy_marker_path(self, target_sandbox_id: str) -> Path:
        digest = hashlib.sha256(_sandbox_tenant_id(target_sandbox_id).encode()).hexdigest()
        return self._root / f".x-{digest[:32]}.json"

    def _provision_marker_path(self, target_sandbox_id: str) -> Path:
        digest = hashlib.sha256(_sandbox_tenant_id(target_sandbox_id).encode()).hexdigest()
        return self._root / f".p-{digest[:32]}.json"

    def _collision_marker_path(self, target_sandbox_id: str) -> Path:
        digest = hashlib.sha256(_sandbox_tenant_id(target_sandbox_id).encode()).hexdigest()
        return self._root / f".c-{digest[:32]}.json"

    @staticmethod
    def _abandon_marker_material(
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
        fingerprint: str,
        quota_bytes: int,
        state: str,
    ) -> dict[str, object]:
        return {
            "schema": "lightwork.customer-sandbox-abandon-marker.v1",
            "sandbox_id_sha256": _text_sha256(sandbox_id),
            "target_sandbox_id_sha256": _text_sha256(target_sandbox_id),
            "snapshot_sha256": snapshot_sha256,
            "fingerprint": fingerprint,
            "quota_bytes": quota_bytes,
            "state": state,
        }

    def _read_abandon_marker(self, path: Path) -> Mapping[str, object] | None:
        if not path.exists():
            return None
        ensure_private_file(path)
        value = self._decode(atomic_read_text(path), label="abandon_marker")
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "sandbox_id_sha256",
            "target_sandbox_id_sha256",
            "snapshot_sha256",
            "fingerprint",
            "quota_bytes",
            "state",
            "marker_sha256",
        }:
            raise CustomerSandboxIntegrityError("sandbox_abandon_marker_corrupt")
        material = dict(value)
        marker_sha256 = _digest(material.pop("marker_sha256", None))
        if (
            material.get("schema") != "lightwork.customer-sandbox-abandon-marker.v1"
            or material.get("state") not in {"intent", "completed"}
            or not hmac.compare_digest(_sha256(material), marker_sha256)
        ):
            raise CustomerSandboxIntegrityError("sandbox_abandon_marker_corrupt")
        return value

    @staticmethod
    def _write_abandon_marker(path: Path, material: Mapping[str, object]) -> None:
        value = dict(material)
        value["marker_sha256"] = _sha256(value)
        atomic_write_text(path, _canonical(value).decode("ascii"))

    @staticmethod
    def _destroy_marker_material(
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
        workspace_sha256: str,
    ) -> dict[str, object]:
        return {
            "schema": "lightwork.customer-sandbox-destroy-marker.v1",
            "sandbox_id_sha256": _text_sha256(sandbox_id),
            "target_sandbox_id_sha256": _text_sha256(target_sandbox_id),
            "snapshot_sha256": snapshot_sha256,
            "workspace_sha256": workspace_sha256,
            "state": "intent",
        }

    def _read_destroy_marker(self, path: Path) -> Mapping[str, object] | None:
        if not path.exists():
            return None
        ensure_private_file(path)
        value = self._decode(atomic_read_text(path), label="destroy_marker")
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "sandbox_id_sha256",
            "target_sandbox_id_sha256",
            "snapshot_sha256",
            "workspace_sha256",
            "state",
            "marker_sha256",
        }:
            raise CustomerSandboxIntegrityError("sandbox_destroy_marker_corrupt")
        material = dict(value)
        marker_sha256 = _digest(material.pop("marker_sha256", None))
        if (
            material.get("schema") != "lightwork.customer-sandbox-destroy-marker.v1"
            or material.get("state") != "intent"
            or not hmac.compare_digest(_sha256(material), marker_sha256)
        ):
            raise CustomerSandboxIntegrityError("sandbox_destroy_marker_corrupt")
        return value

    @staticmethod
    def _write_destroy_marker(path: Path, material: Mapping[str, object]) -> None:
        value = dict(material)
        value["marker_sha256"] = _sha256(value)
        atomic_write_text(path, _canonical(value).decode("ascii"))

    @staticmethod
    def _provision_marker_material(
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
    ) -> dict[str, object]:
        return {
            "schema": "lightwork.customer-sandbox-provision-marker.v1",
            "sandbox_id_sha256": _text_sha256(sandbox_id),
            "target_sandbox_id_sha256": _text_sha256(target_sandbox_id),
            "snapshot_sha256": snapshot_sha256,
            "state": "create_intent",
        }

    def _read_provision_marker(self, path: Path) -> Mapping[str, object] | None:
        if not path.exists():
            return None
        ensure_private_file(path)
        value = self._decode(atomic_read_text(path), label="provision_marker")
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "sandbox_id_sha256",
            "target_sandbox_id_sha256",
            "snapshot_sha256",
            "state",
            "marker_sha256",
        }:
            raise CustomerSandboxIntegrityError("sandbox_provision_marker_corrupt")
        material = dict(value)
        marker_sha256 = _digest(material.pop("marker_sha256", None))
        if (
            material.get("schema") != "lightwork.customer-sandbox-provision-marker.v1"
            or material.get("state") != "create_intent"
            or not hmac.compare_digest(_sha256(material), marker_sha256)
        ):
            raise CustomerSandboxIntegrityError("sandbox_provision_marker_corrupt")
        return value

    @staticmethod
    def _write_provision_marker(path: Path, material: Mapping[str, object]) -> None:
        value = dict(material)
        value["marker_sha256"] = _sha256(value)
        atomic_write_text(path, _canonical(value).decode("ascii"))

    def _provision_marker_matches(
        self,
        marker: Mapping[str, object] | None,
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
    ) -> bool:
        if marker is None:
            return False
        material = dict(marker)
        material.pop("marker_sha256", None)
        return material == self._provision_marker_material(
            sandbox_id=sandbox_id,
            target_sandbox_id=target_sandbox_id,
            snapshot_sha256=snapshot_sha256,
        )

    def _read_collision_marker(self, path: Path) -> Mapping[str, object] | None:
        if not path.exists():
            return None
        ensure_private_file(path)
        value = self._decode(atomic_read_text(path), label="collision_marker")
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "sandbox_id_sha256",
            "target_sandbox_id_sha256",
            "snapshot_sha256",
            "workspace_sha256",
            "state",
            "marker_sha256",
        }:
            raise CustomerSandboxIntegrityError("sandbox_collision_marker_corrupt")
        material = dict(value)
        marker_sha256 = _digest(material.pop("marker_sha256", None))
        if (
            material.get("schema") != "lightwork.customer-sandbox-collision-cleanup.v1"
            or material.get("state") not in {"intent", "completed"}
            or not hmac.compare_digest(_sha256(material), marker_sha256)
        ):
            raise CustomerSandboxIntegrityError("sandbox_collision_marker_corrupt")
        return value

    @staticmethod
    def _write_collision_marker(path: Path, material: Mapping[str, object]) -> None:
        value = dict(material)
        value["marker_sha256"] = _sha256(value)
        atomic_write_text(path, _canonical(value).decode("ascii"))

    @staticmethod
    def _decode(raw: str, *, label: str) -> object:
        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            return json.loads(
                raw,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
                object_pairs_hook=pairs,
            )
        except (TypeError, ValueError) as exc:
            raise CustomerSandboxIntegrityError(f"sandbox_{label}_corrupt") from exc

    def _load_registry(self) -> dict[str, dict[str, Any]]:
        if not self._registry.exists():
            return {}
        ensure_private_file(self._registry)
        value = self._decode(atomic_read_text(self._registry), label="registry")
        if not isinstance(value, Mapping) or set(value) != {"schema", "sandboxes"}:
            raise CustomerSandboxIntegrityError("sandbox_registry_corrupt")
        if value.get("schema") != "lightwork.customer-sandbox-registry.v1":
            raise CustomerSandboxIntegrityError("sandbox_registry_corrupt")
        rows = value.get("sandboxes")
        if not isinstance(rows, list) or len(rows) > 10_000:
            raise CustomerSandboxIntegrityError("sandbox_registry_corrupt")
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                raise CustomerSandboxIntegrityError("sandbox_registry_corrupt")
            target = _sandbox_tenant_id(str(row.get("target_sandbox_id") or ""))
            if target in result:
                raise CustomerSandboxIntegrityError("sandbox_registry_corrupt")
            result[target] = dict(row)
        return result

    def _save_registry(self, records: Mapping[str, Mapping[str, Any]]) -> None:
        payload = {
            "schema": "lightwork.customer-sandbox-registry.v1",
            "sandboxes": [dict(records[key]) for key in sorted(records)],
        }
        atomic_write_text(self._registry, _canonical(payload, maximum=2 * 1024 * 1024).decode())

    @staticmethod
    def _authority_material(
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
        status: str,
        plan: str,
        quota_bytes: int,
        expires_at: float,
    ) -> dict[str, Any]:
        return {
            "schema": TARGET_AUTHORITY_SCHEMA,
            "sandbox_id": sandbox_id,
            "target_sandbox_id": target_sandbox_id,
            "snapshot_sha256": snapshot_sha256,
            "status": status,
            "plan": plan,
            "quota_bytes": quota_bytes,
            "expires_at": expires_at,
        }

    def _authority_from_mapping(self, value: Mapping[str, Any]) -> SandboxTargetAuthority:
        if set(value) != {
            "schema",
            "sandbox_id",
            "target_sandbox_id",
            "snapshot_sha256",
            "workspace_sha256",
            "status",
            "plan",
            "quota_bytes",
            "expires_at",
        }:
            raise CustomerSandboxIntegrityError("sandbox_target_authority_corrupt")
        candidate = SandboxTargetAuthority(**dict(value))
        material = self._authority_material(
            sandbox_id=_opaque_id(candidate.sandbox_id),
            target_sandbox_id=_sandbox_tenant_id(candidate.target_sandbox_id),
            snapshot_sha256=_digest(candidate.snapshot_sha256),
            status=str(candidate.status),
            plan=_opaque_id(candidate.plan, label="plan"),
            quota_bytes=_integer(
                candidate.quota_bytes,
                minimum=4_096,
                maximum=_MAX_QUOTA_BYTES,
                label="quota_bytes",
            ),
            expires_at=_timestamp(candidate.expires_at, label="expires_at"),
        )
        if candidate.schema != TARGET_AUTHORITY_SCHEMA or candidate.status not in {
            "active",
            "suspended",
            "expired",
        }:
            raise CustomerSandboxIntegrityError("sandbox_target_authority_corrupt")
        if not hmac.compare_digest(_sha256(material), _digest(candidate.workspace_sha256)):
            raise CustomerSandboxIntegrityError("sandbox_target_authority_corrupt")
        return candidate

    def _read_workspace_authority(self, target_sandbox_id: str) -> SandboxTargetAuthority:
        target = self._target_path(target_sandbox_id)
        return self._read_authority_at(target)

    def _read_authority_at(self, target: Path) -> SandboxTargetAuthority:
        manifest = target / "current.json"
        if not manifest.exists():
            raise CustomerSandboxNotFound("sandbox_target_missing")
        ensure_private_file(manifest)
        value = self._decode(atomic_read_text(manifest), label="workspace_manifest")
        if not isinstance(value, Mapping):
            raise CustomerSandboxIntegrityError("sandbox_target_authority_corrupt")
        return self._authority_from_mapping(value)

    def inspect(self, target_sandbox_id: str) -> SandboxTargetAuthority | None:
        target_id = _sandbox_tenant_id(target_sandbox_id)
        with self._lock, cross_process_lock(self._registry, strict=True):
            registry = self._load_registry()
            row = registry.get(target_id)
            target = self._target_path(target_id)
            if row is None and not target.exists():
                return None
            if row is None or not target.exists():
                raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
            authority = self._read_workspace_authority(target_id)
            if dict(row) != asdict(authority):
                raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
            return authority

    def _owner(self, target: Path) -> Mapping[str, Any] | None:
        path = target / "owner.json"
        if not path.exists():
            return None
        ensure_private_file(path)
        value = self._decode(atomic_read_text(path), label="workspace_owner")
        if not isinstance(value, Mapping):
            raise CustomerSandboxIntegrityError("sandbox_target_collision")
        return value

    def _abandon_fingerprint_locked(
        self,
        *,
        target: Path,
        registry_row: Mapping[str, Any] | None,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
        quota_bytes: int,
        allow_missing_owner: bool = False,
    ) -> str | None:
        expected_owner = {
            "schema": "lightwork.customer-sandbox-owner.v1",
            "sandbox_id": sandbox_id,
            "target_sandbox_id": target_sandbox_id,
        }
        if not target.exists():
            if registry_row is not None:
                raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
            return None
        self._assert_plain_confined_tree(target)
        owner = self._owner(target)
        if (owner is None and not allow_missing_owner) or (
            owner is not None and dict(owner) != expected_owner
        ):
            raise CustomerSandboxConflict("sandbox_target_collision")
        files = sorted(path for path in target.rglob("*") if path.is_file())
        if len(files) > 64:
            raise CustomerSandboxIntegrityError("sandbox_partial_workspace_oversized")
        total = sum(path.stat().st_size for path in files)
        if total > quota_bytes:
            raise CustomerSandboxIntegrityError("sandbox_partial_workspace_oversized")
        current_path = target / "current.json"
        current = None
        if current_path.exists():
            current = self._read_authority_at(target)
            if (
                current.sandbox_id != sandbox_id
                or current.target_sandbox_id != target_sandbox_id
                or not hmac.compare_digest(current.snapshot_sha256, snapshot_sha256)
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
        registered = None
        if registry_row is not None:
            registered = self._authority_from_mapping(registry_row)
            if current is None or registered != current:
                raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
        file_evidence = []
        for path in files:
            relative = path.relative_to(target).as_posix()
            raw = atomic_read_text(path).encode("utf-8")
            file_evidence.append((relative, hashlib.sha256(raw).hexdigest(), len(raw)))
        return _sha256(
            {
                "schema": "lightwork.customer-sandbox-abandon-authority.v1",
                "sandbox_id": sandbox_id,
                "target_sandbox_id": target_sandbox_id,
                "snapshot_sha256": snapshot_sha256,
                "registry": None if registered is None else asdict(registered),
                "files": file_evidence,
            },
            maximum=2 * 1024 * 1024,
        )

    def abandon_fingerprint(
        self,
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
        quota_bytes: int,
    ) -> str | None:
        selected_sandbox = _opaque_id(sandbox_id)
        target_id = _sandbox_tenant_id(target_sandbox_id)
        selected_snapshot = _digest(snapshot_sha256)
        selected_quota = _integer(
            quota_bytes,
            minimum=4_096,
            maximum=_MAX_QUOTA_BYTES,
            label="quota_bytes",
        )
        with self._lock, cross_process_lock(self._registry, strict=True):
            registry = self._load_registry()
            provision_marker = self._read_provision_marker(
                self._provision_marker_path(target_id)
            )
            allow_missing_owner = self._provision_marker_matches(
                provision_marker,
                sandbox_id=selected_sandbox,
                target_sandbox_id=target_id,
                snapshot_sha256=selected_snapshot,
            )
            if provision_marker is not None and not allow_missing_owner:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            target = self._target_path(target_id)
            if allow_missing_owner and target.exists():
                row = registry.get(target_id)
                registered = None if row is None else self._authority_from_mapping(row)
                self._validate_partial_workspace_locked(
                    quarantine=target,
                    sandbox_id=selected_sandbox,
                    target_sandbox_id=target_id,
                    snapshot_sha256=selected_snapshot,
                    quota_bytes=selected_quota,
                    registered=registered,
                )
            return self._abandon_fingerprint_locked(
                target=target,
                registry_row=registry.get(target_id),
                sandbox_id=selected_sandbox,
                target_sandbox_id=target_id,
                snapshot_sha256=selected_snapshot,
                quota_bytes=selected_quota,
                allow_missing_owner=allow_missing_owner,
            )

    def _validate_partial_workspace_locked(  # noqa: C901
        self,
        *,
        quarantine: Path,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
        quota_bytes: int,
        registered: SandboxTargetAuthority | None,
    ) -> None:
        """Validate the bounded remainder of one marker-authorized workspace."""

        self._assert_plain_confined_tree(quarantine)
        directories = {path for path in quarantine.rglob("*") if path.is_dir()}
        if not directories <= {quarantine / "snapshots"}:
            raise CustomerSandboxConflict("sandbox_target_authority_changed")
        files = sorted(path for path in quarantine.rglob("*") if path.is_file())
        if len(files) > 64 or sum(path.stat().st_size for path in files) > quota_bytes:
            raise CustomerSandboxIntegrityError("sandbox_partial_workspace_oversized")
        owner_path = quarantine / "owner.json"
        current_path = quarantine / "current.json"
        expected_owner = {
            "schema": "lightwork.customer-sandbox-owner.v1",
            "sandbox_id": sandbox_id,
            "target_sandbox_id": target_sandbox_id,
        }
        allowed = {owner_path, current_path}
        for path in files:
            if path in allowed:
                continue
            if path.parent != quarantine / "snapshots":
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            value = self._decode(atomic_read_text(path), label="workspace_snapshot")
            if not isinstance(value, Mapping):
                raise CustomerSandboxIntegrityError("sandbox_snapshot_corrupt")
            try:
                snapshot = SanitizedSandboxSnapshot(**dict(value))
                actual_digest = _sha256(_snapshot_material(snapshot))
            except (TypeError, ValueError) as exc:
                raise CustomerSandboxIntegrityError("sandbox_snapshot_corrupt") from exc
            expected_name = (
                f"{snapshot.snapshot_revision:02d}-"
                f"{snapshot.snapshot_sha256[:20]}.json"
            )
            if (
                snapshot.schema != SNAPSHOT_SCHEMA
                or snapshot.sandbox_id != sandbox_id
                or snapshot.target_sandbox_id != target_sandbox_id
                or path.name != expected_name
                or not hmac.compare_digest(actual_digest, snapshot.snapshot_sha256)
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
        if owner_path.exists() and dict(self._owner(quarantine) or {}) != expected_owner:
            raise CustomerSandboxConflict("sandbox_target_authority_changed")
        if current_path.exists():
            current = self._read_authority_at(quarantine)
            if (
                current.sandbox_id != sandbox_id
                or current.target_sandbox_id != target_sandbox_id
                or not hmac.compare_digest(current.snapshot_sha256, snapshot_sha256)
                or (registered is not None and current != registered)
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")

    def abandon(  # noqa: C901 - exact lost-ack states remain visibly ordered
        self,
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        snapshot_sha256: str,
        quota_bytes: int,
        expected_fingerprint: str | None,
    ) -> None:
        selected_sandbox = _opaque_id(sandbox_id)
        target_id = _sandbox_tenant_id(target_sandbox_id)
        selected_snapshot = _digest(snapshot_sha256)
        selected_quota = _integer(
            quota_bytes,
            minimum=4_096,
            maximum=_MAX_QUOTA_BYTES,
            label="quota_bytes",
        )
        expected = None if expected_fingerprint is None else _digest(expected_fingerprint)
        with self._lock, cross_process_lock(self._registry, strict=True):
            registry = self._load_registry()
            target = self._target_path(target_id)
            quarantine = self._quarantine_path(target_id)
            marker_path = self._abandon_marker_path(target_id)
            marker = self._read_abandon_marker(marker_path)
            provision_marker_path = self._provision_marker_path(target_id)
            provision_marker = self._read_provision_marker(provision_marker_path)
            allow_missing_owner = self._provision_marker_matches(
                provision_marker,
                sandbox_id=selected_sandbox,
                target_sandbox_id=target_id,
                snapshot_sha256=selected_snapshot,
            )
            if provision_marker is not None and not allow_missing_owner:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")

            def marker_matches(state: str) -> bool:
                if marker is None or expected is None:
                    return False
                value = dict(marker)
                value.pop("marker_sha256", None)
                return value == self._abandon_marker_material(
                    sandbox_id=selected_sandbox,
                    target_sandbox_id=target_id,
                    snapshot_sha256=selected_snapshot,
                    fingerprint=expected,
                    quota_bytes=selected_quota,
                    state=state,
                )

            if target.exists():
                if allow_missing_owner:
                    row = registry.get(target_id)
                    registered = (
                        None if row is None else self._authority_from_mapping(row)
                    )
                    self._validate_partial_workspace_locked(
                        quarantine=target,
                        sandbox_id=selected_sandbox,
                        target_sandbox_id=target_id,
                        snapshot_sha256=selected_snapshot,
                        quota_bytes=selected_quota,
                        registered=registered,
                    )
                actual = self._abandon_fingerprint_locked(
                    target=target,
                    registry_row=registry.get(target_id),
                    sandbox_id=selected_sandbox,
                    target_sandbox_id=target_id,
                    snapshot_sha256=selected_snapshot,
                    quota_bytes=selected_quota,
                    allow_missing_owner=allow_missing_owner,
                )
                if actual != expected:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                if actual is None:
                    return
                if quarantine.exists():
                    raise CustomerSandboxConflict("sandbox_destroy_quarantine_collision")
                intent = self._abandon_marker_material(
                    sandbox_id=selected_sandbox,
                    target_sandbox_id=target_id,
                    snapshot_sha256=selected_snapshot,
                    fingerprint=actual,
                    quota_bytes=selected_quota,
                    state="intent",
                )
                self._write_abandon_marker(marker_path, intent)
                marker = {**intent, "marker_sha256": _sha256(intent)}
                target.replace(quarantine)
            elif not quarantine.exists():
                if expected is None:
                    if registry.get(target_id) is not None:
                        raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
                    if provision_marker_path.exists():
                        if not allow_missing_owner:
                            raise CustomerSandboxConflict(
                                "sandbox_target_authority_changed"
                            )
                        ensure_private_file(provision_marker_path)
                        provision_marker_path.unlink()
                    return
                if marker_matches("completed") and registry.get(target_id) is None:
                    return
                if not marker_matches("intent"):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
            elif not (marker_matches("intent") or marker_matches("completed")):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")

            if quarantine.exists():
                if marker_matches("intent") or marker_matches("completed"):
                    row = registry.get(target_id)
                    registered = (
                        None if row is None else self._authority_from_mapping(row)
                    )
                    if registered is not None and (
                        registered.sandbox_id != selected_sandbox
                        or registered.target_sandbox_id != target_id
                        or not hmac.compare_digest(
                            registered.snapshot_sha256,
                            selected_snapshot,
                        )
                    ):
                        raise CustomerSandboxConflict(
                            "sandbox_target_authority_changed"
                        )
                    self._validate_partial_workspace_locked(
                        quarantine=quarantine,
                        sandbox_id=selected_sandbox,
                        target_sandbox_id=target_id,
                        snapshot_sha256=selected_snapshot,
                        quota_bytes=selected_quota,
                        registered=registered,
                    )
                else:
                    quarantined = self._abandon_fingerprint_locked(
                        target=quarantine,
                        registry_row=registry.get(target_id),
                        sandbox_id=selected_sandbox,
                        target_sandbox_id=target_id,
                        snapshot_sha256=selected_snapshot,
                        quota_bytes=selected_quota,
                    )
                    if quarantined != expected:
                        raise CustomerSandboxConflict(
                            "sandbox_target_authority_changed"
                        )
                shutil.rmtree(quarantine)
            if target_id in registry:
                registered = self._authority_from_mapping(registry[target_id])
                if (
                    registered.sandbox_id != selected_sandbox
                    or not hmac.compare_digest(
                        registered.snapshot_sha256,
                        selected_snapshot,
                    )
                ):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                registry.pop(target_id)
                self._save_registry(registry)
            completed = self._abandon_marker_material(
                sandbox_id=selected_sandbox,
                target_sandbox_id=target_id,
                snapshot_sha256=selected_snapshot,
                fingerprint=expected or "0" * 64,
                quota_bytes=selected_quota,
                state="completed",
            )
            self._write_abandon_marker(marker_path, completed)
            if provision_marker_path.exists():
                ensure_private_file(provision_marker_path)
                provision_marker_path.unlink()

    def apply(  # noqa: C901 - closed fail-fast validation keeps mutation ordering visible
        self,
        snapshot: SanitizedSandboxSnapshot,
        *,
        expected_workspace_sha256: str | None,
    ) -> SandboxProvisioningReceipt:
        if type(snapshot) is not SanitizedSandboxSnapshot:
            raise CustomerSandboxValidationError("sandbox_snapshot_invalid")
        if not hmac.compare_digest(_sha256(_snapshot_material(snapshot)), snapshot.snapshot_sha256):
            raise CustomerSandboxIntegrityError("sandbox_snapshot_digest_mismatch")
        target_id = _sandbox_tenant_id(snapshot.target_sandbox_id)
        if _sandbox_tenant_id(snapshot.source_tenant_id) == target_id:
            raise CustomerSandboxValidationError("sandbox_source_target_conflict")
        expected_workspace = (
            None
            if expected_workspace_sha256 is None
            else _digest(expected_workspace_sha256)
        )
        target = self._target_path(target_id)
        snapshot_bytes = _canonical(asdict(snapshot))
        if len(snapshot_bytes) > snapshot.quota_bytes:
            raise CustomerSandboxValidationError("sandbox_snapshot_exceeds_quota")
        with self._lock, cross_process_lock(self._registry, strict=True):
            registry = self._load_registry()
            existing_registry = registry.get(target_id)
            registered = (
                None
                if existing_registry is None
                else self._authority_from_mapping(existing_registry)
            )
            if target.exists():
                self._assert_plain_confined_tree(target)
            owner = self._owner(target) if target.exists() else None
            expected_owner = {
                "schema": "lightwork.customer-sandbox-owner.v1",
                "sandbox_id": snapshot.sandbox_id,
                "target_sandbox_id": target_id,
            }
            provision_marker_path = self._provision_marker_path(target_id)
            provision_marker = self._read_provision_marker(provision_marker_path)
            provision_marker_matches = self._provision_marker_matches(
                provision_marker,
                sandbox_id=snapshot.sandbox_id,
                target_sandbox_id=target_id,
                snapshot_sha256=snapshot.snapshot_sha256,
            )
            if provision_marker is not None and not provision_marker_matches:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            if expected_workspace is None and provision_marker is None and not target.exists():
                intent = self._provision_marker_material(
                    sandbox_id=snapshot.sandbox_id,
                    target_sandbox_id=target_id,
                    snapshot_sha256=snapshot.snapshot_sha256,
                )
                self._write_provision_marker(provision_marker_path, intent)
                provision_marker = {**intent, "marker_sha256": _sha256(intent)}
                provision_marker_matches = True
            if expected_workspace is not None and provision_marker is not None:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            if target.exists() and dict(owner or {}) != expected_owner and not (
                owner is None and expected_workspace is None and provision_marker_matches
            ):
                raise CustomerSandboxConflict("sandbox_target_collision")
            if registered is not None and registered.sandbox_id != snapshot.sandbox_id:
                raise CustomerSandboxConflict("sandbox_target_collision")
            if target.exists() and owner is None and provision_marker_matches:
                self._validate_partial_workspace_locked(
                    quarantine=target,
                    sandbox_id=snapshot.sandbox_id,
                    target_sandbox_id=target_id,
                    snapshot_sha256=snapshot.snapshot_sha256,
                    quota_bytes=snapshot.quota_bytes,
                    registered=registered,
                )
            snapshots = target / "snapshots"
            snapshot_path = (
                snapshots
                / f"{snapshot.snapshot_revision:02d}-{snapshot.snapshot_sha256[:20]}.json"
            )
            material = self._authority_material(
                sandbox_id=snapshot.sandbox_id,
                target_sandbox_id=target_id,
                snapshot_sha256=snapshot.snapshot_sha256,
                status="active",
                plan=snapshot.plan,
                quota_bytes=snapshot.quota_bytes,
                expires_at=snapshot.expires_at,
            )
            authority = SandboxTargetAuthority(
                **material,
                workspace_sha256=_sha256(material),
            )
            expired_material = {**material, "status": "expired"}
            expired_authority = SandboxTargetAuthority(
                **expired_material,
                workspace_sha256=_sha256(expired_material),
            )
            encoded_authority = _canonical(asdict(authority)).decode("ascii")
            owner_bytes = _canonical(expected_owner)
            current = target / "current.json"
            prior = self._read_workspace_authority(target_id) if current.exists() else None
            if (
                expected_workspace is None
                and target.exists()
                and provision_marker is None
                and not (
                    (prior == authority and registered == authority)
                    or (
                        prior == expired_authority
                        and registered in {authority, expired_authority}
                    )
                )
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            if prior == expired_authority and registered in {
                authority,
                expired_authority,
            }:
                if registered != expired_authority:
                    registry[target_id] = asdict(expired_authority)
                    self._save_registry(registry)
                if provision_marker_path.exists():
                    ensure_private_file(provision_marker_path)
                    provision_marker_path.unlink()
                return SandboxProvisioningReceipt(
                    schema=RECEIPT_SCHEMA,
                    sandbox_id=snapshot.sandbox_id,
                    target_sandbox_id=target_id,
                    snapshot_sha256=snapshot.snapshot_sha256,
                    workspace_sha256=expired_authority.workspace_sha256,
                    status="expired",
                    no_change=True,
                    files_written=0 if registered == expired_authority else 1,
                    bytes_written=0,
                )
            if not target.exists():
                if registered is not None or expected_workspace is not None:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
            elif prior is None:
                if registered is not None or expected_workspace is not None:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
            elif prior == authority:
                registry_is_successor = registered == authority
                registry_is_predecessor = (
                    expected_workspace is not None
                    and registered is not None
                    and hmac.compare_digest(
                        registered.workspace_sha256,
                        expected_workspace,
                    )
                )
                registry_is_new_create_partial = (
                    expected_workspace is None and registered is None
                )
                if not (
                    registry_is_successor
                    or registry_is_predecessor
                    or registry_is_new_create_partial
                ):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
            elif (
                expected_workspace is None
                or not hmac.compare_digest(prior.workspace_sha256, expected_workspace)
                or registered != prior
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            existing_files: list[Path] = []
            if target.exists():
                for path in target.rglob("*"):
                    if path.is_file():
                        path.resolve().relative_to(target.resolve())
                        existing_files.append(path)
            snapshot_files = [path for path in existing_files if path.parent == snapshots]
            if len(snapshot_files) > _MAX_SNAPSHOTS_PER_SANDBOX:
                raise CustomerSandboxIntegrityError("sandbox_snapshot_history_corrupt")
            if not snapshot_path.exists() and len(snapshot_files) >= _MAX_SNAPSHOTS_PER_SANDBOX:
                raise CustomerSandboxValidationError("sandbox_snapshot_limit_exhausted")
            prospective_bytes = sum(path.stat().st_size for path in existing_files)
            if owner is None:
                prospective_bytes += len(owner_bytes)
            if not snapshot_path.exists():
                prospective_bytes += len(snapshot_bytes)
            if current.exists():
                prospective_bytes -= current.stat().st_size
            prospective_bytes += len(encoded_authority.encode("ascii"))
            if prospective_bytes > snapshot.quota_bytes:
                raise CustomerSandboxValidationError("sandbox_workspace_exceeds_quota")
            ensure_private_directory(target)
            if owner is None:
                atomic_write_text(target / "owner.json", owner_bytes.decode("ascii"))
            ensure_private_directory(snapshots)
            files_written = 0
            bytes_written = 0
            if snapshot_path.exists():
                ensure_private_file(snapshot_path)
                if atomic_read_text(snapshot_path).encode("ascii") != snapshot_bytes:
                    raise CustomerSandboxIntegrityError("sandbox_immutable_snapshot_changed")
            else:
                atomic_write_text(snapshot_path, snapshot_bytes.decode("ascii"))
                files_written += 1
                bytes_written += len(snapshot_bytes)
            no_change = False
            if current.exists():
                no_change = prior == authority and registered == authority
            if not no_change:
                atomic_write_text(current, encoded_authority)
                registry[target_id] = asdict(authority)
                self._save_registry(registry)
                files_written += 2
                bytes_written += len(encoded_authority)
            if provision_marker_path.exists():
                ensure_private_file(provision_marker_path)
                provision_marker_path.unlink()
            return SandboxProvisioningReceipt(
                schema=RECEIPT_SCHEMA,
                sandbox_id=snapshot.sandbox_id,
                target_sandbox_id=target_id,
                snapshot_sha256=snapshot.snapshot_sha256,
                workspace_sha256=authority.workspace_sha256,
                status="active",
                no_change=no_change,
                files_written=files_written,
                bytes_written=bytes_written,
            )

    def begin_collision_cleanup(
        self,
        snapshot: SanitizedSandboxSnapshot,
        *,
        expected_workspace_sha256: str,
    ) -> SandboxProvisioningReceipt:
        """Durably authorize cleanup of one exact just-provisioned authority."""

        expected = _digest(expected_workspace_sha256)
        target_id = _sandbox_tenant_id(snapshot.target_sandbox_id)
        authority = self.inspect(target_id)
        if (
            authority is None
            or authority.sandbox_id != snapshot.sandbox_id
            or authority.target_sandbox_id != target_id
            or not hmac.compare_digest(
                authority.snapshot_sha256,
                snapshot.snapshot_sha256,
            )
            or not hmac.compare_digest(authority.workspace_sha256, expected)
        ):
            raise CustomerSandboxConflict("sandbox_target_authority_changed")
        marker_path = self._collision_marker_path(target_id)
        material = {
            "schema": "lightwork.customer-sandbox-collision-cleanup.v1",
            "sandbox_id_sha256": _text_sha256(snapshot.sandbox_id),
            "target_sandbox_id_sha256": _text_sha256(target_id),
            "snapshot_sha256": snapshot.snapshot_sha256,
            "workspace_sha256": expected,
            "state": "intent",
        }
        with self._lock:
            prior = self._read_collision_marker(marker_path)
            if prior is not None:
                prior_material = dict(prior)
                prior_material.pop("marker_sha256", None)
                if prior_material != material and prior_material != {
                    **material,
                    "state": "completed",
                }:
                    raise CustomerSandboxConflict("sandbox_collision_marker_conflict")
            self._write_collision_marker(marker_path, material)
        receipt = self.destroy(
            sandbox_id=snapshot.sandbox_id,
            target_sandbox_id=target_id,
            expected_workspace_sha256=expected,
        )
        with self._lock:
            self._write_collision_marker(
                marker_path,
                {**material, "state": "completed"},
            )
        return receipt

    def resume_collision_cleanup(
        self,
        snapshot: SanitizedSandboxSnapshot,
    ) -> bool:
        """Finish an exact collision cleanup without recreating the workspace."""

        target_id = _sandbox_tenant_id(snapshot.target_sandbox_id)
        marker_path = self._collision_marker_path(target_id)
        with self._lock:
            marker = self._read_collision_marker(marker_path)
        if marker is None:
            return False
        expected_marker = {
            "schema": "lightwork.customer-sandbox-collision-cleanup.v1",
            "sandbox_id_sha256": _text_sha256(snapshot.sandbox_id),
            "target_sandbox_id_sha256": _text_sha256(target_id),
            "snapshot_sha256": snapshot.snapshot_sha256,
            "workspace_sha256": marker.get("workspace_sha256"),
            "state": marker.get("state"),
        }
        marker_material = dict(marker)
        marker_material.pop("marker_sha256", None)
        if (
            marker_material != expected_marker
            or marker.get("state") not in {"intent", "completed"}
        ):
            raise CustomerSandboxConflict("sandbox_collision_marker_conflict")
        expected = _digest(marker.get("workspace_sha256"))
        if marker.get("state") == "intent":
            self.destroy(
                sandbox_id=snapshot.sandbox_id,
                target_sandbox_id=target_id,
                expected_workspace_sha256=expected,
            )
            with self._lock:
                self._write_collision_marker(
                    marker_path,
                    {**expected_marker, "state": "completed"},
                )
        return True

    def recreate_after_collision_cleanup(
        self,
        snapshot: SanitizedSandboxSnapshot,
    ) -> SandboxProvisioningReceipt:
        """Recreate only from one exact completed collision-cleanup marker."""

        target_id = _sandbox_tenant_id(snapshot.target_sandbox_id)
        marker_path = self._collision_marker_path(target_id)
        with self._lock:
            marker = self._read_collision_marker(marker_path)
        if (
            marker is None
            or marker.get("state") != "completed"
            or marker.get("sandbox_id_sha256") != _text_sha256(snapshot.sandbox_id)
            or marker.get("target_sandbox_id_sha256") != _text_sha256(target_id)
            or marker.get("snapshot_sha256") != snapshot.snapshot_sha256
        ):
            raise CustomerSandboxConflict("sandbox_collision_marker_conflict")
        receipt = self.apply(snapshot, expected_workspace_sha256=None)
        with self._lock:
            ensure_private_file(marker_path)
            marker_path.unlink()
        return receipt

    def discard_collision_recreation(
        self,
        snapshot: SanitizedSandboxSnapshot,
        *,
        allow_other_provision_intent: bool = False,
    ) -> bool:
        """Remove only the exact bounded partial created from a completed marker."""

        target_id = _sandbox_tenant_id(snapshot.target_sandbox_id)
        marker_path = self._collision_marker_path(target_id)
        material = self._authority_material(
            sandbox_id=snapshot.sandbox_id,
            target_sandbox_id=target_id,
            snapshot_sha256=snapshot.snapshot_sha256,
            status="active",
            plan=snapshot.plan,
            quota_bytes=snapshot.quota_bytes,
            expires_at=snapshot.expires_at,
        )
        desired = SandboxTargetAuthority(**material, workspace_sha256=_sha256(material))
        target = self._target_path(target_id)
        quarantine = self._quarantine_path(target_id)
        snapshot_path = (
            target
            / "snapshots"
            / f"{snapshot.snapshot_revision:02d}-{snapshot.snapshot_sha256[:20]}.json"
        )
        provision_marker_path = self._provision_marker_path(target_id)
        with self._lock, cross_process_lock(self._registry, strict=True):
            marker = self._read_collision_marker(marker_path)
            if (
                marker is None
                or marker.get("state") != "completed"
                or marker.get("sandbox_id_sha256") != _text_sha256(snapshot.sandbox_id)
                or marker.get("target_sandbox_id_sha256") != _text_sha256(target_id)
                or marker.get("snapshot_sha256") != snapshot.snapshot_sha256
            ):
                raise CustomerSandboxConflict("sandbox_collision_marker_conflict")
            provision_marker = self._read_provision_marker(provision_marker_path)
            if provision_marker is not None and not self._provision_marker_matches(
                provision_marker,
                sandbox_id=snapshot.sandbox_id,
                target_sandbox_id=target_id,
                snapshot_sha256=snapshot.snapshot_sha256,
            ):
                if allow_other_provision_intent:
                    return False
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            registry = self._load_registry()
            row = registry.get(target_id)
            registered = None if row is None else self._authority_from_mapping(row)
            if registered is not None and registered != desired:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            if target.exists():
                self._validate_partial_workspace_locked(
                    quarantine=target,
                    sandbox_id=snapshot.sandbox_id,
                    target_sandbox_id=target_id,
                    snapshot_sha256=snapshot.snapshot_sha256,
                    quota_bytes=snapshot.quota_bytes,
                    registered=registered,
                )
                allowed = {target / "owner.json", snapshot_path, target / "current.json"}
                files = {path for path in target.rglob("*") if path.is_file()}
                if not files <= allowed:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                if snapshot_path.exists() and atomic_read_text(
                    snapshot_path
                ) != _canonical(asdict(snapshot)).decode("ascii"):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                current = target / "current.json"
                if current.exists() and self._read_workspace_authority(target_id) != desired:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                if quarantine.exists():
                    raise CustomerSandboxConflict("sandbox_destroy_quarantine_collision")
                target.replace(quarantine)
                self._assert_plain_confined_tree(quarantine)
                shutil.rmtree(quarantine)
            elif quarantine.exists():
                self._validate_partial_workspace_locked(
                    quarantine=quarantine,
                    sandbox_id=snapshot.sandbox_id,
                    target_sandbox_id=target_id,
                    snapshot_sha256=snapshot.snapshot_sha256,
                    quota_bytes=snapshot.quota_bytes,
                    registered=registered,
                )
                shutil.rmtree(quarantine)
            registry.pop(target_id, None)
            self._save_registry(registry)
            if provision_marker_path.exists():
                ensure_private_file(provision_marker_path)
                provision_marker_path.unlink()
            return True

    def retire_collision_cleanup_after_recovery(
        self,
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        proposal_snapshot_sha256: str,
        recovered_snapshot_sha256: str | None,
    ) -> None:
        """Clear only an exact marker after exact recovery or owned removal."""

        selected_sandbox = _opaque_id(sandbox_id)
        target_id = _sandbox_tenant_id(target_sandbox_id)
        proposal = _digest(proposal_snapshot_sha256)
        recovered = (
            None
            if recovered_snapshot_sha256 is None
            else _digest(recovered_snapshot_sha256)
        )
        marker_path = self._collision_marker_path(target_id)
        with self._lock:
            marker = self._read_collision_marker(marker_path)
            if marker is None:
                return
            if (
                marker.get("sandbox_id_sha256") != _text_sha256(selected_sandbox)
                or marker.get("target_sandbox_id_sha256") != _text_sha256(target_id)
                or marker.get("snapshot_sha256") != proposal
            ):
                raise CustomerSandboxConflict("sandbox_collision_marker_conflict")
            authority = self.inspect(target_id)
            if recovered is None:
                if authority is not None:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
            elif (
                authority is None
                or authority.sandbox_id != selected_sandbox
                or not hmac.compare_digest(authority.snapshot_sha256, recovered)
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            material = dict(marker)
            material.pop("marker_sha256", None)
            self._write_collision_marker(
                marker_path,
                {**material, "state": "completed"},
            )
            marker_path.unlink()

    def set_status(
        self,
        *,
        target_sandbox_id: str,
        expected_workspace_sha256: str,
        status: str,
    ) -> SandboxProvisioningReceipt:
        if status not in {"active", "suspended", "expired"}:
            raise CustomerSandboxValidationError("sandbox_target_status_invalid")
        target_id = _sandbox_tenant_id(target_sandbox_id)
        expected = _digest(expected_workspace_sha256)
        with self._lock, cross_process_lock(self._registry, strict=True):
            registry = self._load_registry()
            row = registry.get(target_id)
            if row is None:
                raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
            registered = self._authority_from_mapping(row)
            authority = self._read_workspace_authority(target_id)
            if not hmac.compare_digest(authority.workspace_sha256, expected):
                predecessor_matches = any(
                    hmac.compare_digest(
                        _sha256(
                            self._authority_material(
                                sandbox_id=authority.sandbox_id,
                                target_sandbox_id=target_id,
                                snapshot_sha256=authority.snapshot_sha256,
                                status=prior_status,
                                plan=authority.plan,
                                quota_bytes=authority.quota_bytes,
                                expires_at=authority.expires_at,
                            )
                        ),
                        expected,
                    )
                    for prior_status in {"active", "suspended", "expired"} - {status}
                )
                if registered == authority and authority.status == status and predecessor_matches:
                    return SandboxProvisioningReceipt(
                        RECEIPT_SCHEMA,
                        authority.sandbox_id,
                        target_id,
                        authority.snapshot_sha256,
                        authority.workspace_sha256,
                        status,
                        True,
                        0,
                        0,
                    )
                if (
                    not hmac.compare_digest(registered.workspace_sha256, expected)
                    or authority.sandbox_id != registered.sandbox_id
                    or authority.target_sandbox_id != registered.target_sandbox_id
                    or not hmac.compare_digest(
                        authority.snapshot_sha256,
                        registered.snapshot_sha256,
                    )
                    or authority.plan != registered.plan
                    or authority.quota_bytes != registered.quota_bytes
                    or authority.expires_at != registered.expires_at
                    or authority.status != status
                ):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                registry[target_id] = asdict(authority)
                self._save_registry(registry)
                return SandboxProvisioningReceipt(
                    RECEIPT_SCHEMA,
                    authority.sandbox_id,
                    target_id,
                    authority.snapshot_sha256,
                    authority.workspace_sha256,
                    status,
                    True,
                    1,
                    0,
                )
            if registered != authority:
                raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
            if authority.status == status:
                return SandboxProvisioningReceipt(
                    RECEIPT_SCHEMA,
                    authority.sandbox_id,
                    target_id,
                    authority.snapshot_sha256,
                    authority.workspace_sha256,
                    status,
                    True,
                    0,
                    0,
                )
            material = self._authority_material(
                sandbox_id=authority.sandbox_id,
                target_sandbox_id=target_id,
                snapshot_sha256=authority.snapshot_sha256,
                status=status,
                plan=authority.plan,
                quota_bytes=authority.quota_bytes,
                expires_at=authority.expires_at,
            )
            updated = SandboxTargetAuthority(**material, workspace_sha256=_sha256(material))
            encoded = _canonical(asdict(updated)).decode("ascii")
            atomic_write_text(self._target_path(target_id) / "current.json", encoded)
            registry[target_id] = asdict(updated)
            self._save_registry(registry)
            return SandboxProvisioningReceipt(
                RECEIPT_SCHEMA,
                updated.sandbox_id,
                target_id,
                updated.snapshot_sha256,
                updated.workspace_sha256,
                status,
                False,
                2,
                len(encoded),
            )

    def restore_resync_baseline(
        self,
        snapshot: SanitizedSandboxSnapshot,
        *,
        expected_workspace_sha256: str,
        proposal_snapshot_sha256: str,
    ) -> SandboxProvisioningReceipt:
        """Restore a pinned baseline from one exact failed proposal authority."""

        expected = _digest(expected_workspace_sha256)
        proposal = _digest(proposal_snapshot_sha256)
        target_id = _sandbox_tenant_id(snapshot.target_sandbox_id)
        target = self._target_path(target_id)
        if not any(
            hmac.compare_digest(
                _sha256(
                    self._authority_material(
                        sandbox_id=snapshot.sandbox_id,
                        target_sandbox_id=target_id,
                        snapshot_sha256=snapshot.snapshot_sha256,
                        status=status,
                        plan=snapshot.plan,
                        quota_bytes=snapshot.quota_bytes,
                        expires_at=snapshot.expires_at,
                    )
                ),
                expected,
            )
            for status in _ACTIVE_TARGET_STATES
        ):
            raise CustomerSandboxIntegrityError("sandbox_resync_baseline_corrupt")

        def matches(authority: SandboxTargetAuthority, snapshot_sha256: str) -> bool:
            return (
                authority.sandbox_id == snapshot.sandbox_id
                and authority.target_sandbox_id == target_id
                and hmac.compare_digest(authority.snapshot_sha256, snapshot_sha256)
                and authority.status in _ACTIVE_TARGET_STATES
                and authority.plan == snapshot.plan
                and authority.quota_bytes == snapshot.quota_bytes
                and authority.expires_at == snapshot.expires_at
            )

        with self._lock, cross_process_lock(self._registry, strict=True):
            registry = self._load_registry()
            row = registry.get(target_id)
            provision_marker = self._read_provision_marker(
                self._provision_marker_path(target_id)
            )
            baseline_intent = self._provision_marker_matches(
                provision_marker,
                sandbox_id=snapshot.sandbox_id,
                target_sandbox_id=target_id,
                snapshot_sha256=snapshot.snapshot_sha256,
            )
            if provision_marker is not None and not baseline_intent:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            orphaned_proposal: SandboxTargetAuthority | None = None
            if not target.exists() and row is None:
                authority = None
            elif not target.exists() and row is not None:
                registered = self._authority_from_mapping(row)
                if not matches(registered, proposal):
                    raise CustomerSandboxIntegrityError(
                        "sandbox_target_registry_drift"
                    )
                orphaned_proposal = registered
                authority = None
            elif row is None:
                if not baseline_intent:
                    raise CustomerSandboxIntegrityError(
                        "sandbox_target_registry_drift"
                    )
                self._validate_partial_workspace_locked(
                    quarantine=target,
                    sandbox_id=snapshot.sandbox_id,
                    target_sandbox_id=target_id,
                    snapshot_sha256=snapshot.snapshot_sha256,
                    quota_bytes=snapshot.quota_bytes,
                    registered=None,
                )
                authority = None
            else:
                self._assert_plain_confined_tree(target)
                expected_owner = {
                    "schema": "lightwork.customer-sandbox-owner.v1",
                    "sandbox_id": snapshot.sandbox_id,
                    "target_sandbox_id": target_id,
                }
                if dict(self._owner(target) or {}) != expected_owner:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                registered = self._authority_from_mapping(row)
                authority = self._read_workspace_authority(target_id)
                if registered != authority:
                    manifest_is_known = (
                        matches(authority, proposal)
                        or matches(authority, snapshot.snapshot_sha256)
                    )
                    registry_is_known = (
                        matches(registered, proposal)
                        or matches(registered, snapshot.snapshot_sha256)
                    )
                    if not (manifest_is_known and registry_is_known):
                        raise CustomerSandboxIntegrityError(
                            "sandbox_target_registry_drift"
                        )
                    # Close either exact write-order split durably. A retry can
                    # then resume from one exact authority if rollback loses
                    # its acknowledgement.
                    registry[target_id] = asdict(authority)
                    self._save_registry(registry)
        if orphaned_proposal is not None:
            # Collision cleanup may have durably removed/quarantined the exact
            # proposal target before its registry deletion was acknowledged.
            # destroy revalidates the proposal digest and closes either window.
            self.destroy(
                sandbox_id=snapshot.sandbox_id,
                target_sandbox_id=target_id,
                expected_workspace_sha256=orphaned_proposal.workspace_sha256,
            )
        if baseline_intent:
            # A prior exact baseline recreation may have lost its
            # acknowledgement before removing the pre-create marker.  The
            # marker authorizes only this pinned snapshot, and apply validates
            # absent, partial, split, or complete forms before adopting it.
            return self.apply(snapshot, expected_workspace_sha256=None)
        if authority is None:
            # The provisioning collision-cleanup path may have exactly removed
            # both the owned target and registry row before SQLite rollback.
            return self.apply(snapshot, expected_workspace_sha256=None)
        if not (
            matches(authority, snapshot.snapshot_sha256)
            or matches(authority, proposal)
        ):
            raise CustomerSandboxConflict("sandbox_target_authority_changed")
        predecessor = authority.workspace_sha256
        # apply re-resolves the exact digest under its own filesystem/registry
        # lock, so a change between inspect and mutation fails closed.
        return self.apply(
            snapshot,
            expected_workspace_sha256=predecessor,
        )

    def destroy(  # noqa: C901 - destructive recovery cases stay explicit
        self,
        *,
        sandbox_id: str,
        target_sandbox_id: str,
        expected_workspace_sha256: str,
    ) -> SandboxProvisioningReceipt:
        selected_sandbox = _opaque_id(sandbox_id)
        target_id = _sandbox_tenant_id(target_sandbox_id)
        expected = _digest(expected_workspace_sha256)
        target = self._target_path(target_id)
        quarantine = self._quarantine_path(target_id)
        marker_path = self._destroy_marker_path(target_id)
        with self._lock, cross_process_lock(self._registry, strict=True):
            registry = self._load_registry()
            marker = self._read_destroy_marker(marker_path)

            def marker_matches(snapshot_sha256: str | None = None) -> bool:
                if marker is None:
                    return False
                material = dict(marker)
                material.pop("marker_sha256", None)
                if (
                    material.get("schema")
                    != "lightwork.customer-sandbox-destroy-marker.v1"
                    or material.get("sandbox_id_sha256")
                    != _text_sha256(selected_sandbox)
                    or material.get("target_sandbox_id_sha256")
                    != _text_sha256(target_id)
                    or material.get("workspace_sha256") != expected
                    or material.get("state") != "intent"
                ):
                    return False
                return snapshot_sha256 is None or material.get(
                    "snapshot_sha256"
                ) == snapshot_sha256

            def clear_marker() -> None:
                if marker_path.exists():
                    ensure_private_file(marker_path)
                    marker_path.unlink()

            if not target.exists():
                row = registry.get(target_id)
                if row is None:
                    if quarantine.exists():
                        raise CustomerSandboxIntegrityError("sandbox_target_registry_drift")
                    if marker is not None:
                        if not marker_matches():
                            raise CustomerSandboxConflict(
                                "sandbox_target_authority_changed"
                            )
                        removed_snapshot = _digest(marker.get("snapshot_sha256"))
                        clear_marker()
                    else:
                        removed_snapshot = "0" * 64
                    return SandboxProvisioningReceipt(
                        RECEIPT_SCHEMA,
                        selected_sandbox,
                        target_id,
                        removed_snapshot,
                        None,
                        "destroyed",
                        True,
                        0,
                        0,
                    )
                authority = self._authority_from_mapping(row)
                if (
                    authority.sandbox_id != selected_sandbox
                    or not hmac.compare_digest(authority.workspace_sha256, expected)
                ):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                if marker is not None and not marker_matches(
                    authority.snapshot_sha256
                ):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                if quarantine.exists():
                    if marker_matches(authority.snapshot_sha256):
                        self._validate_partial_workspace_locked(
                            quarantine=quarantine,
                            sandbox_id=selected_sandbox,
                            target_sandbox_id=target_id,
                            snapshot_sha256=authority.snapshot_sha256,
                            quota_bytes=authority.quota_bytes,
                            registered=authority,
                        )
                    else:
                        self._assert_plain_confined_tree(quarantine)
                        quarantined_authority = self._read_authority_at(quarantine)
                        expected_owner = {
                            "schema": "lightwork.customer-sandbox-owner.v1",
                            "sandbox_id": selected_sandbox,
                            "target_sandbox_id": target_id,
                        }
                        if (
                            quarantined_authority != authority
                            or dict(self._owner(quarantine) or {}) != expected_owner
                        ):
                            raise CustomerSandboxConflict(
                                "sandbox_target_authority_changed"
                            )
                    shutil.rmtree(quarantine)
                registry.pop(target_id)
                self._save_registry(registry)
                clear_marker()
                return SandboxProvisioningReceipt(
                    RECEIPT_SCHEMA,
                    selected_sandbox,
                    target_id,
                    authority.snapshot_sha256,
                    None,
                    "destroyed",
                    True,
                    0,
                    0,
                )
            authority = self._read_workspace_authority(target_id)
            if (
                authority.sandbox_id != selected_sandbox
                or not hmac.compare_digest(authority.workspace_sha256, expected)
                or dict(registry.get(target_id) or {}) != asdict(authority)
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            expected_owner = {
                "schema": "lightwork.customer-sandbox-owner.v1",
                "sandbox_id": selected_sandbox,
                "target_sandbox_id": target_id,
            }
            if dict(self._owner(target) or {}) != expected_owner:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            self._assert_plain_confined_tree(target)
            if quarantine.exists():
                raise CustomerSandboxConflict("sandbox_destroy_quarantine_collision")
            intent = self._destroy_marker_material(
                sandbox_id=selected_sandbox,
                target_sandbox_id=target_id,
                snapshot_sha256=authority.snapshot_sha256,
                workspace_sha256=expected,
            )
            if marker is not None and not marker_matches(authority.snapshot_sha256):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            self._write_destroy_marker(marker_path, intent)
            marker = {**intent, "marker_sha256": _sha256(intent)}
            target.replace(quarantine)
            self._assert_plain_confined_tree(quarantine)
            quarantined_authority = self._read_authority_at(quarantine)
            if (
                quarantined_authority != authority
                or dict(self._owner(quarantine) or {}) != expected_owner
            ):
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            shutil.rmtree(quarantine)
            registry.pop(target_id, None)
            self._save_registry(registry)
            clear_marker()
            return SandboxProvisioningReceipt(
                RECEIPT_SCHEMA,
                selected_sandbox,
                target_id,
                authority.snapshot_sha256,
                None,
                "destroyed",
                False,
                0,
                0,
            )

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "execution_sandbox": False,
            "source_tenant_mutated": False,
            "production_data_copied": False,
            "credentials_or_secrets_copied": False,
            "raw_audit_or_world_databases_copied": False,
            "provider_material_copied": False,
            "full_suite_configuration_copy": False,
            "closed_safe_configuration_projection": True,
            "network_io": False,
            "workspace_integrity_verified": False,
            "audit_chain_keyed": False,
            "live_customer_acceptance_verified": False,
            "production_recovery_verified": False,
            "production_scale_verified": False,
        }


class CustomerSandboxLifecycleStore:
    """SQLite authority for snapshots, four-eyes lifecycle, CAS, and audit evidence."""

    _SCHEMA_SQL = """
        CREATE TABLE IF NOT EXISTS customer_sandbox_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema TEXT NOT NULL CHECK (schema = 'lightwork.customer-sandbox-store.v1'),
            version INTEGER NOT NULL CHECK (version = 1)
        );
        CREATE TABLE IF NOT EXISTS customer_sandboxes (
            sandbox_id TEXT PRIMARY KEY,
            source_tenant_id TEXT NOT NULL,
            source_revision INTEGER NOT NULL,
            source_config_sha256 TEXT NOT NULL,
            target_sandbox_id TEXT NOT NULL UNIQUE,
            snapshot_revision INTEGER NOT NULL,
            snapshot_sha256 TEXT NOT NULL,
            module_allowlist_json TEXT NOT NULL,
            expires_at REAL NOT NULL,
            retained_until REAL NOT NULL,
            plan TEXT NOT NULL,
            quota_bytes INTEGER NOT NULL,
            state TEXT NOT NULL,
            operation_kind TEXT NOT NULL,
            revision INTEGER NOT NULL,
            attempts INTEGER NOT NULL,
            max_attempts INTEGER NOT NULL,
            requested_by_sha256 TEXT NOT NULL,
            approved_by_sha256 TEXT,
            destroy_requested_by_sha256 TEXT,
            destroy_approved_by_sha256 TEXT,
            workspace_sha256 TEXT,
            last_error_code TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            destroyed_at REAL,
            integrity_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS customer_sandbox_snapshots (
            sandbox_id TEXT NOT NULL,
            snapshot_revision INTEGER NOT NULL,
            snapshot_sha256 TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            created_at REAL NOT NULL,
            requested_by_sha256 TEXT NOT NULL,
            PRIMARY KEY (sandbox_id, snapshot_revision),
            UNIQUE (sandbox_id, snapshot_sha256),
            FOREIGN KEY (sandbox_id) REFERENCES customer_sandboxes(sandbox_id)
        );
        CREATE TABLE IF NOT EXISTS customer_sandbox_operations (
            key_sha256 TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS customer_sandbox_resync_baselines (
            sandbox_id TEXT NOT NULL,
            snapshot_revision INTEGER NOT NULL,
            baseline_json TEXT NOT NULL,
            PRIMARY KEY (sandbox_id, snapshot_revision),
            FOREIGN KEY (sandbox_id) REFERENCES customer_sandboxes(sandbox_id)
        );
        CREATE TABLE IF NOT EXISTS customer_sandbox_audit (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            sandbox_id TEXT NOT NULL,
            action TEXT NOT NULL,
            detail_sha256 TEXT NOT NULL,
            principal_sha256 TEXT NOT NULL,
            occurred_at REAL NOT NULL,
            previous_sha256 TEXT NOT NULL,
            event_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS customer_sandbox_tombstones (
            sandbox_id TEXT PRIMARY KEY,
            source_tenant_sha256 TEXT NOT NULL,
            target_sandbox_sha256 TEXT NOT NULL,
            final_record_sha256 TEXT NOT NULL,
            destroyed_at REAL NOT NULL,
            retained_until REAL NOT NULL,
            purged_at REAL NOT NULL,
            purged_by_sha256 TEXT NOT NULL,
            idempotency_key_sha256 TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            tombstone_sha256 TEXT NOT NULL
        );
        INSERT OR IGNORE INTO customer_sandbox_meta(singleton,schema,version)
        VALUES (1,'lightwork.customer-sandbox-store.v1',1);
    """

    def __init__(
        self,
        path: str | Path,
        *,
        source_resolver: SourceConfigurationResolver,
        principal_resolver: PrincipalResolver,
        provisioner: LocalCustomerSandboxProvisioner,
        config_gate: ConfigGate,
        target_collision_resolver: TargetCollisionResolver | None = None,
        clock: Callable[[], float] = time.time,
        existing_only: bool = False,
    ) -> None:
        if not callable(source_resolver) or not callable(principal_resolver) or not callable(config_gate):
            raise CustomerSandboxConfigError("sandbox_authority_unavailable")
        if not isinstance(provisioner, LocalCustomerSandboxProvisioner) or not callable(clock):
            raise CustomerSandboxConfigError("sandbox_provisioner_unavailable")
        self._path = Path(path)
        self._existing_only = existing_only
        try:
            if existing_only:
                require_private_directory(self._path.parent)
            else:
                ensure_private_directory(self._path.parent)
        except PermissionError as exc:
            raise CustomerSandboxConfigError("sandbox_existing_authority_invalid") from exc
        self._source_resolver = source_resolver
        self._principal_resolver = principal_resolver
        self._provisioner = provisioner
        self._config_gate = config_gate
        if not callable(target_collision_resolver):
            raise CustomerSandboxConfigError("sandbox_target_authority_unavailable")
        self._target_collision_resolver = target_collision_resolver
        self._clock = clock
        if existing_only:
            self._require_existing_authority()
        else:
            self._initialize()

    def _require_existing_authority(self) -> None:
        """Read-only bootstrap verification for disabled-state remediation."""
        try:
            info = self._path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or self._path.is_symlink()
                or getattr(self._path, "is_junction", lambda: False)()
                or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise OSError("unsafe lifecycle database")
            uri = f"{self._path.resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)
            try:
                connection.execute("PRAGMA query_only=ON")
                check = connection.execute("PRAGMA quick_check(1)").fetchone()
                if check is None or str(check[0]) != "ok":
                    raise sqlite3.DatabaseError("integrity check failed")
                reference = sqlite3.connect(":memory:")
                try:
                    reference.executescript(self._SCHEMA_SQL)
                    expected_schema = reference.execute(
                        "SELECT type,name,tbl_name,sql FROM sqlite_master "
                        "ORDER BY type,name"
                    ).fetchall()
                finally:
                    reference.close()
                actual_schema = connection.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master "
                    "ORDER BY type,name"
                ).fetchall()
                if actual_schema != expected_schema:
                    raise sqlite3.DatabaseError("schema mismatch")
                marker = connection.execute(
                    "SELECT singleton,schema,version FROM customer_sandbox_meta"
                ).fetchall()
                if marker != [(1, "lightwork.customer-sandbox-store.v1", 1)]:
                    raise sqlite3.DatabaseError("schema marker mismatch")
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as exc:
            raise CustomerSandboxConfigError("sandbox_existing_authority_invalid") from exc

    def _connect(self) -> sqlite3.Connection:
        try:
            if self._existing_only:
                uri = f"{self._path.resolve().as_uri()}?mode=rw"
                connection = sqlite3.connect(
                    uri,
                    uri=True,
                    timeout=30,
                    isolation_level=None,
                )
            else:
                connection = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        except sqlite3.Error as exc:
            raise CustomerSandboxConfigError("sandbox_existing_authority_invalid") from exc
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(self._SCHEMA_SQL)

    def _gate(self) -> None:
        try:
            self._config_gate()
        except (KeyboardInterrupt, SystemExit):
            raise
        except CustomerSandboxError:
            raise
        except Exception as exc:
            raise CustomerSandboxConfigError("customer_sandbox_lifecycle_disabled") from exc

    def _admission_enabled(self) -> bool:
        try:
            self._gate()
        except CustomerSandboxConfigError:
            return False
        return True

    def _now(self) -> float:
        return _timestamp(self._clock(), label="clock")

    @staticmethod
    def _record_material(record: CustomerSandboxRecord) -> dict[str, Any]:
        value = asdict(record)
        value.pop("integrity_sha256", None)
        return value

    @classmethod
    def _with_integrity(cls, record: CustomerSandboxRecord) -> CustomerSandboxRecord:
        return replace(record, integrity_sha256=_sha256(cls._record_material(record)))

    @classmethod
    def _validate_record(cls, record: CustomerSandboxRecord) -> CustomerSandboxRecord:
        if (
            type(record) is not CustomerSandboxRecord
            or record.schema != RECORD_SCHEMA
            or record.state not in _STATES
            or record.operation_kind not in {"create", "resync"}
            or not hmac.compare_digest(
                _sha256(cls._record_material(record)),
                _digest(record.integrity_sha256),
            )
        ):
            raise CustomerSandboxIntegrityError("sandbox_record_corrupt")
        return record

    @classmethod
    def _record_from_row(cls, row: sqlite3.Row) -> CustomerSandboxRecord:
        try:
            allowlist = json.loads(str(row["module_allowlist_json"]))
            record = CustomerSandboxRecord(
                schema=RECORD_SCHEMA,
                sandbox_id=str(row["sandbox_id"]),
                source_tenant_id=str(row["source_tenant_id"]),
                source_revision=int(row["source_revision"]),
                source_config_sha256=str(row["source_config_sha256"]),
                target_sandbox_id=str(row["target_sandbox_id"]),
                snapshot_revision=int(row["snapshot_revision"]),
                snapshot_sha256=str(row["snapshot_sha256"]),
                module_allowlist=tuple(allowlist),
                expires_at=float(row["expires_at"]),
                retained_until=float(row["retained_until"]),
                plan=str(row["plan"]),
                quota_bytes=int(row["quota_bytes"]),
                state=str(row["state"]),
                operation_kind=str(row["operation_kind"]),
                revision=int(row["revision"]),
                attempts=int(row["attempts"]),
                max_attempts=int(row["max_attempts"]),
                requested_by_sha256=str(row["requested_by_sha256"]),
                approved_by_sha256=(
                    None if row["approved_by_sha256"] is None else str(row["approved_by_sha256"])
                ),
                destroy_requested_by_sha256=(
                    None
                    if row["destroy_requested_by_sha256"] is None
                    else str(row["destroy_requested_by_sha256"])
                ),
                destroy_approved_by_sha256=(
                    None
                    if row["destroy_approved_by_sha256"] is None
                    else str(row["destroy_approved_by_sha256"])
                ),
                workspace_sha256=(
                    None if row["workspace_sha256"] is None else str(row["workspace_sha256"])
                ),
                last_error_code=(
                    None if row["last_error_code"] is None else str(row["last_error_code"])
                ),
                created_at=float(row["created_at"]),
                updated_at=float(row["updated_at"]),
                destroyed_at=(None if row["destroyed_at"] is None else float(row["destroyed_at"])),
                integrity_sha256=str(row["integrity_sha256"]),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CustomerSandboxIntegrityError("sandbox_record_corrupt") from exc
        return cls._validate_record(record)

    @staticmethod
    def _insert_record(connection: sqlite3.Connection, record: CustomerSandboxRecord) -> None:
        connection.execute(
            "INSERT INTO customer_sandboxes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record.sandbox_id,
                record.source_tenant_id,
                record.source_revision,
                record.source_config_sha256,
                record.target_sandbox_id,
                record.snapshot_revision,
                record.snapshot_sha256,
                json.dumps(record.module_allowlist, separators=(",", ":")),
                record.expires_at,
                record.retained_until,
                record.plan,
                record.quota_bytes,
                record.state,
                record.operation_kind,
                record.revision,
                record.attempts,
                record.max_attempts,
                record.requested_by_sha256,
                record.approved_by_sha256,
                record.destroy_requested_by_sha256,
                record.destroy_approved_by_sha256,
                record.workspace_sha256,
                record.last_error_code,
                record.created_at,
                record.updated_at,
                record.destroyed_at,
                record.integrity_sha256,
            ),
        )

    @staticmethod
    def _update_record(connection: sqlite3.Connection, record: CustomerSandboxRecord) -> None:
        values = list(asdict(record).values())
        del values[0]  # schema is not stored
        allowlist_index = 7
        values[allowlist_index] = json.dumps(record.module_allowlist, separators=(",", ":"))
        sandbox_id = values.pop(0)
        connection.execute(
            "UPDATE customer_sandboxes SET "
            "source_tenant_id=?,source_revision=?,source_config_sha256=?,target_sandbox_id=?,"
            "snapshot_revision=?,snapshot_sha256=?,module_allowlist_json=?,expires_at=?,"
            "retained_until=?,plan=?,quota_bytes=?,state=?,operation_kind=?,revision=?,attempts=?,"
            "max_attempts=?,requested_by_sha256=?,approved_by_sha256=?,"
            "destroy_requested_by_sha256=?,destroy_approved_by_sha256=?,workspace_sha256=?,"
            "last_error_code=?,created_at=?,updated_at=?,destroyed_at=?,integrity_sha256=? "
            "WHERE sandbox_id=?",
            (*values, sandbox_id),
        )

    def _get(self, connection: sqlite3.Connection, sandbox_id: str) -> CustomerSandboxRecord:
        row = connection.execute(
            "SELECT * FROM customer_sandboxes WHERE sandbox_id=?",
            (_opaque_id(sandbox_id),),
        ).fetchone()
        if row is None:
            raise CustomerSandboxNotFound("sandbox_not_found")
        return self._record_from_row(row)

    @staticmethod
    def _tombstone_material(tombstone: CustomerSandboxTombstone) -> dict[str, Any]:
        value = asdict(tombstone)
        value.pop("tombstone_sha256", None)
        return value

    @classmethod
    def _tombstone_from_row(cls, row: sqlite3.Row) -> CustomerSandboxTombstone:
        try:
            tombstone = CustomerSandboxTombstone(
                schema=TOMBSTONE_SCHEMA,
                sandbox_id=str(row["sandbox_id"]),
                source_tenant_sha256=str(row["source_tenant_sha256"]),
                target_sandbox_sha256=str(row["target_sandbox_sha256"]),
                final_record_sha256=str(row["final_record_sha256"]),
                destroyed_at=float(row["destroyed_at"]),
                retained_until=float(row["retained_until"]),
                purged_at=float(row["purged_at"]),
                purged_by_sha256=str(row["purged_by_sha256"]),
                idempotency_key_sha256=str(row["idempotency_key_sha256"]),
                request_sha256=str(row["request_sha256"]),
                tombstone_sha256=str(row["tombstone_sha256"]),
            )
            digests = (
                tombstone.source_tenant_sha256,
                tombstone.target_sandbox_sha256,
                tombstone.final_record_sha256,
                tombstone.purged_by_sha256,
                tombstone.idempotency_key_sha256,
                tombstone.request_sha256,
                tombstone.tombstone_sha256,
            )
            if (
                any(_DIGEST_RE.fullmatch(value) is None for value in digests)
                or not hmac.compare_digest(
                    _sha256(cls._tombstone_material(tombstone)),
                    tombstone.tombstone_sha256,
                )
            ):
                raise ValueError("invalid tombstone")
        except (TypeError, ValueError) as exc:
            raise CustomerSandboxIntegrityError("sandbox_tombstone_corrupt") from exc
        return tombstone

    @staticmethod
    def _snapshot_json(snapshot: SanitizedSandboxSnapshot) -> str:
        return _canonical(asdict(snapshot)).decode("ascii")

    def _snapshot(
        self, connection: sqlite3.Connection, record: CustomerSandboxRecord
    ) -> SanitizedSandboxSnapshot:
        row = connection.execute(
            "SELECT snapshot_json,snapshot_sha256 FROM customer_sandbox_snapshots "
            "WHERE sandbox_id=? AND snapshot_revision=?",
            (record.sandbox_id, record.snapshot_revision),
        ).fetchone()
        if row is None:
            raise CustomerSandboxIntegrityError("sandbox_snapshot_missing")
        try:
            value = json.loads(str(row["snapshot_json"]))
            value["module_allowlist"] = tuple(value["module_allowlist"])
            snapshot = SanitizedSandboxSnapshot(**value)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise CustomerSandboxIntegrityError("sandbox_snapshot_corrupt") from exc
        if (
            snapshot.schema != SNAPSHOT_SCHEMA
            or not hmac.compare_digest(snapshot.snapshot_sha256, record.snapshot_sha256)
            or not hmac.compare_digest(_sha256(_snapshot_material(snapshot)), snapshot.snapshot_sha256)
            or not hmac.compare_digest(str(row["snapshot_sha256"]), snapshot.snapshot_sha256)
        ):
            raise CustomerSandboxIntegrityError("sandbox_snapshot_corrupt")
        return snapshot

    def _resync_baseline(
        self,
        connection: sqlite3.Connection,
        record: CustomerSandboxRecord,
    ) -> CustomerSandboxRecord:
        row = connection.execute(
            "SELECT baseline_json FROM customer_sandbox_resync_baselines "
            "WHERE sandbox_id=? AND snapshot_revision=?",
            (record.sandbox_id, record.snapshot_revision),
        ).fetchone()
        if row is None:
            raise CustomerSandboxIntegrityError("sandbox_resync_baseline_missing")
        try:
            value = json.loads(str(row["baseline_json"]))
            value["module_allowlist"] = tuple(value["module_allowlist"])
            baseline = self._validate_record(CustomerSandboxRecord(**value))
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise CustomerSandboxIntegrityError("sandbox_resync_baseline_corrupt") from exc
        if (
            baseline.sandbox_id != record.sandbox_id
            or baseline.snapshot_revision + 1 != record.snapshot_revision
            or baseline.target_sandbox_id != record.target_sandbox_id
        ):
            raise CustomerSandboxIntegrityError("sandbox_resync_baseline_corrupt")
        return baseline

    @staticmethod
    def _request_hash(action: str, sandbox_id: str, principal: str, payload: object) -> str:
        return _sha256(
            {
                "action": action,
                "sandbox_id": sandbox_id,
                "principal_sha256": principal,
                "payload": payload,
            },
            maximum=512 * 1024,
        )

    @staticmethod
    def _source_bound_payload(
        payload: Mapping[str, object],
        *,
        source_revision: int,
        source_config_sha256: str,
    ) -> dict[str, object]:
        return {
            **payload,
            "source_revision": source_revision,
            "source_config_sha256": source_config_sha256,
        }

    def _replay_row(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
    ) -> tuple[str, CustomerSandboxRecord] | None:
        row = connection.execute(
            "SELECT action,request_sha256,result_json FROM customer_sandbox_operations "
            "WHERE key_sha256=?",
            (key_sha256,),
        ).fetchone()
        if row is None:
            return None
        if row["action"] != action:
            raise CustomerSandboxConflict("sandbox_idempotency_conflict")
        try:
            value = json.loads(str(row["result_json"]))
            value["module_allowlist"] = tuple(value["module_allowlist"])
            record = self._validate_record(CustomerSandboxRecord(**value))
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise CustomerSandboxIntegrityError("sandbox_operation_corrupt") from exc
        return str(row["request_sha256"]), record

    def _replay(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
    ) -> CustomerSandboxRecord | None:
        replay = self._replay_row(
            connection,
            key_sha256=key_sha256,
            action=action,
        )
        if replay is None:
            return None
        stored_request_sha256, record = replay
        if not hmac.compare_digest(stored_request_sha256, request_sha256):
            raise CustomerSandboxConflict("sandbox_idempotency_conflict")
        return record

    def _replay_source_bound(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        sandbox_id: str,
        principal_sha256: str,
        payload: Callable[[CustomerSandboxRecord], Mapping[str, object]],
    ) -> CustomerSandboxRecord | None:
        replay = self._replay_row(
            connection,
            key_sha256=key_sha256,
            action=action,
        )
        if replay is None:
            return None
        stored_request_sha256, record = replay
        request_sha256 = self._request_hash(
            action,
            sandbox_id,
            principal_sha256,
            payload(record),
        )
        if not hmac.compare_digest(stored_request_sha256, request_sha256):
            raise CustomerSandboxConflict("sandbox_idempotency_conflict")
        return record

    @staticmethod
    def _save_operation(
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
        result: CustomerSandboxRecord,
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO customer_sandbox_operations VALUES (?,?,?,?,?)",
            (
                key_sha256,
                action,
                request_sha256,
                _canonical(asdict(result)).decode("ascii"),
                now,
            ),
        )

    @staticmethod
    def _complete_operation(
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
        result: CustomerSandboxRecord,
        now: float,
    ) -> None:
        cursor = connection.execute(
            "UPDATE customer_sandbox_operations SET result_json=?,created_at=? "
            "WHERE key_sha256=? AND action=? AND request_sha256=?",
            (
                _canonical(asdict(result)).decode("ascii"),
                now,
                key_sha256,
                action,
                request_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise CustomerSandboxIntegrityError("sandbox_operation_intent_missing")

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        sandbox_id: str,
        action: str,
        detail_sha256: str,
        principal_sha256: str,
        now: float,
    ) -> None:
        prior = connection.execute(
            "SELECT event_sha256 FROM customer_sandbox_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = "0" * 64 if prior is None else str(prior["event_sha256"])
        material = {
            "schema": AUDIT_SCHEMA,
            "sandbox_id": sandbox_id,
            "action": action,
            "detail_sha256": detail_sha256,
            "principal_sha256": principal_sha256,
            "occurred_at": now,
            "previous_sha256": previous,
        }
        event_sha = _sha256(material)
        connection.execute(
            "INSERT INTO customer_sandbox_audit "
            "(sandbox_id,action,detail_sha256,principal_sha256,occurred_at,previous_sha256,event_sha256) "
            "VALUES (?,?,?,?,?,?,?)",
            (sandbox_id, action, detail_sha256, principal_sha256, now, previous, event_sha),
        )

    @staticmethod
    def _cas(record: CustomerSandboxRecord, expected_revision: int) -> None:
        expected = _integer(
            expected_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="expected_revision",
        )
        if record.revision != expected:
            raise CustomerSandboxConflict("sandbox_revision_conflict")

    def _source_exact(self, record: CustomerSandboxRecord) -> SourceTenantConfiguration:
        source = _validated_source(self._source_resolver, record.source_tenant_id)
        if (
            _sandbox_tenant_id(source.tenant_id) != record.source_tenant_id
            or source.revision != record.source_revision
            or not hmac.compare_digest(source.config_sha256, record.source_config_sha256)
        ):
            raise CustomerSandboxConflict("sandbox_source_authority_changed")
        return source

    def _target_exact(self, record: CustomerSandboxRecord) -> SandboxTargetAuthority:
        if record.workspace_sha256 is None:
            raise CustomerSandboxConflict("sandbox_target_authority_missing")
        authority = self._provisioner.inspect(record.target_sandbox_id)
        if (
            authority is None
            or authority.sandbox_id != record.sandbox_id
            or not hmac.compare_digest(authority.snapshot_sha256, record.snapshot_sha256)
            or not hmac.compare_digest(authority.workspace_sha256, record.workspace_sha256)
        ):
            raise CustomerSandboxConflict("sandbox_target_authority_changed")
        return authority

    def _assert_no_production_target_collision(self, target_sandbox_id: str) -> None:
        try:
            collision = self._target_collision_resolver(target_sandbox_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise CustomerSandboxConfigError("sandbox_target_authority_unavailable") from exc
        if type(collision) is not bool:
            raise CustomerSandboxConfigError("sandbox_target_authority_invalid")
        if collision:
            raise CustomerSandboxConflict("sandbox_target_collision")

    @staticmethod
    def _target_matches_state(
        record: CustomerSandboxRecord,
        authority: SandboxTargetAuthority,
        state: str,
    ) -> bool:
        return (
            authority.sandbox_id == record.sandbox_id
            and authority.target_sandbox_id == record.target_sandbox_id
            and hmac.compare_digest(authority.snapshot_sha256, record.snapshot_sha256)
            and authority.status == state
            and authority.plan == record.plan
            and authority.quota_bytes == record.quota_bytes
            and authority.expires_at == record.expires_at
        )

    def request_sandbox(
        self,
        sandbox_id: str,
        *,
        source_tenant_id: str,
        target_sandbox_id: str,
        module_allowlist: Sequence[str],
        expires_at: float,
        retained_until: float,
        plan: str,
        quota_bytes: int,
        max_attempts: int = 5,
        idempotency_key: str,
    ) -> CustomerSandboxRecord:
        self._gate()
        selected_id = _opaque_id(sandbox_id)
        source_id = _sandbox_tenant_id(source_tenant_id)
        target_id = _sandbox_tenant_id(target_sandbox_id)
        if source_id == target_id:
            raise CustomerSandboxValidationError("sandbox_source_target_conflict")
        expiry = _timestamp(expires_at, label="expires_at")
        retained = _timestamp(retained_until, label="retained_until")
        if not expiry <= retained <= expiry + _MAX_RETENTION_SECONDS:
            raise CustomerSandboxValidationError("sandbox_retention_invalid")
        allowlist = _module_allowlist(tuple(module_allowlist))
        principal = _principal_sha256(self._principal_resolver)
        selected_plan = _opaque_id(plan, label="plan")
        selected_quota = _integer(
            quota_bytes,
            minimum=4_096,
            maximum=_MAX_QUOTA_BYTES,
            label="quota_bytes",
        )
        attempts = _integer(max_attempts, minimum=1, maximum=20, label="max_attempts")
        key = _operation_key(idempotency_key)
        request_payload: dict[str, object] = {
            "source_tenant_id": source_id,
            "target_sandbox_id": target_id,
            "module_allowlist": allowlist,
            "expires_at": expiry,
            "retained_until": retained,
            "plan": selected_plan,
            "quota_bytes": selected_quota,
            "max_attempts": attempts,
        }
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay_source_bound(
                connection,
                key_sha256=key,
                action="request_sandbox",
                sandbox_id=selected_id,
                principal_sha256=principal,
                payload=lambda record: self._source_bound_payload(
                    request_payload,
                    source_revision=record.source_revision,
                    source_config_sha256=record.source_config_sha256,
                ),
            )
            if replay is not None:
                connection.commit()
                return replay
            now = self._now()
            if not now + 60 <= expiry <= now + _MAX_EXPIRY_SECONDS:
                raise CustomerSandboxValidationError("sandbox_expiry_invalid")
            source = _validated_source(self._source_resolver, source_id)
            snapshot = _snapshot_from_source(
                sandbox_id=selected_id,
                source=source,
                target_sandbox_id=target_id,
                snapshot_revision=1,
                module_allowlist=allowlist,
                expires_at=expiry,
                retained_until=retained,
                plan=selected_plan,
                quota_bytes=selected_quota,
                created_at=now,
            )
            request_sha = self._request_hash(
                "request_sandbox",
                selected_id,
                principal,
                self._source_bound_payload(
                    request_payload,
                    source_revision=snapshot.source_revision,
                    source_config_sha256=snapshot.source_config_sha256,
                ),
            )
            if connection.execute(
                "SELECT 1 FROM customer_sandboxes WHERE sandbox_id=? OR target_sandbox_id=? "
                "UNION ALL SELECT 1 FROM customer_sandbox_tombstones WHERE sandbox_id=? LIMIT 1",
                (selected_id, target_id, selected_id),
            ).fetchone():
                raise CustomerSandboxConflict("sandbox_target_collision")
            self._assert_no_production_target_collision(target_id)
            if self._provisioner.inspect(target_id) is not None:
                raise CustomerSandboxConflict("sandbox_target_collision")
            record = self._with_integrity(
                CustomerSandboxRecord(
                    RECORD_SCHEMA,
                    selected_id,
                    source_id,
                    snapshot.source_revision,
                    snapshot.source_config_sha256,
                    target_id,
                    1,
                    snapshot.snapshot_sha256,
                    allowlist,
                    expiry,
                    retained,
                    snapshot.plan,
                    snapshot.quota_bytes,
                    "requested",
                    "create",
                    1,
                    0,
                    attempts,
                    principal,
                    None,
                    None,
                    None,
                    None,
                    None,
                    now,
                    now,
                    None,
                    "0" * 64,
                )
            )
            self._insert_record(connection, record)
            connection.execute(
                "INSERT INTO customer_sandbox_snapshots VALUES (?,?,?,?,?,?)",
                (
                    selected_id,
                    1,
                    snapshot.snapshot_sha256,
                    self._snapshot_json(snapshot),
                    now,
                    principal,
                ),
            )
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_requested",
                detail_sha256=record.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key,
                action="request_sandbox",
                request_sha256=request_sha,
                result=record,
                now=now,
            )
            connection.commit()
            return record

    def get_sandbox(self, sandbox_id: str) -> CustomerSandboxRecord:
        with self._connection() as connection:
            return self._get(connection, sandbox_id)

    def list_sandboxes(self, *, limit: int = 100) -> tuple[CustomerSandboxRecord, ...]:
        bounded = _integer(limit, minimum=1, maximum=500, label="limit")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM customer_sandboxes ORDER BY created_at,sandbox_id LIMIT ?",
                (bounded,),
            ).fetchall()
            return tuple(self._record_from_row(row) for row in rows)

    def status(self) -> Mapping[str, object]:
        return {
            "schema": "lightwork.customer-sandbox-store-status.v1",
            "enabled": self._admission_enabled(),
            **self.product_boundaries(),
        }

    def _simple_transition(
        self,
        sandbox_id: str,
        *,
        action: str,
        expected_revision: int,
        idempotency_key: str,
        allowed_states: frozenset[str],
        target_state: str,
        four_eyes_from: str | None = None,
        admission_required: bool = True,
    ) -> CustomerSandboxRecord:
        if admission_required:
            self._gate()
        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        request_sha = self._request_hash(
            action,
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(
                connection,
                key_sha256=key,
                action=action,
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            now = self._now()
            current = self._get(connection, selected_id)
            self._cas(current, expected_revision)
            if current.state not in allowed_states:
                raise CustomerSandboxConflict("sandbox_state_conflict")
            if four_eyes_from is not None:
                prior = getattr(current, four_eyes_from)
                if prior is None or hmac.compare_digest(prior, principal):
                    raise CustomerSandboxPermissionDenied("sandbox_four_eyes_required")
            if target_state in {"destroy_approved", "abandon_approved"}:
                if target_state == "abandon_approved":
                    fingerprint = self._provisioner.abandon_fingerprint(
                        sandbox_id=current.sandbox_id,
                        target_sandbox_id=current.target_sandbox_id,
                        snapshot_sha256=current.snapshot_sha256,
                        quota_bytes=current.quota_bytes,
                    )
                    if fingerprint != current.workspace_sha256:
                        raise CustomerSandboxConflict("sandbox_target_authority_changed")
                elif current.workspace_sha256 is not None:
                    self._target_exact(current)
                elif self._provisioner.inspect(current.target_sandbox_id) is not None:
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
            else:
                self._source_exact(current)
            changes: dict[str, Any] = {
                "state": target_state,
                "revision": current.revision + 1,
                "updated_at": now,
                "last_error_code": None,
            }
            if target_state in {"approved", "resync_approved"}:
                changes["approved_by_sha256"] = principal
            if target_state in {"destroy_approved", "abandon_approved"}:
                changes["destroy_approved_by_sha256"] = principal
            updated = self._with_integrity(replace(current, **changes))
            self._update_record(connection, updated)
            self._audit(
                connection,
                sandbox_id=selected_id,
                action=action,
                detail_sha256=updated.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key,
                action=action,
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def approve_sandbox(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomerSandboxRecord:
        self._gate()
        with self._connection() as connection:
            current = self._get(connection, sandbox_id)
        target = "approved" if current.state == "requested" else "resync_approved"
        allowed = frozenset({"requested"}) if target == "approved" else frozenset({"resync_requested"})
        return self._simple_transition(
            sandbox_id,
            action="approve_sandbox",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            allowed_states=allowed,
            target_state=target,
            four_eyes_from="requested_by_sha256",
        )

    def _mark_provisioning(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        retry: bool,
        key_sha256: str,
        action: str,
        request_sha256: str,
    ) -> tuple[CustomerSandboxRecord, SanitizedSandboxSnapshot, str, float]:
        self._gate()
        principal = _principal_sha256(self._principal_resolver)
        now = self._now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get(connection, sandbox_id)
            self._cas(current, expected_revision)
            allowed = {"approved", "resync_approved"}
            if retry:
                allowed |= {"provisioning", "failed"}
            if current.state not in allowed or current.approved_by_sha256 is None:
                raise CustomerSandboxConflict("sandbox_state_conflict")
            self._assert_no_production_target_collision(current.target_sandbox_id)
            if now >= current.expires_at:
                raise CustomerSandboxConflict("sandbox_expired")
            if hmac.compare_digest(current.requested_by_sha256, current.approved_by_sha256):
                raise CustomerSandboxIntegrityError("sandbox_four_eyes_corrupt")
            self._source_exact(current)
            snapshot = self._snapshot(connection, current)
            updated = self._with_integrity(
                replace(
                    current,
                    state="provisioning",
                    revision=current.revision + 1,
                    attempts=current.attempts + 1,
                    last_error_code=None,
                    updated_at=now,
                )
            )
            if updated.attempts > updated.max_attempts:
                raise CustomerSandboxConflict("sandbox_attempt_limit_exhausted")
            self._update_record(connection, updated)
            self._audit(
                connection,
                sandbox_id=updated.sandbox_id,
                action="sandbox_provisioning_started",
                detail_sha256=updated.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha256,
                action=action,
                request_sha256=request_sha256,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated, snapshot, principal, now

    def _rollback_terminal_resync(self, sandbox_id: str, principal: str) -> bool:
        """Restore the pinned prior authority after terminal resync failure."""

        now = self._now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._get(connection, sandbox_id)
            if (
                current.state != "failed"
                or current.operation_kind != "resync"
                or current.attempts < current.max_attempts
            ):
                connection.commit()
                return False
            baseline = self._resync_baseline(connection, current)
            prior_snapshot = self._snapshot(connection, baseline)
            proposal_snapshot = self._snapshot(connection, current)
            desired_state = "expired" if now >= baseline.expires_at else baseline.state
            try:
                self._assert_no_production_target_collision(current.target_sandbox_id)
            except CustomerSandboxConflict:
                if desired_state == "active":
                    desired_state = "suspended"
                else:
                    raise
            for attempt in range(2):
                try:
                    if self._provisioner.resume_collision_cleanup(proposal_snapshot):
                        discarded = self._provisioner.discard_collision_recreation(
                            proposal_snapshot,
                            allow_other_provision_intent=True,
                        )
                        if discarded:
                            self._provisioner.retire_collision_cleanup_after_recovery(
                                sandbox_id=current.sandbox_id,
                                target_sandbox_id=current.target_sandbox_id,
                                proposal_snapshot_sha256=current.snapshot_sha256,
                                recovered_snapshot_sha256=None,
                            )
                    receipt = self._provisioner.restore_resync_baseline(
                        prior_snapshot,
                        expected_workspace_sha256=baseline.workspace_sha256,
                        proposal_snapshot_sha256=current.snapshot_sha256,
                    )
                    if receipt.workspace_sha256 is None:
                        raise CustomerSandboxProvisioningError(
                            "sandbox_provisioning_receipt_invalid"
                        )
                    workspace_sha256 = receipt.workspace_sha256
                    if desired_state != "active":
                        status_receipt = self._provisioner.set_status(
                            target_sandbox_id=current.target_sandbox_id,
                            expected_workspace_sha256=workspace_sha256,
                            status=desired_state,
                        )
                        if status_receipt.workspace_sha256 is None:
                            raise CustomerSandboxProvisioningError(
                                "sandbox_provisioning_receipt_invalid"
                            )
                        workspace_sha256 = status_receipt.workspace_sha256
                    break
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:
                    if attempt == 1:
                        raise CustomerSandboxProvisioningError(
                            "sandbox_resync_rollback_retryable"
                        ) from exc
            self._provisioner.retire_collision_cleanup_after_recovery(
                sandbox_id=current.sandbox_id,
                target_sandbox_id=current.target_sandbox_id,
                proposal_snapshot_sha256=current.snapshot_sha256,
                recovered_snapshot_sha256=prior_snapshot.snapshot_sha256,
            )
            restored = self._with_integrity(
                replace(
                    baseline,
                    state=desired_state,
                    revision=current.revision + 1,
                    attempts=0,
                    workspace_sha256=workspace_sha256,
                    last_error_code="sandbox_resync_rolled_back",
                    updated_at=now,
                )
            )
            self._retire_resync_proposal(connection, current)
            self._update_record(connection, restored)
            self._audit(
                connection,
                sandbox_id=current.sandbox_id,
                action="sandbox_resync_rolled_back",
                detail_sha256=restored.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            connection.commit()
            return True

    def _remediation_record(
        self,
        connection: sqlite3.Connection,
        current: CustomerSandboxRecord,
    ) -> CustomerSandboxRecord:
        """Cancel a non-running resync back to its exact live authority.

        A requested snapshot is intentionally persisted before provisioning,
        while the workspace remains pinned to the prior snapshot.  Emergency
        suspension, expiry, and destruction must therefore operate on the
        independently stored baseline, not the proposed snapshot fields.
        Keeping the latest CAS revision makes a lost filesystem acknowledgement
        deterministically adoptable by the next identical remediation retry.
        """

        if not (
            current.operation_kind == "resync"
            and current.state in {"resync_requested", "resync_approved", "failed"}
        ):
            return current
        baseline = self._resync_baseline(connection, current)
        if baseline.state not in _ACTIVE_TARGET_STATES or baseline.workspace_sha256 is None:
            raise CustomerSandboxIntegrityError("sandbox_resync_baseline_corrupt")
        return self._with_integrity(
            replace(
                baseline,
                revision=current.revision,
                updated_at=current.updated_at,
                last_error_code="sandbox_resync_cancelled_for_remediation",
            )
        )

    def _retire_resync_proposal(
        self,
        connection: sqlite3.Connection,
        proposal: CustomerSandboxRecord,
    ) -> None:
        """Remove a cancelled proposal and its replay authority transactionally."""

        if not (
            proposal.operation_kind == "resync"
            and proposal.state in {"resync_requested", "resync_approved", "failed"}
        ):
            return
        rows = connection.execute(
            "SELECT key_sha256,result_json FROM customer_sandbox_operations LIMIT 100001"
        ).fetchall()
        if len(rows) > 100_000:
            raise CustomerSandboxIntegrityError("sandbox_operation_history_oversized")
        keys: list[str] = []
        for row in rows:
            try:
                value = json.loads(str(row["result_json"]))
                value["module_allowlist"] = tuple(value["module_allowlist"])
                result = self._validate_record(CustomerSandboxRecord(**value))
            except (
                TypeError,
                ValueError,
                KeyError,
                json.JSONDecodeError,
                CustomerSandboxError,
            ) as exc:
                raise CustomerSandboxIntegrityError("sandbox_operation_corrupt") from exc
            if (
                result.sandbox_id == proposal.sandbox_id
                and result.operation_kind == "resync"
                and result.snapshot_revision == proposal.snapshot_revision
            ):
                keys.append(str(row["key_sha256"]))
        if keys:
            connection.executemany(
                "DELETE FROM customer_sandbox_operations WHERE key_sha256=?",
                ((key,) for key in keys),
            )
        connection.execute(
            "DELETE FROM customer_sandbox_resync_baselines "
            "WHERE sandbox_id=? AND snapshot_revision=?",
            (proposal.sandbox_id, proposal.snapshot_revision),
        )
        connection.execute(
            "DELETE FROM customer_sandbox_snapshots "
            "WHERE sandbox_id=? AND snapshot_revision=?",
            (proposal.sandbox_id, proposal.snapshot_revision),
        )

    def _expire_provisioned_target(
        self,
        *,
        target_sandbox_id: str,
        expected_workspace_sha256: str,
    ) -> str:
        """Close the one exact active-to-expired filesystem write split."""

        for attempt in range(2):
            try:
                receipt = self._provisioner.set_status(
                    target_sandbox_id=target_sandbox_id,
                    expected_workspace_sha256=expected_workspace_sha256,
                    status="expired",
                )
                if receipt.workspace_sha256 is None:
                    raise CustomerSandboxProvisioningError(
                        "sandbox_provisioning_receipt_invalid"
                    )
                return receipt.workspace_sha256
            except (KeyboardInterrupt, SystemExit):
                raise
            except CustomerSandboxProvisioningError:
                raise
            except Exception as exc:
                if attempt == 1:
                    raise CustomerSandboxProvisioningError(
                        "sandbox_expiry_transition_retryable"
                    ) from exc
        raise CustomerSandboxProvisioningError("sandbox_expiry_transition_retryable")

    def provision_sandbox(  # noqa: C901 - durable intent recovery is intentionally explicit
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        retry: bool = False,
    ) -> CustomerSandboxRecord:
        self._gate()
        selected_id = _opaque_id(sandbox_id)
        principal = _principal_sha256(self._principal_resolver)
        key = _operation_key(idempotency_key)
        action = "retry_provision" if retry else "provision_sandbox"
        request_sha = self._request_hash(
            action,
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        terminal_resync = False
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(
                connection,
                key_sha256=key,
                action=action,
                request_sha256=request_sha,
            )
            if replay is not None:
                if replay.state != "provisioning":
                    connection.commit()
                    return replay
                current = self._get(connection, selected_id)
                if current.state == "failed" and current.attempts >= current.max_attempts:
                    if current.operation_kind != "resync":
                        raise CustomerSandboxConflict("sandbox_attempt_limit_exhausted")
                    terminal_resync = True
                    connection.commit()
                elif not hmac.compare_digest(
                    current.integrity_sha256,
                    replay.integrity_sha256,
                ):
                    raise CustomerSandboxConflict("sandbox_provision_retry_required")
                elif (
                    current.state != "provisioning"
                    or current.sandbox_id != replay.sandbox_id
                    or current.operation_kind != replay.operation_kind
                    or current.snapshot_revision != replay.snapshot_revision
                    or not hmac.compare_digest(
                        current.snapshot_sha256,
                        replay.snapshot_sha256,
                    )
                ):
                    raise CustomerSandboxIntegrityError("sandbox_operation_intent_drift")
                else:
                    snapshot = self._snapshot(connection, current)
                    connection.commit()
            else:
                current = self._get(connection, selected_id)
                terminal_resync = (
                    current.state == "failed"
                    and current.operation_kind == "resync"
                    and current.attempts >= current.max_attempts
                )
                if terminal_resync:
                    self._cas(current, expected_revision)
                    if not retry:
                        raise CustomerSandboxConflict(
                            "sandbox_provision_retry_required"
                        )
                connection.commit()
                if not terminal_resync:
                    current, snapshot, principal, _started = self._mark_provisioning(
                        selected_id,
                        expected_revision=expected_revision,
                        retry=retry,
                        key_sha256=key,
                        action=action,
                        request_sha256=request_sha,
                    )
        if terminal_resync:
            if self._rollback_terminal_resync(selected_id, principal):
                raise CustomerSandboxProvisioningError(
                    "sandbox_resync_rolled_back"
                )
            raise CustomerSandboxConflict("sandbox_attempt_limit_exhausted")
        cleanup_resumed = False
        try:
            cleanup_resumed = self._provisioner.resume_collision_cleanup(snapshot)
            self._assert_no_production_target_collision(current.target_sandbox_id)
            if cleanup_resumed:
                receipt = self._provisioner.recreate_after_collision_cleanup(snapshot)
            else:
                receipt = self._provisioner.apply(
                    snapshot,
                    expected_workspace_sha256=current.workspace_sha256,
                )
            if (
                receipt.status not in {"active", "expired"}
                or receipt.workspace_sha256 is None
                or not hmac.compare_digest(receipt.snapshot_sha256, snapshot.snapshot_sha256)
            ):
                raise CustomerSandboxProvisioningError("sandbox_provisioning_receipt_invalid")
            try:
                self._assert_no_production_target_collision(current.target_sandbox_id)
            except CustomerSandboxError:
                self._provisioner.begin_collision_cleanup(
                    snapshot,
                    expected_workspace_sha256=receipt.workspace_sha256,
                )
                raise
            completion_state = receipt.status
            completion_workspace = receipt.workspace_sha256
            if completion_state == "active" and self._now() >= current.expires_at:
                completion_workspace = self._expire_provisioned_target(
                    target_sandbox_id=current.target_sandbox_id,
                    expected_workspace_sha256=completion_workspace,
                )
                completion_state = "expired"
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if (
                cleanup_resumed
                and isinstance(exc, CustomerSandboxConflict)
                and exc.error_code == "sandbox_target_collision"
            ):
                # Keep the durable operation intent replayable while the
                # independently resolved production collision remains active.
                self._provisioner.discard_collision_recreation(snapshot)
                raise
            error_code = (
                exc.error_code
                if isinstance(exc, CustomerSandboxError)
                else "sandbox_provisioner_failed"
            )
            now = self._now()
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                latest = self._get(connection, selected_id)
                if latest.revision != current.revision or latest.state != "provisioning":
                    raise CustomerSandboxConflict("sandbox_revision_conflict") from exc
                failed = self._with_integrity(
                    replace(
                        latest,
                        state="failed" if latest.attempts >= latest.max_attempts else "provisioning",
                        revision=latest.revision + 1,
                        last_error_code=error_code,
                        updated_at=now,
                    )
                )
                self._update_record(connection, failed)
                self._audit(
                    connection,
                    sandbox_id=selected_id,
                    action="sandbox_provisioning_failed",
                    detail_sha256=failed.integrity_sha256,
                    principal_sha256=principal,
                    now=now,
                )
                connection.commit()
            if failed.state == "failed" and failed.operation_kind == "resync":
                try:
                    self._rollback_terminal_resync(selected_id, principal)
                except CustomerSandboxError:
                    pass
            raise CustomerSandboxProvisioningError("sandbox_provisioning_retryable") from exc
        now = self._now()
        if completion_state == "active" and now >= current.expires_at:
            completion_workspace = self._expire_provisioned_target(
                target_sandbox_id=current.target_sandbox_id,
                expected_workspace_sha256=completion_workspace,
            )
            completion_state = "expired"
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._assert_no_production_target_collision(current.target_sandbox_id)
            except CustomerSandboxError:
                self._provisioner.begin_collision_cleanup(
                    snapshot,
                    expected_workspace_sha256=completion_workspace,
                )
                raise
            replay = self._replay(
                connection,
                key_sha256=key,
                action=action,
                request_sha256=request_sha,
            )
            if replay is None:
                raise CustomerSandboxIntegrityError("sandbox_operation_intent_missing")
            if replay.state != "provisioning":
                connection.commit()
                return replay
            latest = self._get(connection, selected_id)
            if latest.revision != current.revision or latest.state != "provisioning":
                raise CustomerSandboxConflict("sandbox_revision_conflict")
            completed = self._with_integrity(
                replace(
                    latest,
                    state=completion_state,
                    workspace_sha256=completion_workspace,
                    revision=latest.revision + 1,
                    last_error_code=None,
                    updated_at=now,
                )
            )
            if completed.operation_kind == "resync":
                connection.execute(
                    "DELETE FROM customer_sandbox_resync_baselines "
                    "WHERE sandbox_id=? AND snapshot_revision=?",
                    (completed.sandbox_id, completed.snapshot_revision),
                )
            self._update_record(connection, completed)
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_provisioned",
                detail_sha256=completed.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._complete_operation(
                connection,
                key_sha256=key,
                action=action,
                request_sha256=request_sha,
                result=completed,
                now=now,
            )
            connection.commit()
            return completed

    def _target_status_transition(
        self,
        sandbox_id: str,
        *,
        action: str,
        expected_revision: int,
        idempotency_key: str,
        allowed_states: frozenset[str],
        target_state: str,
        admission_required: bool,
    ) -> CustomerSandboxRecord:
        if admission_required:
            self._gate()
        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        request_sha = self._request_hash(
            action,
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(
                connection,
                key_sha256=key,
                action=action,
                request_sha256=request_sha,
            )
            if replay is not None:
                return replay
            now = self._now()
            proposal = self._get(connection, selected_id)
            self._cas(proposal, expected_revision)
            current = self._remediation_record(connection, proposal)
            if current.state == target_state:
                self._target_exact(current)
                if proposal.integrity_sha256 != current.integrity_sha256:
                    current = self._with_integrity(
                        replace(
                            current,
                            revision=current.revision + 1,
                            updated_at=now,
                        )
                    )
                    self._retire_resync_proposal(connection, proposal)
                    self._update_record(connection, current)
                    self._audit(
                        connection,
                        sandbox_id=selected_id,
                        action=action,
                        detail_sha256=current.integrity_sha256,
                        principal_sha256=principal,
                        now=now,
                    )
                self._save_operation(
                    connection,
                    key_sha256=key,
                    action=action,
                    request_sha256=request_sha,
                    result=current,
                    now=now,
                )
                connection.commit()
                return current
            if current.state not in allowed_states:
                raise CustomerSandboxConflict("sandbox_state_conflict")
            if action == "expire_sandbox" and now < current.expires_at:
                raise CustomerSandboxConflict("sandbox_not_expired")
            if target_state == "active":
                self._assert_no_production_target_collision(current.target_sandbox_id)
            if target_state == "active" and now >= current.expires_at:
                raise CustomerSandboxConflict("sandbox_expired")
            try:
                authority = self._provisioner.inspect(current.target_sandbox_id)
            except CustomerSandboxIntegrityError:
                # Recover the one permitted split-brain: manifest is the exact
                # deterministic successor while the registry is its exact
                # predecessor. set_status validates and closes that window.
                receipt = self._provisioner.set_status(
                    target_sandbox_id=current.target_sandbox_id,
                    expected_workspace_sha256=current.workspace_sha256 or "",
                    status=target_state,
                )
                if receipt.workspace_sha256 is None:
                    raise CustomerSandboxProvisioningError(
                        "sandbox_provisioning_receipt_invalid"
                    ) from None
                authority = self._provisioner.inspect(current.target_sandbox_id)
            if authority is None:
                raise CustomerSandboxConflict("sandbox_target_authority_changed")
            if self._target_matches_state(current, authority, target_state):
                # A previous attempt durably changed the workspace but lost its
                # SQLite acknowledgement.  The provisioner has already
                # validated the deterministic authority digest, so adopt it.
                workspace_sha256 = authority.workspace_sha256
            else:
                if (
                    not self._target_matches_state(current, authority, current.state)
                    or current.workspace_sha256 is None
                    or not hmac.compare_digest(
                        authority.workspace_sha256,
                        current.workspace_sha256,
                    )
                ):
                    raise CustomerSandboxConflict("sandbox_target_authority_changed")
                try:
                    receipt = self._provisioner.set_status(
                        target_sandbox_id=current.target_sandbox_id,
                        expected_workspace_sha256=authority.workspace_sha256,
                        status=target_state,
                    )
                except (KeyboardInterrupt, SystemExit):
                    raise
                except CustomerSandboxError:
                    raise
                except Exception as exc:
                    raise CustomerSandboxProvisioningError(
                        "sandbox_status_transition_retryable"
                    ) from exc
                if receipt.workspace_sha256 is None:
                    raise CustomerSandboxProvisioningError(
                        "sandbox_provisioning_receipt_invalid"
                    )
                workspace_sha256 = receipt.workspace_sha256
            updated = self._with_integrity(
                replace(
                    current,
                    state=target_state,
                    workspace_sha256=workspace_sha256,
                    revision=current.revision + 1,
                    updated_at=now,
                    last_error_code=None,
                )
            )
            self._retire_resync_proposal(connection, proposal)
            self._update_record(connection, updated)
            self._audit(
                connection,
                sandbox_id=selected_id,
                action=action,
                detail_sha256=updated.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key,
                action=action,
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def suspend_sandbox(self, sandbox_id: str, *, expected_revision: int, idempotency_key: str):
        return self._target_status_transition(
            sandbox_id,
            action="suspend_sandbox",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            allowed_states=frozenset({"active"}),
            target_state="suspended",
            admission_required=False,
        )

    def resume_sandbox(self, sandbox_id: str, *, expected_revision: int, idempotency_key: str):
        return self._target_status_transition(
            sandbox_id,
            action="resume_sandbox",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            allowed_states=frozenset({"suspended"}),
            target_state="active",
            admission_required=True,
        )

    def expire_sandbox(self, sandbox_id: str, *, expected_revision: int, idempotency_key: str):
        return self._target_status_transition(
            sandbox_id,
            action="expire_sandbox",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            allowed_states=frozenset({"active", "suspended"}),
            target_state="expired",
            admission_required=False,
        )

    def request_resync(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        module_allowlist: Sequence[str] | None = None,
        idempotency_key: str,
    ) -> CustomerSandboxRecord:
        self._gate()
        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        expected = _integer(
            expected_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="expected_revision",
        )
        requested_allowlist = (
            None if module_allowlist is None else _module_allowlist(tuple(module_allowlist))
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay_source_bound(
                connection,
                key_sha256=key,
                action="request_resync",
                sandbox_id=selected_id,
                principal_sha256=principal,
                payload=lambda record: self._source_bound_payload(
                    {
                        "expected_revision": expected,
                        "source_tenant_id": record.source_tenant_id,
                        "module_allowlist": (
                            record.module_allowlist
                            if requested_allowlist is None
                            else requested_allowlist
                        ),
                    },
                    source_revision=record.source_revision,
                    source_config_sha256=record.source_config_sha256,
                ),
            )
            if replay is not None:
                connection.commit()
                return replay
            current = self._get(connection, selected_id)
            self._cas(current, expected)
            if current.state not in _ACTIVE_TARGET_STATES:
                raise CustomerSandboxConflict("sandbox_state_conflict")
            self._assert_no_production_target_collision(current.target_sandbox_id)
            allowlist = (
                current.module_allowlist
                if requested_allowlist is None
                else requested_allowlist
            )
            source = _validated_source(self._source_resolver, current.source_tenant_id)
            if (
                source.revision == current.source_revision
                and hmac.compare_digest(source.config_sha256, current.source_config_sha256)
                and allowlist == current.module_allowlist
            ):
                raise CustomerSandboxConflict("sandbox_resync_no_change")
            now = self._now()
            snapshot = _snapshot_from_source(
                sandbox_id=current.sandbox_id,
                source=source,
                target_sandbox_id=current.target_sandbox_id,
                snapshot_revision=current.snapshot_revision + 1,
                module_allowlist=allowlist,
                expires_at=current.expires_at,
                retained_until=current.retained_until,
                plan=current.plan,
                quota_bytes=current.quota_bytes,
                created_at=now,
            )
            if hmac.compare_digest(snapshot.snapshot_sha256, current.snapshot_sha256):
                raise CustomerSandboxConflict("sandbox_resync_no_change")
            request_sha = self._request_hash(
                "request_resync",
                selected_id,
                principal,
                self._source_bound_payload(
                    {
                        "expected_revision": expected,
                        "source_tenant_id": current.source_tenant_id,
                        "module_allowlist": allowlist,
                    },
                    source_revision=snapshot.source_revision,
                    source_config_sha256=snapshot.source_config_sha256,
                ),
            )
            latest = current
            connection.execute(
                "INSERT INTO customer_sandbox_resync_baselines VALUES (?,?,?)",
                (
                    selected_id,
                    snapshot.snapshot_revision,
                    _canonical(asdict(latest)).decode("ascii"),
                ),
            )
            updated = self._with_integrity(
                replace(
                    latest,
                    source_revision=snapshot.source_revision,
                    source_config_sha256=snapshot.source_config_sha256,
                    snapshot_revision=snapshot.snapshot_revision,
                    snapshot_sha256=snapshot.snapshot_sha256,
                    module_allowlist=snapshot.module_allowlist,
                    state="resync_requested",
                    operation_kind="resync",
                    revision=latest.revision + 1,
                    attempts=0,
                    requested_by_sha256=principal,
                    approved_by_sha256=None,
                    last_error_code=None,
                    updated_at=now,
                )
            )
            self._update_record(connection, updated)
            connection.execute(
                "INSERT INTO customer_sandbox_snapshots VALUES (?,?,?,?,?,?)",
                (
                    selected_id,
                    snapshot.snapshot_revision,
                    snapshot.snapshot_sha256,
                    self._snapshot_json(snapshot),
                    now,
                    principal,
                ),
            )
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_resync_requested",
                detail_sha256=updated.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key,
                action="request_resync",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def request_destroy(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomerSandboxRecord:
        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        request_sha = self._request_hash(
            "request_destroy",
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(
                connection,
                key_sha256=key,
                action="request_destroy",
                request_sha256=request_sha,
            )
            if replay is not None:
                return replay
            now = self._now()
            proposal = self._get(connection, selected_id)
            self._cas(proposal, expected_revision)
            current = self._remediation_record(connection, proposal)
            if current.state not in {"suspended", "expired"}:
                raise CustomerSandboxConflict("sandbox_destroy_requires_suspension")
            self._target_exact(current)
            updated = self._with_integrity(
                replace(
                    current,
                    state="destroy_requested",
                    revision=current.revision + 1,
                    destroy_requested_by_sha256=principal,
                    destroy_approved_by_sha256=None,
                    updated_at=now,
                )
            )
            self._retire_resync_proposal(connection, proposal)
            self._update_record(connection, updated)
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_destroy_requested",
                detail_sha256=updated.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key,
                action="request_destroy",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def approve_destroy(self, sandbox_id: str, *, expected_revision: int, idempotency_key: str):
        record = self._simple_transition(
            sandbox_id,
            action="approve_destroy",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            allowed_states=frozenset({"destroy_requested"}),
            target_state="destroy_approved",
            four_eyes_from="destroy_requested_by_sha256",
            admission_required=False,
        )
        return record

    def request_abandon(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomerSandboxRecord:
        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        request_sha = self._request_hash(
            "request_abandon",
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(
                connection,
                key_sha256=key,
                action="request_abandon",
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            now = self._now()
            current = self._get(connection, selected_id)
            self._cas(current, expected_revision)
            cleanup_allowed = current.state in {"requested", "approved"} or (
                current.state == "failed" and current.attempts >= current.max_attempts
            )
            if current.operation_kind != "create" or not cleanup_allowed:
                raise CustomerSandboxConflict("sandbox_abandon_requires_stale_create")
            workspace_sha256 = self._provisioner.abandon_fingerprint(
                sandbox_id=current.sandbox_id,
                target_sandbox_id=current.target_sandbox_id,
                snapshot_sha256=current.snapshot_sha256,
                quota_bytes=current.quota_bytes,
            )
            updated = self._with_integrity(
                replace(
                    current,
                    state="abandon_requested",
                    revision=current.revision + 1,
                    destroy_requested_by_sha256=principal,
                    destroy_approved_by_sha256=None,
                    workspace_sha256=workspace_sha256,
                    updated_at=now,
                )
            )
            self._update_record(connection, updated)
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_abandon_requested",
                detail_sha256=updated.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key,
                action="request_abandon",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def approve_abandon(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomerSandboxRecord:
        return self._simple_transition(
            sandbox_id,
            action="approve_abandon",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            allowed_states=frozenset({"abandon_requested"}),
            target_state="abandon_approved",
            four_eyes_from="destroy_requested_by_sha256",
            admission_required=False,
        )

    def destroy_sandbox(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomerSandboxRecord:
        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        request_sha = self._request_hash(
            "destroy_sandbox",
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(
                connection,
                key_sha256=key,
                action="destroy_sandbox",
                request_sha256=request_sha,
            )
            if replay is not None:
                return replay
            now = self._now()
            current = self._get(connection, selected_id)
            self._cas(current, expected_revision)
            if (
                current.state != "destroy_approved"
                or current.destroy_requested_by_sha256 is None
                or current.destroy_approved_by_sha256 is None
                or hmac.compare_digest(
                    current.destroy_requested_by_sha256,
                    current.destroy_approved_by_sha256,
                )
                or current.workspace_sha256 is None
            ):
                raise CustomerSandboxPermissionDenied("sandbox_destroy_approval_invalid")
            self._provisioner.destroy(
                sandbox_id=current.sandbox_id,
                target_sandbox_id=current.target_sandbox_id,
                expected_workspace_sha256=current.workspace_sha256,
            )
            updated = self._with_integrity(
                replace(
                    current,
                    state="destroyed",
                    revision=current.revision + 1,
                    updated_at=now,
                    destroyed_at=now,
                    last_error_code=None,
                )
            )
            self._update_record(connection, updated)
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_destroyed",
                detail_sha256=updated.integrity_sha256,
                principal_sha256=principal,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key,
                action="destroy_sandbox",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def abandon_failed_sandbox(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomerSandboxTombstone:
        """Four-eyes cleanup for a terminal initial-create failure."""

        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        request_sha = self._request_hash(
            "abandon_failed_sandbox",
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT * FROM customer_sandbox_tombstones WHERE sandbox_id=?",
                (selected_id,),
            ).fetchone()
            if prior is not None:
                tombstone = self._tombstone_from_row(prior)
                if (
                    not hmac.compare_digest(tombstone.idempotency_key_sha256, key)
                    or not hmac.compare_digest(tombstone.request_sha256, request_sha)
                ):
                    raise CustomerSandboxConflict("sandbox_idempotency_conflict")
                connection.commit()
                return tombstone
            now = self._now()
            current = self._get(connection, selected_id)
            self._cas(current, expected_revision)
            if (
                current.state != "abandon_approved"
                or current.operation_kind != "create"
                or current.destroy_requested_by_sha256 is None
                or current.destroy_approved_by_sha256 is None
                or hmac.compare_digest(
                    current.destroy_requested_by_sha256,
                    current.destroy_approved_by_sha256,
                )
            ):
                raise CustomerSandboxPermissionDenied("sandbox_abandon_approval_invalid")
            self._provisioner.abandon(
                sandbox_id=current.sandbox_id,
                target_sandbox_id=current.target_sandbox_id,
                snapshot_sha256=current.snapshot_sha256,
                quota_bytes=current.quota_bytes,
                expected_fingerprint=current.workspace_sha256,
            )
            self._provisioner.retire_collision_cleanup_after_recovery(
                sandbox_id=current.sandbox_id,
                target_sandbox_id=current.target_sandbox_id,
                proposal_snapshot_sha256=current.snapshot_sha256,
                recovered_snapshot_sha256=None,
            )
            tombstone = CustomerSandboxTombstone(
                TOMBSTONE_SCHEMA,
                current.sandbox_id,
                _text_sha256(current.source_tenant_id),
                _text_sha256(current.target_sandbox_id),
                current.integrity_sha256,
                now,
                current.retained_until,
                now,
                principal,
                key,
                request_sha,
                "0" * 64,
            )
            tombstone = replace(
                tombstone,
                tombstone_sha256=_sha256(self._tombstone_material(tombstone)),
            )
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_failed_create_abandoned",
                detail_sha256=tombstone.tombstone_sha256,
                principal_sha256=principal,
                now=now,
            )
            connection.execute(
                "INSERT INTO customer_sandbox_tombstones VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tombstone.sandbox_id,
                    tombstone.source_tenant_sha256,
                    tombstone.target_sandbox_sha256,
                    tombstone.final_record_sha256,
                    tombstone.destroyed_at,
                    tombstone.retained_until,
                    tombstone.purged_at,
                    tombstone.purged_by_sha256,
                    tombstone.idempotency_key_sha256,
                    tombstone.request_sha256,
                    tombstone.tombstone_sha256,
                ),
            )
            operation_rows = connection.execute(
                "SELECT key_sha256,result_json FROM customer_sandbox_operations LIMIT 100001"
            ).fetchall()
            if len(operation_rows) > 100_000:
                raise CustomerSandboxIntegrityError("sandbox_operation_history_oversized")
            for row in operation_rows:
                try:
                    value = json.loads(str(row["result_json"]))
                except json.JSONDecodeError as exc:
                    raise CustomerSandboxIntegrityError("sandbox_operation_corrupt") from exc
                if value.get("sandbox_id") == selected_id:
                    connection.execute(
                        "DELETE FROM customer_sandbox_operations WHERE key_sha256=?",
                        (str(row["key_sha256"]),),
                    )
            connection.execute(
                "DELETE FROM customer_sandbox_resync_baselines WHERE sandbox_id=?",
                (selected_id,),
            )
            connection.execute(
                "DELETE FROM customer_sandbox_snapshots WHERE sandbox_id=?",
                (selected_id,),
            )
            connection.execute(
                "DELETE FROM customer_sandboxes WHERE sandbox_id=?",
                (selected_id,),
            )
            connection.commit()
            return tombstone

    def purge_destroyed_sandbox(
        self,
        sandbox_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomerSandboxTombstone:
        """Purge retained configuration only; keep digest-only chained audit evidence."""

        principal = _principal_sha256(self._principal_resolver)
        selected_id = _opaque_id(sandbox_id)
        key = _operation_key(idempotency_key)
        request_sha = self._request_hash(
            "purge_destroyed_sandbox",
            selected_id,
            principal,
            {"expected_revision": expected_revision},
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT * FROM customer_sandbox_tombstones WHERE sandbox_id=?",
                (selected_id,),
            ).fetchone()
            if prior is not None:
                tombstone = self._tombstone_from_row(prior)
                if (
                    not hmac.compare_digest(tombstone.idempotency_key_sha256, key)
                    or not hmac.compare_digest(tombstone.request_sha256, request_sha)
                ):
                    raise CustomerSandboxConflict("sandbox_idempotency_conflict")
                connection.commit()
                return tombstone
            now = self._now()
            current = self._get(connection, selected_id)
            self._cas(current, expected_revision)
            if current.state != "destroyed" or current.destroyed_at is None:
                raise CustomerSandboxConflict("sandbox_retention_purge_requires_destroyed")
            if now < current.retained_until:
                raise CustomerSandboxConflict("sandbox_retention_not_elapsed")
            tombstone = CustomerSandboxTombstone(
                schema=TOMBSTONE_SCHEMA,
                sandbox_id=current.sandbox_id,
                source_tenant_sha256=_text_sha256(current.source_tenant_id),
                target_sandbox_sha256=_text_sha256(current.target_sandbox_id),
                final_record_sha256=current.integrity_sha256,
                destroyed_at=current.destroyed_at,
                retained_until=current.retained_until,
                purged_at=now,
                purged_by_sha256=principal,
                idempotency_key_sha256=key,
                request_sha256=request_sha,
                tombstone_sha256="0" * 64,
            )
            tombstone = replace(
                tombstone,
                tombstone_sha256=_sha256(self._tombstone_material(tombstone)),
            )
            operation_rows = connection.execute(
                "SELECT key_sha256,result_json FROM customer_sandbox_operations LIMIT 100001"
            ).fetchall()
            if len(operation_rows) > 100_000:
                raise CustomerSandboxIntegrityError("sandbox_operation_history_oversized")
            operation_keys: list[str] = []
            for row in operation_rows:
                try:
                    value = json.loads(str(row["result_json"]))
                    value["module_allowlist"] = tuple(value["module_allowlist"])
                    result = self._validate_record(CustomerSandboxRecord(**value))
                except (
                    TypeError,
                    ValueError,
                    KeyError,
                    json.JSONDecodeError,
                    CustomerSandboxError,
                ) as exc:
                    raise CustomerSandboxIntegrityError("sandbox_operation_corrupt") from exc
                if result.sandbox_id == selected_id:
                    operation_keys.append(str(row["key_sha256"]))
            self._audit(
                connection,
                sandbox_id=selected_id,
                action="sandbox_retention_purged",
                detail_sha256=tombstone.tombstone_sha256,
                principal_sha256=principal,
                now=now,
            )
            connection.execute(
                "INSERT INTO customer_sandbox_tombstones VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tombstone.sandbox_id,
                    tombstone.source_tenant_sha256,
                    tombstone.target_sandbox_sha256,
                    tombstone.final_record_sha256,
                    tombstone.destroyed_at,
                    tombstone.retained_until,
                    tombstone.purged_at,
                    tombstone.purged_by_sha256,
                    tombstone.idempotency_key_sha256,
                    tombstone.request_sha256,
                    tombstone.tombstone_sha256,
                ),
            )
            if operation_keys:
                connection.executemany(
                    "DELETE FROM customer_sandbox_operations WHERE key_sha256=?",
                    ((value,) for value in operation_keys),
                )
            connection.execute(
                "DELETE FROM customer_sandbox_resync_baselines WHERE sandbox_id=?",
                (selected_id,),
            )
            connection.execute(
                "DELETE FROM customer_sandbox_snapshots WHERE sandbox_id=?",
                (selected_id,),
            )
            connection.execute(
                "DELETE FROM customer_sandboxes WHERE sandbox_id=?",
                (selected_id,),
            )
            connection.commit()
            return tombstone

    def get_tombstone(self, sandbox_id: str) -> CustomerSandboxTombstone:
        selected = _opaque_id(sandbox_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM customer_sandbox_tombstones WHERE sandbox_id=?",
                (selected,),
            ).fetchone()
            if row is None:
                raise CustomerSandboxNotFound("sandbox_tombstone_not_found")
            return self._tombstone_from_row(row)

    def history(self, sandbox_id: str, *, limit: int = 100) -> tuple[CustomerSandboxAuditEvent, ...]:
        selected = _opaque_id(sandbox_id)
        bounded = _integer(limit, minimum=1, maximum=500, label="limit")
        with self._connection() as connection:
            exists = connection.execute(
                "SELECT 1 FROM customer_sandboxes WHERE sandbox_id=? "
                "UNION ALL SELECT 1 FROM customer_sandbox_tombstones WHERE sandbox_id=? LIMIT 1",
                (selected, selected),
            ).fetchone()
            if exists is None:
                raise CustomerSandboxNotFound("sandbox_not_found")
            rows = connection.execute(
                "SELECT * FROM customer_sandbox_audit WHERE sandbox_id=? "
                "ORDER BY sequence DESC LIMIT ?",
                (selected, bounded),
            ).fetchall()
            return tuple(
                CustomerSandboxAuditEvent(
                    AUDIT_SCHEMA,
                    int(row["sequence"]),
                    str(row["sandbox_id"]),
                    str(row["action"]),
                    str(row["detail_sha256"]),
                    str(row["principal_sha256"]),
                    float(row["occurred_at"]),
                    str(row["previous_sha256"]),
                    str(row["event_sha256"]),
                )
                for row in rows
            )

    def verify_integrity(self) -> Mapping[str, object]:
        with self._connection() as connection:
            records = [self._record_from_row(row) for row in connection.execute(
                "SELECT * FROM customer_sandboxes ORDER BY sandbox_id"
            ).fetchall()]
            tombstones = [
                self._tombstone_from_row(row)
                for row in connection.execute(
                    "SELECT * FROM customer_sandbox_tombstones ORDER BY sandbox_id"
                ).fetchall()
            ]
            if {record.sandbox_id for record in records} & {
                tombstone.sandbox_id for tombstone in tombstones
            }:
                raise CustomerSandboxIntegrityError("sandbox_tombstone_collision")
            snapshot_count = 0
            for record in records:
                rows = connection.execute(
                    "SELECT snapshot_revision,snapshot_sha256,snapshot_json FROM "
                    "customer_sandbox_snapshots WHERE sandbox_id=? ORDER BY snapshot_revision",
                    (record.sandbox_id,),
                ).fetchall()
                if not 1 <= len(rows) <= _MAX_SNAPSHOTS_PER_SANDBOX:
                    raise CustomerSandboxIntegrityError("sandbox_snapshot_history_corrupt")
                expected_revision = 1
                for row in rows:
                    if int(row["snapshot_revision"]) != expected_revision:
                        raise CustomerSandboxIntegrityError("sandbox_snapshot_history_corrupt")
                    try:
                        value = json.loads(str(row["snapshot_json"]))
                        if not isinstance(value, Mapping):
                            raise TypeError("snapshot is not a mapping")
                        stored = str(value.get("snapshot_sha256") or "")
                        material = dict(value)
                        material.pop("snapshot_sha256", None)
                        valid = hmac.compare_digest(
                            str(row["snapshot_sha256"]), stored
                        ) and hmac.compare_digest(_sha256(material), _digest(stored))
                    except (
                        TypeError,
                        ValueError,
                        json.JSONDecodeError,
                        CustomerSandboxError,
                    ) as exc:
                        raise CustomerSandboxIntegrityError(
                            "sandbox_snapshot_history_corrupt"
                        ) from exc
                    if not valid:
                        raise CustomerSandboxIntegrityError("sandbox_snapshot_history_corrupt")
                    expected_revision += 1
                    snapshot_count += 1
            baseline_rows = connection.execute(
                "SELECT sandbox_id,snapshot_revision,baseline_json "
                "FROM customer_sandbox_resync_baselines "
                "ORDER BY sandbox_id,snapshot_revision LIMIT 10001"
            ).fetchall()
            if len(baseline_rows) > 10_000:
                raise CustomerSandboxIntegrityError("sandbox_resync_baseline_oversized")
            expected_baselines = {
                (record.sandbox_id, record.snapshot_revision)
                for record in records
                if record.operation_kind == "resync"
                and record.state
                in {"resync_requested", "resync_approved", "provisioning", "failed"}
            }
            actual_baselines: set[tuple[str, int]] = set()
            current_by_id = {record.sandbox_id: record for record in records}
            for row in baseline_rows:
                key = (str(row["sandbox_id"]), int(row["snapshot_revision"]))
                actual_baselines.add(key)
                current = current_by_id.get(key[0])
                try:
                    value = json.loads(str(row["baseline_json"]))
                    value["module_allowlist"] = tuple(value["module_allowlist"])
                    baseline = self._validate_record(CustomerSandboxRecord(**value))
                except (
                    TypeError,
                    ValueError,
                    KeyError,
                    json.JSONDecodeError,
                    CustomerSandboxError,
                ) as exc:
                    raise CustomerSandboxIntegrityError(
                        "sandbox_resync_baseline_corrupt"
                    ) from exc
                if (
                    current is None
                    or baseline.sandbox_id != current.sandbox_id
                    or baseline.target_sandbox_id != current.target_sandbox_id
                    or baseline.snapshot_revision >= current.snapshot_revision
                    or baseline.state not in _ACTIVE_TARGET_STATES
                    or baseline.workspace_sha256 is None
                ):
                    raise CustomerSandboxIntegrityError("sandbox_resync_baseline_corrupt")
            if actual_baselines != expected_baselines:
                raise CustomerSandboxIntegrityError("sandbox_resync_baseline_corrupt")
            previous = "0" * 64
            audit_count = 0
            for row in connection.execute(
                "SELECT * FROM customer_sandbox_audit ORDER BY sequence"
            ).fetchall():
                material = {
                    "schema": AUDIT_SCHEMA,
                    "sandbox_id": str(row["sandbox_id"]),
                    "action": str(row["action"]),
                    "detail_sha256": str(row["detail_sha256"]),
                    "principal_sha256": str(row["principal_sha256"]),
                    "occurred_at": float(row["occurred_at"]),
                    "previous_sha256": str(row["previous_sha256"]),
                }
                if (
                    not hmac.compare_digest(material["previous_sha256"], previous)
                    or not hmac.compare_digest(_sha256(material), str(row["event_sha256"]))
                ):
                    raise CustomerSandboxIntegrityError("sandbox_audit_chain_corrupt")
                previous = str(row["event_sha256"])
                audit_count += 1
            operation_rows = connection.execute(
                "SELECT key_sha256,action,request_sha256,result_json "
                "FROM customer_sandbox_operations ORDER BY created_at,key_sha256 LIMIT 100001"
            ).fetchall()
            if len(operation_rows) > 100_000:
                raise CustomerSandboxIntegrityError("sandbox_operation_history_oversized")
            for row in operation_rows:
                if (
                    _DIGEST_RE.fullmatch(str(row["key_sha256"])) is None
                    or str(row["action"]) not in _ACTIONS
                    or _DIGEST_RE.fullmatch(str(row["request_sha256"])) is None
                ):
                    raise CustomerSandboxIntegrityError("sandbox_operation_corrupt")
                try:
                    value = json.loads(str(row["result_json"]))
                    value["module_allowlist"] = tuple(value["module_allowlist"])
                    self._validate_record(CustomerSandboxRecord(**value))
                except (
                    TypeError,
                    ValueError,
                    KeyError,
                    json.JSONDecodeError,
                    CustomerSandboxError,
                ) as exc:
                    raise CustomerSandboxIntegrityError("sandbox_operation_corrupt") from exc
            return {
                "schema": "lightwork.customer-sandbox-integrity.v1",
                "records": len(records),
                "tombstones": len(tombstones),
                "snapshots": snapshot_count,
                "audit_events": audit_count,
                "operations": len(operation_rows),
                "resync_baselines": len(baseline_rows),
                "audit_head_sha256": previous,
                "valid": True,
            }

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            **LocalCustomerSandboxProvisioner.product_boundaries(),
            "default_off": True,
            "disabled_admission_replay_blocked": True,
            "global_admin_enforced_by_dashboard": True,
            "four_eyes_snapshot_approval": True,
            "four_eyes_destroy_approval": True,
            "immutable_sanitized_snapshots": True,
            "bounded_local_provisioner_available": True,
        }


__all__ = [
    "AI_GOVERNANCE_SOURCE_SECTIONS",
    "AUDIT_SCHEMA",
    "CustomerSandboxAuditEvent",
    "CustomerSandboxConfigError",
    "CustomerSandboxConflict",
    "CustomerSandboxError",
    "CustomerSandboxIntegrityError",
    "CustomerSandboxLifecycleStore",
    "CustomerSandboxNotFound",
    "CustomerSandboxPermissionDenied",
    "CustomerSandboxProvisioningError",
    "CustomerSandboxRecord",
    "CustomerSandboxTombstone",
    "CustomerSandboxValidationError",
    "LocalCustomerSandboxProvisioner",
    "RECORD_SCHEMA",
    "RECEIPT_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "SUPPORTED_SANDBOX_MODULES",
    "TOMBSTONE_SCHEMA",
    "SandboxProvisioningReceipt",
    "SandboxTargetAuthority",
    "SanitizedSandboxSnapshot",
    "SourceTenantConfiguration",
    "enabled",
    "require_enabled",
]
