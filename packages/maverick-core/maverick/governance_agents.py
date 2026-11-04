"""Packaged, tenant-bound governance-agent authority.

This module composes five named governance experiences over Lightwork's
existing approval, capability, budget, and audit principles:

* breach response;
* privacy-risk assessment;
* privacy-program copilot;
* knowledgebase governance; and
* third-party risk.

The agents are decision aids, not autonomous authorities.  Raw context is
ephemeral.  Durable state contains bounded metadata, SHA-256 pins, closed
finding/action codes, human decisions, execution receipts, and a chained audit
history.  Every run requires human review.  Externally consequential actions
also require an independently approved execution-enabled policy, two distinct
reviewers, an injected idempotent dispatcher, and an explicit call to
``execute``.  All capabilities are disabled by default.

The module does not ship legal conclusions, regulatory content, provider
credentials, live intelligence, or an LLM.  Analysis and action adapters are
injected seams whose exact authority is pinned and revalidated.

Tenant-local quotas apply transactional backpressure.  An analysis submission
durably reserves its future run, idempotency operation, and audit capacity
before invoking the adapter.  Expired terminal run content is deleted only
after its exact idempotency backlink becomes a durable tombstone.  Tombstones
remain chargeable operation records; this module does not claim an external
archive or allow replay safety to be traded for storage reclamation.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, fields, is_dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .budget import Budget, BudgetExceeded
from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
POLICY_SCHEMA = "lightwork.governance-agent.policy.v1"
ADAPTER_AUTHORITY_SCHEMA = "lightwork.governance-agent.adapter-authority.v1"
DISPATCHER_AUTHORITY_SCHEMA = "lightwork.governance-agent.dispatcher-authority.v1"
CONTEXT_SCHEMA = "lightwork.governance-agent.context.v1"
FINDING_SCHEMA = "lightwork.governance-agent.finding.v1"
RUN_SCHEMA = "lightwork.governance-agent.run.v1"
APPROVAL_SCHEMA = "lightwork.governance-agent.approval.v1"
EXECUTION_SCHEMA = "lightwork.governance-agent.execution.v1"
AUDIT_SCHEMA = "lightwork.governance-agent.audit.v1"
INTEGRITY_SCHEMA = "lightwork.governance-agent.integrity.v1"
ANALYSIS_RESERVATION_SCHEMA = "lightwork.governance-agent.analysis-reservation.v1"

NON_CONCLUSION_NOTICE = (
    "Governance-agent output is decision support requiring authorized human "
    "review. It is not legal advice, a compliance determination, a provider "
    "mutation, or a certification."
)

AGENT_KINDS = frozenset(
    {
        "breach_response",
        "privacy_risk_assessment",
        "program_copilot",
        "knowledgebase_governance",
        "third_party_risk",
    }
)

CAPABILITY_REGISTRY: Mapping[str, frozenset[str]] = {
    "breach_response": frozenset(
        {
            "incident_triage",
            "evidence_preservation_plan",
            "containment_plan",
            "notification_draft",
            "regulatory_clock_review",
        }
    ),
    "privacy_risk_assessment": frozenset(
        {
            "data_minimization_review",
            "lawful_basis_review",
            "dpia_threshold_review",
            "transfer_risk_review",
            "rights_impact_review",
        }
    ),
    "program_copilot": frozenset(
        {
            "program_status_summary",
            "control_gap_analysis",
            "evidence_request_draft",
            "improvement_plan_draft",
            "metric_exception_review",
        }
    ),
    "knowledgebase_governance": frozenset(
        {
            "citation_review",
            "freshness_review",
            "content_gap_analysis",
            "access_scope_review",
            "article_update_draft",
        }
    ),
    "third_party_risk": frozenset(
        {
            "intake_triage",
            "inherent_risk_review",
            "questionnaire_summary",
            "critical_event_review",
            "remediation_plan_draft",
        }
    ),
}

FINDING_CODES: Mapping[str, frozenset[str]] = {
    "breach_response": frozenset(
        {
            "incident_scope_unclear",
            "sensitive_data_possible",
            "containment_incomplete",
            "evidence_preservation_gap",
            "notification_clock_review_required",
            "stakeholder_escalation_required",
        }
    ),
    "privacy_risk_assessment": frozenset(
        {
            "purpose_not_pinned",
            "data_minimization_gap",
            "lawful_basis_review_required",
            "high_risk_processing_possible",
            "cross_border_review_required",
            "rights_impact_unresolved",
        }
    ),
    "program_copilot": frozenset(
        {
            "control_evidence_stale",
            "metric_outlier",
            "owner_missing",
            "program_gap",
            "evidence_request_recommended",
            "status_indeterminate",
        }
    ),
    "knowledgebase_governance": frozenset(
        {
            "citation_missing",
            "source_stale",
            "content_gap",
            "access_scope_too_broad",
            "conflicting_guidance",
            "review_required",
        }
    ),
    "third_party_risk": frozenset(
        {
            "criticality_unresolved",
            "sensitive_access_possible",
            "questionnaire_gap",
            "external_signal_requires_review",
            "remediation_required",
            "offboarding_dependency_open",
        }
    ),
}

ACTION_CODES: Mapping[str, frozenset[str]] = {
    "breach_response": frozenset(
        {
            "create_incident_task",
            "draft_notification",
            "request_legal_review",
            "preserve_evidence",
            "escalate_incident",
        }
    ),
    "privacy_risk_assessment": frozenset(
        {
            "open_dpia_review",
            "request_data_reduction",
            "request_legal_basis_review",
            "request_transfer_review",
            "assign_privacy_owner",
        }
    ),
    "program_copilot": frozenset(
        {
            "create_evidence_request",
            "create_remediation_task",
            "assign_control_owner",
            "draft_program_update",
            "escalate_metric_exception",
        }
    ),
    "knowledgebase_governance": frozenset(
        {
            "request_citation",
            "request_source_refresh",
            "draft_article_update",
            "restrict_article_access",
            "assign_content_owner",
        }
    ),
    "third_party_risk": frozenset(
        {
            "request_assessment",
            "create_vendor_remediation",
            "escalate_vendor_event",
            "request_due_diligence",
            "suspend_onboarding_review",
        }
    ),
}

SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
RATIONALE_CODES = frozenset(
    {
        "evidence_sufficient",
        "evidence_partial",
        "evidence_conflicting",
        "evidence_stale",
        "authority_required",
        "policy_threshold",
        "human_override",
        "false_positive",
        "risk_accepted",
        "not_applicable",
    }
)
LIMITATION_CODES = frozenset(
    {
        "source_incomplete",
        "source_stale",
        "provider_unavailable",
        "human_context_required",
        "legal_review_required",
        "calibration_unverified",
        "live_feed_unavailable",
        "content_corpus_unavailable",
    }
)
REVIEW_DECISIONS = frozenset({"approve", "reject"})
RUN_STATES = frozenset(
    {
        "pending_review",
        "approved",
        "rejected",
        "executing",
        "executed",
        "execution_failed",
        "revoked",
    }
)
EXECUTION_OUTCOMES = frozenset({"applied", "no_change", "failed"})
SOURCE_KINDS = frozenset(
    {
        "audit",
        "assessment",
        "control",
        "document",
        "incident",
        "inventory",
        "knowledge",
        "metric",
        "policy",
        "provider_signal",
        "risk",
        "vendor",
    }
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CONTEXT_ITEMS = 1_000
_MAX_CONTEXT_BYTES = 10 * 1024 * 1024
_MAX_FINDINGS = 1_000
_MAX_APPROVALS = 8
_MAX_EXECUTION_ATTEMPTS = 8
_MAX_POLICY_RECORDS = 1_000_000
_MAX_RUN_RECORDS = 1_000_000
_MAX_OPERATION_RECORDS = 2_000_000
_MAX_AUDIT_EVENTS = 5_000_000
_MAX_ANALYSIS_LEASE_SECONDS = 24 * 60 * 60
_MIN_RETENTION_SECONDS = 60 * 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_ZERO_DIGEST = "0" * 64


class GovernanceAgentError(RuntimeError):
    """Base packaged-governance-agent error."""


class GovernanceAgentConfigError(GovernanceAgentError):
    """A required feature gate or authority is unavailable."""


class GovernanceAgentValidationError(GovernanceAgentError, ValueError):
    """Caller or adapter material is outside the closed contract."""


class GovernanceAgentConflict(GovernanceAgentError):
    """An idempotency, revision, lease, or authority pin changed."""


class GovernanceAgentQuotaExceeded(GovernanceAgentConflict):
    """A tenant-scoped durable-state quota applied safe backpressure."""


class GovernanceAgentNotFound(GovernanceAgentError):
    """A tenant-local agent object does not exist."""


class GovernanceAgentPermissionDenied(GovernanceAgentError):
    """Authenticated human or execution authority is insufficient."""


class GovernanceAgentIntegrityError(GovernanceAgentError):
    """Adapter or persisted state failed integrity verification."""


def enabled() -> bool:
    """Return true only for an exact ``governance_agents.enable = true`` gate."""

    try:
        from .config import config_source_errors, load_config

        config = load_config()
        if config_source_errors():
            return False
    except Exception:
        return False
    table = config.get("governance_agents") if isinstance(config, Mapping) else None
    return isinstance(table, Mapping) and table.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise GovernanceAgentConfigError(
            "packaged governance agents are disabled; explicitly enable governance_agents.enable"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    def _default(item: object) -> object:
        if is_dataclass(item) and not isinstance(item, type):
            return asdict(item)
        raise TypeError(f"{type(item).__name__} is not JSON serializable")

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_default,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise GovernanceAgentValidationError(
            "governance-agent state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise GovernanceAgentValidationError(
            "governance-agent state exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise GovernanceAgentValidationError("tenant_id is invalid") from exc


def _id(value: object, label: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise GovernanceAgentValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise GovernanceAgentValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise GovernanceAgentValidationError(f"{label} must be a finite timestamp")
    return float(value)


def _positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise GovernanceAgentValidationError(f"{label} must be an integer between 1 and {maximum}")
    return value


def _closed(value: object, label: str, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise GovernanceAgentValidationError(f"{label} is outside its closed vocabulary")
    return value


def _unique_closed(
    values: object,
    label: str,
    allowed: frozenset[str],
    *,
    maximum: int,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= maximum:
        raise GovernanceAgentValidationError(f"{label} is outside its item bound")
    normalized = tuple(_closed(value, label, allowed) for value in values)
    if tuple(sorted(set(normalized))) != normalized:
        raise GovernanceAgentValidationError(f"{label} must be unique and sorted")
    return normalized


def _bounded_codes(
    values: object,
    label: str,
    allowed: frozenset[str],
    *,
    maximum: int,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > maximum:
        raise GovernanceAgentValidationError(f"{label} is outside its item bound")
    normalized = tuple(_closed(value, label, allowed) for value in values)
    if tuple(sorted(set(normalized))) != normalized:
        raise GovernanceAgentValidationError(f"{label} must be unique and sorted")
    return normalized


@dataclass(frozen=True, slots=True)
class GovernanceAgentLimits:
    """Default bounds, optionally replaced per tenant by an injected resolver."""

    max_context_items: int = 100
    max_context_bytes: int = 1_048_576
    max_output_bytes: int = 262_144
    retention_seconds: int = 31_536_000
    max_policy_records: int = 10_000
    max_run_records: int = 25_000
    max_operation_records: int = 50_000
    max_audit_events: int = 250_000
    analysis_lease_seconds: int = 300

    def __post_init__(self) -> None:
        _positive_int(self.max_context_items, "max_context_items", _MAX_CONTEXT_ITEMS)
        _positive_int(self.max_context_bytes, "max_context_bytes", _MAX_CONTEXT_BYTES)
        _positive_int(self.max_output_bytes, "max_output_bytes", _MAX_JSON_BYTES)
        if not _MIN_RETENTION_SECONDS <= self.retention_seconds <= _MAX_RETENTION_SECONDS:
            raise GovernanceAgentValidationError("retention_seconds is outside its bound")
        _positive_int(self.max_policy_records, "max_policy_records", _MAX_POLICY_RECORDS)
        _positive_int(self.max_run_records, "max_run_records", _MAX_RUN_RECORDS)
        _positive_int(
            self.max_operation_records,
            "max_operation_records",
            _MAX_OPERATION_RECORDS,
        )
        _positive_int(self.max_audit_events, "max_audit_events", _MAX_AUDIT_EVENTS)
        _positive_int(
            self.analysis_lease_seconds,
            "analysis_lease_seconds",
            _MAX_ANALYSIS_LEASE_SECONDS,
        )


@dataclass(frozen=True, slots=True)
class GovernanceAgentTenantSnapshot:
    """One exact tenant configuration admitted for a governed operation."""

    tenant_id: str
    enabled_agents: tuple[str, ...]
    limits: GovernanceAgentLimits

    def __post_init__(self) -> None:
        tenant = _tenant(self.tenant_id)
        if isinstance(self.enabled_agents, (str, bytes)) or not isinstance(
            self.enabled_agents, Sequence
        ):
            raise GovernanceAgentConfigError(
                "governance-agent enabled_agents authority is invalid"
            )
        raw_agents = tuple(self.enabled_agents)
        if (
            not raw_agents
            or len(raw_agents) != len(set(raw_agents))
            or any(agent not in AGENT_KINDS for agent in raw_agents)
        ):
            raise GovernanceAgentConfigError(
                "governance-agent enabled_agents authority is invalid"
            )
        if not isinstance(self.limits, GovernanceAgentLimits):
            raise GovernanceAgentConfigError(
                "governance-agent tenant limits authority is invalid"
            )
        object.__setattr__(self, "tenant_id", tenant)
        object.__setattr__(self, "enabled_agents", tuple(sorted(raw_agents)))


def load_governance_agent_tenant_snapshot(
    tenant_id: str,
    config: Mapping[str, Any] | None = None,
) -> GovernanceAgentTenantSnapshot:
    """Load one tenant-bound, fail-closed governance-agent config snapshot.

    Configured limits are restrictive ceilings over the long-standing secure
    defaults.  Omitting a limit therefore preserves the existing behavior,
    while a larger configured value cannot silently expand an admitted request.
    """

    tenant = _tenant(tenant_id)
    if config is None:
        try:
            from .config import config_source_errors, load_config
            from .paths import tenant_scope

            with tenant_scope(tenant=tenant):
                config = load_config()
                if config_source_errors():
                    raise GovernanceAgentConfigError(
                        "governance-agent tenant configuration is unreadable"
                    )
        except GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentConfigError(
                "governance-agent tenant configuration is unavailable"
            ) from exc
    if not isinstance(config, Mapping):
        raise GovernanceAgentConfigError(
            "governance-agent tenant configuration must be an object"
        )
    table = config.get("governance_agents")
    if not isinstance(table, Mapping) or table.get("enable") is not True:
        raise GovernanceAgentConfigError("packaged governance agents are disabled")

    raw_agents = table.get("enabled_agents")
    if raw_agents is None:
        selected_agents = tuple(sorted(AGENT_KINDS))
    else:
        if isinstance(raw_agents, (str, bytes)) or not isinstance(raw_agents, Sequence):
            raise GovernanceAgentConfigError(
                "governance-agent enabled_agents authority is invalid"
            )
        selected_agents = tuple(raw_agents)
    defaults = GovernanceAgentLimits()
    configured_limits: dict[str, int] = {}
    for name in (
        "max_context_items",
        "max_context_bytes",
        "max_output_bytes",
        "retention_seconds",
    ):
        default = getattr(defaults, name)
        value = table.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise GovernanceAgentConfigError(
                f"governance-agent {name} authority is invalid"
            )
        configured_limits[name] = min(default, value)
    try:
        limits = GovernanceAgentLimits(**configured_limits)
    except GovernanceAgentValidationError as exc:
        raise GovernanceAgentConfigError(
            "governance-agent tenant limits authority is invalid"
        ) from exc
    return GovernanceAgentTenantSnapshot(
        tenant_id=tenant,
        enabled_agents=selected_agents,
        limits=limits,
    )


@dataclass(frozen=True, slots=True)
class GovernanceAgentPolicy:
    schema: str
    tenant_sha256: str
    policy_id: str
    revision: int
    agent_kind: str
    allowed_capabilities: tuple[str, ...]
    required_approvals: int
    execution_enabled: bool
    publisher_principal: str
    approver_principals: tuple[str, ...]
    valid_until: float
    revoked: bool
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceAgentAdapterAuthority:
    schema: str
    adapter_id: str
    revision: int
    agent_kind: str
    implementation_sha256: str
    configuration_sha256: str
    deterministic: bool
    network_access: bool
    legal_conclusion_enabled: bool
    valid_until: float
    revoked: bool
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceAgentDispatcherAuthority:
    """Independently enrolled authority for one exact execution dispatcher."""

    schema: str
    dispatcher_id: str
    revision: int
    agent_kind: str
    implementation_sha256: str
    configuration_sha256: str
    execution_enabled: bool
    valid_until: float
    revoked: bool
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceContextItem:
    item_id: str
    source_kind: str
    source_ref: str
    source_revision: int
    collected_at: float
    content: bytes


@dataclass(frozen=True, slots=True)
class GovernanceContextRecord:
    schema: str
    item_id: str
    source_kind: str
    source_ref: str
    source_revision: int
    collected_at: float
    byte_length: int
    content_sha256: str
    record_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceAgentFinding:
    schema: str
    finding_id: str
    finding_code: str
    severity: str
    evidence_item_ids: tuple[str, ...]
    recommended_action_code: str | None
    rationale_code: str
    confidence_bps: int
    finding_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceAgentAnalysis:
    findings: tuple[GovernanceAgentFinding, ...]
    limitations: tuple[str, ...]
    complete: bool


@dataclass(frozen=True, slots=True)
class GovernanceAgentApproval:
    schema: str
    principal: str
    decision: str
    rationale_code: str
    run_revision: int
    decided_at: float
    approval_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceAgentExecutionOutcome:
    schema: str
    tenant_sha256: str
    run_id: str
    run_revision: int
    execution_idempotency_sha256: str
    action_codes_sha256: str
    dispatcher_authority_sha256: str
    outcome: str
    provider_status_code: str
    external_reference_sha256: str | None
    retryable: bool
    receipt_proof_sha256: str
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceAgentRun:
    schema: str
    tenant_id: str
    run_id: str
    revision: int
    state: str
    agent_kind: str
    capability: str
    policy_id: str
    policy_revision: int
    policy_authority_sha256: str
    adapter_authority_sha256: str
    execution_dispatcher_authority_sha256: str | None
    request_sha256: str
    context: tuple[GovernanceContextRecord, ...]
    findings: tuple[GovernanceAgentFinding, ...]
    limitations: tuple[str, ...]
    analysis_complete: bool
    requested_by: str
    approvals: tuple[GovernanceAgentApproval, ...]
    execution_attempts: int
    execution_idempotency_sha256: str | None
    execution_outcome: GovernanceAgentExecutionOutcome | None
    failure_code: str | None
    retained_until: float
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class GovernanceAgentIntegrityReport:
    schema: str
    tenant_id: str
    verified_policies: int
    verified_runs: int
    audit_events: int
    terminal_audit_sha256: str


def _execution_action_codes_sha256(run: GovernanceAgentRun) -> str:
    actions = sorted(
        {
            finding.recommended_action_code
            for finding in run.findings
            if finding.recommended_action_code is not None
        }
    )
    return _sha256(
        {
            "schema": "lightwork.governance-agent.execution-actions.v1",
            "tenant_sha256": hashlib.sha256(run.tenant_id.encode("utf-8")).hexdigest(),
            "run_id": run.run_id,
            "action_codes": actions,
        }
    )


@runtime_checkable
class GovernanceAnalysisAdapter(Protocol):
    def __call__(
        self,
        *,
        tenant_id: str,
        run_id: str,
        agent_kind: str,
        capability: str,
        context: tuple[GovernanceContextItem, ...],
        authority: GovernanceAgentAdapterAuthority,
    ) -> GovernanceAgentAnalysis: ...


@runtime_checkable
class GovernanceActionDispatcher(Protocol):
    def __call__(
        self,
        *,
        run: GovernanceAgentRun,
        idempotency_key: str,
    ) -> GovernanceAgentExecutionOutcome: ...


@runtime_checkable
class GovernanceExecutionReceiptVerifier(Protocol):
    def __call__(
        self,
        authority: GovernanceAgentDispatcherAuthority,
        outcome: GovernanceAgentExecutionOutcome,
    ) -> bool: ...


AnalysisBindingResolver = Callable[
    [str, str],
    tuple[GovernanceAgentAdapterAuthority, GovernanceAnalysisAdapter],
]
ExecutionBindingResolver = Callable[
    [str, str],
    tuple[
        GovernanceAgentDispatcherAuthority,
        GovernanceActionDispatcher,
        GovernanceExecutionReceiptVerifier,
    ],
]
ExecutionTokenEscrow = Callable[[str, str, str, str], bool]
ExecutionTokenResolver = Callable[[str, str], str]


def build_adapter_authority(
    *,
    adapter_id: str,
    revision: int,
    agent_kind: str,
    implementation_sha256: str,
    configuration_sha256: str,
    deterministic: bool,
    network_access: bool,
    legal_conclusion_enabled: bool,
    valid_until: float,
    revoked: bool = False,
) -> GovernanceAgentAdapterAuthority:
    """Build a self-pinned adapter authority for independent enrollment."""

    payload = {
        "schema": ADAPTER_AUTHORITY_SCHEMA,
        "adapter_id": _id(adapter_id, "adapter_id"),
        "revision": _positive_int(revision, "revision", 2_147_483_647),
        "agent_kind": _closed(agent_kind, "agent_kind", AGENT_KINDS),
        "implementation_sha256": _digest(implementation_sha256, "implementation_sha256"),
        "configuration_sha256": _digest(configuration_sha256, "configuration_sha256"),
        "deterministic": deterministic,
        "network_access": network_access,
        "legal_conclusion_enabled": legal_conclusion_enabled,
        "valid_until": _timestamp(valid_until, "valid_until"),
        "revoked": revoked,
    }
    for key in ("deterministic", "network_access", "legal_conclusion_enabled", "revoked"):
        if not isinstance(payload[key], bool):
            raise GovernanceAgentValidationError(f"{key} must be true or false")
    return GovernanceAgentAdapterAuthority(
        **payload,
        authority_sha256=_sha256(payload),
    )


def build_dispatcher_authority(
    *,
    dispatcher_id: str,
    revision: int,
    agent_kind: str,
    implementation_sha256: str,
    configuration_sha256: str,
    execution_enabled: bool,
    valid_until: float,
    revoked: bool = False,
) -> GovernanceAgentDispatcherAuthority:
    """Build a self-pinned value that still requires independent enrollment."""

    payload = {
        "schema": DISPATCHER_AUTHORITY_SCHEMA,
        "dispatcher_id": _id(dispatcher_id, "dispatcher_id"),
        "revision": _positive_int(revision, "revision", 2_147_483_647),
        "agent_kind": _closed(agent_kind, "agent_kind", AGENT_KINDS),
        "implementation_sha256": _digest(implementation_sha256, "implementation_sha256"),
        "configuration_sha256": _digest(configuration_sha256, "configuration_sha256"),
        "execution_enabled": execution_enabled,
        "valid_until": _timestamp(valid_until, "valid_until"),
        "revoked": revoked,
    }
    for key in ("execution_enabled", "revoked"):
        if not isinstance(payload[key], bool):
            raise GovernanceAgentValidationError(f"{key} must be true or false")
    return GovernanceAgentDispatcherAuthority(
        **payload,
        authority_sha256=_sha256(payload),
    )


def build_finding(
    *,
    agent_kind: str,
    finding_id: str,
    finding_code: str,
    severity: str,
    evidence_item_ids: Sequence[str],
    recommended_action_code: str | None,
    rationale_code: str,
    confidence_bps: int,
) -> GovernanceAgentFinding:
    """Build a canonical closed-vocabulary adapter finding."""

    kind = _closed(agent_kind, "agent_kind", AGENT_KINDS)
    evidence = tuple(_id(value, "evidence_item_id") for value in evidence_item_ids)
    if (
        not evidence
        or len(evidence) > _MAX_CONTEXT_ITEMS
        or tuple(sorted(set(evidence))) != evidence
    ):
        raise GovernanceAgentValidationError(
            "evidence_item_ids must be non-empty, unique, sorted, and bounded"
        )
    action = None
    if recommended_action_code is not None:
        action = _closed(
            recommended_action_code,
            "recommended_action_code",
            ACTION_CODES[kind],
        )
    if (
        isinstance(confidence_bps, bool)
        or not isinstance(confidence_bps, int)
        or not 0 <= confidence_bps <= 10_000
    ):
        raise GovernanceAgentValidationError("confidence_bps must be between 0 and 10000")
    payload = {
        "schema": FINDING_SCHEMA,
        "finding_id": _id(finding_id, "finding_id"),
        "finding_code": _closed(finding_code, "finding_code", FINDING_CODES[kind]),
        "severity": _closed(severity, "severity", SEVERITIES),
        "evidence_item_ids": evidence,
        "recommended_action_code": action,
        "rationale_code": _closed(rationale_code, "rationale_code", RATIONALE_CODES),
        "confidence_bps": confidence_bps,
    }
    return GovernanceAgentFinding(**payload, finding_sha256=_sha256(payload))


def _dataclass_from_mapping(cls: type[Any], value: object, label: str) -> Any:
    if not isinstance(value, Mapping):
        raise GovernanceAgentIntegrityError(f"persisted {label} is invalid")
    expected = {field.name for field in fields(cls)}
    if set(value) != expected:
        raise GovernanceAgentIntegrityError(f"persisted {label} shape is invalid")
    try:
        return cls(**dict(value))
    except (TypeError, ValueError) as exc:
        raise GovernanceAgentIntegrityError(f"persisted {label} is invalid") from exc


class GovernanceAgentStore:
    """Durable packaged-agent control plane with explicit human authority."""

    def __init__(
        self,
        path: str | Path,
        *,
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        policy_approver_resolver: Callable[[str, str, int], Sequence[str]] | None = None,
        analysis_binding_resolver: AnalysisBindingResolver | None = None,
        execution_binding_resolver: ExecutionBindingResolver | None = None,
        execution_token_escrow: ExecutionTokenEscrow | None = None,
        execution_token_resolver: ExecutionTokenResolver | None = None,
        tenant_snapshot_resolver: Callable[
            [str], GovernanceAgentTenantSnapshot
        ]
        | None = None,
        tenant_limits_resolver: Callable[[str], GovernanceAgentLimits] | None = None,
        clock: Callable[[], float] = time.time,
        limits: GovernanceAgentLimits | None = None,
        budget: Budget | None = None,
    ) -> None:
        config_gate()
        if not callable(principal_resolver) or not callable(clock):
            raise GovernanceAgentConfigError("principal_resolver and clock must be callable")
        if tenant_snapshot_resolver is not None and not callable(tenant_snapshot_resolver):
            raise GovernanceAgentConfigError("tenant_snapshot_resolver must be callable")
        if tenant_limits_resolver is not None and not callable(tenant_limits_resolver):
            raise GovernanceAgentConfigError("tenant_limits_resolver must be callable")
        if tenant_snapshot_resolver is not None and tenant_limits_resolver is not None:
            raise GovernanceAgentConfigError(
                "tenant snapshot and legacy limits resolvers are mutually exclusive"
            )
        self.path = Path(path)
        self._principal_resolver = principal_resolver
        self._policy_approver_resolver = policy_approver_resolver
        self._analysis_binding_resolver = analysis_binding_resolver
        self._execution_binding_resolver = execution_binding_resolver
        self._execution_token_escrow = execution_token_escrow
        self._execution_token_resolver = execution_token_resolver
        self._tenant_snapshot_resolver = tenant_snapshot_resolver
        self._tenant_limits_resolver = tenant_limits_resolver
        self._clock = clock
        self.limits = limits or GovernanceAgentLimits()
        self.budget = budget or Budget(max_tool_calls=500)
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise GovernanceAgentPermissionDenied("an authenticated runtime principal is required")
        return _id(actor, "authenticated principal")

    def _now(self) -> float:
        return _timestamp(self._clock(), "clock")

    def _tenant_snapshot_for(self, tenant_id: str) -> GovernanceAgentTenantSnapshot:
        tenant = _tenant(tenant_id)
        resolver = self._tenant_snapshot_resolver
        if resolver is None:
            limits_resolver = self._tenant_limits_resolver
            if limits_resolver is None:
                limits = self.limits
            else:
                try:
                    limits = limits_resolver(tenant)
                except GovernanceAgentError:
                    raise
                except Exception as exc:
                    raise GovernanceAgentConfigError(
                        "tenant quota authority is unavailable"
                    ) from exc
                if not isinstance(limits, GovernanceAgentLimits):
                    raise GovernanceAgentConfigError(
                        "tenant quota authority returned invalid limits"
                    )
            return GovernanceAgentTenantSnapshot(
                tenant_id=tenant,
                enabled_agents=tuple(sorted(AGENT_KINDS)),
                limits=limits,
            )
        try:
            snapshot = resolver(tenant)
        except GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentConfigError(
                "governance-agent tenant snapshot authority is unavailable"
            ) from exc
        if not isinstance(snapshot, GovernanceAgentTenantSnapshot):
            raise GovernanceAgentConfigError(
                "governance-agent tenant snapshot authority is invalid"
            )
        if not text_equals(snapshot.tenant_id, tenant):
            raise GovernanceAgentConfigError(
                "governance-agent tenant snapshot authority is misbound"
            )
        return snapshot

    def _limits_for(self, tenant_id: str) -> GovernanceAgentLimits:
        return self._tenant_snapshot_for(tenant_id).limits

    @staticmethod
    def _require_agent_enabled(
        snapshot: GovernanceAgentTenantSnapshot,
        agent_kind: str,
    ) -> None:
        if agent_kind not in snapshot.enabled_agents:
            raise GovernanceAgentConfigError(
                "governance-agent kind is disabled by tenant configuration"
            )

    @staticmethod
    def _validate_adapter_authority(
        authority: object,
        *,
        agent_kind: str,
        now: float,
    ) -> GovernanceAgentAdapterAuthority:
        if not isinstance(authority, GovernanceAgentAdapterAuthority):
            raise GovernanceAgentConfigError("analysis adapter authority is invalid")
        if authority.schema != ADAPTER_AUTHORITY_SCHEMA:
            raise GovernanceAgentValidationError("adapter authority schema is invalid")
        material = asdict(authority)
        authority_digest = material.pop("authority_sha256")
        if not secrets.compare_digest(_sha256(material), authority_digest):
            raise GovernanceAgentIntegrityError("adapter authority digest is invalid")
        if authority.agent_kind != agent_kind:
            raise GovernanceAgentConflict("adapter authority agent kind changed")
        if authority.revoked or authority.valid_until <= now or authority.legal_conclusion_enabled:
            raise GovernanceAgentConfigError("adapter authority is unavailable or unsafe")
        return authority

    def _resolve_analysis_binding(
        self,
        tenant_id: str,
        agent_kind: str,
        proposed_authority: GovernanceAgentAdapterAuthority,
        proposed_adapter: GovernanceAnalysisAdapter,
    ) -> GovernanceAgentAdapterAuthority:
        proposed = self._validate_adapter_authority(
            proposed_authority,
            agent_kind=agent_kind,
            now=self._now(),
        )
        resolver = self._analysis_binding_resolver
        if not callable(resolver):
            raise GovernanceAgentConfigError(
                "analysis requires an independent enrolled binding resolver"
            )
        try:
            resolved = resolver(tenant_id, agent_kind)
        except GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentConfigError("analysis binding authority is unavailable") from exc
        if not isinstance(resolved, tuple) or len(resolved) != 2:
            raise GovernanceAgentConfigError("analysis binding authority is invalid")
        authority, adapter = resolved
        validated = self._validate_adapter_authority(
            authority,
            agent_kind=agent_kind,
            now=self._now(),
        )
        if (
            validated != proposed
            or not secrets.compare_digest(
                validated.authority_sha256,
                proposed.authority_sha256,
            )
            or adapter is not proposed_adapter
        ):
            raise GovernanceAgentPermissionDenied(
                "caller-proposed analysis binding does not match enrolled authority"
            )
        return validated

    @staticmethod
    def _validate_dispatcher_authority(
        authority: object,
        *,
        agent_kind: str,
        now: float,
    ) -> GovernanceAgentDispatcherAuthority:
        if not isinstance(authority, GovernanceAgentDispatcherAuthority):
            raise GovernanceAgentConfigError("execution dispatcher authority is invalid")
        if authority.schema != DISPATCHER_AUTHORITY_SCHEMA:
            raise GovernanceAgentValidationError("dispatcher authority schema is invalid")
        material = asdict(authority)
        authority_digest = material.pop("authority_sha256")
        if not secrets.compare_digest(_sha256(material), authority_digest):
            raise GovernanceAgentIntegrityError("dispatcher authority digest is invalid")
        if authority.agent_kind != agent_kind:
            raise GovernanceAgentConflict("dispatcher authority agent kind changed")
        if authority.revoked or authority.valid_until <= now or not authority.execution_enabled:
            raise GovernanceAgentConfigError("dispatcher authority is unavailable or disabled")
        return authority

    def _resolve_execution_binding(
        self,
        tenant_id: str,
        agent_kind: str,
        proposed_dispatcher: GovernanceActionDispatcher,
    ) -> tuple[GovernanceAgentDispatcherAuthority, GovernanceExecutionReceiptVerifier]:
        resolver = self._execution_binding_resolver
        if not callable(resolver):
            raise GovernanceAgentConfigError(
                "execution requires an independent enrolled binding resolver"
            )
        try:
            resolved = resolver(tenant_id, agent_kind)
        except GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentConfigError("execution binding authority is unavailable") from exc
        if not isinstance(resolved, tuple) or len(resolved) != 3:
            raise GovernanceAgentConfigError("execution binding authority is invalid")
        authority, dispatcher, verifier = resolved
        validated = self._validate_dispatcher_authority(
            authority,
            agent_kind=agent_kind,
            now=self._now(),
        )
        if dispatcher is not proposed_dispatcher:
            raise GovernanceAgentPermissionDenied(
                "caller-proposed dispatcher does not match enrolled authority"
            )
        if not callable(verifier):
            raise GovernanceAgentConfigError("execution receipt verifier is unavailable")
        return validated, verifier

    def _escrow_and_confirm_execution_token(
        self,
        tenant_id: str,
        run_id: str,
        token: str,
        token_sha256: str,
    ) -> None:
        escrow = self._execution_token_escrow
        resolver = self._execution_token_resolver
        if not callable(escrow) or not callable(resolver):
            raise GovernanceAgentConfigError(
                "execution requires durable token escrow and recovery resolution"
            )
        try:
            escrowed = escrow(tenant_id, run_id, token, token_sha256)
            recovered = resolver(tenant_id, run_id)
        except GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentConfigError("execution token escrow is unavailable") from exc
        if escrowed is not True or not isinstance(recovered, str):
            raise GovernanceAgentConfigError("execution token escrow was not confirmed")
        recovered_sha256 = hashlib.sha256(recovered.encode("utf-8")).hexdigest()
        if not secrets.compare_digest(recovered_sha256, token_sha256):
            raise GovernanceAgentIntegrityError("execution token escrow confirmation mismatched")

    def _recover_execution_token(self, tenant_id: str, run_id: str, expected_sha256: str) -> str:
        resolver = self._execution_token_resolver
        if not callable(resolver):
            raise GovernanceAgentConfigError("execution token recovery authority is unavailable")
        try:
            token = resolver(tenant_id, run_id)
        except GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentConfigError("execution token recovery is unavailable") from exc
        if not isinstance(token, str) or not secrets.compare_digest(
            hashlib.sha256(token.encode("utf-8")).hexdigest(), expected_sha256
        ):
            raise GovernanceAgentPermissionDenied("execution recovery token did not match")
        return token

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.create_function(
            "lightwork_governance_updated_at", 2, self._indexed_run_updated_at,
            deterministic=True,
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _indexed_run_updated_at(payload_json: str, integrity_sha256: str) -> float:
        """Validate the timestamp while SQLite maintains the recent-run index.

        The indexed value is derived from existing canonical source material;
        it is neither a mutable mirror nor a substitute for returned-row checks.
        """
        payload = json.loads(payload_json)
        if not isinstance(payload, dict) or _sha256(payload) != integrity_sha256:
            raise GovernanceAgentIntegrityError("persisted run failed integrity verification")
        return _timestamp(payload.get("updated_at"), "persisted run update time")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policies(
                    tenant_id TEXT NOT NULL,policy_id TEXT NOT NULL,revision INTEGER NOT NULL,
                    revoked INTEGER NOT NULL,valid_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,policy_id,revision)
                );
                CREATE INDEX IF NOT EXISTS policy_current
                    ON policies(tenant_id,policy_id,revision DESC);
                CREATE TABLE IF NOT EXISTS runs(
                    tenant_id TEXT NOT NULL,run_id TEXT NOT NULL,state TEXT NOT NULL,
                    revision INTEGER NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,run_id)
                );
                CREATE INDEX IF NOT EXISTS run_state
                    ON runs(tenant_id,state,retained_until);
                CREATE TABLE IF NOT EXISTS operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,result_id TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS analysis_reservations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,run_id TEXT NOT NULL,
                    owner_sha256 TEXT NOT NULL,lease_expires_at REAL NOT NULL,
                    revision INTEGER NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256),
                    UNIQUE(tenant_id,run_id)
                );
                CREATE INDEX IF NOT EXISTS analysis_reservation_expiry
                    ON analysis_reservations(tenant_id,lease_expires_at);
                CREATE TABLE IF NOT EXISTS audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise GovernanceAgentIntegrityError(
                    "governance-agent database schema is unsupported"
                )
            try:
                for name, scope in (("run_recent", "tenant_id"),
                                    ("run_state_recent", "tenant_id,state")):
                    connection.execute(
                        f"CREATE INDEX IF NOT EXISTS {name} ON runs({scope},"
                        "lightwork_governance_updated_at(payload_json,integrity_sha256) DESC,run_id)"
                    )
            except sqlite3.DatabaseError as exc:
                raise GovernanceAgentIntegrityError(
                    "governance-agent recent review records are unavailable"
                ) from exc
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _load_payload(row: sqlite3.Row, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise GovernanceAgentIntegrityError(f"persisted {label} is not canonical JSON") from exc
        if not isinstance(payload, dict) or _sha256(payload) != row["integrity_sha256"]:
            raise GovernanceAgentIntegrityError(f"persisted {label} failed integrity verification")
        return payload

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha256 = hashlib.sha256(key.encode("utf-8")).hexdigest()
        request_sha256 = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha256),
        ).fetchone()
        if row is not None:
            GovernanceAgentStore._verify_operation_row(row, tenant_id)
            if row["request_sha256"] != request_sha256:
                raise GovernanceAgentConflict(
                    "idempotency key is bound to different canonical content"
                )
        return request_sha256, row

    @staticmethod
    def _verify_operation_row(
        row: sqlite3.Row,
        tenant_id: str,
    ) -> dict[str, str]:
        binding = {
            "tenant_id": row["tenant_id"],
            "operation_sha256": row["operation_sha256"],
            "request_sha256": row["request_sha256"],
            "result_kind": row["result_kind"],
            "result_id": row["result_id"],
        }
        try:
            _digest(binding["operation_sha256"], "operation_sha256")
            _digest(binding["request_sha256"], "request_sha256")
            _id(binding["result_id"], "operation result_id")
            valid_digest = secrets.compare_digest(
                _sha256(binding),
                row["integrity_sha256"],
            )
        except (GovernanceAgentValidationError, TypeError) as exc:
            raise GovernanceAgentIntegrityError("persisted idempotency binding is invalid") from exc
        if (
            binding["tenant_id"] != tenant_id
            or binding["result_kind"] not in {"policy", "run", "run_tombstone"}
            or not valid_digest
        ):
            raise GovernanceAgentIntegrityError(
                "persisted idempotency binding failed integrity verification"
            )
        return binding

    def _require_capacity(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        resource: str,
        tenant_limits: GovernanceAgentLimits | None = None,
    ) -> None:
        """Apply tenant-local durable-state backpressure inside a write transaction."""

        contracts = {
            "policies": "SELECT COUNT(*) FROM policies WHERE tenant_id=?",
            "runs": (
                "SELECT (SELECT COUNT(*) FROM runs WHERE tenant_id=?) + "
                "(SELECT COUNT(*) FROM analysis_reservations WHERE tenant_id=?)"
            ),
            "operations": (
                "SELECT (SELECT COUNT(*) FROM operations WHERE tenant_id=?) + "
                "(SELECT COUNT(*) FROM analysis_reservations WHERE tenant_id=?)"
            ),
            "audit": (
                "SELECT (SELECT COUNT(*) FROM audit_events WHERE tenant_id=?) + "
                "(SELECT COUNT(*) FROM analysis_reservations WHERE tenant_id=?)"
            ),
        }
        try:
            query = contracts[resource]
        except KeyError as exc:  # pragma: no cover - internal programming error
            raise GovernanceAgentConfigError("unknown governance-agent quota") from exc
        tenant_limits = tenant_limits or self._limits_for(tenant_id)
        maximum = {
            "policies": tenant_limits.max_policy_records,
            "runs": tenant_limits.max_run_records,
            "operations": tenant_limits.max_operation_records,
            "audit": tenant_limits.max_audit_events,
        }[resource]
        parameters = (
            (tenant_id, tenant_id) if resource in {"runs", "operations", "audit"} else (tenant_id,)
        )
        row = connection.execute(query, parameters).fetchone()
        if row is None or not isinstance(row[0], int):
            raise GovernanceAgentIntegrityError("durable-state quota could not be verified")
        if int(row[0]) >= maximum:
            raise GovernanceAgentQuotaExceeded(f"tenant {resource} quota is exhausted")

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
        tenant_limits: GovernanceAgentLimits | None = None,
    ) -> None:
        binding = {
            "tenant_id": tenant_id,
            "operation_sha256": hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest(),
            "request_sha256": request_sha256,
            "result_kind": result_kind,
            "result_id": result_id,
        }
        self._require_capacity(connection, tenant_id, "operations", tenant_limits)
        connection.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?,?)",
            (
                tenant_id,
                binding["operation_sha256"],
                request_sha256,
                result_kind,
                result_id,
                _sha256(binding),
            ),
        )

    def _tombstone_run_operation(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        run: GovernanceAgentRun,
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND result_kind='run' AND result_id=?",
            (tenant_id, run.run_id),
        ).fetchall()
        if len(rows) != 1:
            raise GovernanceAgentIntegrityError(
                "purged run must have exactly one idempotency backlink"
            )
        binding = self._verify_operation_row(rows[0], tenant_id)
        if not secrets.compare_digest(binding["request_sha256"], run.request_sha256):
            raise GovernanceAgentIntegrityError(
                "run idempotency backlink request digest is invalid"
            )
        tombstone = {**binding, "result_kind": "run_tombstone"}
        result = connection.execute(
            "UPDATE operations SET result_kind='run_tombstone',integrity_sha256=? "
            "WHERE tenant_id=? AND operation_sha256=? AND integrity_sha256=?",
            (
                _sha256(tombstone),
                tenant_id,
                binding["operation_sha256"],
                rows[0]["integrity_sha256"],
            ),
        )
        if result.rowcount != 1:
            raise GovernanceAgentConflict("run idempotency backlink changed during purge")

    @staticmethod
    def _verify_analysis_reservation_row(
        row: sqlite3.Row,
        tenant_id: str,
    ) -> dict[str, object]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise GovernanceAgentIntegrityError(
                "persisted analysis reservation is not canonical JSON"
            ) from exc
        expected_fields = {
            "schema",
            "tenant_id",
            "operation_sha256",
            "request_sha256",
            "run_id",
            "owner_sha256",
            "lease_expires_at",
            "revision",
        }
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise GovernanceAgentIntegrityError("persisted analysis reservation shape is invalid")
        try:
            valid_integrity = secrets.compare_digest(
                _sha256(payload),
                row["integrity_sha256"],
            )
            operation_sha256 = _digest(payload["operation_sha256"], "operation_sha256")
            request_sha256 = _digest(payload["request_sha256"], "request_sha256")
            owner_sha256 = _digest(payload["owner_sha256"], "owner_sha256")
            run_id = _id(payload["run_id"], "run_id")
            lease_expires_at = _timestamp(payload["lease_expires_at"], "lease_expires_at")
            revision = _positive_int(payload["revision"], "revision", 2_147_483_647)
            row_lease_expires_at = float(row["lease_expires_at"])
            row_revision = int(row["revision"])
        except (GovernanceAgentValidationError, TypeError, ValueError, OverflowError) as exc:
            raise GovernanceAgentIntegrityError(
                "persisted analysis reservation content is invalid"
            ) from exc
        if (
            not valid_integrity
            or payload["schema"] != ANALYSIS_RESERVATION_SCHEMA
            or payload["tenant_id"] != tenant_id
            or row["tenant_id"] != tenant_id
            or row["operation_sha256"] != operation_sha256
            or row["request_sha256"] != request_sha256
            or row["run_id"] != run_id
            or row["owner_sha256"] != owner_sha256
            or row_lease_expires_at != lease_expires_at
            or row_revision != revision
        ):
            raise GovernanceAgentIntegrityError(
                "persisted analysis reservation mirror columns are invalid"
            )
        return payload

    def _reserve_analysis(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha256: str,
        run_id: str,
        now: float,
        tenant_limits: GovernanceAgentLimits,
        actor: str,
    ) -> str:
        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha256 = hashlib.sha256(key.encode("utf-8")).hexdigest()
        self._purge_analysis_reservations(
            connection,
            tenant_id,
            now=now,
            actor=actor,
            tenant_limits=tenant_limits,
            limit=100,
            exclude_operation_sha256=operation_sha256,
        )
        row = connection.execute(
            "SELECT * FROM analysis_reservations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha256),
        ).fetchone()
        if row is None:
            run_row = connection.execute(
                "SELECT * FROM analysis_reservations WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
            if run_row is not None:
                self._verify_analysis_reservation_row(run_row, tenant_id)
                raise GovernanceAgentConflict("run_id has a different analysis reservation")
            self._require_capacity(connection, tenant_id, "runs", tenant_limits)
            self._require_capacity(connection, tenant_id, "operations", tenant_limits)
            self._require_capacity(connection, tenant_id, "audit", tenant_limits)
            revision = 1
        else:
            existing = self._verify_analysis_reservation_row(row, tenant_id)
            if not secrets.compare_digest(str(existing["request_sha256"]), request_sha256):
                raise GovernanceAgentConflict(
                    "idempotency key is bound to different canonical content"
                )
            if existing["run_id"] != run_id:
                raise GovernanceAgentConflict("analysis reservation run binding changed")
            if float(existing["lease_expires_at"]) > now:
                raise GovernanceAgentConflict("analysis request is already in flight")
            revision = int(existing["revision"]) + 1
        owner_token = f"ga-analysis:{secrets.token_urlsafe(32)}"
        owner_sha256 = hashlib.sha256(owner_token.encode("utf-8")).hexdigest()
        payload = {
            "schema": ANALYSIS_RESERVATION_SCHEMA,
            "tenant_id": tenant_id,
            "operation_sha256": operation_sha256,
            "request_sha256": request_sha256,
            "run_id": run_id,
            "owner_sha256": owner_sha256,
            "lease_expires_at": now + tenant_limits.analysis_lease_seconds,
            "revision": revision,
        }
        values = (
            request_sha256,
            run_id,
            owner_sha256,
            payload["lease_expires_at"],
            revision,
            _canonical(payload).decode("ascii"),
            _sha256(payload),
        )
        if row is None:
            connection.execute(
                "INSERT INTO analysis_reservations VALUES(?,?,?,?,?,?,?,?,?)",
                (tenant_id, operation_sha256, *values),
            )
        else:
            result = connection.execute(
                "UPDATE analysis_reservations SET request_sha256=?,run_id=?,owner_sha256=?,"
                "lease_expires_at=?,revision=?,payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND operation_sha256=? AND revision=?",
                (*values, tenant_id, operation_sha256, revision - 1),
            )
            if result.rowcount != 1:
                raise GovernanceAgentConflict("analysis reservation lease changed")
        return owner_token

    def _complete_analysis_reservation(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha256: str,
        run_id: str,
        owner_token: str,
    ) -> None:
        operation_sha256 = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        row = connection.execute(
            "SELECT * FROM analysis_reservations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha256),
        ).fetchone()
        if row is None:
            raise GovernanceAgentConflict("analysis reservation is no longer owned")
        payload = self._verify_analysis_reservation_row(row, tenant_id)
        owner_sha256 = hashlib.sha256(owner_token.encode("utf-8")).hexdigest()
        if (
            not secrets.compare_digest(str(payload["request_sha256"]), request_sha256)
            or payload["run_id"] != run_id
            or not secrets.compare_digest(str(payload["owner_sha256"]), owner_sha256)
        ):
            raise GovernanceAgentConflict("analysis reservation is no longer owned")
        result = connection.execute(
            "DELETE FROM analysis_reservations "
            "WHERE tenant_id=? AND operation_sha256=? AND revision=? AND owner_sha256=?",
            (
                tenant_id,
                operation_sha256,
                int(payload["revision"]),
                owner_sha256,
            ),
        )
        if result.rowcount != 1:
            raise GovernanceAgentConflict("analysis reservation lease changed")

    def _purge_analysis_reservations(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        *,
        now: float,
        actor: str,
        tenant_limits: GovernanceAgentLimits,
        limit: int,
        exclude_operation_sha256: str | None = None,
    ) -> int:
        query = "SELECT * FROM analysis_reservations WHERE tenant_id=? AND lease_expires_at<=?"
        parameters: tuple[object, ...] = (tenant_id, now)
        if exclude_operation_sha256 is not None:
            query += " AND operation_sha256<>?"
            parameters = (*parameters, exclude_operation_sha256)
        query += " ORDER BY lease_expires_at,operation_sha256 LIMIT ?"
        rows = connection.execute(query, (*parameters, limit)).fetchall()
        for row in rows:
            payload = self._verify_analysis_reservation_row(row, tenant_id)
            if float(payload["lease_expires_at"]) > now:
                raise GovernanceAgentIntegrityError(
                    "analysis reservation expiry selection is invalid"
                )
            result = connection.execute(
                "DELETE FROM analysis_reservations WHERE tenant_id=? "
                "AND operation_sha256=? AND revision=? AND owner_sha256=?",
                (
                    tenant_id,
                    payload["operation_sha256"],
                    payload["revision"],
                    payload["owner_sha256"],
                ),
            )
            if result.rowcount != 1:
                raise GovernanceAgentConflict("analysis reservation changed during cleanup")
            self._audit(
                connection,
                tenant_id,
                "analysis_reservation_expired",
                "analysis_reservation",
                str(payload["run_id"]),
                int(payload["revision"]),
                actor,
                {"operation_sha256": payload["operation_sha256"]},
                tenant_limits,
            )
        return len(rows)

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        subject_kind: str,
        subject_id: str,
        subject_revision: int,
        actor: str,
        details: Mapping[str, object],
        tenant_limits: GovernanceAgentLimits | None = None,
    ) -> str:
        row = connection.execute(
            "SELECT sequence,integrity_sha256 FROM audit_events "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        tenant_limits = tenant_limits or self._limits_for(tenant_id)
        self._require_capacity(connection, tenant_id, "audit", tenant_limits)
        sequence = 1 if row is None else int(row["sequence"]) + 1
        if sequence > tenant_limits.max_audit_events:
            raise GovernanceAgentQuotaExceeded("tenant audit quota is exhausted")
        previous = _ZERO_DIGEST if row is None else row["integrity_sha256"]
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant_id,
            "sequence": sequence,
            "action": _id(action, "audit action"),
            "subject_kind": _id(subject_kind, "audit subject_kind"),
            "subject_id": _id(subject_id, "audit subject_id"),
            "subject_revision": subject_revision,
            "actor": actor,
            "details": dict(details),
            "occurred_at": self._now(),
            "previous_sha256": previous,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO audit_events VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )
        return digest

    @staticmethod
    def _policy_from_payload(payload: Mapping[str, Any]) -> GovernanceAgentPolicy:
        data = dict(payload)
        try:
            data["allowed_capabilities"] = tuple(data["allowed_capabilities"])
            data["approver_principals"] = tuple(data["approver_principals"])
        except (KeyError, TypeError) as exc:
            raise GovernanceAgentIntegrityError("persisted policy shape is invalid") from exc
        policy = _dataclass_from_mapping(GovernanceAgentPolicy, data, "policy")
        material = asdict(policy)
        authority = material.pop("authority_sha256")
        if _sha256(material) != authority:
            raise GovernanceAgentIntegrityError("persisted policy authority is invalid")
        return policy

    @staticmethod
    def _run_from_payload(payload: Mapping[str, Any]) -> GovernanceAgentRun:
        data = dict(payload)
        try:
            data["context"] = tuple(
                _dataclass_from_mapping(GovernanceContextRecord, item, "context record")
                for item in data["context"]
            )
            findings = []
            for item in data["findings"]:
                normalized = dict(item)
                normalized["evidence_item_ids"] = tuple(normalized["evidence_item_ids"])
                findings.append(
                    _dataclass_from_mapping(GovernanceAgentFinding, normalized, "finding")
                )
            data["findings"] = tuple(findings)
            data["approvals"] = tuple(
                _dataclass_from_mapping(GovernanceAgentApproval, item, "approval")
                for item in data["approvals"]
            )
            if data["execution_outcome"] is not None:
                data["execution_outcome"] = _dataclass_from_mapping(
                    GovernanceAgentExecutionOutcome,
                    data["execution_outcome"],
                    "execution outcome",
                )
            data["limitations"] = tuple(data["limitations"])
        except KeyError as exc:
            raise GovernanceAgentIntegrityError("persisted run shape is invalid") from exc
        run = _dataclass_from_mapping(GovernanceAgentRun, data, "run")
        material = asdict(run)
        integrity = material.pop("integrity_sha256")
        if _sha256(material) != integrity:
            raise GovernanceAgentIntegrityError("persisted run integrity is invalid")
        return run

    def _get_policy(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        policy_id: str,
        revision: int | None = None,
    ) -> GovernanceAgentPolicy:
        if revision is None:
            row = connection.execute(
                "SELECT * FROM policies WHERE tenant_id=? AND policy_id=? "
                "ORDER BY revision DESC LIMIT 1",
                (tenant_id, policy_id),
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM policies WHERE tenant_id=? AND policy_id=? AND revision=?",
                (tenant_id, policy_id, revision),
            ).fetchone()
        if row is None:
            raise GovernanceAgentNotFound("governance-agent policy was not found")
        policy = self._policy_from_payload(self._load_payload(row, "policy"))
        self._verify_policy_row(row, tenant_id, policy)
        return policy

    def _get_run(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        run_id: str,
    ) -> GovernanceAgentRun:
        row = connection.execute(
            "SELECT * FROM runs WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone()
        if row is None:
            raise GovernanceAgentNotFound("governance-agent run was not found")
        run = self._run_from_payload(self._load_payload(row, "run"))
        self._verify_run_row(row, tenant_id, run)
        return run

    @staticmethod
    def _verify_policy_row(
        row: sqlite3.Row,
        tenant_id: str,
        policy: GovernanceAgentPolicy,
    ) -> None:
        """Bind query-driving SQLite columns to the canonical policy payload."""

        if (
            row["tenant_id"] != tenant_id
            or policy.tenant_sha256 != hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
            or row["policy_id"] != policy.policy_id
            or int(row["revision"]) != policy.revision
            or bool(row["revoked"]) != policy.revoked
            or float(row["valid_until"]) != policy.valid_until
        ):
            raise GovernanceAgentIntegrityError("persisted policy mirror columns are invalid")

    @staticmethod
    def _verify_run_row(
        row: sqlite3.Row,
        tenant_id: str,
        run: GovernanceAgentRun,
    ) -> None:
        """Bind query, CAS, and retention columns to the canonical run payload."""

        if (
            row["tenant_id"] != tenant_id
            or run.tenant_id != tenant_id
            or row["run_id"] != run.run_id
            or row["state"] != run.state
            or int(row["revision"]) != run.revision
            or float(row["retained_until"]) != run.retained_until
        ):
            raise GovernanceAgentIntegrityError("persisted run mirror columns are invalid")

    @staticmethod
    def _write_run(
        connection: sqlite3.Connection,
        tenant_id: str,
        run: GovernanceAgentRun,
        expected_revision: int,
    ) -> None:
        payload = asdict(run)
        digest = _sha256(payload)
        result = connection.execute(
            "UPDATE runs SET state=?,revision=?,retained_until=?,payload_json=?,"
            "integrity_sha256=? WHERE tenant_id=? AND run_id=? AND revision=?",
            (
                run.state,
                run.revision,
                run.retained_until,
                _canonical(payload).decode("ascii"),
                digest,
                tenant_id,
                run.run_id,
                expected_revision,
            ),
        )
        if result.rowcount != 1:
            raise GovernanceAgentConflict("governance-agent run revision changed")

    @staticmethod
    def _replace_run(run: GovernanceAgentRun, **changes: object) -> GovernanceAgentRun:
        payload = asdict(run)
        payload.update(changes)
        payload.pop("integrity_sha256", None)
        # Rehydrate nested values because asdict recursively converts them.
        payload["context"] = tuple(
            item if isinstance(item, GovernanceContextRecord) else GovernanceContextRecord(**item)
            for item in payload["context"]
        )
        payload["findings"] = tuple(
            item if isinstance(item, GovernanceAgentFinding) else GovernanceAgentFinding(**item)
            for item in payload["findings"]
        )
        payload["approvals"] = tuple(
            item if isinstance(item, GovernanceAgentApproval) else GovernanceAgentApproval(**item)
            for item in payload["approvals"]
        )
        outcome = payload.get("execution_outcome")
        if isinstance(outcome, Mapping):
            payload["execution_outcome"] = GovernanceAgentExecutionOutcome(**outcome)
        digest = _sha256(payload)
        return GovernanceAgentRun(**payload, integrity_sha256=digest)

    def publish_policy(
        self,
        tenant_id: str,
        *,
        policy_id: str,
        revision: int,
        agent_kind: str,
        allowed_capabilities: Sequence[str],
        required_approvals: int,
        execution_enabled: bool,
        approver_principals: Sequence[str],
        valid_until: float,
        idempotency_key: str,
    ) -> GovernanceAgentPolicy:
        """Publish a revisioned policy after independent approval."""

        tenant = _tenant(tenant_id)
        actor = self._actor()
        kind = _closed(agent_kind, "agent_kind", AGENT_KINDS)
        tenant_snapshot = self._tenant_snapshot_for(tenant)
        self._require_agent_enabled(tenant_snapshot, kind)
        capabilities = _unique_closed(
            list(allowed_capabilities),
            "allowed_capabilities",
            CAPABILITY_REGISTRY[kind],
            maximum=len(CAPABILITY_REGISTRY[kind]),
        )
        approvals = tuple(sorted(_id(item, "approver_principal") for item in approver_principals))
        if len(approvals) < 2 or len(set(approvals)) != len(approvals) or actor in approvals:
            raise GovernanceAgentPermissionDenied(
                "policy publication requires two distinct approvers other than the publisher"
            )
        if not callable(self._policy_approver_resolver):
            raise GovernanceAgentConfigError(
                "policy publication requires an independent approver resolver"
            )
        try:
            resolved_approvals = tuple(
                sorted(
                    _id(item, "resolved approver principal")
                    for item in self._policy_approver_resolver(
                        tenant,
                        _id(policy_id, "policy_id"),
                        revision,
                    )
                )
            )
        except GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentConfigError("policy approval authority is unavailable") from exc
        if (
            len(resolved_approvals) < 2
            or len(set(resolved_approvals)) != len(resolved_approvals)
        ):
            raise GovernanceAgentConfigError(
                "policy approval authority returned an invalid eligible roster"
            )
        if not set(approvals).issubset(resolved_approvals):
            raise GovernanceAgentPermissionDenied(
                "caller-proposed policy approvers are not a subset of the independent authority"
            )
        approval_count = _positive_int(required_approvals, "required_approvals", _MAX_APPROVALS)
        if execution_enabled is not False and execution_enabled is not True:
            raise GovernanceAgentValidationError("execution_enabled must be true or false")
        if execution_enabled and approval_count < 2:
            raise GovernanceAgentValidationError(
                "execution-enabled policies require at least two run approvals"
            )
        now = self._now()
        expiry = _timestamp(valid_until, "valid_until")
        if expiry <= now:
            raise GovernanceAgentValidationError("valid_until must be in the future")
        rev = _positive_int(revision, "revision", 2_147_483_647)
        request = {
            "policy_id": _id(policy_id, "policy_id"),
            "revision": rev,
            "agent_kind": kind,
            "allowed_capabilities": capabilities,
            "required_approvals": approval_count,
            "execution_enabled": execution_enabled,
            "approver_principals": approvals,
            "valid_until": expiry,
        }
        with self._connect() as connection:
            self._begin(connection)
            tenant_limits = tenant_snapshot.limits
            request_sha256, previous = self._operation(connection, tenant, idempotency_key, request)
            if previous is not None:
                if (
                    previous["result_kind"] != "policy"
                    or previous["result_id"] != request["policy_id"]
                ):
                    raise GovernanceAgentIntegrityError(
                        "policy idempotency result binding is invalid"
                    )
                policy = self._get_policy(connection, tenant, request["policy_id"], rev)
                connection.commit()
                return policy
            latest = connection.execute(
                "SELECT revision FROM policies WHERE tenant_id=? AND policy_id=? "
                "ORDER BY revision DESC LIMIT 1",
                (tenant, request["policy_id"]),
            ).fetchone()
            if latest is not None and rev <= int(latest["revision"]):
                raise GovernanceAgentConflict("policy revision must increase")
            self._require_capacity(connection, tenant, "policies", tenant_limits)
            material = {
                "schema": POLICY_SCHEMA,
                "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                **request,
                "publisher_principal": actor,
                "revoked": False,
            }
            policy = GovernanceAgentPolicy(
                **material,
                authority_sha256=_sha256(material),
            )
            payload = asdict(policy)
            connection.execute(
                "INSERT INTO policies VALUES(?,?,?,?,?,?,?)",
                (
                    tenant,
                    policy.policy_id,
                    policy.revision,
                    0,
                    policy.valid_until,
                    _canonical(payload).decode("ascii"),
                    _sha256(payload),
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha256,
                "policy",
                policy.policy_id,
                tenant_limits,
            )
            self._audit(
                connection,
                tenant,
                "policy_published",
                "policy",
                policy.policy_id,
                policy.revision,
                actor,
                {"authority_sha256": policy.authority_sha256},
                tenant_limits,
            )
            connection.commit()
            return policy

    def revoke_policy(
        self,
        tenant_id: str,
        policy_id: str,
        *,
        revision: int,
        reason_code: str,
    ) -> GovernanceAgentPolicy:
        tenant = _tenant(tenant_id)
        actor = self._actor()
        reason = _closed(reason_code, "reason_code", RATIONALE_CODES)
        with self._connect() as connection:
            self._begin(connection)
            policy = self._get_policy(connection, tenant, _id(policy_id, "policy_id"), revision)
            if policy.revoked:
                connection.commit()
                return policy
            material = asdict(policy)
            material.pop("authority_sha256")
            material["revoked"] = True
            revoked = GovernanceAgentPolicy(
                **material,
                authority_sha256=_sha256(material),
            )
            payload = asdict(revoked)
            result = connection.execute(
                "UPDATE policies SET revoked=1,payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND policy_id=? AND revision=? AND revoked=0",
                (
                    _canonical(payload).decode("ascii"),
                    _sha256(payload),
                    tenant,
                    revoked.policy_id,
                    revoked.revision,
                ),
            )
            if result.rowcount != 1:
                raise GovernanceAgentConflict("policy revocation raced another change")
            self._audit(
                connection,
                tenant,
                "policy_revoked",
                "policy",
                revoked.policy_id,
                revoked.revision,
                actor,
                {"reason_code": reason},
            )
            connection.commit()
            return revoked

    def submit_run(  # noqa: C901 - trust-boundary validation is intentionally linear
        self,
        tenant_id: str,
        *,
        run_id: str,
        policy_id: str,
        policy_revision: int,
        capability: str,
        context: Sequence[GovernanceContextItem],
        adapter_authority: GovernanceAgentAdapterAuthority,
        adapter: GovernanceAnalysisAdapter,
        idempotency_key: str,
    ) -> GovernanceAgentRun:
        """Run bounded analysis and persist only digest-safe structured output."""

        tenant = _tenant(tenant_id)
        requester = self._actor()
        run_ref = _id(run_id, "run_id")
        tenant_snapshot = self._tenant_snapshot_for(tenant)
        tenant_limits = tenant_snapshot.limits
        if not callable(adapter):
            raise GovernanceAgentConfigError("analysis adapter must be callable")
        now = self._now()
        if len(context) < 1 or len(context) > tenant_limits.max_context_items:
            raise GovernanceAgentValidationError("context is outside its item bound")
        records: list[GovernanceContextRecord] = []
        seen: set[str] = set()
        total_bytes = 0
        for item in context:
            if not isinstance(item, GovernanceContextItem):
                raise GovernanceAgentValidationError(
                    "context entries must be GovernanceContextItem values"
                )
            item_id = _id(item.item_id, "context item_id")
            if item_id in seen:
                raise GovernanceAgentValidationError("context item_id values must be unique")
            seen.add(item_id)
            if not isinstance(item.content, bytes) or not item.content:
                raise GovernanceAgentValidationError("context content must be non-empty bytes")
            total_bytes += len(item.content)
            if total_bytes > tenant_limits.max_context_bytes:
                raise GovernanceAgentValidationError("context exceeds its byte bound")
            material = {
                "schema": CONTEXT_SCHEMA,
                "item_id": item_id,
                "source_kind": _closed(item.source_kind, "source_kind", SOURCE_KINDS),
                "source_ref": _id(item.source_ref, "source_ref"),
                "source_revision": _positive_int(
                    item.source_revision, "source_revision", 2_147_483_647
                ),
                "collected_at": _timestamp(item.collected_at, "collected_at"),
                "byte_length": len(item.content),
                "content_sha256": hashlib.sha256(item.content).hexdigest(),
            }
            records.append(GovernanceContextRecord(**material, record_sha256=_sha256(material)))
        records.sort(key=lambda value: value.item_id)
        request = {
            "run_id": run_ref,
            "policy_id": _id(policy_id, "policy_id"),
            "policy_revision": _positive_int(policy_revision, "policy_revision", 2_147_483_647),
            "capability": _id(capability, "capability"),
            "context": [asdict(value) for value in records],
            "adapter_authority_sha256": adapter_authority.authority_sha256,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha256, previous = self._operation(connection, tenant, idempotency_key, request)
            if previous is not None:
                if previous["result_kind"] == "run_tombstone":
                    raise GovernanceAgentConflict("idempotent run result expired and is tombstoned")
                if previous["result_kind"] != "run" or previous["result_id"] != run_ref:
                    raise GovernanceAgentIntegrityError("run idempotency result binding is invalid")
                run = self._get_run(connection, tenant, previous["result_id"])
                self._require_agent_enabled(tenant_snapshot, run.agent_kind)
                connection.commit()
                return run
            policy = self._get_policy(
                connection, tenant, request["policy_id"], request["policy_revision"]
            )
            self._require_agent_enabled(tenant_snapshot, policy.agent_kind)
            if policy.revoked or policy.valid_until <= now:
                raise GovernanceAgentConfigError("governance-agent policy is unavailable")
            if capability not in policy.allowed_capabilities:
                raise GovernanceAgentPermissionDenied("capability is not granted by policy")
            enrolled_adapter_authority = self._resolve_analysis_binding(
                tenant,
                policy.agent_kind,
                adapter_authority,
                adapter,
            )
            if (
                connection.execute(
                    "SELECT 1 FROM runs WHERE tenant_id=? AND run_id=?", (tenant, run_ref)
                ).fetchone()
                is not None
            ):
                raise GovernanceAgentConflict("run_id already exists")
            tombstones = connection.execute(
                "SELECT * FROM operations WHERE tenant_id=? "
                "AND result_kind='run_tombstone' AND result_id=?",
                (tenant, run_ref),
            ).fetchall()
            for tombstone in tombstones:
                self._verify_operation_row(tombstone, tenant)
            if tombstones:
                raise GovernanceAgentConflict("run_id is retained by a purge tombstone")
            analysis_owner_token = self._reserve_analysis(
                connection,
                tenant,
                idempotency_key,
                request_sha256,
                run_ref,
                now,
                tenant_limits,
                requester,
            )
            connection.commit()

        try:
            self.budget.record_tool_call()
            analysis = adapter(
                tenant_id=tenant,
                run_id=run_ref,
                agent_kind=policy.agent_kind,
                capability=capability,
                context=tuple(context),
                authority=adapter_authority,
            )
        except BudgetExceeded as exc:
            raise GovernanceAgentConfigError("governance-agent budget is exhausted") from exc
        if not isinstance(analysis, GovernanceAgentAnalysis):
            raise GovernanceAgentIntegrityError("analysis adapter returned an invalid result")
        limitations = _bounded_codes(
            list(analysis.limitations),
            "limitations",
            LIMITATION_CODES,
            maximum=len(LIMITATION_CODES),
        )
        if not isinstance(analysis.complete, bool):
            raise GovernanceAgentIntegrityError("analysis completeness flag is invalid")
        if analysis.complete and limitations:
            raise GovernanceAgentIntegrityError("complete analysis cannot disclose limitations")
        if not analysis.complete and not limitations:
            raise GovernanceAgentIntegrityError("incomplete analysis must disclose limitations")
        if not 1 <= len(analysis.findings) <= _MAX_FINDINGS:
            raise GovernanceAgentIntegrityError("analysis findings are outside their bound")
        finding_ids: set[str] = set()
        normalized_findings: list[GovernanceAgentFinding] = []
        for finding in analysis.findings:
            if not isinstance(finding, GovernanceAgentFinding):
                raise GovernanceAgentIntegrityError("adapter finding is invalid")
            material = asdict(finding)
            digest = material.pop("finding_sha256")
            if _sha256(material) != digest:
                raise GovernanceAgentIntegrityError("adapter finding digest is invalid")
            if finding.finding_code not in FINDING_CODES[policy.agent_kind]:
                raise GovernanceAgentIntegrityError("adapter finding code is not authorized")
            if (
                finding.recommended_action_code is not None
                and finding.recommended_action_code not in ACTION_CODES[policy.agent_kind]
            ):
                raise GovernanceAgentIntegrityError("adapter action code is not authorized")
            if finding.finding_id in finding_ids:
                raise GovernanceAgentIntegrityError("adapter finding ids are not unique")
            finding_ids.add(finding.finding_id)
            if not set(finding.evidence_item_ids).issubset(seen):
                raise GovernanceAgentIntegrityError(
                    "adapter finding cites context outside the exact request"
                )
            normalized_findings.append(finding)
        normalized_findings.sort(key=lambda value: value.finding_id)
        output_material = {
            "findings": [asdict(value) for value in normalized_findings],
            "limitations": limitations,
            "complete": analysis.complete,
        }
        _canonical(output_material, maximum=tenant_limits.max_output_bytes)

        created = self._now()
        run_material = {
            "schema": RUN_SCHEMA,
            "tenant_id": tenant,
            "run_id": run_ref,
            "revision": 1,
            "state": "pending_review",
            "agent_kind": policy.agent_kind,
            "capability": capability,
            "policy_id": policy.policy_id,
            "policy_revision": policy.revision,
            "policy_authority_sha256": policy.authority_sha256,
            "adapter_authority_sha256": adapter_authority.authority_sha256,
            "execution_dispatcher_authority_sha256": None,
            "request_sha256": request_sha256,
            "context": tuple(records),
            "findings": tuple(normalized_findings),
            "limitations": limitations,
            "analysis_complete": analysis.complete,
            "requested_by": requester,
            "approvals": (),
            "execution_attempts": 0,
            "execution_idempotency_sha256": None,
            "execution_outcome": None,
            "failure_code": None,
            "retained_until": created + tenant_limits.retention_seconds,
            "created_at": created,
            "updated_at": created,
        }
        run = GovernanceAgentRun(
            **run_material,
            integrity_sha256=_sha256(run_material),
        )
        current_adapter_authority = self._resolve_analysis_binding(
            tenant,
            policy.agent_kind,
            adapter_authority,
            adapter,
        )
        if not secrets.compare_digest(
            current_adapter_authority.authority_sha256,
            enrolled_adapter_authority.authority_sha256,
        ):
            raise GovernanceAgentConflict("adapter authority changed during analysis")
        with self._connect() as connection:
            self._begin(connection)
            # Revalidate exact authorities after untrusted adapter computation.
            current = self._get_policy(connection, tenant, policy.policy_id, policy.revision)
            if (
                current.revoked
                or current.valid_until <= self._now()
                or current.authority_sha256 != policy.authority_sha256
            ):
                raise GovernanceAgentConflict("policy authority changed during analysis")
            request_again, previous = self._operation(connection, tenant, idempotency_key, request)
            if request_again != request_sha256:
                raise GovernanceAgentConflict("analysis request changed")
            if previous is not None:
                if previous["result_kind"] == "run_tombstone":
                    raise GovernanceAgentConflict("idempotent run result expired and is tombstoned")
                raise GovernanceAgentConflict("analysis reservation is no longer owned")
            self._complete_analysis_reservation(
                connection,
                tenant,
                idempotency_key,
                request_sha256,
                run_ref,
                analysis_owner_token,
            )
            payload = asdict(run)
            connection.execute(
                "INSERT INTO runs VALUES(?,?,?,?,?,?,?)",
                (
                    tenant,
                    run.run_id,
                    run.state,
                    run.revision,
                    run.retained_until,
                    _canonical(payload).decode("ascii"),
                    _sha256(payload),
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha256,
                "run",
                run.run_id,
                tenant_limits,
            )
            self._audit(
                connection,
                tenant,
                "analysis_submitted",
                "run",
                run.run_id,
                run.revision,
                requester,
                {
                    "policy_authority_sha256": run.policy_authority_sha256,
                    "adapter_authority_sha256": run.adapter_authority_sha256,
                    "request_sha256": run.request_sha256,
                    "analysis_complete": run.analysis_complete,
                },
                tenant_limits,
            )
            connection.commit()
            return run

    def review(
        self,
        tenant_id: str,
        run_id: str,
        *,
        expected_revision: int,
        decision: str,
        rationale_code: str,
    ) -> GovernanceAgentRun:
        """Record an independently authenticated human review."""

        tenant = _tenant(tenant_id)
        actor = self._actor()
        tenant_snapshot = self._tenant_snapshot_for(tenant)
        decision_value = _closed(decision, "decision", REVIEW_DECISIONS)
        rationale = _closed(rationale_code, "rationale_code", RATIONALE_CODES)
        with self._connect() as connection:
            self._begin(connection)
            run = self._get_run(connection, tenant, _id(run_id, "run_id"))
            self._require_agent_enabled(tenant_snapshot, run.agent_kind)
            if run.revision != expected_revision:
                raise GovernanceAgentConflict("governance-agent run revision changed")
            if run.state not in {"pending_review", "approved"}:
                raise GovernanceAgentConflict("run cannot be reviewed in its current state")
            if actor == run.requested_by or actor in {item.principal for item in run.approvals}:
                raise GovernanceAgentPermissionDenied(
                    "requesters cannot approve their own run and reviewers cannot vote twice"
                )
            if len(run.approvals) >= _MAX_APPROVALS:
                raise GovernanceAgentConflict("run review limit is exhausted")
            policy = self._get_policy(connection, tenant, run.policy_id, run.policy_revision)
            if (
                policy.revoked
                or policy.valid_until <= self._now()
                or policy.authority_sha256 != run.policy_authority_sha256
            ):
                raise GovernanceAgentConflict("run policy authority is no longer valid")
            if actor not in set(policy.approver_principals):
                raise GovernanceAgentPermissionDenied(
                    "reviewer is not enrolled by the exact run policy"
                )
            decided_at = self._now()
            approval_material = {
                "schema": APPROVAL_SCHEMA,
                "principal": actor,
                "decision": decision_value,
                "rationale_code": rationale,
                "run_revision": run.revision,
                "decided_at": decided_at,
            }
            approval = GovernanceAgentApproval(
                **approval_material,
                approval_sha256=_sha256(approval_material),
            )
            approvals = (*run.approvals, approval)
            approvals_count = sum(item.decision == "approve" for item in approvals)
            state = (
                "rejected"
                if decision_value == "reject"
                else "approved"
                if approvals_count >= policy.required_approvals
                else "pending_review"
            )
            updated = self._replace_run(
                run,
                revision=run.revision + 1,
                state=state,
                approvals=approvals,
                updated_at=decided_at,
            )
            self._write_run(connection, tenant, updated, run.revision)
            self._audit(
                connection,
                tenant,
                "run_reviewed",
                "run",
                run.run_id,
                updated.revision,
                actor,
                {"decision": decision_value, "rationale_code": rationale, "state": state},
            )
            connection.commit()
            return updated

    def execute(
        self,
        tenant_id: str,
        run_id: str,
        *,
        expected_revision: int,
        dispatcher: GovernanceActionDispatcher,
    ) -> GovernanceAgentRun:
        """Dispatch an approved action through an exact idempotent seam.

        A stable secret-bearing idempotency token is passed to the dispatcher;
        only its SHA-256 digest is retained.  Retrying a failed or interrupted
        execution therefore uses the same token and cannot authorize a second
        logical mutation.
        """

        if not callable(dispatcher):
            raise GovernanceAgentConfigError("action dispatcher must be callable")
        tenant = _tenant(tenant_id)
        actor = self._actor()
        tenant_snapshot = self._tenant_snapshot_for(tenant)
        with self._connect() as connection:
            self._begin(connection)
            run = self._get_run(connection, tenant, _id(run_id, "run_id"))
            self._require_agent_enabled(tenant_snapshot, run.agent_kind)
            if run.revision != expected_revision:
                raise GovernanceAgentConflict("governance-agent run revision changed")
            if run.state not in {"approved", "execution_failed", "executing"}:
                raise GovernanceAgentConflict("run is not eligible for execution")
            if run.execution_attempts >= _MAX_EXECUTION_ATTEMPTS:
                raise GovernanceAgentConflict("execution retry limit is exhausted")
            policy = self._get_policy(connection, tenant, run.policy_id, run.policy_revision)
            if (
                policy.revoked
                or not policy.execution_enabled
                or policy.valid_until <= self._now()
                or policy.authority_sha256 != run.policy_authority_sha256
            ):
                raise GovernanceAgentPermissionDenied(
                    "execution policy is disabled, expired, revoked, or changed"
                )
            if len({item.principal for item in run.approvals if item.decision == "approve"}) < max(
                2, policy.required_approvals
            ):
                raise GovernanceAgentPermissionDenied(
                    "execution requires the policy approval threshold and two humans"
                )
            actions = sorted(
                {
                    item.recommended_action_code
                    for item in run.findings
                    if item.recommended_action_code is not None
                }
            )
            if not actions:
                raise GovernanceAgentConflict("run contains no approved action proposal")
            dispatcher_authority, receipt_verifier = self._resolve_execution_binding(
                tenant,
                run.agent_kind,
                dispatcher,
            )
            if run.execution_idempotency_sha256 is None:
                token = f"ga:{secrets.token_urlsafe(32)}"
                token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
            else:
                # A plaintext token is intentionally not durable.  Recovery from
                # a previously entered executing/failed state must use an exact
                # deployment resolver instead of inventing a new authority.
                raise GovernanceAgentConflict(
                    "execution token is already committed; use recover_execution"
                )
            self._escrow_and_confirm_execution_token(
                tenant,
                run.run_id,
                token,
                token_sha256,
            )
            executing = self._replace_run(
                run,
                revision=run.revision + 1,
                state="executing",
                execution_attempts=run.execution_attempts + 1,
                execution_idempotency_sha256=token_sha256,
                execution_dispatcher_authority_sha256=(dispatcher_authority.authority_sha256),
                failure_code=None,
                updated_at=self._now(),
            )
            self._write_run(connection, tenant, executing, run.revision)
            self._audit(
                connection,
                tenant,
                "execution_intent_created",
                "run",
                run.run_id,
                executing.revision,
                actor,
                {"action_codes": actions, "idempotency_sha256": token_sha256},
            )
            connection.commit()

        try:
            self.budget.record_tool_call()
            outcome = dispatcher(run=executing, idempotency_key=token)
        except BudgetExceeded:
            return self._record_execution_failure(
                tenant, executing, "budget_exhausted", retryable=False, actor=actor
            )
        except Exception:
            return self._record_execution_failure(
                tenant, executing, "dispatcher_unavailable", retryable=True, actor=actor
            )
        return self._finalize_execution(
            tenant,
            executing,
            outcome,
            dispatcher=dispatcher,
            dispatcher_authority=dispatcher_authority,
            receipt_verifier=receipt_verifier,
            actor=actor,
        )

    def recover_execution(
        self,
        tenant_id: str,
        run_id: str,
        *,
        expected_revision: int,
        dispatcher: GovernanceActionDispatcher,
    ) -> GovernanceAgentRun:
        """Recover an executing/failed action using its original token authority."""

        if not callable(dispatcher):
            raise GovernanceAgentConfigError("execution recovery requires a dispatcher")
        tenant = _tenant(tenant_id)
        actor = self._actor()
        tenant_snapshot = self._tenant_snapshot_for(tenant)
        with self._connect() as connection:
            run = self._get_run(connection, tenant, _id(run_id, "run_id"))
        self._require_agent_enabled(tenant_snapshot, run.agent_kind)
        if run.revision != expected_revision:
            raise GovernanceAgentConflict("governance-agent run revision changed")
        if run.state not in {"executing", "execution_failed"}:
            raise GovernanceAgentConflict("run does not need execution recovery")
        if run.execution_attempts >= _MAX_EXECUTION_ATTEMPTS:
            raise GovernanceAgentConflict("execution retry limit is exhausted")
        if run.execution_idempotency_sha256 is None:
            raise GovernanceAgentIntegrityError("execution token digest is missing")
        if run.failure_code in {
            "budget_exhausted",
            "dispatcher_authority_changed",
            "invalid_dispatch_receipt",
        }:
            raise GovernanceAgentConflict("execution failure is not retryable")
        if run.execution_outcome is not None and not run.execution_outcome.retryable:
            raise GovernanceAgentConflict("execution outcome is not retryable")
        token = self._recover_execution_token(
            tenant,
            run.run_id,
            run.execution_idempotency_sha256,
        )
        with self._connect() as connection:
            self._begin(connection)
            current = self._get_run(connection, tenant, run.run_id)
            if current.revision != run.revision or current.state not in {
                "executing",
                "execution_failed",
            }:
                raise GovernanceAgentConflict("execution state changed before recovery")
            policy = self._get_policy(
                connection,
                tenant,
                current.policy_id,
                current.policy_revision,
            )
            if (
                policy.revoked
                or not policy.execution_enabled
                or policy.valid_until <= self._now()
                or policy.authority_sha256 != current.policy_authority_sha256
            ):
                raise GovernanceAgentPermissionDenied(
                    "execution policy is disabled, expired, revoked, or changed"
                )
            if len(
                {item.principal for item in current.approvals if item.decision == "approve"}
            ) < max(2, policy.required_approvals):
                raise GovernanceAgentPermissionDenied(
                    "execution recovery requires the policy approval threshold and two humans"
                )
            if current.execution_dispatcher_authority_sha256 is None:
                raise GovernanceAgentIntegrityError("dispatcher authority digest is missing")
            dispatcher_authority, receipt_verifier = self._resolve_execution_binding(
                tenant,
                current.agent_kind,
                dispatcher,
            )
            if not secrets.compare_digest(
                dispatcher_authority.authority_sha256,
                current.execution_dispatcher_authority_sha256,
            ):
                raise GovernanceAgentPermissionDenied(
                    "execution dispatcher authority changed after intent creation"
                )
            recovering = self._replace_run(
                current,
                revision=current.revision + 1,
                state="executing",
                execution_attempts=current.execution_attempts + 1,
                failure_code=None,
                updated_at=self._now(),
            )
            self._write_run(connection, tenant, recovering, current.revision)
            self._audit(
                connection,
                tenant,
                "execution_recovery_started",
                "run",
                run.run_id,
                recovering.revision,
                actor,
                {"idempotency_sha256": run.execution_idempotency_sha256},
            )
            connection.commit()
        try:
            self.budget.record_tool_call()
            outcome = dispatcher(run=recovering, idempotency_key=token)
        except BudgetExceeded:
            return self._record_execution_failure(
                tenant, recovering, "budget_exhausted", retryable=False, actor=actor
            )
        except Exception:
            return self._record_execution_failure(
                tenant, recovering, "dispatcher_unavailable", retryable=True, actor=actor
            )
        return self._finalize_execution(
            tenant,
            recovering,
            outcome,
            dispatcher=dispatcher,
            dispatcher_authority=dispatcher_authority,
            receipt_verifier=receipt_verifier,
            actor=actor,
        )

    def _validate_outcome(
        self,
        outcome: object,
        run: GovernanceAgentRun,
        dispatcher_authority: GovernanceAgentDispatcherAuthority,
        receipt_verifier: GovernanceExecutionReceiptVerifier,
    ) -> GovernanceAgentExecutionOutcome:
        if not isinstance(outcome, GovernanceAgentExecutionOutcome):
            raise GovernanceAgentIntegrityError("dispatcher returned an invalid outcome")
        material = asdict(outcome)
        digest = material.pop("receipt_sha256")
        if not secrets.compare_digest(_sha256(material), digest):
            raise GovernanceAgentIntegrityError("execution receipt digest is invalid")
        if outcome.schema != EXECUTION_SCHEMA:
            raise GovernanceAgentIntegrityError("execution receipt schema is invalid")
        expected_tenant = hashlib.sha256(run.tenant_id.encode("utf-8")).hexdigest()
        expected_dispatcher = run.execution_dispatcher_authority_sha256
        if expected_dispatcher is None:
            raise GovernanceAgentIntegrityError("dispatcher authority digest is missing")
        if (
            not secrets.compare_digest(outcome.tenant_sha256, expected_tenant)
            or outcome.run_id != run.run_id
            or outcome.run_revision != run.revision
            or run.execution_idempotency_sha256 is None
            or not secrets.compare_digest(
                outcome.execution_idempotency_sha256,
                run.execution_idempotency_sha256,
            )
            or not secrets.compare_digest(
                outcome.action_codes_sha256,
                _execution_action_codes_sha256(run),
            )
            or not secrets.compare_digest(
                outcome.dispatcher_authority_sha256,
                expected_dispatcher,
            )
            or not secrets.compare_digest(
                dispatcher_authority.authority_sha256,
                expected_dispatcher,
            )
        ):
            raise GovernanceAgentIntegrityError(
                "execution receipt is not bound to the exact intent authority"
            )
        _closed(outcome.outcome, "execution outcome", EXECUTION_OUTCOMES)
        _id(outcome.provider_status_code, "provider_status_code")
        if outcome.external_reference_sha256 is not None:
            _digest(outcome.external_reference_sha256, "external_reference_sha256")
        if not isinstance(outcome.retryable, bool):
            raise GovernanceAgentIntegrityError("execution retryable flag is invalid")
        _digest(outcome.receipt_proof_sha256, "receipt_proof_sha256")
        if outcome.outcome in {"applied", "no_change"} and outcome.retryable:
            raise GovernanceAgentIntegrityError("successful outcome cannot be retryable")
        if run.execution_idempotency_sha256 is None:
            raise GovernanceAgentIntegrityError("execution authority digest is missing")
        try:
            verified = receipt_verifier(dispatcher_authority, outcome)
        except Exception as exc:
            raise GovernanceAgentIntegrityError("execution receipt verifier failed closed") from exc
        if verified is not True:
            raise GovernanceAgentIntegrityError("execution receipt proof is not trusted")
        return outcome

    def _finalize_execution(
        self,
        tenant: str,
        run: GovernanceAgentRun,
        outcome: object,
        *,
        dispatcher: GovernanceActionDispatcher,
        dispatcher_authority: GovernanceAgentDispatcherAuthority,
        receipt_verifier: GovernanceExecutionReceiptVerifier,
        actor: str,
    ) -> GovernanceAgentRun:
        try:
            current_authority, current_verifier = self._resolve_execution_binding(
                tenant,
                run.agent_kind,
                dispatcher,
            )
        except GovernanceAgentError:
            return self._record_execution_failure(
                tenant,
                run,
                "dispatcher_authority_changed",
                retryable=False,
                actor=actor,
            )
        if current_verifier is not receipt_verifier or not secrets.compare_digest(
            current_authority.authority_sha256,
            dispatcher_authority.authority_sha256,
        ):
            return self._record_execution_failure(
                tenant,
                run,
                "dispatcher_authority_changed",
                retryable=False,
                actor=actor,
            )
        try:
            valid = self._validate_outcome(
                outcome,
                run,
                current_authority,
                current_verifier,
            )
        except GovernanceAgentError:
            return self._record_execution_failure(
                tenant, run, "invalid_dispatch_receipt", retryable=False, actor=actor
            )
        state = "executed" if valid.outcome in {"applied", "no_change"} else "execution_failed"
        failure = None if state == "executed" else "provider_rejected"
        with self._connect() as connection:
            self._begin(connection)
            current = self._get_run(connection, tenant, run.run_id)
            if current.revision != run.revision or current.state not in {
                "executing",
                "execution_failed",
            }:
                raise GovernanceAgentConflict("execution state changed before receipt commit")
            updated = self._replace_run(
                current,
                revision=current.revision + 1,
                state=state,
                execution_outcome=valid,
                failure_code=failure,
                updated_at=self._now(),
            )
            self._write_run(connection, tenant, updated, current.revision)
            self._audit(
                connection,
                tenant,
                "execution_completed" if state == "executed" else "execution_failed",
                "run",
                run.run_id,
                updated.revision,
                actor,
                {
                    "outcome": valid.outcome,
                    "provider_status_code": valid.provider_status_code,
                    "receipt_sha256": valid.receipt_sha256,
                },
            )
            connection.commit()
            return updated

    def _record_execution_failure(
        self,
        tenant: str,
        run: GovernanceAgentRun,
        failure_code: str,
        *,
        retryable: bool,
        actor: str,
    ) -> GovernanceAgentRun:
        failure = _id(failure_code, "failure_code")
        with self._connect() as connection:
            self._begin(connection)
            current = self._get_run(connection, tenant, run.run_id)
            if current.revision != run.revision:
                raise GovernanceAgentConflict("execution state changed before failure commit")
            updated = self._replace_run(
                current,
                revision=current.revision + 1,
                state="execution_failed",
                failure_code=failure,
                updated_at=self._now(),
            )
            self._write_run(connection, tenant, updated, current.revision)
            self._audit(
                connection,
                tenant,
                "execution_failed",
                "run",
                run.run_id,
                updated.revision,
                actor,
                {"failure_code": failure, "retryable": retryable},
            )
            connection.commit()
            return updated

    def revoke_run(
        self,
        tenant_id: str,
        run_id: str,
        *,
        expected_revision: int,
        reason_code: str,
    ) -> GovernanceAgentRun:
        tenant = _tenant(tenant_id)
        actor = self._actor()
        reason = _closed(reason_code, "reason_code", RATIONALE_CODES)
        with self._connect() as connection:
            self._begin(connection)
            run = self._get_run(connection, tenant, _id(run_id, "run_id"))
            if run.revision != expected_revision:
                raise GovernanceAgentConflict("governance-agent run revision changed")
            if run.state == "revoked":
                connection.commit()
                return run
            if run.state == "executing":
                raise GovernanceAgentConflict("an in-flight execution cannot be revoked")
            updated = self._replace_run(
                run,
                revision=run.revision + 1,
                state="revoked",
                updated_at=self._now(),
            )
            self._write_run(connection, tenant, updated, run.revision)
            self._audit(
                connection,
                tenant,
                "run_revoked",
                "run",
                run.run_id,
                updated.revision,
                actor,
                {"reason_code": reason},
            )
            connection.commit()
            return updated

    def get_run(self, tenant_id: str, run_id: str) -> GovernanceAgentRun:
        tenant = _tenant(tenant_id)
        self._actor()
        with self._connect() as connection:
            return self._get_run(connection, tenant, _id(run_id, "run_id"))

    def has_run_tombstone(self, tenant_id: str, run_id: str) -> bool:
        """Return whether retention left an integrity-checked replay tombstone."""

        tenant = _tenant(tenant_id)
        run_ref = _id(run_id, "run_id")
        self._actor()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM operations WHERE tenant_id=? "
                "AND result_kind='run_tombstone' AND result_id=?",
                (tenant, run_ref),
            ).fetchall()
        for row in rows:
            self._verify_operation_row(row, tenant)
        if len(rows) > 1:
            raise GovernanceAgentIntegrityError(
                "run retention tombstone identity is ambiguous"
            )
        return len(rows) == 1

    def get_policy(
        self,
        tenant_id: str,
        policy_id: str,
        *,
        revision: int | None = None,
    ) -> GovernanceAgentPolicy:
        tenant = _tenant(tenant_id)
        self._actor()
        if revision is not None:
            revision = _positive_int(revision, "revision", 2_147_483_647)
        with self._connect() as connection:
            return self._get_policy(
                connection,
                tenant,
                _id(policy_id, "policy_id"),
                revision,
            )

    def list_policies(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> tuple[GovernanceAgentPolicy, ...]:
        """Current revision of each tenant policy, each verified, for pickers."""

        tenant = _tenant(tenant_id)
        self._actor()
        count = _positive_int(limit, "limit", 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT policy_id FROM policies WHERE tenant_id=? "
                "GROUP BY policy_id ORDER BY policy_id LIMIT ?",
                (tenant, count),
            ).fetchall()
            return tuple(
                self._get_policy(connection, tenant, str(row["policy_id"]))
                for row in rows
            )

    def list_runs(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        limit: int = 100,
    ) -> tuple[GovernanceAgentRun, ...]:
        tenant = _tenant(tenant_id)
        self._actor()
        count = _positive_int(limit, "limit", 1_000)
        if state is not None:
            _closed(state, "state", RUN_STATES)
        with self._connect() as connection:
            if state is None:
                rows = connection.execute(
                    "SELECT * FROM runs WHERE tenant_id=? ORDER BY "
                    "lightwork_governance_updated_at(payload_json,integrity_sha256) DESC,run_id LIMIT ?",
                    (tenant, count),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM runs WHERE tenant_id=? AND state=? "
                    "ORDER BY lightwork_governance_updated_at(payload_json,integrity_sha256) DESC,run_id LIMIT ?",
                    (tenant, state, count),
                ).fetchall()
            runs: list[GovernanceAgentRun] = []
            for row in rows:
                run = self._run_from_payload(self._load_payload(row, "run"))
                self._verify_run_row(row, tenant, run)
                runs.append(run)
            return tuple(runs)

    def purge_expired_analysis_reservations(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> int:
        """Release expired, digest-only analysis leases with an audit record."""

        tenant = _tenant(tenant_id)
        actor = self._actor()
        count = _positive_int(limit, "limit", 1_000)
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            purged = self._purge_analysis_reservations(
                connection,
                tenant,
                now=now,
                actor=actor,
                tenant_limits=self._limits_for(tenant),
                limit=count,
            )
            connection.commit()
            return purged

    def purge_expired(self, tenant_id: str, *, limit: int = 100) -> int:
        """Delete expired terminal runs while retaining replay tombstones."""

        tenant = _tenant(tenant_id)
        actor = self._actor()
        count = _positive_int(limit, "limit", 1_000)
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            tenant_limits = self._limits_for(tenant)
            rows = connection.execute(
                "SELECT * FROM runs WHERE tenant_id=? "
                "AND state IN ('executed','rejected','revoked') AND retained_until<=? "
                "ORDER BY retained_until LIMIT ?",
                (tenant, now, count),
            ).fetchall()
            for row in rows:
                run = self._run_from_payload(self._load_payload(row, "run"))
                self._verify_run_row(row, tenant, run)
                self._tombstone_run_operation(connection, tenant, run)
                result = connection.execute(
                    "DELETE FROM runs WHERE tenant_id=? AND run_id=?",
                    (tenant, run.run_id),
                )
                if result.rowcount != 1:
                    raise GovernanceAgentConflict("run changed during retention purge")
                self._audit(
                    connection,
                    tenant,
                    "run_purged",
                    "run",
                    run.run_id,
                    run.revision,
                    actor,
                    {"retention_expired": True},
                    tenant_limits,
                )
            connection.commit()
            return len(rows)

    def verify_integrity(self, tenant_id: str) -> GovernanceAgentIntegrityReport:
        tenant = _tenant(tenant_id)
        self._actor()
        verified_policies = 0
        verified_runs = 0
        previous = _ZERO_DIGEST
        audit_count = 0
        with self._connect() as connection:
            policy_ids: set[str] = set()
            for row in connection.execute(
                "SELECT * FROM policies WHERE tenant_id=? ORDER BY policy_id,revision",
                (tenant,),
            ):
                policy = self._policy_from_payload(self._load_payload(row, "policy"))
                self._verify_policy_row(row, tenant, policy)
                policy_ids.add(policy.policy_id)
                verified_policies += 1
            runs: dict[str, GovernanceAgentRun] = {}
            for row in connection.execute(
                "SELECT * FROM runs WHERE tenant_id=? ORDER BY run_id", (tenant,)
            ):
                run = self._run_from_payload(self._load_payload(row, "run"))
                self._verify_run_row(row, tenant, run)
                runs[run.run_id] = run
                verified_runs += 1
            operation_sha256s: set[str] = set()
            live_run_backlinks: set[str] = set()
            tombstoned_run_ids: set[str] = set()
            for row in connection.execute(
                "SELECT * FROM operations WHERE tenant_id=? ORDER BY operation_sha256",
                (tenant,),
            ):
                binding = self._verify_operation_row(row, tenant)
                operation_sha256s.add(binding["operation_sha256"])
                result_kind = binding["result_kind"]
                result_id = binding["result_id"]
                if result_kind == "policy":
                    if result_id not in policy_ids:
                        raise GovernanceAgentIntegrityError(
                            "policy idempotency binding has no persisted result"
                        )
                elif result_kind == "run":
                    run = runs.get(result_id)
                    if run is None:
                        raise GovernanceAgentIntegrityError(
                            "run idempotency binding has no persisted result"
                        )
                    if result_id in live_run_backlinks or not secrets.compare_digest(
                        binding["request_sha256"],
                        run.request_sha256,
                    ):
                        raise GovernanceAgentIntegrityError(
                            "run idempotency backlink is ambiguous or invalid"
                        )
                    live_run_backlinks.add(result_id)
                elif result_kind == "run_tombstone":
                    if result_id in runs or result_id in tombstoned_run_ids:
                        raise GovernanceAgentIntegrityError(
                            "run tombstone conflicts with persisted identity"
                        )
                    tombstoned_run_ids.add(result_id)
                else:  # pragma: no cover - guarded by _verify_operation_row
                    raise GovernanceAgentIntegrityError(
                        "persisted idempotency result kind is invalid"
                    )
            if set(runs) != live_run_backlinks:
                raise GovernanceAgentIntegrityError(
                    "persisted run has no unique idempotency backlink"
                )
            reserved_run_ids: set[str] = set()
            for row in connection.execute(
                "SELECT * FROM analysis_reservations WHERE tenant_id=? ORDER BY operation_sha256",
                (tenant,),
            ):
                reservation = self._verify_analysis_reservation_row(row, tenant)
                operation_sha256 = str(reservation["operation_sha256"])
                run_id = str(reservation["run_id"])
                if (
                    operation_sha256 in operation_sha256s
                    or run_id in runs
                    or run_id in tombstoned_run_ids
                    or run_id in reserved_run_ids
                ):
                    raise GovernanceAgentIntegrityError(
                        "analysis reservation conflicts with persisted identity"
                    )
                reserved_run_ids.add(run_id)
            for row in connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? ORDER BY sequence", (tenant,)
            ):
                payload = self._load_payload(row, "audit event")
                audit_count += 1
                if (
                    payload.get("tenant_id") != tenant
                    or int(row["sequence"]) != audit_count
                    or payload.get("sequence") != audit_count
                    or payload.get("previous_sha256") != previous
                ):
                    raise GovernanceAgentIntegrityError("audit chain is discontinuous")
                previous = row["integrity_sha256"]
        return GovernanceAgentIntegrityReport(
            schema=INTEGRITY_SCHEMA,
            tenant_id=tenant,
            verified_policies=verified_policies,
            verified_runs=verified_runs,
            audit_events=audit_count,
            terminal_audit_sha256=previous,
        )


def execution_receipt_signing_payload(
    *,
    run: GovernanceAgentRun,
    dispatcher_authority: GovernanceAgentDispatcherAuthority,
    outcome: str,
    provider_status_code: str,
    external_reference_sha256: str | None = None,
    retryable: bool = False,
) -> dict[str, object]:
    """Return the exact content an enrolled dispatcher must sign or MAC."""

    if not isinstance(run, GovernanceAgentRun):
        raise GovernanceAgentValidationError("execution run binding is invalid")
    if not isinstance(dispatcher_authority, GovernanceAgentDispatcherAuthority):
        raise GovernanceAgentValidationError("dispatcher authority binding is invalid")
    if run.execution_idempotency_sha256 is None:
        raise GovernanceAgentValidationError("execution token digest is unavailable")
    if run.execution_dispatcher_authority_sha256 is None or not secrets.compare_digest(
        run.execution_dispatcher_authority_sha256,
        dispatcher_authority.authority_sha256,
    ):
        raise GovernanceAgentValidationError("dispatcher authority is not pinned to run")
    material = {
        "schema": EXECUTION_SCHEMA,
        "tenant_sha256": hashlib.sha256(run.tenant_id.encode("utf-8")).hexdigest(),
        "run_id": _id(run.run_id, "run_id"),
        "run_revision": _positive_int(run.revision, "run_revision", 2_147_483_647),
        "execution_idempotency_sha256": _digest(
            run.execution_idempotency_sha256,
            "execution_idempotency_sha256",
        ),
        "action_codes_sha256": _execution_action_codes_sha256(run),
        "dispatcher_authority_sha256": dispatcher_authority.authority_sha256,
        "outcome": _closed(outcome, "outcome", EXECUTION_OUTCOMES),
        "provider_status_code": _id(provider_status_code, "provider_status_code"),
        "external_reference_sha256": (
            None
            if external_reference_sha256 is None
            else _digest(external_reference_sha256, "external_reference_sha256")
        ),
        "retryable": retryable,
    }
    if not isinstance(retryable, bool):
        raise GovernanceAgentValidationError("retryable must be true or false")
    if material["outcome"] in {"applied", "no_change"} and retryable:
        raise GovernanceAgentValidationError("successful outcomes cannot be retryable")
    return material


def build_execution_outcome(
    *,
    run: GovernanceAgentRun,
    dispatcher_authority: GovernanceAgentDispatcherAuthority,
    outcome: str,
    provider_status_code: str,
    receipt_proof_sha256: str,
    external_reference_sha256: str | None = None,
    retryable: bool = False,
) -> GovernanceAgentExecutionOutcome:
    """Build a bound receipt whose proof still needs independent verification."""

    material = execution_receipt_signing_payload(
        run=run,
        dispatcher_authority=dispatcher_authority,
        outcome=outcome,
        provider_status_code=provider_status_code,
        external_reference_sha256=external_reference_sha256,
        retryable=retryable,
    )
    material["receipt_proof_sha256"] = _digest(
        receipt_proof_sha256,
        "receipt_proof_sha256",
    )
    return GovernanceAgentExecutionOutcome(
        **material,
        receipt_sha256=_sha256(material),
    )


__all__ = [
    "ACTION_CODES",
    "AGENT_KINDS",
    "CAPABILITY_REGISTRY",
    "FINDING_CODES",
    "LIMITATION_CODES",
    "NON_CONCLUSION_NOTICE",
    "GovernanceActionDispatcher",
    "GovernanceAgentAdapterAuthority",
    "GovernanceAgentAnalysis",
    "GovernanceAgentConfigError",
    "GovernanceAgentConflict",
    "GovernanceAgentError",
    "GovernanceAgentExecutionOutcome",
    "GovernanceAgentDispatcherAuthority",
    "GovernanceAgentFinding",
    "GovernanceAgentIntegrityError",
    "GovernanceAgentIntegrityReport",
    "GovernanceAgentLimits",
    "GovernanceAgentNotFound",
    "GovernanceAgentPermissionDenied",
    "GovernanceAgentPolicy",
    "GovernanceAgentQuotaExceeded",
    "GovernanceAgentRun",
    "GovernanceAgentStore",
    "GovernanceAgentTenantSnapshot",
    "GovernanceAgentValidationError",
    "GovernanceAnalysisAdapter",
    "GovernanceExecutionReceiptVerifier",
    "GovernanceContextItem",
    "GovernanceContextRecord",
    "build_adapter_authority",
    "build_dispatcher_authority",
    "build_execution_outcome",
    "build_finding",
    "enabled",
    "execution_receipt_signing_payload",
    "load_governance_agent_tenant_snapshot",
    "require_enabled",
]
