"""Governed promotion of immutable research candidates.

Research completion and production activation are deliberately separate.  A
completed run may be useful evidence even when its result is negative, and a
successful evaluator score is never deployment authority.  This module binds
the exact run, artifacts, lineage, target, policy, resources, and independent
human decision into a durable state machine before a deployment adapter is
allowed to stage or activate anything.

The candidate process never receives a signing key or an authority object.
Every privileged transition resolves current server-owned authority again and
every effect rechecks the current run/rights and artifact observations while
holding the installation authority/effect fence.  Adapter failures after a
durable claim become ``uncertain`` and require reconciliation; they are never
silently retried.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import asdict, dataclass
from typing import Protocol

from .governed_records import GovernedRecordStore
from .paths import canonical_tenant_id, tenant_scope
from .privacy_ops import RecordConflict

CANDIDATE_SCHEMA = "lightwork.candidate-manifest.v1"
PROMOTION_SCHEMA = "lightwork.candidate-promotion.v1"
STUDY_CLAIM_SCHEMA = "lightwork.research-study-claim.v1"
AUTHORITY_SCHEMA = "lightwork.candidate-promotion-authority.v1"
POLICY_SCHEMA = "lightwork.candidate-promotion-policy.v1"
OBSERVATION_SCHEMA = "lightwork.deployment-observation.v1"
RECEIPT_SCHEMA = "lightwork.deployment-effect-receipt.v1"
CANARY_SCHEMA = "lightwork.deployment-canary-observation.v1"
RECONCILIATION_SCHEMA = "lightwork.deployment-reconciliation.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PURPOSE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_SCHEMA = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_SOURCE = re.compile(r"(?:artifact|catalog):[A-Za-z0-9][A-Za-z0-9_.:/-]{0,2000}\Z")
_KINDS = frozenset({"bundle", "code", "component", "weights"})
_CONCLUSIONS = frozenset({"qualified", "negative", "inconclusive"})
_ACTIONS = frozenset({"review", "stage", "activate", "canary", "rollback", "reconcile"})
_STATES = frozenset({
    "awaiting_review", "not_advancing", "denied", "blocked", "authorized",
    "stage_claimed", "staged", "activation_claimed", "canary", "active",
    "rollback_claimed", "rolled_back", "uncertain",
})
_MAX_RECORDS = 10_000
_MAX_LIST = 256


class CandidatePromotionError(RuntimeError):
    """Base class for controlled candidate-promotion failures."""


class CandidatePromotionConflict(CandidatePromotionError):
    """Persisted material, state, or an optimistic revision changed."""


class CandidatePromotionDenied(CandidatePromotionError, PermissionError):
    """Current rights, policy, or named authority denies the operation."""


class CandidatePromotionNotFound(CandidatePromotionError, LookupError):
    """The requested tenant-scoped candidate does not exist."""


class CandidatePromotionUnavailable(CandidatePromotionError):
    """A required trusted resolver or deployment adapter is unavailable."""


class CandidatePromotionInterrupted(CandidatePromotionError):
    """An effect was claimed but its outcome cannot be established."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("promotion material is not canonical JSON") from exc


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    result = " ".join(value.split())
    if not result or len(result) > maximum:
        raise ValueError(f"{label} is required and must be at most {maximum} characters")
    return result


def _identifier(value: object, label: str) -> str:
    result = _text(value, label, 128)
    if _ID.fullmatch(result) is None:
        raise ValueError(f"{label} is invalid")
    return result


def _purpose(value: object, label: str) -> str:
    result = _text(value, label, 64)
    if _PURPOSE.fullmatch(result) is None:
        raise ValueError(f"{label} is invalid")
    return result


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} must be a positive finite timestamp")
    return float(value)


def _schema(value: object, label: str) -> str:
    result = _text(value, label, 256)
    if _SCHEMA.fullmatch(result) is None:
        raise ValueError(f"{label} is invalid")
    return result


def _principal(value: object, label: str, *, named_user: bool = False) -> str:
    result = _text(value, label, 512)
    if named_user and not result.startswith("user:"):
        raise ValueError(f"{label} must be a named user")
    return result


@dataclass(frozen=True)
class ArtifactCommitment:
    artifact_id: str
    kind: str
    source_ref: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _identifier(self.artifact_id, "artifact_id")
        if self.kind not in _KINDS:
            raise ValueError("candidate artifact kind is unsupported")
        if not isinstance(self.source_ref, str) or _SOURCE.fullmatch(self.source_ref) is None:
            raise ValueError("candidate artifact needs a safe catalog or artifact reference")
        _sha(self.sha256, "artifact sha256")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or not 0 < self.size_bytes <= 2**50
        ):
            raise ValueError("candidate artifact size is outside its bounded range")


@dataclass(frozen=True)
class ArtifactObservation:
    tenant: str
    source_ref: str
    sha256: str
    size_bytes: int
    authority_sha256: str

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        if not isinstance(self.source_ref, str) or _SOURCE.fullmatch(self.source_ref) is None:
            raise ValueError("artifact observation source is invalid")
        _sha(self.sha256, "artifact observation sha256")
        _sha(self.authority_sha256, "artifact observation authority_sha256")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or not 0 < self.size_bytes <= 2**50
        ):
            raise ValueError("artifact observation size is outside its bounded range")


@dataclass(frozen=True)
class LineageCommitment:
    kind: str
    asset_id: str
    version: str
    manifest_sha256: str
    required_action_if_revoked: str

    def __post_init__(self) -> None:
        if self.kind not in {"dataset", "model"}:
            raise ValueError("candidate lineage kind is unsupported")
        _identifier(self.asset_id, "lineage asset_id")
        _identifier(self.version, "lineage version")
        _sha(self.manifest_sha256, "lineage manifest_sha256")
        _purpose(self.required_action_if_revoked, "lineage required action")


@dataclass(frozen=True)
class StudyClaim:
    report_sha256: str
    conclusion: str
    conclusion_evidence_sha256: str
    evaluator_id: str
    evaluator_version: str
    metric_protocol_sha256: str
    schema: str = STUDY_CLAIM_SCHEMA

    def __post_init__(self) -> None:
        _sha(self.report_sha256, "study report_sha256")
        if self.conclusion not in _CONCLUSIONS:
            raise ValueError("study conclusion is unsupported")
        _sha(self.conclusion_evidence_sha256, "study conclusion_evidence_sha256")
        _identifier(self.evaluator_id, "study evaluator_id")
        _identifier(self.evaluator_version, "study evaluator_version")
        _sha(self.metric_protocol_sha256, "study metric_protocol_sha256")
        if self.schema != STUDY_CLAIM_SCHEMA:
            raise ValueError("study claim schema is unsupported")


@dataclass(frozen=True)
class TrustedStudyAdmission:
    """Server-owned evaluator evidence bound to one exact completed run."""

    tenant: str
    run_id: str
    run_manifest_sha256: str
    result_sha256: str
    output_artifact_sha256: str
    study: StudyClaim
    artifacts: tuple[ArtifactCommitment, ...]
    authority_sha256: str

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.run_id, "study admission run_id")
        _sha(self.run_manifest_sha256, "study admission run manifest_sha256")
        _sha(self.result_sha256, "study admission result_sha256")
        _sha(self.output_artifact_sha256, "study admission output_artifact_sha256")
        _sha(self.authority_sha256, "study admission authority_sha256")
        if type(self.study) is not StudyClaim:
            raise ValueError("trusted study admission requires an exact study claim")
        if type(self.artifacts) is not tuple or not 1 <= len(self.artifacts) <= 64:
            raise ValueError("trusted study admission requires one to 64 artifacts")
        if any(type(item) is not ArtifactCommitment for item in self.artifacts):
            raise ValueError("trusted study admission artifacts are malformed")
        keys = [(item.kind, item.artifact_id) for item in self.artifacts]
        if keys != sorted(set(keys)):
            raise ValueError("trusted study admission artifacts must be unique and sorted")
        if not any(
            hmac.compare_digest(item.sha256, self.output_artifact_sha256)
            for item in self.artifacts
        ):
            raise ValueError("trusted study artifacts do not include the completed run output")


@dataclass(frozen=True)
class RunPromotionAdmission:
    """Current trusted projection of one completed research run and study."""

    tenant: str
    principal: str
    candidate_principal: str
    run_id: str
    run_manifest_sha256: str
    registry_binding_sha256: str
    result_sha256: str
    output_artifact_sha256: str
    lineage: tuple[LineageCommitment, ...]
    authority_sha256: str
    study_admission: TrustedStudyAdmission

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _principal(self.principal, "run principal")
        _principal(self.candidate_principal, "candidate principal")
        _identifier(self.run_id, "run_id")
        _sha(self.run_manifest_sha256, "run manifest_sha256")
        _sha(self.registry_binding_sha256, "registry binding_sha256")
        _sha(self.result_sha256, "run result_sha256")
        _sha(self.output_artifact_sha256, "run output_artifact_sha256")
        _sha(self.authority_sha256, "run authority_sha256")
        if not self.lineage or len(self.lineage) > 128:
            raise ValueError("run promotion lineage must contain one to 128 assets")
        keys = [(item.kind, item.asset_id, item.version) for item in self.lineage]
        if any(type(item) is not LineageCommitment for item in self.lineage):
            raise ValueError("run promotion lineage is malformed")
        if keys != sorted(set(keys)):
            raise ValueError("run promotion lineage must be unique and sorted")
        admission = self.study_admission
        if (
            type(admission) is not TrustedStudyAdmission
            or admission.tenant != self.tenant
            or admission.run_id != self.run_id
            or not hmac.compare_digest(
                admission.run_manifest_sha256, self.run_manifest_sha256
            )
            or not hmac.compare_digest(admission.result_sha256, self.result_sha256)
            or not hmac.compare_digest(
                admission.output_artifact_sha256, self.output_artifact_sha256
            )
        ):
            raise ValueError("trusted study admission is not bound to this completed run")


@dataclass(frozen=True)
class PromotionTarget:
    target_id: str
    expected_active_sha256: str
    state_schema: str
    queued_intent_schema: str
    external_reconciliation_schema: str

    def __post_init__(self) -> None:
        _identifier(self.target_id, "promotion target_id")
        _sha(self.expected_active_sha256, "expected active artifact sha256")
        _schema(self.state_schema, "target state_schema")
        _schema(self.queued_intent_schema, "target queued_intent_schema")
        _schema(self.external_reconciliation_schema, "target reconciliation_schema")


@dataclass(frozen=True)
class ResourceRequirements:
    max_memory_bytes: int
    max_storage_bytes: int
    max_cpu_cores: float
    required_providers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value, label, maximum in (
            (self.max_memory_bytes, "max_memory_bytes", 2**50),
            (self.max_storage_bytes, "max_storage_bytes", 2**60),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError(f"{label} is outside its bounded range")
        if (
            isinstance(self.max_cpu_cores, bool)
            or not isinstance(self.max_cpu_cores, int | float)
            or not math.isfinite(float(self.max_cpu_cores))
            or not 0 <= float(self.max_cpu_cores) <= 4096
        ):
            raise ValueError("max_cpu_cores is outside its bounded range")
        providers = tuple(_identifier(value, "required provider") for value in self.required_providers)
        if len(providers) > 64 or providers != tuple(sorted(set(providers))):
            raise ValueError("required providers must be unique and sorted")


@dataclass(frozen=True)
class PromotionTargetPreset:
    """Deployment-owned target and resource envelope selected by safe name."""

    preset_id: str
    target: PromotionTarget
    resources: ResourceRequirements
    authority_sha256: str

    def __post_init__(self) -> None:
        preset = _identifier(self.preset_id, "promotion target preset")
        if (
            type(self.target) is not PromotionTarget
            or type(self.resources) is not ResourceRequirements
        ):
            raise ValueError("promotion target preset is malformed")
        if preset != self.target.target_id:
            raise ValueError("promotion target preset must name its exact deployment target")
        _sha(self.authority_sha256, "promotion target preset authority_sha256")


@dataclass(frozen=True)
class CanaryInvariant:
    metric: str
    comparison: str
    threshold: float

    def __post_init__(self) -> None:
        _purpose(self.metric, "canary metric")
        if self.comparison not in {"at_least", "at_most"}:
            raise ValueError("canary comparison must be at_least or at_most")
        if (
            isinstance(self.threshold, bool)
            or not isinstance(self.threshold, int | float)
            or not math.isfinite(float(self.threshold))
        ):
            raise ValueError("canary threshold must be finite")


@dataclass(frozen=True)
class PromotionPolicy:
    policy_id: str
    version: str
    allowed_targets: tuple[str, ...]
    role_actions: tuple[tuple[str, tuple[str, ...]], ...]
    canary_invariants: tuple[CanaryInvariant, ...]
    review_ttl_seconds: int = 3600
    schema: str = POLICY_SCHEMA

    def __post_init__(self) -> None:
        _identifier(self.policy_id, "promotion policy_id")
        _identifier(self.version, "promotion policy version")
        targets = tuple(_identifier(value, "allowed promotion target") for value in self.allowed_targets)
        if not targets or len(targets) > 64 or targets != tuple(sorted(set(targets))):
            raise ValueError("allowed promotion targets must be unique and sorted")
        if not self.role_actions or len(self.role_actions) > 32:
            raise ValueError("promotion policy requires role actions")
        roles: list[str] = []
        for role, actions in self.role_actions:
            roles.append(_identifier(role, "promotion role"))
            if (
                not actions
                or len(actions) > len(_ACTIONS)
                or any(action not in _ACTIONS for action in actions)
                or tuple(actions) != tuple(sorted(set(actions)))
            ):
                raise ValueError("promotion role actions are invalid")
        if roles != sorted(set(roles)):
            raise ValueError("promotion roles must be unique and sorted")
        metrics = [item.metric for item in self.canary_invariants]
        if (
            not self.canary_invariants
            or len(metrics) > 64
            or any(type(item) is not CanaryInvariant for item in self.canary_invariants)
            or metrics != sorted(set(metrics))
        ):
            raise ValueError("canary invariants must be unique and sorted")
        if (
            isinstance(self.review_ttl_seconds, bool)
            or not isinstance(self.review_ttl_seconds, int)
            or not 60 <= self.review_ttl_seconds <= 7 * 24 * 3600
        ):
            raise ValueError("promotion review ttl is outside its bounded range")
        if self.schema != POLICY_SCHEMA:
            raise ValueError("promotion policy schema is unsupported")

    @property
    def sha256(self) -> str:
        return _digest(asdict(self))

    def permits(self, role: str, action: str) -> bool:
        return action in dict(self.role_actions).get(role, ())


@dataclass(frozen=True)
class PromotionAuthority:
    tenant: str
    principal: str
    role: str
    actions: tuple[str, ...]
    authorization_sha256: str
    valid_until: float
    schema: str = AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _principal(self.principal, "promotion principal", named_user=True)
        _identifier(self.role, "promotion role")
        if (
            not self.actions
            or len(self.actions) > len(_ACTIONS)
            or any(action not in _ACTIONS for action in self.actions)
            or self.actions != tuple(sorted(set(self.actions)))
        ):
            raise ValueError("promotion authority actions are invalid")
        _sha(self.authorization_sha256, "promotion authorization_sha256")
        _timestamp(self.valid_until, "promotion authority valid_until")
        if self.schema != AUTHORITY_SCHEMA:
            raise ValueError("promotion authority schema is unsupported")


@dataclass(frozen=True)
class DeploymentObservation:
    tenant: str
    target_id: str
    active_artifact_sha256: str
    state_schema: str
    queued_intent_schema: str
    external_state_sha256: str
    pending_intents_sha256: str
    rollback_handle: str
    rollback_compatible: bool
    evidence_sha256: str
    schema: str = OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.target_id, "deployment target_id")
        for value, label in (
            (self.active_artifact_sha256, "active artifact sha256"),
            (self.external_state_sha256, "external state sha256"),
            (self.pending_intents_sha256, "pending intents sha256"),
            (self.evidence_sha256, "deployment evidence sha256"),
        ):
            _sha(value, label)
        _schema(self.state_schema, "deployment state_schema")
        _schema(self.queued_intent_schema, "deployment queued_intent_schema")
        _text(self.rollback_handle, "rollback handle", 1024)
        if type(self.rollback_compatible) is not bool:
            raise ValueError("rollback compatibility must be boolean")
        if self.schema != OBSERVATION_SCHEMA:
            raise ValueError("deployment observation schema is unsupported")


@dataclass(frozen=True)
class DeploymentEffectReceipt:
    tenant: str
    target_id: str
    operation_id: str
    action: str
    before_sha256: str
    after_sha256: str
    evidence_sha256: str
    schema: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.target_id, "effect target_id")
        _identifier(self.operation_id, "effect operation_id")
        if self.action not in {"stage", "activate", "rollback"}:
            raise ValueError("deployment effect action is unsupported")
        _sha(self.before_sha256, "effect before_sha256")
        _sha(self.after_sha256, "effect after_sha256")
        _sha(self.evidence_sha256, "effect evidence_sha256")
        if self.schema != RECEIPT_SCHEMA:
            raise ValueError("deployment effect receipt schema is unsupported")


@dataclass(frozen=True)
class CanaryObservation:
    tenant: str
    target_id: str
    active_artifact_sha256: str
    metrics: tuple[tuple[str, float], ...]
    evidence_sha256: str
    schema: str = CANARY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.target_id, "canary target_id")
        _sha(self.active_artifact_sha256, "canary active artifact sha256")
        names: list[str] = []
        for name, value in self.metrics:
            names.append(_purpose(name, "canary metric"))
            if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(float(value)):
                raise ValueError("canary metric value must be finite")
        if names != sorted(set(names)):
            raise ValueError("canary metrics must be unique and sorted")
        _sha(self.evidence_sha256, "canary evidence_sha256")
        if self.schema != CANARY_SCHEMA:
            raise ValueError("canary observation schema is unsupported")


@dataclass(frozen=True)
class DeploymentReconciliation:
    tenant: str
    target_id: str
    active_artifact_sha256: str
    state_schema: str
    queued_intent_schema: str
    state_restored: bool
    pending_intents_reconciled: bool
    external_state_reconciled: bool
    evidence_sha256: str
    schema: str = RECONCILIATION_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.target_id, "reconciliation target_id")
        _sha(self.active_artifact_sha256, "reconciliation active artifact sha256")
        _schema(self.state_schema, "reconciliation state_schema")
        _schema(self.queued_intent_schema, "reconciliation queued_intent_schema")
        if any(type(value) is not bool for value in (
            self.state_restored,
            self.pending_intents_reconciled,
            self.external_state_reconciled,
        )):
            raise ValueError("reconciliation results must be booleans")
        _sha(self.evidence_sha256, "reconciliation evidence_sha256")
        if self.schema != RECONCILIATION_SCHEMA:
            raise ValueError("deployment reconciliation schema is unsupported")


class CandidateDeploymentAdapter(Protocol):
    def observe(self, tenant: str, target_id: str) -> DeploymentObservation: ...
    def stage(self, manifest: Mapping[str, object]) -> DeploymentEffectReceipt: ...
    def activate(
        self, manifest: Mapping[str, object], stage_receipt: Mapping[str, object]
    ) -> DeploymentEffectReceipt: ...
    def canary(self, manifest: Mapping[str, object]) -> CanaryObservation: ...
    def rollback(
        self, manifest: Mapping[str, object], rollback_handle: str
    ) -> DeploymentEffectReceipt: ...
    def reconcile(self, manifest: Mapping[str, object]) -> DeploymentReconciliation: ...


def _event(events: Sequence[Mapping[str, object]], *, state: str, actor: str,
           at: float, details: Mapping[str, object]) -> dict:
    material = {
        "sequence": len(events) + 1,
        "state": state,
        "actor": actor,
        "at": at,
        "details": dict(details),
        "previous_event_sha256": (
            None if not events else str(events[-1].get("event_sha256") or "")
        ),
    }
    return {**material, "event_sha256": _digest(material)}


def _validate_events(value: object, state: str) -> list[dict]:
    if not isinstance(value, list) or not value or len(value) > 128:
        raise CandidatePromotionConflict("candidate history is malformed")
    previous = None
    for index, raw in enumerate(value, start=1):
        if not isinstance(raw, dict):
            raise CandidatePromotionConflict("candidate history is malformed")
        actual = raw.get("event_sha256")
        material = {key: item for key, item in raw.items() if key != "event_sha256"}
        if (
            raw.get("sequence") != index
            or raw.get("previous_event_sha256") != previous
            or not isinstance(actual, str)
            or _SHA.fullmatch(actual) is None
            or not hmac.compare_digest(actual, _digest(material))
        ):
            raise CandidatePromotionConflict("candidate history chain is broken")
        previous = actual
    if value[-1].get("state") != state:
        raise CandidatePromotionConflict("candidate history does not match current state")
    return value


class CandidatePromotions:
    """Tenant-scoped, independently authorized candidate-promotion service."""

    def __init__(
        self,
        *,
        run_admission_resolver: Callable[[str, str, str], RunPromotionAdmission],
        artifact_resolver: Callable[[str, str], ArtifactObservation],
        target_preset_resolver: Callable[[str, str], PromotionTargetPreset],
        completed_runs_resolver: Callable[[str, str], Sequence[str]],
        authority_resolver: Callable[[str, str], PromotionAuthority],
        policy_resolver: Callable[[], PromotionPolicy],
        deployment_adapter: CandidateDeploymentAdapter | None = None,
        record_store: GovernedRecordStore | None = None,
        effect_fence: Callable[[], AbstractContextManager[object]] | None = None,
    ) -> None:
        from .authority_effects import authority_effect_fence

        self.run_admission_resolver = run_admission_resolver
        self.artifact_resolver = artifact_resolver
        self.target_preset_resolver = target_preset_resolver
        self.completed_runs_resolver = completed_runs_resolver
        self.authority_resolver = authority_resolver
        self.policy_resolver = policy_resolver
        self.deployment_adapter = deployment_adapter
        self.store = record_store or GovernedRecordStore(
            "candidate-promotions", "candidate", "candidate-promotion"
        )
        self.effect_fence = effect_fence or authority_effect_fence

    @staticmethod
    def _record_id(tenant: str, candidate_id: str) -> str:
        material = f"{canonical_tenant_id(tenant)}\0{candidate_id}".encode()
        return f"candidate-{hashlib.sha256(material).hexdigest()[:48]}"

    def _policy(self) -> PromotionPolicy:
        try:
            policy = self.policy_resolver()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise CandidatePromotionUnavailable("promotion policy is unavailable") from exc
        if type(policy) is not PromotionPolicy:
            raise CandidatePromotionUnavailable("promotion policy is unavailable")
        return policy

    def _authority(self, tenant: str, principal: str, action: str,
                   policy: PromotionPolicy, now: float) -> PromotionAuthority:
        actor = _principal(principal, "promotion actor", named_user=True)
        try:
            authority = self.authority_resolver(tenant, actor)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise CandidatePromotionDenied("current promotion authority is unavailable") from exc
        if (
            type(authority) is not PromotionAuthority
            or authority.tenant != tenant
            or authority.principal != actor
            or action not in authority.actions
            or not policy.permits(authority.role, action)
            or authority.valid_until <= now
        ):
            raise CandidatePromotionDenied("current promotion authority denies this action")
        return authority

    def _run(self, tenant: str, principal: str, run_id: str) -> RunPromotionAdmission:
        try:
            admission = self.run_admission_resolver(tenant, principal, run_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise CandidatePromotionDenied("current research rights deny promotion") from exc
        if (
            type(admission) is not RunPromotionAdmission
            or admission.tenant != tenant
            or admission.principal != principal
            or admission.run_id != run_id
        ):
            raise CandidatePromotionDenied("current research rights deny promotion")
        return admission

    def _preset(self, tenant: str, preset_id: str) -> PromotionTargetPreset:
        exact_id = _identifier(preset_id, "promotion target preset")
        try:
            preset = self.target_preset_resolver(tenant, exact_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise CandidatePromotionUnavailable(
                "the selected deployment target preset is unavailable"
            ) from exc
        if (
            type(preset) is not PromotionTargetPreset
            or preset.preset_id != exact_id
            or preset.target.target_id != exact_id
        ):
            raise CandidatePromotionUnavailable(
                "the selected deployment target preset is unavailable"
            )
        return preset

    def proposal_options(self, tenant: str, principal: str) -> dict:
        """List safe names only; evaluator and deployment claims stay server-owned."""

        canonical = canonical_tenant_id(tenant)
        actor = _principal(principal, "promotion principal", named_user=True)
        with tenant_scope(tenant=canonical):
            policy = self._policy()
            try:
                values = self.completed_runs_resolver(canonical, actor)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise CandidatePromotionUnavailable(
                    "completed research runs are unavailable"
                ) from exc
            if isinstance(values, str | bytes) or not isinstance(values, Sequence):
                raise CandidatePromotionUnavailable("completed research runs are unavailable")
            run_ids = tuple(_identifier(value, "completed run_id") for value in values)
            if len(run_ids) > _MAX_LIST or run_ids != tuple(sorted(set(run_ids))):
                raise CandidatePromotionUnavailable("completed research runs are unavailable")
            presets = []
            for preset_id in policy.allowed_targets:
                preset = self._preset(canonical, preset_id)
                presets.append(
                    {"preset_id": preset.preset_id, "target_id": preset.target.target_id}
                )
            return {"completed_runs": list(run_ids), "target_presets": presets}

    def _observe_artifacts(
        self, tenant: str, artifacts: Sequence[ArtifactCommitment]
    ) -> tuple[ArtifactObservation, ...]:
        observations: list[ArtifactObservation] = []
        for artifact in artifacts:
            try:
                observed = self.artifact_resolver(tenant, artifact.source_ref)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise CandidatePromotionUnavailable(
                    f"candidate artifact {artifact.artifact_id} is unavailable"
                ) from exc
            if (
                type(observed) is not ArtifactObservation
                or observed.tenant != tenant
                or observed.source_ref != artifact.source_ref
            ):
                raise CandidatePromotionUnavailable(
                    f"candidate artifact {artifact.artifact_id} is unavailable"
                )
            if (
                not hmac.compare_digest(observed.sha256, artifact.sha256)
                or observed.size_bytes != artifact.size_bytes
            ):
                raise CandidatePromotionConflict(
                    f"candidate artifact {artifact.artifact_id} changed after evaluation"
                )
            observations.append(observed)
        return tuple(observations)

    @staticmethod
    def _view(record: Mapping[str, object]) -> dict:
        return {
            key: record.get(key)
            for key in (
                "schema", "candidate_id", "requested_by", "candidate_principal",
                "manifest", "manifest_sha256", "policy_sha256", "state", "review",
                "deployment", "block", "revision", "created_at", "updated_at", "events",
            )
        }

    def _record(self, tenant: str, candidate_id: str) -> dict:
        exact_id = _identifier(candidate_id, "candidate_id")
        record = self.store.get(self._record_id(tenant, exact_id))
        if record is None or record.get("tenant") != tenant or record.get("candidate_id") != exact_id:
            raise CandidatePromotionNotFound("candidate was not found in this workspace")
        if record.get("schema") != PROMOTION_SCHEMA or record.get("state") not in _STATES:
            raise CandidatePromotionConflict("candidate promotion record is malformed")
        manifest = record.get("manifest")
        digest = record.get("manifest_sha256")
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") != CANDIDATE_SCHEMA
            or not isinstance(digest, str)
            or _SHA.fullmatch(digest) is None
            or not hmac.compare_digest(digest, _digest(manifest))
        ):
            raise CandidatePromotionConflict("candidate manifest integrity check failed")
        _validate_events(record.get("events"), str(record["state"]))
        review = record.get("review")
        if review is not None:
            if not isinstance(review, dict):
                raise CandidatePromotionConflict("candidate review is malformed")
            expected = review.get("decision_sha256")
            actual = _digest({key: value for key, value in review.items() if key != "decision_sha256"})
            if not isinstance(expected, str) or not hmac.compare_digest(expected, actual):
                raise CandidatePromotionConflict("candidate review integrity check failed")
        return record

    @staticmethod
    def _artifacts(values: Sequence[ArtifactCommitment]) -> tuple[ArtifactCommitment, ...]:
        if isinstance(values, str | bytes) or not isinstance(values, Sequence):
            raise ValueError("candidate artifacts must be a bounded list")
        artifacts = tuple(values)
        if not 1 <= len(artifacts) <= 64 or any(type(item) is not ArtifactCommitment for item in artifacts):
            raise ValueError("candidate artifacts must contain one to 64 exact commitments")
        keys = [(item.kind, item.artifact_id) for item in artifacts]
        if keys != sorted(set(keys)):
            raise ValueError("candidate artifacts must be unique and sorted")
        return artifacts

    def request(
        self,
        tenant: str,
        principal: str,
        *,
        candidate_id: str,
        run_id: str,
        target_preset: str,
    ) -> dict:
        canonical = canonical_tenant_id(tenant)
        actor = _principal(principal, "candidate requester", named_user=True)
        exact_id = _identifier(candidate_id, "candidate_id")
        exact_run_id = _identifier(run_id, "run_id")
        exact_preset_id = _identifier(target_preset, "promotion target preset")
        with tenant_scope(tenant=canonical), self.effect_fence():
            policy = self._policy()
            run = self._run(canonical, actor, exact_run_id)
            worker = run.candidate_principal
            study_admission = run.study_admission
            study = study_admission.study
            exact_artifacts = self._artifacts(study_admission.artifacts)
            preset = self._preset(canonical, exact_preset_id)
            target = preset.target
            resources = preset.resources
            if target.target_id not in policy.allowed_targets:
                raise CandidatePromotionDenied("promotion policy does not permit this target")
            request_material = {
                "candidate_id": exact_id,
                "candidate_principal": worker,
                "run_id": exact_run_id,
                "run_admission_sha256": _digest(asdict(run)),
                "target_preset": exact_preset_id,
                "target_preset_sha256": _digest(asdict(preset)),
            }
            request_sha256 = _digest(request_material)
            prior = self.store.get(self._record_id(canonical, exact_id))
            if prior is not None:
                record = self._record(canonical, exact_id)
                if (
                    record.get("requested_by") == actor
                    and record.get("request_sha256") == request_sha256
                ):
                    return self._view(record)
                raise CandidatePromotionConflict("candidate id already has different material")
            observations = self._observe_artifacts(canonical, exact_artifacts)
            if not any(hmac.compare_digest(item.sha256, run.output_artifact_sha256) for item in exact_artifacts):
                raise CandidatePromotionConflict("candidate artifacts do not include the evaluated run output")
            now = self.store.authoritative_time()
            manifest = {
                "schema": CANDIDATE_SCHEMA,
                "candidate_id": exact_id,
                "candidate_principal": worker,
                "run": asdict(run),
                "study": asdict(study),
                "artifacts": [asdict(item) for item in exact_artifacts],
                "artifact_authorities": [item.authority_sha256 for item in observations],
                "target_preset": asdict(preset),
                "target": asdict(target),
                "resources": asdict(resources),
                "requested_at": now,
            }
            state = "awaiting_review" if study.conclusion == "qualified" else "not_advancing"
            details = {
                "conclusion": study.conclusion,
                "advancement_allowed": state == "awaiting_review",
            }
            record = {
                "id": self._record_id(canonical, exact_id),
                "schema": PROMOTION_SCHEMA,
                "tenant": canonical,
                "candidate_id": exact_id,
                "requested_by": actor,
                "candidate_principal": worker,
                "request_sha256": request_sha256,
                "manifest": manifest,
                "manifest_sha256": _digest(manifest),
                "policy_sha256": policy.sha256,
                "state": state,
                "review": None,
                "deployment": None,
                "block": (
                    None
                    if state == "awaiting_review"
                    else {
                        "reason_code": f"study_{study.conclusion}",
                        "detail": "The study remains complete, but this result cannot advance to production.",
                        "remediation": [],
                    }
                ),
                "events": [_event([], state=state, actor=actor, at=now, details=details)],
            }
            try:
                saved = self.store.create(
                    record,
                    actor=actor,
                    action="candidate.promotion.request",
                    max_records=_MAX_RECORDS,
                )
            except RecordConflict as exc:
                raise CandidatePromotionConflict("candidate changed during request") from exc
            return self._view(saved)

    def _lineage_remediation(self, record: Mapping[str, object]) -> list[dict]:
        run = record["manifest"]["run"]  # validated manifest shape at creation
        result = []
        for item in run.get("lineage", ()):  # type: ignore[union-attr]
            result.append({
                "kind": item["kind"],
                "asset_id": item["asset_id"],
                "version": item["version"],
                "manifest_sha256": item["manifest_sha256"],
                "required_action": item["required_action_if_revoked"],
            })
        return result

    def _update_state(
        self,
        record: Mapping[str, object],
        *,
        state: str,
        actor: str,
        action: str,
        details: Mapping[str, object],
        mutate: Callable[[dict], None] | None = None,
    ) -> dict:
        now = self.store.authoritative_time()

        def apply(value: dict) -> None:
            if mutate is not None:
                mutate(value)
            value["state"] = state
            value["events"].append(
                _event(value["events"], state=state, actor=actor, at=now, details=details)
            )

        try:
            saved = self.store.update(
                str(record["id"]),
                apply,
                expected_revision=int(record["revision"]),
                actor=actor,
                action=action,
            )
        except RecordConflict as exc:
            raise CandidatePromotionConflict("candidate revision changed") from exc
        if saved is None:
            raise CandidatePromotionNotFound("candidate disappeared during transition")
        return saved

    def _block(self, record: Mapping[str, object], *, actor: str,
               reason_code: str, detail: str) -> dict:
        remediation = self._lineage_remediation(record)

        def mutate(value: dict) -> None:
            value["block"] = {
                "reason_code": _purpose(reason_code, "block reason_code"),
                "detail": _text(detail, "block detail", 1000),
                "remediation": remediation,
            }

        return self._update_state(
            record,
            state="blocked",
            actor=actor,
            action="candidate.promotion.block",
            details={"reason_code": reason_code, "lineage_count": len(remediation)},
            mutate=mutate,
        )

    def _revalidate(self, record: Mapping[str, object], policy: PromotionPolicy) -> None:
        if not hmac.compare_digest(str(record.get("policy_sha256") or ""), policy.sha256):
            raise CandidatePromotionConflict("promotion policy changed; request a fresh review")
        manifest = record["manifest"]
        stored_run = manifest["run"]  # type: ignore[index]
        current = self._run(
            str(record["tenant"]),
            str(record["requested_by"]),
            str(record["manifest"]["run"]["run_id"]),  # type: ignore[index]
        )
        if not hmac.compare_digest(_digest(asdict(current)), _digest(stored_run)):
            raise CandidatePromotionDenied("current research rights or run evidence changed")
        stored_preset = manifest.get("target_preset")  # type: ignore[union-attr]
        if not isinstance(stored_preset, Mapping):
            raise CandidatePromotionConflict("candidate target preset is malformed")
        current_preset = self._preset(
            str(record["tenant"]), str(stored_preset.get("preset_id") or "")
        )
        if not hmac.compare_digest(
            _digest(asdict(current_preset)), _digest(stored_preset)
        ):
            raise CandidatePromotionConflict(
                "deployment target preset changed; request a fresh review"
            )
        artifacts = tuple(ArtifactCommitment(**item) for item in manifest["artifacts"])  # type: ignore[index]
        observations = self._observe_artifacts(str(record["tenant"]), artifacts)
        stored_authorities = tuple(manifest.get("artifact_authorities", ()))  # type: ignore[union-attr]
        if tuple(item.authority_sha256 for item in observations) != stored_authorities:
            raise CandidatePromotionConflict("candidate artifact authority changed; request a fresh review")

    def review(
        self,
        tenant: str,
        reviewer: str,
        candidate_id: str,
        *,
        expected_revision: int,
        approve: bool,
        reason_code: str,
        evidence_sha256: str,
        note: str = "",
    ) -> dict:
        canonical = canonical_tenant_id(tenant)
        actor = _principal(reviewer, "promotion reviewer", named_user=True)
        if type(approve) is not bool:
            raise ValueError("promotion review decision must be boolean")
        reason = _purpose(reason_code, "review reason_code")
        evidence = _sha(evidence_sha256, "review evidence_sha256")
        review_note = "" if note == "" else _text(note, "review note", 1024)
        with tenant_scope(tenant=canonical), self.effect_fence():
            record = self._record(canonical, candidate_id)
            if record["revision"] != expected_revision:
                raise CandidatePromotionConflict("candidate revision changed")
            if record["state"] != "awaiting_review":
                raise CandidatePromotionConflict("candidate is not awaiting review")
            policy = self._policy()
            now = self.store.authoritative_time()
            authority = self._authority(canonical, actor, "review", policy, now)
            if actor in {record["requested_by"], record["candidate_principal"]}:
                raise CandidatePromotionDenied("a candidate cannot approve its own promotion")
            try:
                self._revalidate(record, policy)
            except CandidatePromotionDenied:
                self._block(
                    record,
                    actor=actor,
                    reason_code="lineage_rights_changed",
                    detail="Current research rights or lineage no longer permits promotion.",
                )
                raise
            review = {
                "reviewed_by": actor,
                "role": authority.role,
                "authorization_sha256": authority.authorization_sha256,
                "manifest_sha256": record["manifest_sha256"],
                "policy_sha256": policy.sha256,
                "approved": approve,
                "reason_code": reason,
                "note": review_note,
                "evidence_sha256": evidence,
                "reviewed_at": now,
                "expires_at": min(authority.valid_until, now + policy.review_ttl_seconds),
            }
            review["decision_sha256"] = _digest(review)

            def mutate(value: dict) -> None:
                value["review"] = review
                value["block"] = None

            saved = self._update_state(
                record,
                state="authorized" if approve else "denied",
                actor=actor,
                action="candidate.promotion.review",
                details={"approved": approve, "decision_sha256": review["decision_sha256"]},
                mutate=mutate,
            )
            return self._view(saved)

    def _current_review(self, record: Mapping[str, object], policy: PromotionPolicy,
                        actor: str, action: str, now: float) -> PromotionAuthority:
        if actor in {record["requested_by"], record["candidate_principal"]}:
            raise CandidatePromotionDenied("a candidate cannot operate its own promotion")
        review = record.get("review")
        if (
            not isinstance(review, dict)
            or review.get("approved") is not True
            or review.get("manifest_sha256") != record.get("manifest_sha256")
            or review.get("policy_sha256") != policy.sha256
            or not isinstance(review.get("expires_at"), int | float)
            or float(review["expires_at"]) <= now
        ):
            raise CandidatePromotionDenied("promotion approval is missing, stale, or expired")
        reviewer = review.get("reviewed_by")
        if not isinstance(reviewer, str) or reviewer in {
            record["requested_by"], record["candidate_principal"],
        }:
            raise CandidatePromotionDenied("promotion approval is not independently authorized")
        reviewer_authority = self._authority(
            str(record["tenant"]), reviewer, "review", policy, now,
        )
        if (
            review.get("role") != reviewer_authority.role
            or review.get("authorization_sha256")
            != reviewer_authority.authorization_sha256
        ):
            raise CandidatePromotionDenied("promotion approval authority changed")
        return self._authority(str(record["tenant"]), actor, action, policy, now)

    def _post_deployment_authority(
        self,
        record: Mapping[str, object],
        policy: PromotionPolicy,
        actor: str,
        action: str,
        now: float,
    ) -> PromotionAuthority:
        """Authorize safety operations without depending on an expired review.

        Once an effect may have occurred, rollback and reconciliation must stay
        available to a currently authorized operator even when the original
        approval expires or policy/lineage changes.  Candidate and requester
        identities remain unable to operate their own deployment.
        """

        if actor in {record["requested_by"], record["candidate_principal"]}:
            raise CandidatePromotionDenied("a candidate cannot operate its own promotion")
        return self._authority(str(record["tenant"]), actor, action, policy, now)

    def _adapter(self) -> CandidateDeploymentAdapter:
        adapter = self.deployment_adapter
        required = ("observe", "stage", "activate", "canary", "rollback", "reconcile")
        if adapter is None or any(not callable(getattr(adapter, name, None)) for name in required):
            raise CandidatePromotionUnavailable("a trusted deployment adapter is unavailable")
        return adapter

    @staticmethod
    def _invoke_adapter(adapter, method, record, actor, *args):
        """Give an installed adapter the already-checked current named actor.

        Older deployment adapters retain their existing protocol. An adapter
        may recheck native operation rights inside this effect-scoped context;
        the candidate manifest and its immutable approval are never rewritten.
        """
        scope = getattr(adapter, "authority_scope", None)
        with scope(str(record["tenant"]), actor) if callable(scope) else nullcontext():
            return getattr(adapter, method)(record["manifest"], *args)

    @staticmethod
    def _target(record: Mapping[str, object]) -> PromotionTarget:
        return PromotionTarget(**record["manifest"]["target"])  # type: ignore[index]

    @staticmethod
    def _candidate_sha(record: Mapping[str, object]) -> str:
        return str(record["manifest"]["run"]["output_artifact_sha256"])  # type: ignore[index]

    def _validate_observation(self, record: Mapping[str, object], value: object) -> DeploymentObservation:
        target = self._target(record)
        if (
            type(value) is not DeploymentObservation
            or value.tenant != record["tenant"]
            or value.target_id != target.target_id
            or value.active_artifact_sha256 != target.expected_active_sha256
            or value.state_schema != target.state_schema
            or value.queued_intent_schema != target.queued_intent_schema
            or value.rollback_compatible is not True
        ):
            raise CandidatePromotionConflict(
                "deployment target or rollback compatibility changed before staging"
            )
        return value

    def _validate_receipt(self, record: Mapping[str, object], value: object, *,
                          action: str, before: str, after: str) -> DeploymentEffectReceipt:
        target = self._target(record)
        if (
            type(value) is not DeploymentEffectReceipt
            or value.tenant != record["tenant"]
            or value.target_id != target.target_id
            or value.action != action
            or value.before_sha256 != before
            or value.after_sha256 != after
        ):
            raise CandidatePromotionInterrupted("deployment returned an unbound effect receipt")
        return value

    def stage(self, tenant: str, operator: str, candidate_id: str, *, expected_revision: int) -> dict:
        canonical = canonical_tenant_id(tenant)
        actor = _principal(operator, "promotion operator", named_user=True)
        with tenant_scope(tenant=canonical), self.effect_fence():
            record = self._record(canonical, candidate_id)
            if record["revision"] != expected_revision or record["state"] != "authorized":
                raise CandidatePromotionConflict("candidate is not at the authorized revision")
            policy = self._policy()
            now = self.store.authoritative_time()
            authority = self._current_review(record, policy, actor, "stage", now)
            try:
                self._revalidate(record, policy)
            except CandidatePromotionDenied:
                self._block(
                    record,
                    actor=actor,
                    reason_code="lineage_rights_changed",
                    detail="Current research rights or lineage no longer permits staging.",
                )
                raise
            adapter = self._adapter()
            observation = self._validate_observation(
                record, adapter.observe(canonical, self._target(record).target_id)
            )

            def claim(value: dict) -> None:
                value["deployment"] = {
                    "authority_sha256": authority.authorization_sha256,
                    "before": asdict(observation),
                    "stage_receipt": None,
                    "activation_receipt": None,
                    "canary": None,
                    "rollback_receipt": None,
                    "reconciliation": None,
                }

            claimed = self._update_state(
                record,
                state="stage_claimed",
                actor=actor,
                action="candidate.promotion.stage-claim",
                details={"before_evidence_sha256": observation.evidence_sha256},
                mutate=claim,
            )
            try:
                receipt = self._validate_receipt(
                    claimed,
                    self._invoke_adapter(adapter, "stage", claimed, actor),
                    action="stage",
                    before=observation.active_artifact_sha256,
                    after=self._candidate_sha(claimed),
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                uncertain = self._update_state(
                    claimed,
                    state="uncertain",
                    actor=actor,
                    action="candidate.promotion.stage-uncertain",
                    details={"reason_code": "stage_outcome_uncertain"},
                )
                raise CandidatePromotionInterrupted(
                    f"candidate staging outcome is uncertain at revision {uncertain['revision']}"
                ) from exc

            def complete(value: dict) -> None:
                value["deployment"]["stage_receipt"] = asdict(receipt)

            saved = self._update_state(
                claimed,
                state="staged",
                actor=actor,
                action="candidate.promotion.stage",
                details={"operation_id": receipt.operation_id},
                mutate=complete,
            )
            return self._view(saved)

    def activate(self, tenant: str, operator: str, candidate_id: str, *, expected_revision: int) -> dict:
        canonical = canonical_tenant_id(tenant)
        actor = _principal(operator, "promotion operator", named_user=True)
        with tenant_scope(tenant=canonical), self.effect_fence():
            record = self._record(canonical, candidate_id)
            if record["revision"] != expected_revision or record["state"] != "staged":
                raise CandidatePromotionConflict("candidate is not at the staged revision")
            policy = self._policy()
            now = self.store.authoritative_time()
            self._current_review(record, policy, actor, "activate", now)
            try:
                self._revalidate(record, policy)
            except CandidatePromotionDenied:
                self._block(
                    record,
                    actor=actor,
                    reason_code="lineage_rights_changed",
                    detail="Current research rights or lineage no longer permits activation.",
                )
                raise
            adapter = self._adapter()
            claimed = self._update_state(
                record,
                state="activation_claimed",
                actor=actor,
                action="candidate.promotion.activation-claim",
                details={"stage_operation_id": record["deployment"]["stage_receipt"]["operation_id"]},  # type: ignore[index]
            )
            before = self._target(record).expected_active_sha256
            after = self._candidate_sha(record)
            try:
                receipt = self._validate_receipt(
                    claimed,
                    self._invoke_adapter(adapter, "activate", claimed, actor, claimed["deployment"]["stage_receipt"]),
                    action="activate",
                    before=before,
                    after=after,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                uncertain = self._update_state(
                    claimed,
                    state="uncertain",
                    actor=actor,
                    action="candidate.promotion.activation-uncertain",
                    details={"reason_code": "activation_outcome_uncertain"},
                )
                raise CandidatePromotionInterrupted(
                    f"candidate activation outcome is uncertain at revision {uncertain['revision']}"
                ) from exc

            def complete(value: dict) -> None:
                value["deployment"]["activation_receipt"] = asdict(receipt)

            saved = self._update_state(
                claimed,
                state="canary",
                actor=actor,
                action="candidate.promotion.activate",
                details={"operation_id": receipt.operation_id},
                mutate=complete,
            )
            return self._view(saved)

    @staticmethod
    def _canary_failures(policy: PromotionPolicy, observation: CanaryObservation) -> list[dict]:
        metrics = dict(observation.metrics)
        failures = []
        for invariant in policy.canary_invariants:
            value = metrics.get(invariant.metric)
            passed = value is not None and (
                value >= invariant.threshold
                if invariant.comparison == "at_least"
                else value <= invariant.threshold
            )
            if not passed:
                failures.append({
                    "metric": invariant.metric,
                    "comparison": invariant.comparison,
                    "threshold": invariant.threshold,
                    "observed": value,
                })
        return failures

    def _rollback_from(self, record: Mapping[str, object], *, actor: str,
                       policy: PromotionPolicy, adapter: CandidateDeploymentAdapter,
                       reason_code: str) -> dict:
        deployment = record.get("deployment")
        if not isinstance(deployment, dict) or not isinstance(deployment.get("before"), dict):
            raise CandidatePromotionConflict("rollback snapshot is unavailable")
        before = DeploymentObservation(**deployment["before"])
        claimed = self._update_state(
            record,
            state="rollback_claimed",
            actor=actor,
            action="candidate.promotion.rollback-claim",
            details={"reason_code": reason_code, "rollback_evidence_sha256": before.evidence_sha256},
        )
        candidate_sha = self._candidate_sha(record)
        try:
            receipt = self._validate_receipt(
                claimed,
                self._invoke_adapter(adapter, "rollback", claimed, actor, before.rollback_handle),
                action="rollback",
                before=candidate_sha,
                after=before.active_artifact_sha256,
            )
            reconciliation = self._invoke_adapter(adapter, "reconcile", claimed, actor)
            target = self._target(record)
            if (
                type(reconciliation) is not DeploymentReconciliation
                or reconciliation.tenant != record["tenant"]
                or reconciliation.target_id != target.target_id
                or reconciliation.active_artifact_sha256 != before.active_artifact_sha256
                or reconciliation.state_schema != before.state_schema
                or reconciliation.queued_intent_schema != before.queued_intent_schema
                or reconciliation.state_restored is not True
                or reconciliation.pending_intents_reconciled is not True
                or reconciliation.external_state_reconciled is not True
            ):
                raise CandidatePromotionConflict(
                    "rollback did not restore compatible state and reconcile pending effects"
                )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            uncertain = self._update_state(
                claimed,
                state="uncertain",
                actor=actor,
                action="candidate.promotion.rollback-uncertain",
                details={"reason_code": "rollback_outcome_uncertain"},
            )
            raise CandidatePromotionInterrupted(
                f"candidate rollback outcome is uncertain at revision {uncertain['revision']}"
            ) from exc

        def complete(value: dict) -> None:
            value["deployment"]["rollback_receipt"] = asdict(receipt)
            value["deployment"]["reconciliation"] = asdict(reconciliation)

        return self._update_state(
            claimed,
            state="rolled_back",
            actor=actor,
            action="candidate.promotion.rollback",
            details={
                "operation_id": receipt.operation_id,
                "reconciliation_evidence_sha256": reconciliation.evidence_sha256,
            },
            mutate=complete,
        )

    def assess_canary(
        self, tenant: str, operator: str, candidate_id: str, *, expected_revision: int
    ) -> dict:
        canonical = canonical_tenant_id(tenant)
        actor = _principal(operator, "promotion operator", named_user=True)
        with tenant_scope(tenant=canonical), self.effect_fence():
            record = self._record(canonical, candidate_id)
            if record["revision"] != expected_revision or record["state"] != "canary":
                raise CandidatePromotionConflict("candidate is not at the canary revision")
            policy = self._policy()
            now = self.store.authoritative_time()
            self._post_deployment_authority(record, policy, actor, "canary", now)
            # Assessing a canary can synchronously trigger a production
            # rollback. Require that authority up front, while the shared
            # authority/effect fence is held, even when this observation later
            # passes and no rollback is needed.
            self._post_deployment_authority(record, policy, actor, "rollback", now)
            try:
                self._revalidate(record, policy)
            except (
                CandidatePromotionConflict,
                CandidatePromotionDenied,
                CandidatePromotionUnavailable,
            ):
                # Rights, policy, artifact authority, or availability drift
                # after activation is itself a failed invariant.  Production
                # does not keep serving while a blocked record waits for a new
                # review that can no longer authorize the deployed bytes.
                return self._view(self._rollback_from(
                    record,
                    actor=actor,
                    policy=policy,
                    adapter=self._adapter(),
                    reason_code="lineage_rights_changed",
                ))
            adapter = self._adapter()
            try:
                observation = self._invoke_adapter(adapter, "canary", record, actor)
                if (
                    type(observation) is not CanaryObservation
                    or observation.tenant != canonical
                    or observation.target_id != self._target(record).target_id
                    or observation.active_artifact_sha256 != self._candidate_sha(record)
                ):
                    raise CandidatePromotionInterrupted(
                        "canary observation is not bound to the candidate"
                    )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                return self._view(self._rollback_from(
                    record,
                    actor=actor,
                    policy=policy,
                    adapter=adapter,
                    reason_code="canary_observation_unavailable",
                ))
            failures = self._canary_failures(policy, observation)
            if failures:
                def retain(value: dict) -> None:
                    value["deployment"]["canary"] = {
                        **asdict(observation), "passed": False, "failures": failures,
                    }

                failed = self._update_state(
                    record,
                    state="canary",
                    actor=actor,
                    action="candidate.promotion.canary-failed",
                    details={"evidence_sha256": observation.evidence_sha256, "failures": failures},
                    mutate=retain,
                )
                return self._view(self._rollback_from(
                    failed,
                    actor=actor,
                    policy=policy,
                    adapter=adapter,
                    reason_code="canary_invariant_failed",
                ))

            def retain(value: dict) -> None:
                value["deployment"]["canary"] = {
                    **asdict(observation), "passed": True, "failures": [],
                }

            saved = self._update_state(
                record,
                state="active",
                actor=actor,
                action="candidate.promotion.canary-pass",
                details={"evidence_sha256": observation.evidence_sha256},
                mutate=retain,
            )
            return self._view(saved)

    def rollback(
        self, tenant: str, operator: str, candidate_id: str, *, expected_revision: int,
        reason_code: str,
    ) -> dict:
        canonical = canonical_tenant_id(tenant)
        actor = _principal(operator, "promotion operator", named_user=True)
        reason = _purpose(reason_code, "rollback reason_code")
        with tenant_scope(tenant=canonical), self.effect_fence():
            record = self._record(canonical, candidate_id)
            if record["revision"] != expected_revision or record["state"] not in {"canary", "active"}:
                raise CandidatePromotionConflict("candidate is not at a rollback-compatible revision")
            policy = self._policy()
            now = self.store.authoritative_time()
            self._post_deployment_authority(record, policy, actor, "rollback", now)
            saved = self._rollback_from(
                record,
                actor=actor,
                policy=policy,
                adapter=self._adapter(),
                reason_code=reason,
            )
            return self._view(saved)

    def reconcile(
        self, tenant: str, operator: str, candidate_id: str, *, expected_revision: int
    ) -> dict:
        """Resolve an uncertain effect without replaying stage/activate/rollback."""

        canonical = canonical_tenant_id(tenant)
        actor = _principal(operator, "promotion operator", named_user=True)
        with tenant_scope(tenant=canonical), self.effect_fence():
            record = self._record(canonical, candidate_id)
            if record["revision"] != expected_revision or record["state"] != "uncertain":
                raise CandidatePromotionConflict("candidate is not at an uncertain revision")
            policy = self._policy()
            now = self.store.authoritative_time()
            self._post_deployment_authority(record, policy, actor, "reconcile", now)
            observation = self._invoke_adapter(self._adapter(), "reconcile", record, actor)
            if (
                type(observation) is not DeploymentReconciliation
                or observation.tenant != canonical
                or observation.target_id != self._target(record).target_id
            ):
                raise CandidatePromotionInterrupted("deployment reconciliation is unbound")
            candidate_sha = self._candidate_sha(record)
            previous_sha = self._target(record).expected_active_sha256
            if (
                observation.active_artifact_sha256 == previous_sha
                and observation.state_restored
                and observation.pending_intents_reconciled
                and observation.external_state_reconciled
            ):
                state = "rolled_back"
            elif observation.active_artifact_sha256 == candidate_sha:
                state = "canary"
            else:
                raise CandidatePromotionInterrupted("deployment reconciliation remains uncertain")

            def retain(value: dict) -> None:
                value["deployment"]["reconciliation"] = asdict(observation)

            saved = self._update_state(
                record,
                state=state,
                actor=actor,
                action="candidate.promotion.reconcile",
                details={"evidence_sha256": observation.evidence_sha256},
                mutate=retain,
            )
            return self._view(saved)

    def inspect(self, tenant: str, principal: str, candidate_id: str) -> dict:
        canonical = canonical_tenant_id(tenant)
        _principal(principal, "promotion principal", named_user=True)
        with tenant_scope(tenant=canonical):
            return self._view(self._record(canonical, candidate_id))

    def list(self, tenant: str, principal: str, *, limit: int = 100) -> list[dict]:
        canonical = canonical_tenant_id(tenant)
        _principal(principal, "promotion principal", named_user=True)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
        with tenant_scope(tenant=canonical):
            rows = [
                self._record(canonical, str(row["candidate_id"]))
                for row in self.store.list(limit=_MAX_RECORDS)
                if row.get("tenant") == canonical
            ]
            rows.sort(key=lambda row: (float(row.get("created_at", 0)), str(row["id"])), reverse=True)
            return [self._view(row) for row in rows[:limit]]


__all__ = [
    "AUTHORITY_SCHEMA", "ArtifactCommitment", "ArtifactObservation", "CANDIDATE_SCHEMA",
    "CANARY_SCHEMA", "CanaryInvariant", "CandidateDeploymentAdapter",
    "CandidatePromotionConflict", "CandidatePromotionDenied", "CandidatePromotionError",
    "CandidatePromotionInterrupted", "CandidatePromotionNotFound",
    "CandidatePromotionUnavailable", "CandidatePromotions", "DeploymentEffectReceipt",
    "DeploymentObservation", "DeploymentReconciliation", "LineageCommitment",
    "POLICY_SCHEMA", "PROMOTION_SCHEMA", "PromotionAuthority", "PromotionPolicy",
    "PromotionTarget", "PromotionTargetPreset", "RECEIPT_SCHEMA",
    "RECONCILIATION_SCHEMA", "ResourceRequirements", "RunPromotionAdmission",
    "STUDY_CLAIM_SCHEMA", "StudyClaim", "TrustedStudyAdmission",
]
