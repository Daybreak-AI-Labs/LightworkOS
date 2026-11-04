"""Tenant-private, externally verifiable model-change receipts.

Training evidence is useful only when it is bound to the exact data boundary,
base artifact, trainer, result, and human decision that produced a model
change.  This module records that binding without persisting prompts,
completions, transcripts, examples, or other training content.

There are two independent signatures:

* an offline human approver signs the normalized :class:`TrainingRunEvidence`;
* :class:`maverick.audit.signing.AuditSigner` signs and hash-chains the complete
  tenant-private receipt.

Verification is fail-closed.  Both signatures must resolve through explicit
external key-id registries.  A public key disclosed by a receipt is never a
trust root (and is rejected as an unexpected field).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

RECEIPT_SCHEMA = "lightwork.training-receipt.v2"
# The public v1 shape remains an assurance API; its subject/payload digests bind v2.
TRANSPARENCY_SCHEMA = "lightwork.training-transparency-commitment.v1"
ASSURANCE_SCHEMA = "lightwork.training-assurance-commitment.v1"
TRAINING_RECEIPT_EVENT = "model_change.training_receipt"
APPROVAL_MESSAGE_VERSION = "lightwork-training-approval-v2"
MAX_RECEIPT_STORE_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_ROW_BYTES = 1024 * 1024
MAX_RECEIPT_ROWS = 100_000

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})")
_KEY_ID_RE = re.compile(r"[0-9a-f]{16}")
_SIG_RE = re.compile(r"[0-9a-f]{128}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}")
_HYPERPARAMETER_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
_HYPERPARAMETER_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+/@-]{0,63}")
_METRIC_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:/-]{0,95}")

_DATA_SCOPES = frozenset({"tenant_private", "public_synthetic"})
_CONSENT_SCOPES = frozenset(
    {"tenant_training", "hosted_training", "public_synthetic_training"},
)
_BANNED_HYPERPARAMETER_TERMS = frozenset(
    {
        "completion",
        "content",
        "conversation",
        "example",
        "message",
        "prompt",
        "response",
        "text",
        "transcript",
        "trajectory",
    },
)


class TrainingReceiptError(RuntimeError):
    """Receipt issuance or tenant-private storage was refused."""


@dataclass(frozen=True, slots=True)
class DataBoundaryEvidence:
    """Content-free evidence for the admitted training-data boundary."""

    data_scope: str
    consent_scope: str
    consent_record_id: str
    consent_evidence_sha256: str
    boundary_policy_sha256: str
    redaction_evidence_sha256: str
    retention_policy_sha256: str
    hosted_training: bool = False
    cross_tenant_data: bool = False
    raw_training_data_exported: bool = False


@dataclass(frozen=True, slots=True)
class BaseModelEvidence:
    """Exact, immutable upstream model and license identity."""

    model_id: str
    revision: str
    license_id: str
    license_evidence_sha256: str
    artifact_sha256: str
    tokenizer_sha256: str
    artifact_format: str
    artifact_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class TrainingBackendEvidence:
    """Reproducible trainer identity and content-free hyperparameters."""

    backend: str
    backend_version: str
    algorithm: str
    algorithm_version: str
    hyperparameters: Mapping[str, Any]
    source_revision: str
    dependency_lock_sha256: str
    container_image_sha256: str
    hardware_profile_sha256: str
    egress_policy_sha256: str
    config_sha256: str
    log_sha256: str
    final_checkpoint_sha256: str
    deterministic_seed: int


@dataclass(frozen=True, slots=True)
class EvaluationEvidence:
    """Comparable, aggregate-only baseline/candidate/holdout results."""

    protocol_sha256: str
    run_sha256: str
    sealed_holdout_sha256: str
    qualification_evidence_sha256: str
    qualification_policy_sha256: str
    baseline_metrics: Mapping[str, float]
    candidate_metrics: Mapping[str, float]
    holdout_metrics: Mapping[str, float]


@dataclass(frozen=True, slots=True)
class AdapterEvidence:
    """Immutable output artifact identity."""

    adapter_id: str
    artifact_format: str
    artifact_sha256: str
    runtime_compatibility_sha256: str
    checkpoint_sha256: str


@dataclass(frozen=True, slots=True)
class TrainingRunEvidence:
    """All non-approval evidence bound by an offline human signature."""

    run_id: str
    tenant_id: str
    started_at: str
    completed_at: str
    dataset_sha256: str
    environment_id: str
    environment_version: str
    environment_sha256: str
    data_boundary: DataBoundaryEvidence
    base_model: BaseModelEvidence
    training: TrainingBackendEvidence
    adapter: AdapterEvidence
    evaluation: EvaluationEvidence


@dataclass(frozen=True, slots=True)
class TrainingApprovalRequest:
    """Domain-separated approval request for one exact run-evidence digest."""

    tenant_id: str
    run_id: str
    subject_sha256: str

    def message(
        self,
        *,
        approver_id: str,
        approver_key_id: str,
        decision: str,
        approved_at: str,
    ) -> bytes:
        """Canonical bytes binding the human identity, decision, and time."""

        return _canonical_bytes(
            {
                "version": APPROVAL_MESSAGE_VERSION,
                "tenant_id": self.tenant_id,
                "run_id": self.run_id,
                "subject_sha256": self.subject_sha256,
                "approver_id": approver_id,
                "approver_key_id": approver_key_id,
                "decision": decision,
                "approved_at": approved_at,
            },
        )


@dataclass(frozen=True, slots=True)
class HumanApprovalEvidence:
    """Externally signed approval; no public key is self-disclosed."""

    approver_id: str
    approver_key_id: str
    decision: str
    approved_at: str
    subject_sha256: str
    signature: str


@dataclass(frozen=True, slots=True)
class IssuedTrainingReceipt:
    """A private receipt plus separately transported trust/bootstrap material."""

    receipt: dict[str, Any]
    signing_public_key: str
    public_commitment: dict[str, str]


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_revision(value: object, field: str) -> str:
    if not isinstance(value, str) or not _REVISION_RE.fullmatch(value):
        raise ValueError(
            f"{field} must be an immutable 40/64-hex commit or sha256 digest",
        )
    return value


def _require_deterministic_seed(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value < 0 or value >= 2**63:
        raise ValueError(f"{field} must be between 0 and 2^63 - 1")
    return value


def _require_token(value: object, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field} must be a bounded opaque identifier")
    return value


def _require_tenant_id(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    from ..paths import canonical_tenant_id

    canonical = canonical_tenant_id(value)
    if canonical != value:
        raise ValueError(f"{field} must use its canonical Unicode form")
    return value


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError(f"{field} must be UTC")
    return parsed


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("receipt clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_hyperparameter(value: object, *, path: str, depth: int = 0) -> object:
    if depth > 2:
        raise ValueError(f"{path} exceeds the permitted nesting depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 10**15:
            raise ValueError(f"{path} is outside the permitted numeric range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > 10**15:
            raise ValueError(f"{path} must be a finite bounded number")
        return value
    if isinstance(value, str):
        if not _HYPERPARAMETER_TOKEN_RE.fullmatch(value):
            raise ValueError(
                f"{path} strings must be short machine tokens, never raw content",
            )
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > 32:
            raise ValueError(f"{path} contains too many values")
        return [
            _normalize_hyperparameter(item, path=f"{path}[]", depth=depth + 1) for item in value
        ]
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise ValueError(f"{path} contains too many fields")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _HYPERPARAMETER_NAME_RE.fullmatch(key):
                raise ValueError(f"{path} contains an invalid field name")
            terms = {part for part in re.split(r"[_.-]+", key.lower()) if part}
            singular_terms = {term.rstrip("s") for term in terms}
            if terms.intersection(_BANNED_HYPERPARAMETER_TERMS) or singular_terms.intersection(
                _BANNED_HYPERPARAMETER_TERMS
            ):
                raise ValueError(
                    f"{path}.{key} could contain raw prompts or outputs and is forbidden",
                )
            normalized[key] = _normalize_hyperparameter(
                item,
                path=f"{path}.{key}",
                depth=depth + 1,
            )
        return dict(sorted(normalized.items()))
    raise ValueError(f"{path} contains an unsupported value type")


def _normalize_metrics(value: object, field: str) -> dict[str, float]:
    if not isinstance(value, Mapping) or not value or len(value) > 128:
        raise ValueError(f"{field} must be a non-empty bounded metric mapping")
    normalized: dict[str, float] = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not _METRIC_NAME_RE.fullmatch(name):
            raise ValueError(f"{field} contains an invalid metric name")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"{field}.{name} must be numeric")
        number = float(raw)
        if not math.isfinite(number) or abs(number) > 10**15:
            raise ValueError(f"{field}.{name} must be finite and bounded")
        normalized[name] = number
    return dict(sorted(normalized.items()))


def _normalize_evidence(  # noqa: C901 - validation remains linear and auditable
    evidence: TrainingRunEvidence,
) -> dict[str, Any]:
    if not isinstance(evidence, TrainingRunEvidence):
        raise ValueError("evidence must be TrainingRunEvidence")
    _require_token(evidence.run_id, "run_id")
    _require_tenant_id(evidence.tenant_id, "tenant_id")
    started = _parse_utc(evidence.started_at, "started_at")
    completed = _parse_utc(evidence.completed_at, "completed_at")
    if completed < started:
        raise ValueError("completed_at cannot precede started_at")
    _require_sha256(evidence.dataset_sha256, "dataset_sha256")
    _require_token(evidence.environment_id, "environment_id")
    _require_token(evidence.environment_version, "environment_version")
    _require_sha256(evidence.environment_sha256, "environment_sha256")

    boundary = evidence.data_boundary
    if not isinstance(boundary, DataBoundaryEvidence):
        raise ValueError("data_boundary must be DataBoundaryEvidence")
    if boundary.data_scope not in _DATA_SCOPES:
        raise ValueError("data_boundary.data_scope is unsupported")
    if boundary.consent_scope not in _CONSENT_SCOPES:
        raise ValueError("data_boundary.consent_scope is unsupported")
    _require_token(boundary.consent_record_id, "data_boundary.consent_record_id")
    _require_sha256(
        boundary.consent_evidence_sha256,
        "data_boundary.consent_evidence_sha256",
    )
    _require_sha256(
        boundary.boundary_policy_sha256,
        "data_boundary.boundary_policy_sha256",
    )
    _require_sha256(
        boundary.redaction_evidence_sha256,
        "data_boundary.redaction_evidence_sha256",
    )
    _require_sha256(
        boundary.retention_policy_sha256,
        "data_boundary.retention_policy_sha256",
    )
    if not isinstance(boundary.hosted_training, bool):
        raise ValueError("data_boundary.hosted_training must be a boolean")
    if not isinstance(boundary.cross_tenant_data, bool):
        raise ValueError("data_boundary.cross_tenant_data must be a boolean")
    if not isinstance(boundary.raw_training_data_exported, bool):
        raise ValueError("data_boundary.raw_training_data_exported must be a boolean")
    if boundary.cross_tenant_data:
        raise ValueError("cross-tenant training data is forbidden")
    if boundary.raw_training_data_exported:
        raise ValueError("raw training-data export is forbidden")
    if boundary.hosted_training and boundary.consent_scope != "hosted_training":
        raise ValueError("hosted training requires exact hosted_training consent")
    if not boundary.hosted_training and boundary.consent_scope == "hosted_training":
        raise ValueError("hosted_training consent cannot mislabel a local run")
    if boundary.data_scope == "tenant_private" and boundary.consent_scope not in {
        "tenant_training",
        "hosted_training",
    }:
        raise ValueError("tenant-private data requires tenant or hosted consent")
    if (
        boundary.data_scope == "public_synthetic"
        and boundary.consent_scope != "public_synthetic_training"
    ):
        raise ValueError("public synthetic data requires its exact consent scope")

    base = evidence.base_model
    if not isinstance(base, BaseModelEvidence):
        raise ValueError("base_model must be BaseModelEvidence")
    _require_token(base.model_id, "base_model.model_id")
    _require_revision(base.revision, "base_model.revision")
    _require_token(base.license_id, "base_model.license_id")
    _require_sha256(
        base.license_evidence_sha256,
        "base_model.license_evidence_sha256",
    )
    _require_sha256(base.artifact_sha256, "base_model.artifact_sha256")
    _require_sha256(base.tokenizer_sha256, "base_model.tokenizer_sha256")
    _require_token(base.artifact_format, "base_model.artifact_format")
    _require_sha256(
        base.artifact_manifest_sha256,
        "base_model.artifact_manifest_sha256",
    )

    training = evidence.training
    if not isinstance(training, TrainingBackendEvidence):
        raise ValueError("training must be TrainingBackendEvidence")
    _require_token(training.backend, "training.backend")
    _require_token(training.backend_version, "training.backend_version")
    _require_token(training.algorithm, "training.algorithm")
    _require_token(training.algorithm_version, "training.algorithm_version")
    hyperparameters = _normalize_hyperparameter(
        training.hyperparameters,
        path="training.hyperparameters",
    )
    if not isinstance(hyperparameters, dict) or not hyperparameters:
        raise ValueError("training.hyperparameters must be a non-empty mapping")
    _require_revision(training.source_revision, "training.source_revision")
    _require_sha256(
        training.dependency_lock_sha256,
        "training.dependency_lock_sha256",
    )
    _require_sha256(
        training.container_image_sha256,
        "training.container_image_sha256",
    )
    _require_sha256(
        training.hardware_profile_sha256,
        "training.hardware_profile_sha256",
    )
    _require_sha256(
        training.egress_policy_sha256,
        "training.egress_policy_sha256",
    )
    _require_sha256(training.config_sha256, "training.config_sha256")
    _require_sha256(training.log_sha256, "training.log_sha256")
    _require_sha256(
        training.final_checkpoint_sha256,
        "training.final_checkpoint_sha256",
    )
    _require_deterministic_seed(
        training.deterministic_seed,
        "training.deterministic_seed",
    )

    adapter = evidence.adapter
    if not isinstance(adapter, AdapterEvidence):
        raise ValueError("adapter must be AdapterEvidence")
    _require_token(adapter.adapter_id, "adapter.adapter_id")
    _require_token(adapter.artifact_format, "adapter.artifact_format")
    _require_sha256(adapter.artifact_sha256, "adapter.artifact_sha256")
    _require_sha256(
        adapter.runtime_compatibility_sha256,
        "adapter.runtime_compatibility_sha256",
    )
    _require_sha256(adapter.checkpoint_sha256, "adapter.checkpoint_sha256")

    evaluation = evidence.evaluation
    if not isinstance(evaluation, EvaluationEvidence):
        raise ValueError("evaluation must be EvaluationEvidence")
    _require_sha256(evaluation.protocol_sha256, "evaluation.protocol_sha256")
    _require_sha256(evaluation.run_sha256, "evaluation.run_sha256")
    _require_sha256(
        evaluation.sealed_holdout_sha256,
        "evaluation.sealed_holdout_sha256",
    )
    _require_sha256(
        evaluation.qualification_evidence_sha256,
        "evaluation.qualification_evidence_sha256",
    )
    _require_sha256(
        evaluation.qualification_policy_sha256,
        "evaluation.qualification_policy_sha256",
    )
    baseline = _normalize_metrics(evaluation.baseline_metrics, "baseline_metrics")
    candidate = _normalize_metrics(evaluation.candidate_metrics, "candidate_metrics")
    holdout = _normalize_metrics(evaluation.holdout_metrics, "holdout_metrics")
    if set(baseline) != set(candidate) or set(candidate) != set(holdout):
        raise ValueError("baseline, candidate, and holdout metric names must match")

    normalized = asdict(evidence)
    normalized["training"]["hyperparameters"] = hyperparameters
    normalized["training"]["hyperparameters_sha256"] = _sha256(hyperparameters)
    normalized["evaluation"]["baseline_metrics"] = baseline
    normalized["evaluation"]["candidate_metrics"] = candidate
    normalized["evaluation"]["holdout_metrics"] = holdout
    return normalized


def approval_request(evidence: TrainingRunEvidence) -> TrainingApprovalRequest:
    """Return the exact content-free run evidence an offline human approves."""

    normalized = _normalize_evidence(evidence)
    return TrainingApprovalRequest(
        tenant_id=evidence.tenant_id,
        run_id=evidence.run_id,
        subject_sha256=_sha256(normalized),
    )


def _trusted_public_key(
    trusted_pubkeys: Mapping[str, str] | None,
    key_id: object,
) -> str | None:
    if (
        not isinstance(trusted_pubkeys, Mapping)
        or not isinstance(key_id, str)
        or not _KEY_ID_RE.fullmatch(key_id)
    ):
        return None
    raw = trusted_pubkeys.get(key_id)
    if not isinstance(raw, str):
        return None
    public_key = raw.strip().lower()
    try:
        public_bytes = bytes.fromhex(public_key)
    except ValueError:
        return None
    if len(public_bytes) != 32:
        return None
    derived = hashlib.sha256(public_bytes).hexdigest()[:16]
    return public_key if derived == key_id else None


def _server_training_approver_registry() -> dict[str, str]:
    """Resolve human training-approval roots from deployment policy only."""
    try:
        from ..approval_signing import key_id, trusted_global_approver_keys

        approver_values = trusted_global_approver_keys()
    except (OSError, RuntimeError, ValueError) as exc:
        raise TrainingReceiptError(
            "server-side training-approver trust registry is unavailable",
        ) from exc
    approver_keys: dict[str, str] = {}
    for raw in approver_values:
        if not isinstance(raw, str):
            raise TrainingReceiptError(
                "server-side approver registry contains a malformed key",
            )
        public_key = raw.strip().lower()
        try:
            decoded = bytes.fromhex(public_key)
        except ValueError as exc:
            raise TrainingReceiptError(
                "server-side approver registry contains a malformed key",
            ) from exc
        if len(decoded) != 32:
            raise TrainingReceiptError(
                "server-side approver registry contains a malformed key",
            )
        identifier = key_id(public_key)
        if not _KEY_ID_RE.fullmatch(identifier):
            raise TrainingReceiptError(
                "server-side approver registry contains a malformed key",
            )
        existing = approver_keys.get(identifier)
        if existing is not None and existing != public_key:
            raise TrainingReceiptError(
                "server-side approver registry contains a key-id collision",
            )
        approver_keys[identifier] = public_key
    if not approver_keys:
        raise TrainingReceiptError(
            "server-side training-approver trust registry is empty",
        )
    if any(
        _trusted_public_key(approver_keys, identifier) is None
        for identifier in approver_keys
    ):
        raise TrainingReceiptError(
            "server-side approver trust registry is invalid",
        )
    return dict(sorted(approver_keys.items()))


def server_training_trust_registries() -> tuple[dict[str, str], dict[str, str]]:
    """Resolve receipt and human trust roots from server-side policy only.

    Receipt signing keys come from the protected tenant audit-key registry.
    Human keys come from the deployment's validated self-improvement approver
    policy. Request bodies and receipt-disclosed keys are deliberately absent
    from this trust path.
    """
    try:
        from ..audit.signing import trusted_audit_public_keys

        receipt_keys = trusted_audit_public_keys()
    except (OSError, RuntimeError, ValueError) as exc:
        raise TrainingReceiptError(
            "server-side training trust registry is unavailable",
        ) from exc
    approver_keys = _server_training_approver_registry()
    if not receipt_keys:
        raise TrainingReceiptError(
            "server-side receipt-signing trust registry is empty",
        )
    if any(
        _trusted_public_key(receipt_keys, identifier) is None
        for identifier in receipt_keys
    ):
        raise TrainingReceiptError(
            "server-side receipt trust registry is invalid",
        )
    return dict(sorted(receipt_keys.items())), dict(sorted(approver_keys.items()))


def _verify_ed25519(public_key: str, signature: str, message: bytes) -> bool:
    try:
        from ..audit.signing import verify_ed25519

        return bool(verify_ed25519(public_key, signature, message))
    except (ImportError, TypeError, ValueError):
        return False


def _validate_approval(
    approval: HumanApprovalEvidence,
    request: TrainingApprovalRequest,
    *,
    completed_at: datetime,
    trusted_approver_pubkeys: Mapping[str, str] | None,
) -> datetime:
    if not isinstance(approval, HumanApprovalEvidence):
        raise ValueError("approval must be HumanApprovalEvidence")
    _require_token(approval.approver_id, "approval.approver_id")
    if approval.decision != "approved":
        raise ValueError("human decision must be exactly approved")
    if approval.subject_sha256 != request.subject_sha256:
        raise ValueError("human approval is not bound to this run evidence")
    approved_at = _parse_utc(approval.approved_at, "approval.approved_at")
    if approved_at < completed_at:
        raise ValueError("human approval cannot precede training completion")
    if not _KEY_ID_RE.fullmatch(approval.approver_key_id):
        raise ValueError("approval.approver_key_id is invalid")
    if not _SIG_RE.fullmatch(approval.signature):
        raise ValueError("approval.signature is invalid")
    public_key = _trusted_public_key(
        trusted_approver_pubkeys,
        approval.approver_key_id,
    )
    if public_key is None or not _verify_ed25519(
        public_key,
        approval.signature,
        request.message(
            approver_id=approval.approver_id,
            approver_key_id=approval.approver_key_id,
            decision=approval.decision,
            approved_at=approval.approved_at,
        ),
    ):
        raise ValueError("human approval is not signed by a trusted approver")
    return approved_at


def _active_tenant() -> str:
    from ..paths import current_tenant_id_strict, data_dir

    tenant_id = current_tenant_id_strict()
    if not tenant_id:
        raise TrainingReceiptError(
            "training receipts require an explicit tenant scope",
        )
    _require_tenant_id(tenant_id, "active tenant_id")
    data_dir(tenant=tenant_id)  # tenant namespace admission is authoritative
    return tenant_id


def receipts_path() -> Path:
    """Return the active tenant's private append-only receipt path."""

    from ..paths import data_dir

    _active_tenant()
    return data_dir("model_improvement", "training_receipts.ndjson")


def _read_receipt(path: Path, receipt_id: str) -> dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TrainingReceiptError("training receipt could not be recovered") from exc
    for raw_line in reversed(lines):
        try:
            row = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("receipt_id") == receipt_id:
            return row
    raise TrainingReceiptError("training receipt could not be recovered")


def _strict_receipt_json(raw: str) -> object:
    def reject_constant(token: str) -> object:
        raise ValueError(f"non-standard JSON constant {token!r}")

    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field {key!r}")
            result[key] = value
        return result

    return json.loads(
        raw,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicates,
    )


def issue_training_receipt(
    evidence: TrainingRunEvidence,
    approval: HumanApprovalEvidence,
) -> IssuedTrainingReceipt:
    """Validate, sign, chain, and persist one tenant-private training receipt.

    Approver roots always resolve from protected deployment policy. A caller
    cannot nominate the key whose statement the platform audit key co-signs.
    """

    tenant_id = _active_tenant()
    normalized = _normalize_evidence(evidence)
    trusted_approver_pubkeys = _server_training_approver_registry()
    if evidence.tenant_id != tenant_id:
        raise TrainingReceiptError("run evidence does not belong to the active tenant")
    request = TrainingApprovalRequest(
        tenant_id=evidence.tenant_id,
        run_id=evidence.run_id,
        subject_sha256=_sha256(normalized),
    )
    completed_at = _parse_utc(evidence.completed_at, "completed_at")
    approved_at = _validate_approval(
        approval,
        request,
        completed_at=completed_at,
        trusted_approver_pubkeys=trusted_approver_pubkeys,
    )
    now = datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("receipt clock must return a timezone-aware datetime")
    now = now.astimezone(timezone.utc)
    if approved_at > now + timedelta(minutes=5):
        raise ValueError("human approval is implausibly future-dated")

    receipt_id = uuid.uuid4().hex
    event: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "event": TRAINING_RECEIPT_EVENT,
        "receipt_id": receipt_id,
        "issued_at": _utc_timestamp(now),
        "tenant_id": tenant_id,
        "evidence": normalized,
        "approval": asdict(approval),
        "approval_subject_sha256": request.subject_sha256,
    }
    event["receipt_payload_sha256"] = _sha256(event)

    from ..audit.signing import AuditSigner

    path = receipts_path()
    signer = AuditSigner(path)
    if not signer.write(event):
        raise TrainingReceiptError("audit signer refused the training receipt")
    receipt = _read_receipt(path, receipt_id)
    key_id = receipt.get("key_id")
    if not isinstance(key_id, str):
        raise TrainingReceiptError("signed training receipt has no key id")
    receipt_trust = {key_id: signer.public_key_hex}
    if not verify_training_receipt(
        receipt,
        trusted_receipt_pubkeys=receipt_trust,
        trusted_approver_pubkeys=trusted_approver_pubkeys,
    ):
        raise TrainingReceiptError("signed training receipt failed self-check")
    return IssuedTrainingReceipt(
        receipt=receipt,
        signing_public_key=signer.public_key_hex,
        public_commitment=_public_commitment(receipt),
    )


def read_training_receipt(receipt_id: str) -> dict[str, Any]:
    """Read one unverified receipt from only the active tenant's store."""

    _require_token(receipt_id, "receipt_id")
    tenant_id = _active_tenant()
    receipt = _read_receipt(receipts_path(), receipt_id)
    if receipt.get("tenant_id") != tenant_id:
        raise TrainingReceiptError("receipt tenant does not match the active tenant")
    return receipt


def read_verified_training_receipt(
    receipt_id: str,
    *,
    trusted_receipt_pubkeys: Mapping[str, str] | None,
    trusted_approver_pubkeys: Mapping[str, str] | None,
    expected_tenant_id: str | None = None,
) -> dict[str, Any]:
    """Read one receipt only after verifying its complete store prefix.

    Every row from genesis through the selected row must have a valid external
    receipt signature, a valid external human signature, a unique receipt id,
    and an exact ``prev_hash`` link. This prevents a valid detached row from
    being substituted for membership in the tenant's append-only history.
    Detecting a valid signed tail rollback additionally requires an external
    publication/anchor of the latest commitment.
    """
    _require_token(receipt_id, "receipt_id")
    tenant_id = _active_tenant()
    expected = expected_tenant_id or tenant_id
    if expected != tenant_id:
        raise TrainingReceiptError(
            "verified receipt tenant does not match the active tenant",
        )
    path = receipts_path()
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TrainingReceiptError(
            "training receipt chain could not be verified",
        ) from exc
    if size <= 0 or size > MAX_RECEIPT_STORE_BYTES:
        raise TrainingReceiptError(
            "training receipt chain exceeds its storage boundary",
        )

    previous = ""
    selected: dict[str, Any] | None = None
    seen_ids: set[str] = set()
    rows = 0
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            for raw_line in handle:
                if not raw_line.strip():
                    raise TrainingReceiptError(
                        "training receipt chain contains a blank row",
                    )
                rows += 1
                if rows > MAX_RECEIPT_ROWS:
                    raise TrainingReceiptError(
                        "training receipt chain exceeds its row boundary",
                    )
                if len(raw_line.encode("utf-8")) > MAX_RECEIPT_ROW_BYTES:
                    raise TrainingReceiptError(
                        "training receipt chain contains an oversized row",
                    )
                try:
                    row = _strict_receipt_json(raw_line)
                except (json.JSONDecodeError, ValueError) as exc:
                    raise TrainingReceiptError(
                        "training receipt chain contains malformed JSON",
                    ) from exc
                if not isinstance(row, dict):
                    raise TrainingReceiptError(
                        "training receipt chain contains a non-object row",
                    )
                row_id = row.get("receipt_id")
                if not isinstance(row_id, str) or row_id in seen_ids:
                    raise TrainingReceiptError(
                        "training receipt chain contains an invalid identity",
                    )
                seen_ids.add(row_id)
                if row.get("prev_hash") != previous:
                    raise TrainingReceiptError(
                        "training receipt chain link is invalid",
                    )
                if not verify_training_receipt(
                    row,
                    trusted_receipt_pubkeys=trusted_receipt_pubkeys,
                    trusted_approver_pubkeys=trusted_approver_pubkeys,
                    expected_tenant_id=expected,
                ):
                    raise TrainingReceiptError(
                        "training receipt chain contains an unverified row",
                    )
                previous = str(row["hash"])
                if row_id == receipt_id:
                    selected = row
    except (OSError, UnicodeError) as exc:
        raise TrainingReceiptError(
            "training receipt chain could not be verified",
        ) from exc
    if selected is None:
        raise TrainingReceiptError(
            "training receipt could not be recovered from the verified chain",
        )
    return selected


def _expect_exact_keys(value: object, expected: set[str], field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{field} has missing or unexpected fields")
    return value


def _evidence_from_record(value: object) -> TrainingRunEvidence:
    root = _expect_exact_keys(
        value,
        {
            "run_id",
            "tenant_id",
            "started_at",
            "completed_at",
            "dataset_sha256",
            "environment_id",
            "environment_version",
            "environment_sha256",
            "data_boundary",
            "base_model",
            "training",
            "adapter",
            "evaluation",
        },
        "evidence",
    )
    boundary = _expect_exact_keys(
        root["data_boundary"],
        {
            "data_scope",
            "consent_scope",
            "consent_record_id",
            "consent_evidence_sha256",
            "boundary_policy_sha256",
            "redaction_evidence_sha256",
            "retention_policy_sha256",
            "hosted_training",
            "cross_tenant_data",
            "raw_training_data_exported",
        },
        "evidence.data_boundary",
    )
    base = _expect_exact_keys(
        root["base_model"],
        {
            "model_id",
            "revision",
            "license_id",
            "license_evidence_sha256",
            "artifact_sha256",
            "tokenizer_sha256",
            "artifact_format",
            "artifact_manifest_sha256",
        },
        "evidence.base_model",
    )
    training = _expect_exact_keys(
        root["training"],
        {
            "backend",
            "backend_version",
            "algorithm",
            "algorithm_version",
            "hyperparameters",
            "hyperparameters_sha256",
            "source_revision",
            "dependency_lock_sha256",
            "container_image_sha256",
            "hardware_profile_sha256",
            "egress_policy_sha256",
            "config_sha256",
            "log_sha256",
            "final_checkpoint_sha256",
            "deterministic_seed",
        },
        "evidence.training",
    )
    adapter = _expect_exact_keys(
        root["adapter"],
        {
            "adapter_id",
            "artifact_format",
            "artifact_sha256",
            "runtime_compatibility_sha256",
            "checkpoint_sha256",
        },
        "evidence.adapter",
    )
    evaluation = _expect_exact_keys(
        root["evaluation"],
        {
            "protocol_sha256",
            "run_sha256",
            "sealed_holdout_sha256",
            "qualification_evidence_sha256",
            "qualification_policy_sha256",
            "baseline_metrics",
            "candidate_metrics",
            "holdout_metrics",
        },
        "evidence.evaluation",
    )
    hyperparameters = training["hyperparameters"]
    if _sha256(hyperparameters) != training["hyperparameters_sha256"]:
        raise ValueError("hyperparameter digest does not match")
    return TrainingRunEvidence(
        run_id=root["run_id"],
        tenant_id=root["tenant_id"],
        started_at=root["started_at"],
        completed_at=root["completed_at"],
        dataset_sha256=root["dataset_sha256"],
        environment_id=root["environment_id"],
        environment_version=root["environment_version"],
        environment_sha256=root["environment_sha256"],
        data_boundary=DataBoundaryEvidence(**boundary),
        base_model=BaseModelEvidence(**base),
        training=TrainingBackendEvidence(
            backend=training["backend"],
            backend_version=training["backend_version"],
            algorithm=training["algorithm"],
            algorithm_version=training["algorithm_version"],
            hyperparameters=hyperparameters,
            source_revision=training["source_revision"],
            dependency_lock_sha256=training["dependency_lock_sha256"],
            container_image_sha256=training["container_image_sha256"],
            hardware_profile_sha256=training["hardware_profile_sha256"],
            egress_policy_sha256=training["egress_policy_sha256"],
            config_sha256=training["config_sha256"],
            log_sha256=training["log_sha256"],
            final_checkpoint_sha256=training["final_checkpoint_sha256"],
            deterministic_seed=training["deterministic_seed"],
        ),
        adapter=AdapterEvidence(**adapter),
        evaluation=EvaluationEvidence(**evaluation),
    )


def verify_training_receipt(
    receipt: Mapping[str, Any],
    *,
    trusted_receipt_pubkeys: Mapping[str, str] | None,
    trusted_approver_pubkeys: Mapping[str, str] | None,
    expected_tenant_id: str | None = None,
) -> bool:
    """Verify both signatures, every digest, schema, and tenant binding.

    ``trusted_*_pubkeys`` are external ``key_id -> raw Ed25519 public key hex``
    registries.  No public key in ``receipt`` is consulted.
    """

    try:
        active_tenant: str | None
        from ..paths import current_tenant_id_strict

        active_tenant = current_tenant_id_strict()
        if active_tenant:
            _require_tenant_id(active_tenant, "active tenant_id")
        expected = expected_tenant_id or active_tenant
        if not expected:
            return False
        _require_tenant_id(expected, "expected_tenant_id")
        if active_tenant and expected != active_tenant:
            return False

        row = _expect_exact_keys(
            receipt,
            {
                "schema",
                "event",
                "receipt_id",
                "issued_at",
                "tenant_id",
                "evidence",
                "approval",
                "approval_subject_sha256",
                "receipt_payload_sha256",
                "prev_hash",
                "key_id",
                "hash",
                "sig",
            },
            "receipt",
        )
        if row["schema"] != RECEIPT_SCHEMA or row["event"] != TRAINING_RECEIPT_EVENT:
            return False
        _require_token(row["receipt_id"], "receipt_id")
        issued_at = _parse_utc(row["issued_at"], "issued_at")
        if row["tenant_id"] != expected:
            return False
        evidence = _evidence_from_record(row["evidence"])
        normalized = _normalize_evidence(evidence)
        if normalized != row["evidence"] or evidence.tenant_id != expected:
            return False
        request = TrainingApprovalRequest(
            tenant_id=evidence.tenant_id,
            run_id=evidence.run_id,
            subject_sha256=_sha256(normalized),
        )
        if row["approval_subject_sha256"] != request.subject_sha256:
            return False
        approval_map = _expect_exact_keys(
            row["approval"],
            {
                "approver_id",
                "approver_key_id",
                "decision",
                "approved_at",
                "subject_sha256",
                "signature",
            },
            "approval",
        )
        approval = HumanApprovalEvidence(**approval_map)
        approved_at = _validate_approval(
            approval,
            request,
            completed_at=_parse_utc(evidence.completed_at, "completed_at"),
            trusted_approver_pubkeys=trusted_approver_pubkeys,
        )
        if issued_at + timedelta(minutes=5) < approved_at:
            return False

        event = {
            key: value
            for key, value in row.items()
            if key not in {"receipt_payload_sha256", "prev_hash", "key_id", "hash", "sig"}
        }
        if _sha256(event) != row["receipt_payload_sha256"]:
            return False
        previous = row["prev_hash"]
        if not isinstance(previous, str) or (previous and not _SHA256_RE.fullmatch(previous)):
            return False
        if not _SHA256_RE.fullmatch(str(row["hash"])):
            return False
        if not _SIG_RE.fullmatch(str(row["sig"])):
            return False
        unsigned = {key: value for key, value in row.items() if key not in {"hash", "sig"}}
        row_hash = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, default=str).encode("utf-8"),
        ).hexdigest()
        if row_hash != row["hash"]:
            return False
        public_key = _trusted_public_key(trusted_receipt_pubkeys, row["key_id"])
        return bool(public_key and _verify_ed25519(public_key, row["sig"], bytes.fromhex(row_hash)))
    except (KeyError, TypeError, ValueError):
        return False


def _public_commitment(receipt: Mapping[str, Any]) -> dict[str, str]:
    evidence = receipt["evidence"]
    return {
        "schema": TRANSPARENCY_SCHEMA,
        "dataset_sha256": evidence["dataset_sha256"],
        "environment_sha256": evidence["environment_sha256"],
        "base_model_artifact_sha256": evidence["base_model"]["artifact_sha256"],
        "adapter_sha256": evidence["adapter"]["artifact_sha256"],
        "approval_subject_sha256": receipt["approval_subject_sha256"],
        "receipt_payload_sha256": receipt["receipt_payload_sha256"],
        "event_hash": receipt["hash"],
        "key_id": receipt["key_id"],
    }


def _assurance_commitment(receipt: Mapping[str, Any]) -> dict[str, str]:
    """Return content-free qualification commitments from a private receipt."""

    evidence = receipt["evidence"]
    base_model = evidence["base_model"]
    evaluation = evidence["evaluation"]
    return {
        "schema": ASSURANCE_SCHEMA,
        "dataset_sha256": evidence["dataset_sha256"],
        "base_model_license_id": base_model["license_id"],
        "base_model_license_evidence_sha256": base_model[
            "license_evidence_sha256"
        ],
        "evaluation_run_sha256": evaluation["run_sha256"],
        "sealed_holdout_sha256": evaluation["sealed_holdout_sha256"],
        "qualification_evidence_sha256": evaluation[
            "qualification_evidence_sha256"
        ],
        "qualification_policy_sha256": evaluation[
            "qualification_policy_sha256"
        ],
        "adapter_sha256": evidence["adapter"]["artifact_sha256"],
        "receipt_payload_sha256": receipt["receipt_payload_sha256"],
    }


def public_transparency_commitment(
    receipt: Mapping[str, Any],
    *,
    trusted_receipt_pubkeys: Mapping[str, str] | None,
    trusted_approver_pubkeys: Mapping[str, str] | None,
    expected_tenant_id: str | None = None,
) -> dict[str, str]:
    """Expose the v1-compatible digest commitment for the verified v2 receipt.

    ``receipt_payload_sha256`` and ``approval_subject_sha256`` transitively bind
    every reproducibility digest in the private receipt while preserving the
    strict public shape consumed by model-risk assurance.
    """

    if not verify_training_receipt(
        receipt,
        trusted_receipt_pubkeys=trusted_receipt_pubkeys,
        trusted_approver_pubkeys=trusted_approver_pubkeys,
        expected_tenant_id=expected_tenant_id,
    ):
        raise ValueError("cannot publish a commitment for an unverified receipt")
    return _public_commitment(receipt)


def model_risk_assurance_commitment(
    receipt: Mapping[str, Any],
    *,
    trusted_receipt_pubkeys: Mapping[str, str] | None,
    trusted_approver_pubkeys: Mapping[str, str] | None,
    expected_tenant_id: str | None = None,
) -> dict[str, str]:
    """Expose qualification commitments only after full receipt verification."""

    if not verify_training_receipt(
        receipt,
        trusted_receipt_pubkeys=trusted_receipt_pubkeys,
        trusted_approver_pubkeys=trusted_approver_pubkeys,
        expected_tenant_id=expected_tenant_id,
    ):
        raise ValueError(
            "cannot publish assurance commitments for an unverified receipt"
        )
    return _assurance_commitment(receipt)


__all__ = [
    "APPROVAL_MESSAGE_VERSION",
    "ASSURANCE_SCHEMA",
    "AdapterEvidence",
    "BaseModelEvidence",
    "DataBoundaryEvidence",
    "EvaluationEvidence",
    "HumanApprovalEvidence",
    "IssuedTrainingReceipt",
    "RECEIPT_SCHEMA",
    "TRANSPARENCY_SCHEMA",
    "TrainingApprovalRequest",
    "TrainingBackendEvidence",
    "TrainingReceiptError",
    "TrainingRunEvidence",
    "approval_request",
    "issue_training_receipt",
    "model_risk_assurance_commitment",
    "public_transparency_commitment",
    "read_training_receipt",
    "read_verified_training_receipt",
    "receipts_path",
    "server_training_trust_registries",
    "verify_training_receipt",
]
