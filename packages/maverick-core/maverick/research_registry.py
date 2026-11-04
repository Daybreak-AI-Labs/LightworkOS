"""Governed dataset and model versions for tenant research work.

Registry manifests contain commitments and opaque source references, never raw
dataset rows, credentials, or model weights.  A dataset is usable only while its
independent data-use decision (and optional consent authority) still resolves.
Approval is a separate, named mutation over immutable version material.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .governed_records import GovernedRecordStore, configured_governed_records_backend
from .knowledge_retrieval import source_selected
from .paths import canonical_tenant_id, data_dir, tenant_scope
from .privacy_ops import RecordConflict

DATASET_SCHEMA = "lightwork.research-dataset-version.v1"
MODEL_SCHEMA = "lightwork.research-model-version.v1"
REGISTRY_REF_SCHEMA = "lightwork.research-registry-ref.v1"
DATA_USE_AUTHORITY_SCHEMA = "lightwork.research-data-use-authority.v1"
CONSENT_AUTHORITY_SCHEMA = "lightwork.research-consent-authority.v1"
REVIEW_AUTHORITY_SCHEMA = "lightwork.research-registry-review-authority.v1"
TRAINING_RECEIPT_AUTHORITY_SCHEMA = "lightwork.research-training-receipt-authority.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PURPOSE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})\Z")
_KINDS = frozenset({"dataset", "model"})
_ACTIONS = frozenset({"analyze", "export", "read", "train"})
# A data-use decision names the strongest use that was reviewed.  Reading for
# human display is a narrower use of material approved for analysis or export,
# but it is never implied by training-only authority.  Every other effectful
# action remains exact.
_ACTION_AUTHORITIES = {
    "read": frozenset({"read", "analyze", "export"}),
    "analyze": frozenset({"analyze"}),
    "export": frozenset({"export"}),
    "train": frozenset({"train"}),
}
_MUTABLE_REVISIONS = frozenset({"current", "default", "head", "latest", "main", "master", "stable"})
_MAX_LINEAGE = 128
_MAX_RECORDS = 2_048
_MAX_LIST = 250


class ResearchRegistryError(RuntimeError):
    """Base registry error."""


class ResearchRegistryConflict(ResearchRegistryError):
    """A version, approval, or current authority changed."""


class ResearchRegistryNotFound(ResearchRegistryError, LookupError):
    """No matching tenant registry version exists."""


class ResearchRegistryDenied(ResearchRegistryError, PermissionError):
    """Current rights or approval do not permit this research use."""


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("registry material must be finite JSON") from exc
    if len(encoded) > 512 * 1024:
        raise ValueError("registry material exceeds its size boundary")
    return encoded


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _dataset_boundary_sha256(content_sha256s: Sequence[str]) -> str:
    values = tuple(_sha(value, "dataset boundary SHA-256") for value in content_sha256s)
    if len(values) == 1:
        return values[0]
    return _digest(
        {
            "schema": "lightwork.research-dataset-boundary.v1",
            "content_sha256s": list(values),
        }
    )


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{label} is not a bounded identifier")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _text(value: object, label: str, maximum: int = 1_024) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    result = value.strip()
    if len(result.encode("utf-8")) > maximum or any(ord(char) < 32 for char in result):
        raise ValueError(f"{label} is not bounded text")
    return result


def _source_ref(value: object) -> str:
    result = _text(value, "source_ref", 2_048)
    parsed = urlsplit(result)
    if parsed.scheme == "https":
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("source_ref cannot contain credentials, query, or fragment")
    elif not re.fullmatch(r"(?:urn|catalog|artifact):[A-Za-z0-9][A-Za-z0-9._:/-]{0,2000}", result):
        raise ValueError("source_ref must be a safe HTTPS or opaque catalog reference")
    return result


def _immutable_revision(value: object) -> str:
    result = _identifier(value, "immutable_provider_revision")
    if result.lower() in _MUTABLE_REVISIONS:
        raise ValueError("mutable provider revision aliases are not accepted")
    return result


def _purposes(values: Sequence[str], label: str = "allowed_purposes") -> tuple[str, ...]:
    if isinstance(values, str | bytes) or not isinstance(values, Sequence):
        raise ValueError(f"{label} must be a bounded list")
    result = tuple(sorted({_identifier_purpose(value, label) for value in values}))
    if not 1 <= len(result) <= 32:
        raise ValueError(f"{label} must contain one to 32 values")
    return result


def _identifier_purpose(value: object, label: str) -> str:
    if not isinstance(value, str) or not _PURPOSE.fullmatch(value):
        raise ValueError(f"{label} contains an invalid purpose")
    return value


def _constraints(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, str | bytes) or not isinstance(values, Sequence):
        raise ValueError("usage_constraints must be a bounded list")
    result = tuple(sorted({_text(value, "usage constraint", 256) for value in values}))
    if not 1 <= len(result) <= 32:
        raise ValueError("usage_constraints must contain one to 32 values")
    return result


def _timestamp(value: object, label: str) -> float:
    if (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} must be a positive finite timestamp")
    return float(value)


@dataclass(frozen=True)
class ResearchAssetRef:
    """Caller-carried locator whose digest is always resolved from the registry."""

    kind: str
    asset_id: str
    version: str
    manifest_sha256: str
    schema: str = REGISTRY_REF_SCHEMA

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError("registry reference kind is unsupported")
        _identifier(self.asset_id, "asset_id")
        _identifier(self.version, "version")
        _sha(self.manifest_sha256, "manifest_sha256")
        if self.schema != REGISTRY_REF_SCHEMA:
            raise ValueError("registry reference schema is unsupported")


@dataclass(frozen=True)
class DataUseAuthority:
    """Current result from the independent data-use authority."""

    tenant: str
    decision_id: str
    decision_sha256: str
    asset_id: str
    action: str
    purpose_codes: tuple[str, ...]
    expires_at: float
    authority_sha256: str
    schema: str = DATA_USE_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.decision_id, "decision_id")
        _sha(self.decision_sha256, "decision_sha256")
        _identifier(self.asset_id, "asset_id")
        if self.action not in _ACTIONS:
            raise ValueError("data-use action is unsupported")
        if tuple(self.purpose_codes) != _purposes(self.purpose_codes, "purpose_codes"):
            raise ValueError("purpose_codes must be unique and sorted")
        _timestamp(self.expires_at, "expires_at")
        _sha(self.authority_sha256, "authority_sha256")
        if self.schema != DATA_USE_AUTHORITY_SCHEMA:
            raise ValueError("data-use authority schema is unsupported")


@dataclass(frozen=True)
class ConsentAuthority:
    """Current optional consent authority for one dataset version."""

    tenant: str
    record_id: str
    evidence_sha256: str
    allowed_purposes: tuple[str, ...]
    valid_until: float
    revoked: bool
    schema: str = CONSENT_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.record_id, "consent record_id")
        _sha(self.evidence_sha256, "consent evidence_sha256")
        if tuple(self.allowed_purposes) != _purposes(self.allowed_purposes):
            raise ValueError("consent purposes must be unique and sorted")
        _timestamp(self.valid_until, "consent valid_until")
        if not isinstance(self.revoked, bool):
            raise ValueError("consent revoked must be boolean")
        if self.schema != CONSENT_AUTHORITY_SCHEMA:
            raise ValueError("consent authority schema is unsupported")


@dataclass(frozen=True)
class RegistryReviewAuthority:
    """Current named reviewer authority supplied by trusted composition."""

    tenant: str
    principal: str
    authorization_sha256: str
    schema: str = REVIEW_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        if not isinstance(self.principal, str) or not self.principal.startswith("user:"):
            raise ValueError("a named registry reviewer is required")
        _text(self.principal, "reviewer principal", 512)
        _sha(self.authorization_sha256, "reviewer authorization_sha256")
        if self.schema != REVIEW_AUTHORITY_SCHEMA:
            raise ValueError("registry review authority schema is unsupported")


@dataclass(frozen=True)
class TrainingReceiptAuthority:
    """Verified signed training receipt material bound into a model version."""

    tenant: str
    receipt_id: str
    receipt_payload_sha256: str
    run_id: str
    dataset_sha256: str
    environment_id: str
    environment_version: str
    environment_sha256: str
    training_source_revision: str
    deterministic_seed: int
    base_model_artifact_sha256: str
    output_artifact_sha256: str
    approval_subject_sha256: str
    completed_at: str
    authority_sha256: str
    schema: str = TRAINING_RECEIPT_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.receipt_id, "training receipt_id")
        _sha(self.receipt_payload_sha256, "training receipt_payload_sha256")
        _identifier(self.run_id, "training run_id")
        _sha(self.dataset_sha256, "training dataset_sha256")
        _identifier(self.environment_id, "training environment_id")
        _identifier(self.environment_version, "training environment_version")
        _sha(self.environment_sha256, "training environment_sha256")
        if not isinstance(self.training_source_revision, str) or not _REVISION.fullmatch(
            self.training_source_revision
        ):
            raise ValueError("training source revision must be immutable")
        if (
            isinstance(self.deterministic_seed, bool)
            or not isinstance(self.deterministic_seed, int)
            or not 0 <= self.deterministic_seed < 2**63
        ):
            raise ValueError("training deterministic seed is invalid")
        _sha(
            self.base_model_artifact_sha256,
            "training base_model_artifact_sha256",
        )
        _sha(self.output_artifact_sha256, "training output_artifact_sha256")
        _sha(self.approval_subject_sha256, "training approval_subject_sha256")
        _text(self.completed_at, "training completed_at", 64)
        _sha(self.authority_sha256, "training authority_sha256")
        if self.schema != TRAINING_RECEIPT_AUTHORITY_SCHEMA:
            raise ValueError("training receipt authority schema is unsupported")


@dataclass(frozen=True)
class DatasetAdmission:
    tenant: str
    reference: ResearchAssetRef
    source_ref: str
    content_sha256: str
    license_id: str
    license_evidence_sha256: str
    allowed_purpose: str
    usage_constraints: tuple[str, ...]
    provenance_kind: str
    synthetic_provenance: Mapping[str, object] | None
    data_use_authority: DataUseAuthority
    consent_authority: ConsentAuthority | None
    approval_sha256: str


@dataclass(frozen=True)
class ModelAdmission:
    tenant: str
    reference: ResearchAssetRef
    source_ref: str
    artifact_sha256: str
    license_id: str
    license_evidence_sha256: str
    allowed_purpose: str
    usage_constraints: tuple[str, ...]
    provider_model_identity: str
    immutable_provider_revision: str | None
    observed_from: float | None
    observed_until: float | None
    reproducibility_limitation: str | None
    dataset_lineage_purpose: str | None
    dataset_lineage: tuple[ResearchAssetRef, ...]
    model_lineage: tuple[ResearchAssetRef, ...]
    provenance_kind: str
    training_receipt_authority: TrainingReceiptAuthority | None
    approval_sha256: str


def verified_training_receipt_resolver(
    *,
    trusted_receipt_pubkeys: Mapping[str, str],
    trusted_approver_pubkeys: Mapping[str, str],
) -> Callable[[str, str], TrainingReceiptAuthority]:
    """Build a resolver backed by the fully verified tenant receipt chain.

    The local receipt file is intentionally refused when governed records use a
    shared backend. A distributed deployment must inject a resolver backed by
    its own shared, authenticated receipt authority.
    """

    receipt_roots = dict(trusted_receipt_pubkeys)
    approver_roots = dict(trusted_approver_pubkeys)

    def resolve(tenant: str, receipt_id: str) -> TrainingReceiptAuthority:
        canonical = canonical_tenant_id(tenant)
        if configured_governed_records_backend() != "local":
            raise ResearchRegistryDenied(
                "shared research registry requires a deployment-shared training-receipt resolver"
            )
        from .training.receipts import read_verified_training_receipt

        with tenant_scope(tenant=canonical):
            try:
                receipt = read_verified_training_receipt(
                    receipt_id,
                    trusted_receipt_pubkeys=receipt_roots,
                    trusted_approver_pubkeys=approver_roots,
                    expected_tenant_id=canonical,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise ResearchRegistryDenied("signed training receipt cannot be verified") from exc
        try:
            evidence = receipt["evidence"]
            base_model = evidence["base_model"]
            training = evidence["training"]
            adapter = evidence["adapter"]
            material = {
                "tenant": canonical,
                "receipt_id": receipt["receipt_id"],
                "receipt_payload_sha256": receipt["receipt_payload_sha256"],
                "run_id": evidence["run_id"],
                "dataset_sha256": evidence["dataset_sha256"],
                "environment_id": evidence["environment_id"],
                "environment_version": evidence["environment_version"],
                "environment_sha256": evidence["environment_sha256"],
                "training_source_revision": training["source_revision"],
                "deterministic_seed": training["deterministic_seed"],
                "base_model_artifact_sha256": base_model["artifact_sha256"],
                "output_artifact_sha256": adapter["artifact_sha256"],
                "approval_subject_sha256": receipt["approval_subject_sha256"],
                "completed_at": evidence["completed_at"],
            }
        except (KeyError, TypeError) as exc:
            raise ResearchRegistryDenied("signed training receipt evidence is incomplete") from exc
        material["authority_sha256"] = _digest(material)
        try:
            return TrainingReceiptAuthority(**material)
        except (TypeError, ValueError) as exc:
            raise ResearchRegistryDenied("signed training receipt evidence is malformed") from exc

    return resolve


def resolve_data_use_authority(
    tenant: str,
    decision_id: str,
    expected_decision_sha256: str,
) -> DataUseAuthority:
    """Revalidate one DUG decision against its current independent authorities."""
    from .data_use_governance import DataUseGovernanceStore
    from .data_use_policy_compiler import DataUsePolicyCompiler, thaw_control_ir

    if configured_governed_records_backend() != "local":
        raise ResearchRegistryDenied(
            "shared research registry requires a deployment-shared data-use resolver"
        )
    store = DataUseGovernanceStore(
        data_dir(
            "data_use_governance",
            "data-use-governance.sqlite3",
            tenant=tenant,
        )
    )
    decision = store.get_authorization_decision(tenant, decision_id)
    if not isinstance(decision, Mapping):
        raise ResearchRegistryDenied("data-use decision is unavailable")
    compiled = thaw_control_ir(
        DataUsePolicyCompiler(store).compile(
            tenant,
            decision_id,
            expected_decision_sha256=expected_decision_sha256,
        )
    )
    request = decision.get("authority", {}).get("request", {})
    if (
        decision.get("outcome") != "allow"
        or not isinstance(request, Mapping)
        or request.get("status") != "authorized"
    ):
        raise ResearchRegistryDenied("data-use decision does not grant uncontrolled research use")
    bindings = compiled.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ResearchRegistryDenied("compiled data-use binding is unavailable")
    return DataUseAuthority(
        tenant=tenant,
        decision_id=decision_id,
        decision_sha256=_sha(decision.get("decision_sha256"), "decision_sha256"),
        asset_id=_identifier(decision.get("asset_id"), "asset_id"),
        action=_text(decision.get("action"), "action", 32),
        purpose_codes=_purposes(request.get("purpose_codes", ()), "purpose_codes"),
        expires_at=_timestamp(decision.get("expires_at"), "expires_at"),
        authority_sha256=_digest(bindings),
    )


class ResearchRegistry:
    """Tenant-bound registry with immutable manifests and mutable approval state."""

    def __init__(
        self,
        *,
        data_use_resolver: Callable[[str, str, str], DataUseAuthority] = resolve_data_use_authority,
        consent_resolver: Callable[[str, str], ConsentAuthority] | None = None,
        review_authority_resolver: (Callable[[str, str], RegistryReviewAuthority] | None) = None,
        training_receipt_resolver: (Callable[[str, str], TrainingReceiptAuthority] | None) = None,
        record_store: GovernedRecordStore | None = None,
        effect_fence=None,
    ) -> None:
        from .authority_effects import authority_effect_fence

        self.data_use_resolver = data_use_resolver
        self.consent_resolver = consent_resolver
        self.review_authority_resolver = review_authority_resolver
        self.training_receipt_resolver = training_receipt_resolver
        self.effect_fence = effect_fence or authority_effect_fence
        self.store = record_store or GovernedRecordStore(
            "research-registry",
            "research-asset",
            "research-registry-asset",
        )

    @staticmethod
    def _record_id(kind: str, tenant: str, asset_id: str, version: str) -> str:
        material = f"{canonical_tenant_id(tenant)}\0{kind}\0{asset_id}\0{version}"
        return f"research-asset-{kind[:1]}-{hashlib.sha256(material.encode()).hexdigest()[:44]}"

    @staticmethod
    def _reference(record: Mapping[str, object]) -> ResearchAssetRef:
        return ResearchAssetRef(
            kind=str(record["kind"]),
            asset_id=str(record["asset_id"]),
            version=str(record["version"]),
            manifest_sha256=str(record["manifest_sha256"]),
        )

    def _get(self, tenant: str, reference: ResearchAssetRef) -> dict:
        if type(reference) is not ResearchAssetRef:
            raise ValueError("an exact ResearchAssetRef is required")
        record = self.store.get(
            self._record_id(reference.kind, tenant, reference.asset_id, reference.version)
        )
        if record is None:
            raise ResearchRegistryNotFound("research registry version was not found")
        if (
            record.get("tenant") != tenant
            or record.get("kind") != reference.kind
            or record.get("asset_id") != reference.asset_id
            or record.get("version") != reference.version
        ):
            raise ResearchRegistryNotFound("research registry version was not found")
        manifest = record.get("manifest")
        if not isinstance(manifest, dict):
            raise ResearchRegistryConflict("research registry manifest is malformed")
        expected = _digest(manifest)
        if not hmac.compare_digest(str(record.get("manifest_sha256") or ""), expected):
            raise ResearchRegistryConflict("research registry manifest digest does not match")
        if not hmac.compare_digest(reference.manifest_sha256, expected):
            raise ResearchRegistryConflict("research registry reference is stale or forged")
        return record

    def _create(self, tenant: str, actor: str, kind: str, manifest: dict) -> dict:
        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "actor", 512)
        if not principal.startswith("user:"):
            raise ValueError("a named user actor is required")
        digest = _digest(manifest)
        record_id = self._record_id(kind, canonical, manifest["asset_id"], manifest["version"])
        with tenant_scope(tenant=canonical):
            prior = self.store.get(record_id)
            if prior is not None:
                reference = ResearchAssetRef(
                    kind=kind,
                    asset_id=str(manifest["asset_id"]),
                    version=str(manifest["version"]),
                    manifest_sha256=digest,
                )
                validated = self._get(canonical, reference)
                if validated.get("registered_by") == principal:
                    return validated
                raise ResearchRegistryConflict(
                    "registry version already exists with different material"
                )
            try:
                return self.store.create(
                    {
                        "id": record_id,
                        "schema": DATASET_SCHEMA if kind == "dataset" else MODEL_SCHEMA,
                        "tenant": canonical,
                        "kind": kind,
                        "asset_id": manifest["asset_id"],
                        "version": manifest["version"],
                        "manifest": manifest,
                        "manifest_sha256": digest,
                        "registered_by": principal,
                        "state": "draft",
                        "approval": None,
                        "revocation": None,
                    },
                    actor=principal,
                    action=f"research.registry.{kind}.register",
                    max_records=_MAX_RECORDS,
                )
            except RecordConflict as exc:
                raise ResearchRegistryConflict("registry version was created concurrently") from exc

    def _review_authority(self, tenant: str, principal: str) -> RegistryReviewAuthority:
        if self.review_authority_resolver is None:
            raise ResearchRegistryDenied("registry review authority cannot be resolved")
        try:
            authority = self.review_authority_resolver(tenant, principal)
        except (KeyboardInterrupt, SystemExit):
            raise
        except ResearchRegistryError:
            raise
        except Exception as exc:
            raise ResearchRegistryDenied("registry review authority is unavailable") from exc
        if (
            type(authority) is not RegistryReviewAuthority
            or authority.tenant != tenant
            or authority.principal != principal
        ):
            raise ResearchRegistryDenied("registry review authority is unavailable")
        return authority

    @staticmethod
    def _refs(
        values: Sequence[ResearchAssetRef], *, kind: str, label: str
    ) -> tuple[ResearchAssetRef, ...]:
        if isinstance(values, str | bytes) or not isinstance(values, Sequence):
            raise ValueError(f"{label} must be a bounded list")
        refs = tuple(values)
        if len(refs) > _MAX_LINEAGE or any(type(item) is not ResearchAssetRef for item in refs):
            raise ValueError(f"{label} contains an invalid registry reference")
        if any(item.kind != kind for item in refs):
            raise ValueError(f"{label} contains the wrong registry kind")
        keys = [(item.asset_id, item.version, item.manifest_sha256) for item in refs]
        if keys != sorted(set(keys)):
            raise ValueError(f"{label} must be unique and sorted")
        return refs

    def preflight_dataset_ingestion(
        self,
        tenant: str,
        *,
        dataset_id: str,
        allowed_purposes: Sequence[str],
        data_use_action: str,
        data_use_decision_id: str,
        data_use_decision_sha256: str,
        consent_record_id: str | None = None,
        consent_evidence_sha256: str | None = None,
    ) -> None:
        """Resolve source authority before an ingestion adapter may read bytes.

        A caller that must inspect an installed source to derive its content
        commitment uses this preflight first.  Durable registration repeats
        the same checks after inspection so a revocation in between cannot
        produce a registry record.
        """

        canonical = canonical_tenant_id(tenant)
        action = _text(data_use_action, "data_use_action", 32)
        if action not in _ACTIONS:
            raise ValueError("data_use_action is unsupported")
        if (consent_record_id is None) != (consent_evidence_sha256 is None):
            raise ValueError("consent record and evidence digest must be supplied together")
        manifest = {
            "asset_id": _identifier(dataset_id, "dataset_id"),
            "allowed_purposes": list(_purposes(allowed_purposes)),
            "data_use_action": action,
            "data_use_decision_id": _identifier(
                data_use_decision_id,
                "data_use_decision_id",
            ),
            "data_use_decision_sha256": _sha(
                data_use_decision_sha256,
                "data_use_decision_sha256",
            ),
            "consent_record_id": (
                None
                if consent_record_id is None
                else _identifier(consent_record_id, "consent_record_id")
            ),
            "consent_evidence_sha256": (
                None
                if consent_evidence_sha256 is None
                else _sha(consent_evidence_sha256, "consent_evidence_sha256")
            ),
        }
        with tenant_scope(tenant=canonical), self.effect_fence():
            for purpose in manifest["allowed_purposes"]:
                self._validate_dataset_authority(canonical, manifest, purpose)

    def register_dataset(
        self,
        tenant: str,
        actor: str,
        *,
        dataset_id: str,
        version: str,
        source_ref: str,
        content_sha256: str,
        license_id: str,
        license_evidence_sha256: str,
        allowed_purposes: Sequence[str],
        usage_constraints: Sequence[str],
        data_use_action: str,
        data_use_decision_id: str,
        data_use_decision_sha256: str,
        consent_record_id: str | None = None,
        consent_evidence_sha256: str | None = None,
        parent_datasets: Sequence[ResearchAssetRef] = (),
        provenance_kind: str | None = None,
        synthetic_generator_id: str | None = None,
        synthetic_generator_version: str | None = None,
        synthetic_generator_sha256: str | None = None,
        synthetic_config_sha256: str | None = None,
        synthetic_seed: int | None = None,
    ) -> ResearchAssetRef:
        canonical = canonical_tenant_id(tenant)
        action = _text(data_use_action, "data_use_action", 32)
        if action not in _ACTIONS:
            raise ValueError("data_use_action is unsupported")
        if (consent_record_id is None) != (consent_evidence_sha256 is None):
            raise ValueError("consent record and evidence digest must be supplied together")
        parents = self._refs(parent_datasets, kind="dataset", label="parent_datasets")
        provenance = (
            "derived"
            if provenance_kind is None and parents
            else "source"
            if provenance_kind is None
            else _identifier_purpose(provenance_kind, "provenance_kind")
        )
        if provenance not in {"derived", "source", "synthetic"}:
            raise ValueError("dataset provenance_kind must be derived, source, or synthetic")
        synthetic_values = (
            synthetic_generator_id,
            synthetic_generator_version,
            synthetic_generator_sha256,
            synthetic_config_sha256,
            synthetic_seed,
        )
        if provenance == "synthetic":
            if parents:
                raise ValueError(
                    "synthetic fixture provenance cannot be replaced by parent lineage"
                )
            if any(value is None for value in synthetic_values):
                raise ValueError(
                    "synthetic datasets require generator, version, artifact, config, and seed"
                )
            if (
                isinstance(synthetic_seed, bool)
                or not isinstance(synthetic_seed, int)
                or not 0 <= synthetic_seed < 2**63
            ):
                raise ValueError("synthetic_seed must be between zero and 2^63 - 1")
            synthetic = {
                "generator_id": _identifier(
                    synthetic_generator_id,
                    "synthetic_generator_id",
                ),
                "generator_version": _identifier(
                    synthetic_generator_version,
                    "synthetic_generator_version",
                ),
                "generator_sha256": _sha(
                    synthetic_generator_sha256,
                    "synthetic_generator_sha256",
                ),
                "config_sha256": _sha(
                    synthetic_config_sha256,
                    "synthetic_config_sha256",
                ),
                "seed": synthetic_seed,
            }
        else:
            if any(value is not None for value in synthetic_values):
                raise ValueError("only synthetic datasets can carry generator provenance")
            if provenance == "derived" and not parents:
                raise ValueError("derived dataset provenance requires parent lineage")
            synthetic = None
        manifest = {
            "kind": "dataset",
            "asset_id": _identifier(dataset_id, "dataset_id"),
            "version": _identifier(version, "version"),
            "source_ref": _source_ref(source_ref),
            "content_sha256": _sha(content_sha256, "content_sha256"),
            "license_id": _identifier(license_id, "license_id"),
            "license_evidence_sha256": _sha(license_evidence_sha256, "license_evidence_sha256"),
            "allowed_purposes": list(_purposes(allowed_purposes)),
            "usage_constraints": list(_constraints(usage_constraints)),
            "data_use_action": action,
            "data_use_decision_id": _identifier(data_use_decision_id, "data_use_decision_id"),
            "data_use_decision_sha256": _sha(data_use_decision_sha256, "data_use_decision_sha256"),
            "consent_record_id": (
                None
                if consent_record_id is None
                else _identifier(consent_record_id, "consent_record_id")
            ),
            "consent_evidence_sha256": (
                None
                if consent_evidence_sha256 is None
                else _sha(consent_evidence_sha256, "consent_evidence_sha256")
            ),
            "parent_datasets": [asdict(item) for item in parents],
            "provenance_kind": provenance,
            "synthetic_provenance": synthetic,
        }
        # Registering a dataset is the registry's ingestion boundary.  A draft
        # cannot by itself be used by a run, but accepting an unresolvable
        # rights claim here would still let unsupported source metadata enter
        # the governed catalogue.  Resolve every declared purpose, consent
        # authority, and parent with the same action before the durable write.
        # Approval, queue, worker start, export, and promotion repeat these
        # checks because this admission is deliberately not cached.
        with tenant_scope(tenant=canonical), self.effect_fence():
            for purpose in manifest["allowed_purposes"]:
                self._validate_dataset_authority(canonical, manifest, purpose)
                for parent in parents:
                    self.resolve_dataset(
                        canonical,
                        parent,
                        purpose=purpose,
                        action=action,
                    )
            return self._reference(self._create(canonical, actor, "dataset", manifest))

    def register_model(
        self,
        tenant: str,
        actor: str,
        *,
        model_id: str,
        version: str,
        source_ref: str,
        artifact_sha256: str,
        license_id: str,
        license_evidence_sha256: str,
        allowed_purposes: Sequence[str],
        usage_constraints: Sequence[str],
        provider_model_identity: str,
        immutable_provider_revision: str | None,
        observed_from: float | None = None,
        observed_until: float | None = None,
        reproducibility_limitation: str | None = None,
        dataset_lineage: Sequence[ResearchAssetRef] = (),
        dataset_lineage_purpose: str | None = None,
        model_lineage: Sequence[ResearchAssetRef] = (),
        provenance_kind: str = "external",
        training_receipt_id: str | None = None,
        training_receipt_sha256: str | None = None,
        training_dataset_sha256: str | None = None,
    ) -> ResearchAssetRef:
        canonical = canonical_tenant_id(tenant)
        datasets = self._refs(dataset_lineage, kind="dataset", label="dataset_lineage")
        models = self._refs(model_lineage, kind="model", label="model_lineage")
        if datasets:
            lineage_purpose = _identifier_purpose(
                dataset_lineage_purpose, "dataset_lineage_purpose"
            )
        elif dataset_lineage_purpose is not None:
            raise ValueError("dataset_lineage_purpose requires dataset lineage")
        else:
            lineage_purpose = None
        provenance = _identifier_purpose(provenance_kind, "provenance_kind")
        if provenance not in {"external", "trained"}:
            raise ValueError("provenance_kind must be external or trained")
        receipt_values = (
            training_receipt_id,
            training_receipt_sha256,
            training_dataset_sha256,
        )
        if provenance == "trained":
            if not datasets:
                raise ValueError("trained models require dataset lineage")
            if not models:
                raise ValueError("trained models require base-model lineage")
            if any(value is None for value in receipt_values):
                raise ValueError(
                    "trained models require a signed training receipt and dataset digest"
                )
            receipt_id = _identifier(training_receipt_id, "training_receipt_id")
            receipt_sha256 = _sha(
                training_receipt_sha256,
                "training_receipt_sha256",
            )
            training_dataset = _sha(
                training_dataset_sha256,
                "training_dataset_sha256",
            )
        else:
            if any(value is not None for value in receipt_values):
                raise ValueError("external models cannot claim a signed training receipt")
            receipt_id = receipt_sha256 = training_dataset = None
        if immutable_provider_revision is None:
            if (
                observed_from is None
                or observed_until is None
                or reproducibility_limitation is None
            ):
                raise ValueError(
                    "unpinnable models require an observation window and explicit limitation"
                )
            start = _timestamp(observed_from, "observed_from")
            end = _timestamp(observed_until, "observed_until")
            if end <= start:
                raise ValueError("observed_until must be after observed_from")
            limitation = _text(reproducibility_limitation, "reproducibility_limitation", 512)
            revision = None
        else:
            revision = _immutable_revision(immutable_provider_revision)
            if any(
                value is not None
                for value in (observed_from, observed_until, reproducibility_limitation)
            ):
                raise ValueError("pinned models cannot carry an unpinnable observation window")
            start = end = limitation = None
        with tenant_scope(tenant=canonical):
            for reference in (*datasets, *models):
                self._get(canonical, reference)
        manifest = {
            "kind": "model",
            "asset_id": _identifier(model_id, "model_id"),
            "version": _identifier(version, "version"),
            "source_ref": _source_ref(source_ref),
            "artifact_sha256": _sha(artifact_sha256, "artifact_sha256"),
            "license_id": _identifier(license_id, "license_id"),
            "license_evidence_sha256": _sha(license_evidence_sha256, "license_evidence_sha256"),
            "allowed_purposes": list(_purposes(allowed_purposes)),
            "usage_constraints": list(_constraints(usage_constraints)),
            "provider_model_identity": _text(
                provider_model_identity, "provider_model_identity", 256
            ),
            "immutable_provider_revision": revision,
            "observed_from": start,
            "observed_until": end,
            "reproducibility_limitation": limitation,
            "dataset_lineage": [asdict(item) for item in datasets],
            "dataset_lineage_purpose": lineage_purpose,
            "model_lineage": [asdict(item) for item in models],
            "provenance_kind": provenance,
            "training_receipt_id": receipt_id,
            "training_receipt_sha256": receipt_sha256,
            "training_dataset_sha256": training_dataset,
        }
        return self._reference(self._create(canonical, actor, "model", manifest))

    def _approval_sha(self, tenant: str, record: Mapping[str, object]) -> str:
        approval = record.get("approval")
        if not isinstance(approval, Mapping):
            raise ResearchRegistryDenied("research registry version is not approved")
        if set(approval) != {
            "approved_by",
            "approver_authority",
            "approved_at",
            "manifest_sha256",
            "approval_sha256",
        }:
            raise ResearchRegistryConflict("registry approval is malformed")
        actual = _sha(approval.get("approval_sha256"), "approval_sha256")
        expected = _digest(
            {key: value for key, value in approval.items() if key != "approval_sha256"}
        )
        if not hmac.compare_digest(actual, expected) or approval.get(
            "manifest_sha256"
        ) != record.get("manifest_sha256"):
            raise ResearchRegistryConflict("registry approval digest does not match")
        approver = _text(approval.get("approved_by"), "approved_by", 512)
        current = self._review_authority(tenant, approver)
        if approval.get("approver_authority") != asdict(current):
            raise ResearchRegistryDenied("registry reviewer authority changed")
        _timestamp(approval.get("approved_at"), "approved_at")
        return actual

    def _validate_dataset_authority(
        self,
        tenant: str,
        manifest: Mapping[str, object],
        purpose: str,
    ) -> tuple[DataUseAuthority, ConsentAuthority | None]:
        allowed_purpose = _identifier_purpose(purpose, "purpose")
        if allowed_purpose not in manifest.get("allowed_purposes", ()):
            raise ResearchRegistryDenied("dataset is not approved for this purpose")
        try:
            authority = self.data_use_resolver(
                tenant,
                str(manifest["data_use_decision_id"]),
                str(manifest["data_use_decision_sha256"]),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except ResearchRegistryError:
            raise
        except Exception as exc:
            raise ResearchRegistryDenied("data-use authority cannot be revalidated") from exc
        if type(authority) is not DataUseAuthority or authority.tenant != tenant:
            raise ResearchRegistryDenied("data-use authority is unavailable")
        if (
            authority.decision_id != manifest["data_use_decision_id"]
            or authority.decision_sha256 != manifest["data_use_decision_sha256"]
            or authority.asset_id != manifest["asset_id"]
            or authority.action != manifest["data_use_action"]
            or allowed_purpose not in authority.purpose_codes
            or authority.expires_at <= self.store.authoritative_time()
        ):
            raise ResearchRegistryDenied("dataset data-use authority is stale or does not match")
        consent_id = manifest.get("consent_record_id")
        consent = None
        if consent_id is not None:
            if self.consent_resolver is None:
                raise ResearchRegistryDenied("dataset consent authority cannot be revalidated")
            try:
                consent = self.consent_resolver(tenant, str(consent_id))
            except (KeyboardInterrupt, SystemExit):
                raise
            except ResearchRegistryError:
                raise
            except Exception as exc:
                raise ResearchRegistryDenied("dataset consent authority is unavailable") from exc
            if type(consent) is not ConsentAuthority or consent.tenant != tenant:
                raise ResearchRegistryDenied("dataset consent authority is unavailable")
            if (
                consent.record_id != consent_id
                or consent.evidence_sha256 != manifest.get("consent_evidence_sha256")
                or consent.revoked
                or consent.valid_until <= self.store.authoritative_time()
                or allowed_purpose not in consent.allowed_purposes
            ):
                raise ResearchRegistryDenied("dataset consent is revoked, stale, or mismatched")
        return authority, consent

    def approve(
        self,
        tenant: str,
        actor: str,
        reference: ResearchAssetRef,
        *,
        expected_revision: int,
    ) -> ResearchAssetRef:
        canonical = canonical_tenant_id(tenant)
        approver = _text(actor, "actor", 512)
        if not approver.startswith("user:"):
            raise ValueError("a named user approver is required")
        with tenant_scope(tenant=canonical), self.effect_fence():
            review_authority = self._review_authority(canonical, approver)
            current = self._get(canonical, reference)
            if current["registered_by"] == approver:
                raise ResearchRegistryDenied(
                    "registry approval requires a different named reviewer"
                )
            if current["kind"] == "dataset":
                effective_action = str(current["manifest"]["data_use_action"])
                for purpose in current["manifest"]["allowed_purposes"]:
                    self._validate_dataset_authority(canonical, current["manifest"], purpose)
                    for raw in current["manifest"].get("parent_datasets", ()):
                        if not isinstance(raw, dict):
                            raise ResearchRegistryConflict("dataset lineage is malformed")
                        self.resolve_dataset(
                            canonical,
                            ResearchAssetRef(**raw),
                            purpose=purpose,
                            action=effective_action,
                        )
            else:
                for purpose in current["manifest"]["allowed_purposes"]:
                    self._validate_lineage(canonical, current["manifest"], purpose)
            approved_at = self.store.authoritative_time()
            approval = {
                "approved_by": approver,
                "approver_authority": asdict(review_authority),
                "approved_at": approved_at,
                "manifest_sha256": current["manifest_sha256"],
            }
            approval["approval_sha256"] = _digest(approval)

            def mutate(record: dict) -> None:
                if record.get("state") != "draft" or record.get("approval") is not None:
                    raise ResearchRegistryConflict("only a draft registry version can be approved")
                if record.get("manifest_sha256") != reference.manifest_sha256:
                    raise ResearchRegistryConflict("registry manifest changed before approval")
                record.update(state="approved", approval=approval)

            saved = self.store.update(
                current["id"],
                mutate,
                expected_revision=expected_revision,
                actor=approver,
                action=f"research.registry.{reference.kind}.approve",
            )
            if saved is None:
                raise ResearchRegistryNotFound("research registry version was not found")
            return self._reference(saved)

    def revoke(
        self,
        tenant: str,
        actor: str,
        reference: ResearchAssetRef,
        *,
        expected_revision: int,
        reason_code: str,
        evidence_sha256: str,
    ) -> ResearchAssetRef:
        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "actor", 512)
        if not principal.startswith("user:"):
            raise ValueError("a named user actor is required")
        reason = _identifier_purpose(reason_code, "reason_code")
        evidence = _sha(evidence_sha256, "evidence_sha256")
        with tenant_scope(tenant=canonical), self.effect_fence():
            review_authority = self._review_authority(canonical, principal)
            current = self._get(canonical, reference)
            revoked_at = self.store.authoritative_time()

            def mutate(record: dict) -> None:
                if record.get("state") != "approved":
                    raise ResearchRegistryConflict(
                        "only an approved registry version can be revoked"
                    )
                record.update(
                    state="revoked",
                    revocation={
                        "revoked_by": principal,
                        "review_authority": asdict(review_authority),
                        "revoked_at": revoked_at,
                        "reason_code": reason,
                        "evidence_sha256": evidence,
                    },
                )

            saved = self.store.update(
                current["id"],
                mutate,
                expected_revision=expected_revision,
                actor=principal,
                action=f"research.registry.{reference.kind}.revoke",
            )
            if saved is None:
                raise ResearchRegistryNotFound("research registry version was not found")
            return self._reference(saved)

    def resolve_training_receipt(
        self,
        tenant: str,
        receipt_id: str,
        expected_receipt_sha256: str,
    ) -> TrainingReceiptAuthority:
        """Resolve an exact, currently trusted signed training receipt."""

        canonical = canonical_tenant_id(tenant)
        exact_id = _identifier(receipt_id, "training_receipt_id")
        exact_sha256 = _sha(
            expected_receipt_sha256,
            "training_receipt_sha256",
        )
        if self.training_receipt_resolver is None:
            raise ResearchRegistryDenied("signed training receipt authority cannot be resolved")
        with tenant_scope(tenant=canonical):
            try:
                authority = self.training_receipt_resolver(canonical, exact_id)
            except (KeyboardInterrupt, SystemExit):
                raise
            except ResearchRegistryError:
                raise
            except Exception as exc:
                raise ResearchRegistryDenied(
                    "signed training receipt authority is unavailable"
                ) from exc
        if (
            type(authority) is not TrainingReceiptAuthority
            or authority.tenant != canonical
            or authority.receipt_id != exact_id
            or not hmac.compare_digest(
                authority.receipt_payload_sha256,
                exact_sha256,
            )
        ):
            raise ResearchRegistryDenied(
                "signed training receipt is stale, forged, or tenant-mismatched"
            )
        material = asdict(authority)
        material.pop("authority_sha256")
        material.pop("schema")
        if not hmac.compare_digest(authority.authority_sha256, _digest(material)):
            raise ResearchRegistryDenied("signed training receipt authority digest does not match")
        return authority

    def _validate_lineage(
        self,
        tenant: str,
        manifest: Mapping[str, object],
        model_purpose: str,
    ) -> TrainingReceiptAuthority | None:
        dataset_purpose = manifest.get("dataset_lineage_purpose")
        dataset_rows = manifest.get("dataset_lineage", ())
        model_rows = manifest.get("model_lineage", ())
        if not isinstance(dataset_rows, list) or not isinstance(model_rows, list):
            raise ResearchRegistryConflict("model lineage is malformed")
        if dataset_rows and not isinstance(dataset_purpose, str):
            raise ResearchRegistryConflict("model dataset lineage purpose is unavailable")
        provenance = manifest.get("provenance_kind", "external")
        if provenance not in {"external", "trained"}:
            raise ResearchRegistryConflict("model provenance kind is unsupported")
        dataset_action = "train" if provenance == "trained" else None
        datasets: list[DatasetAdmission] = []
        for raw in dataset_rows:
            if not isinstance(raw, dict):
                raise ResearchRegistryConflict("model dataset lineage is malformed")
            reference = ResearchAssetRef(**raw)
            if reference.kind != "dataset":
                raise ResearchRegistryConflict("model lineage has the wrong registry kind")
            datasets.append(
                self.resolve_dataset(
                    tenant,
                    reference,
                    purpose=str(dataset_purpose),
                    action=dataset_action,
                )
            )
        models: list[ModelAdmission] = []
        for raw in model_rows:
            if not isinstance(raw, dict):
                raise ResearchRegistryConflict("model lineage is malformed")
            reference = ResearchAssetRef(**raw)
            if reference.kind != "model":
                raise ResearchRegistryConflict("model lineage has the wrong registry kind")
            models.append(self.resolve_model(tenant, reference, purpose=model_purpose))
        if provenance == "external":
            if any(
                manifest.get(field) is not None
                for field in (
                    "training_receipt_id",
                    "training_receipt_sha256",
                    "training_dataset_sha256",
                )
            ):
                raise ResearchRegistryConflict(
                    "external model carries unexpected training receipt material"
                )
            return None
        try:
            receipt_id = str(manifest["training_receipt_id"])
            receipt_sha256 = str(manifest["training_receipt_sha256"])
            training_dataset_sha256 = _sha(
                manifest["training_dataset_sha256"],
                "training_dataset_sha256",
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ResearchRegistryConflict("trained model receipt binding is malformed") from exc
        receipt = self.resolve_training_receipt(
            tenant,
            receipt_id,
            receipt_sha256,
        )
        if (
            receipt.dataset_sha256 != training_dataset_sha256
            or receipt.output_artifact_sha256 != manifest.get("artifact_sha256")
            or _dataset_boundary_sha256(tuple(item.content_sha256 for item in datasets))
            != training_dataset_sha256
            or not any(
                item.artifact_sha256 == receipt.base_model_artifact_sha256 for item in models
            )
        ):
            raise ResearchRegistryDenied(
                "signed training receipt does not bind this model and dataset lineage"
            )
        return receipt

    def resolve_dataset(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        *,
        purpose: str,
        action: str | None = None,
    ) -> DatasetAdmission:
        canonical = canonical_tenant_id(tenant)
        expected_action = None if action is None else _text(action, "action", 32)
        if expected_action is not None and expected_action not in _ACTIONS:
            raise ValueError("data-use action is unsupported")
        with tenant_scope(tenant=canonical):
            record = self._get(canonical, reference)
            if record.get("state") != "approved":
                raise ResearchRegistryDenied("dataset version is not currently approved")
            authority, consent = self._validate_dataset_authority(
                canonical, record["manifest"], purpose
            )
            if (
                expected_action is not None
                and authority.action not in _ACTION_AUTHORITIES[expected_action]
            ):
                raise ResearchRegistryDenied("dataset is not authorized for the requested action")
            manifest = record["manifest"]
            for raw in manifest.get("parent_datasets", ()):
                if not isinstance(raw, dict):
                    raise ResearchRegistryConflict("dataset lineage is malformed")
                parent = ResearchAssetRef(**raw)
                if parent.kind != "dataset":
                    raise ResearchRegistryConflict("dataset lineage has the wrong registry kind")
                self.resolve_dataset(
                    canonical,
                    parent,
                    purpose=purpose,
                    action=expected_action,
                )
            return DatasetAdmission(
                tenant=canonical,
                reference=self._reference(record),
                source_ref=str(manifest["source_ref"]),
                content_sha256=str(manifest["content_sha256"]),
                license_id=str(manifest["license_id"]),
                license_evidence_sha256=str(manifest["license_evidence_sha256"]),
                allowed_purpose=purpose,
                usage_constraints=tuple(manifest["usage_constraints"]),
                provenance_kind=str(manifest.get("provenance_kind", "source")),
                synthetic_provenance=manifest.get("synthetic_provenance"),
                data_use_authority=authority,
                consent_authority=consent,
                approval_sha256=self._approval_sha(canonical, record),
            )

    def resolve_model(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        *,
        purpose: str,
    ) -> ModelAdmission:
        canonical = canonical_tenant_id(tenant)
        allowed_purpose = _identifier_purpose(purpose, "purpose")
        with tenant_scope(tenant=canonical):
            record = self._get(canonical, reference)
            if record.get("state") != "approved":
                raise ResearchRegistryDenied("model version is not currently approved")
            manifest = record["manifest"]
            if allowed_purpose not in manifest.get("allowed_purposes", ()):
                raise ResearchRegistryDenied("model is not approved for this purpose")
            training_receipt = self._validate_lineage(
                canonical,
                manifest,
                allowed_purpose,
            )
            return ModelAdmission(
                tenant=canonical,
                reference=self._reference(record),
                source_ref=str(manifest["source_ref"]),
                artifact_sha256=str(manifest["artifact_sha256"]),
                license_id=str(manifest["license_id"]),
                license_evidence_sha256=str(manifest["license_evidence_sha256"]),
                allowed_purpose=allowed_purpose,
                usage_constraints=tuple(manifest["usage_constraints"]),
                provider_model_identity=str(manifest["provider_model_identity"]),
                immutable_provider_revision=manifest["immutable_provider_revision"],
                observed_from=manifest["observed_from"],
                observed_until=manifest["observed_until"],
                reproducibility_limitation=manifest["reproducibility_limitation"],
                dataset_lineage_purpose=manifest["dataset_lineage_purpose"],
                dataset_lineage=tuple(
                    ResearchAssetRef(**item) for item in manifest["dataset_lineage"]
                ),
                model_lineage=tuple(ResearchAssetRef(**item) for item in manifest["model_lineage"]),
                provenance_kind=str(manifest.get("provenance_kind", "external")),
                training_receipt_authority=training_receipt,
                approval_sha256=self._approval_sha(canonical, record),
            )

    def inspect(self, tenant: str, reference: ResearchAssetRef) -> dict:
        """Read one exact tenant version for a separately authorized service layer."""
        canonical = canonical_tenant_id(tenant)
        with tenant_scope(tenant=canonical):
            record = self._get(canonical, reference)
            return {
                "schema": record["schema"],
                "tenant": record["tenant"],
                "reference": asdict(self._reference(record)),
                "manifest": dict(record["manifest"]),
                "state": record["state"],
                "registered_by": record["registered_by"],
                "approval": record.get("approval"),
                "revocation": record.get("revocation"),
                "revision": record["revision"],
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
            }

    def list(
        self,
        tenant: str,
        *,
        kind: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return bounded exact versions for an authorized service projection.

        This registry deliberately has no implicit "latest" lookup.  Every row
        carries the immutable reference that a later run must submit verbatim.
        Tenant authorization remains the responsibility of the service layer,
        just as it is for :meth:`inspect` and :meth:`derivative_impact`.
        """

        canonical = canonical_tenant_id(tenant)
        if kind is not None and kind not in _KINDS:
            raise ValueError("registry kind is unsupported")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
        with tenant_scope(tenant=canonical):
            rows = [
                row
                for row in self.store.list(limit=_MAX_RECORDS)
                if row.get("tenant") == canonical and (kind is None or row.get("kind") == kind)
            ]
            rows.sort(
                key=lambda row: (float(row.get("created_at", 0)), str(row.get("id", ""))),
                reverse=True,
            )
            return [self.inspect(canonical, self._reference(row)) for row in rows[:limit]]

    def knowledge_candidate_page(
        self,
        tenant: str,
        *,
        source_selectors: Sequence[str] | None,
        limit: int = 250,
        after: tuple[float, str] | None = None,
        snapshot: tuple[float, str] | None = None,
    ) -> dict:
        """Source-filtered immutable-key page, not a permission or content result.

        The registry is bounded by its configured capacity. Filtering its metadata
        before inspecting the selected page avoids projecting unrelated content.
        Approval, purpose, consent and live source authority remain service checks.
        ``snapshot`` excludes later additions; mutations are always freshly read.
        """
        canonical = canonical_tenant_id(tenant)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
        if source_selectors is not None and (
            isinstance(source_selectors, str | bytes)
            or not isinstance(source_selectors, Sequence)
            or not 1 <= len(source_selectors) <= 64
            or any(not isinstance(value, str) or not 1 <= len(value) <= 2048 for value in source_selectors)
        ):
            raise ValueError("knowledge source selectors must be a bounded list")

        def position(row: Mapping) -> tuple[float, str]:
            return float(row["created_at"]), str(row["id"])

        with tenant_scope(tenant=canonical):
            rows = []
            for row in self.store.list(limit=_MAX_RECORDS):
                if row.get("tenant") != canonical or row.get("kind") != "dataset":
                    continue
                manifest = row.get("manifest")
                if not isinstance(manifest, Mapping):
                    raise ResearchRegistryConflict("research registry manifest is malformed")
                if source_selectors is not None and not source_selected(
                    str(row.get("asset_id") or ""),
                    str(manifest.get("source_ref") or ""),
                    source_selectors,
                ):
                    continue
                rows.append(row)
            rows.sort(key=position, reverse=True)
            ceiling = snapshot if snapshot is not None else position(rows[0]) if rows else None
            selected = [
                row for row in rows
                if (ceiling is None or position(row) <= ceiling)
                and (after is None or position(row) < after)
            ]
            page = selected[:limit]
            return {
                "items": [self.inspect(canonical, self._reference(row)) for row in page],
                "snapshot": ceiling,
                "last": position(page[-1]) if page else after,
                "has_more": len(selected) > limit,
            }

    def derivative_impact(self, tenant: str, reference: ResearchAssetRef) -> dict:
        """Return bounded transitive dependants without claiming weight unlearning."""
        canonical = canonical_tenant_id(tenant)
        with tenant_scope(tenant=canonical):
            source = self._get(canonical, reference)
            rows = [
                row for row in self.store.list(limit=_MAX_RECORDS) if row.get("tenant") == canonical
            ]
            frontier = {reference.manifest_sha256}
            found: dict[str, dict] = {}
            while frontier:
                target = frontier.pop()
                for row in rows:
                    if row["id"] in found or row["id"] == source["id"]:
                        continue
                    manifest = row.get("manifest", {})
                    lineage = [
                        *manifest.get("parent_datasets", ()),
                        *manifest.get("dataset_lineage", ()),
                        *manifest.get("model_lineage", ()),
                    ]
                    if any(item.get("manifest_sha256") == target for item in lineage):
                        found[row["id"]] = row
                        frontier.add(str(row["manifest_sha256"]))
            derivatives = [
                {
                    "reference": asdict(self._reference(row)),
                    "state": row["state"],
                    "required_action": (
                        "retire_or_retrain_model"
                        if row["kind"] == "model"
                        else "invalidate_dataset"
                    ),
                }
                for row in sorted(found.values(), key=lambda item: item["id"])
            ]
            return {
                "source": asdict(reference),
                "source_state": source["state"],
                "derivatives": derivatives,
                "raw_deletion_removes_weight_influence": False,
            }


__all__ = [
    "ConsentAuthority",
    "DATASET_SCHEMA",
    "DATA_USE_AUTHORITY_SCHEMA",
    "DataUseAuthority",
    "DatasetAdmission",
    "MODEL_SCHEMA",
    "ModelAdmission",
    "REGISTRY_REF_SCHEMA",
    "REVIEW_AUTHORITY_SCHEMA",
    "RegistryReviewAuthority",
    "ResearchAssetRef",
    "ResearchRegistry",
    "ResearchRegistryConflict",
    "ResearchRegistryDenied",
    "ResearchRegistryError",
    "ResearchRegistryNotFound",
    "TRAINING_RECEIPT_AUTHORITY_SCHEMA",
    "TrainingReceiptAuthority",
    "resolve_data_use_authority",
    "verified_training_receipt_resolver",
]
