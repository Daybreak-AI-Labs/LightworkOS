"""Governed, digest-only media provenance receipts behind a real C2PA adapter.

This module is a control plane, not a C2PA implementation.  It does not parse,
validate, create, or cryptographically sign C2PA manifests itself.  Those
operations are available only through explicitly injected ``C2PAVerifier`` and
``C2PASigner`` adapters.  The default service has no adapter and therefore
reports the capability as unsupported rather than manufacturing a validity
claim.

Only closed, adapter-attested receipts and SHA-256 content bindings are
persisted.  Media bytes are transient and have no persistence field.  Exported
records label validity and trust as adapter-reported facts and carry explicit
coverage and standards limitations; they are not certifications.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

ADAPTER_RECEIPT_SCHEMA = "lightwork.c2pa-adapter-receipt.v1"
PROVENANCE_RECORD_SCHEMA = "lightwork.ai-media-provenance.v1"
SAFE_EXPORT_SCHEMA = "lightwork.ai-media-provenance-export.v1"

STANDARDS_LIMITATIONS = (
    "C2PA parsing, signature validation, trust-chain evaluation, and signing "
    "are performed only by the named external adapter; Lightwork does not "
    "reimplement or certify those cryptographic operations.",
    "Validity and trust states are adapter-reported observations for the exact "
    "content digest, asset, deployment, and context binding shown here.",
    "Assertion coverage is limited to the listed assertion codes and does not "
    "prove authorship, ownership, truth, copyright, consent, or the absence of "
    "undisclosed edits or AI generation.",
    "A release approval is an internal human governance decision, not C2PA, "
    "regulatory, conformity-assessment, or certification-body approval.",
)

_RECORDS = GovernedRecordStore(
    "ai_media_provenance", "AMP", "ai_media_provenance"
)

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_RECORD_ID_RE = re.compile(r"AMP-[0-9a-f]{32}\Z")
_TENANT_REF_RE = re.compile(r"TEN-[0-9a-f]{24}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]{0,127}\Z")
_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/+\-=]{0,255}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_MAX_RECORDS = 10_000
_MAX_REFERENCE_LIST = 500
_MAX_ASSERTIONS = 64
_MAX_RECEIPT_BYTES = 128 * 1024
_MAX_MEDIA_BYTES = 64 * 1024 * 1024
_MAX_FUTURE_SKEW_SECONDS = 300.0

_RECEIPT_FIELDS = frozenset({
    "schema",
    "operation",
    "adapter_id",
    "adapter_version",
    "standard",
    "receipt_id",
    "observed_at",
    "media_kind",
    "source_content_sha256",
    "content_sha256",
    "asset_id",
    "asset_revision",
    "asset_version_digest",
    "deployment_id",
    "deployment_revision",
    "deployment_artifact_digest",
    "context_id",
    "context_revision",
    "context_digest",
    "manifest_sha256",
    "claim_generator",
    "signing_time",
    "validation_state",
    "assertion_codes",
    "trust_chain_state",
    "receipt_sha256",
})
_RELEASE_FIELDS = frozenset({
    "prepared_at",
    "purpose_code",
    "preparation_evidence_sha256",
    "prepared_by",
    "reviewed_at",
    "outcome",
    "review_evidence_sha256",
    "reviewed_by",
})
_RECORD_FIELDS = frozenset({
    "id",
    "schema",
    "tenant_ref",
    "operation",
    "adapter_id",
    "adapter_version",
    "standard",
    "observed_at",
    "media_kind",
    "source_content_sha256",
    "content_sha256",
    "asset_id",
    "asset_revision",
    "asset_version_digest",
    "deployment_id",
    "deployment_revision",
    "deployment_artifact_digest",
    "context_id",
    "context_revision",
    "context_digest",
    "manifest_sha256",
    "claim_generator",
    "signing_time",
    "validation_state",
    "assertion_codes",
    "trust_chain_state",
    "receipt_id_sha256",
    "receipt_sha256",
    "payload_sha256",
    "recorded_by_kind",
    "recorded_by",
    "status",
    "release",
    "state_sha256",
})
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_IMMUTABLE_FIELDS = tuple(
    sorted(
        _RECORD_FIELDS
        - {
            "id",
            "payload_sha256",
            "recorded_by_kind",
            "recorded_by",
            "status",
            "release",
            "state_sha256",
        }
    )
)


class MediaProvenanceError(RuntimeError):
    """Base failure for governed media provenance."""


class MediaProvenanceConfigError(MediaProvenanceError):
    """The default-off feature is disabled."""


class MediaProvenanceUnavailable(MediaProvenanceError):
    """A real C2PA adapter is not configured or available."""


class MediaProvenanceStateError(MediaProvenanceError):
    """Persisted provenance state is missing or malformed."""


class MediaProvenanceBindingError(MediaProvenanceError):
    """Current asset, deployment, or context authority does not match."""


class MediaProvenanceIdempotencyConflict(MediaProvenanceError):
    """A receipt identity was reused with different content."""


class MediaKind(str, Enum):
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"


class ProvenanceOperation(str, Enum):
    VERIFICATION = "verification"
    SIGNING = "signing"


class ValidationState(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    INDETERMINATE = "indeterminate"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class TrustChainState(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class ReleaseOutcome(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REMEDIATION = "needs_remediation"


class ActorKind(str, Enum):
    HUMAN = "human"
    SYSTEM = "system"


@dataclass(frozen=True)
class MediaProvenanceActor:
    kind: ActorKind | str
    principal: str


@dataclass(frozen=True)
class C2PABinding:
    """Exact transient authority binding supplied to a C2PA adapter."""

    media_kind: str
    source_content_sha256: str
    asset_id: str
    asset_revision: int
    asset_version_digest: str
    deployment_id: str
    deployment_revision: int
    deployment_artifact_digest: str
    context_id: str
    context_revision: int
    context_digest: str


@dataclass(frozen=True)
class NormalizedC2PAReceipt:
    operation: str
    adapter_id: str
    adapter_version: str
    standard: str
    receipt_id: str
    observed_at: float
    media_kind: str
    source_content_sha256: str
    content_sha256: str
    asset_id: str
    asset_revision: int
    asset_version_digest: str
    deployment_id: str
    deployment_revision: int
    deployment_artifact_digest: str
    context_id: str
    context_revision: int
    context_digest: str
    manifest_sha256: str
    claim_generator: str
    signing_time: float
    validation_state: str
    assertion_codes: tuple[str, ...]
    trust_chain_state: str
    receipt_sha256: str


@dataclass(frozen=True)
class SignedMediaResult:
    """Transient signed bytes plus the persisted digest-only record projection."""

    media: bytes
    record: dict[str, Any]


@runtime_checkable
class C2PAVerifier(Protocol):
    """Boundary implemented by a real C2PA validation library or service."""

    adapter_id: str
    adapter_version: str

    def is_available(self) -> bool: ...

    def verify(self, media: bytes, *, binding: C2PABinding) -> Mapping[str, Any]: ...

    def attest_receipt(
        self, receipt: Mapping[str, Any], *, binding: C2PABinding
    ) -> Mapping[str, Any]: ...


@runtime_checkable
class C2PASigner(Protocol):
    """Boundary implemented by a real C2PA signer with managed key custody."""

    adapter_id: str
    adapter_version: str

    def is_available(self) -> bool: ...

    def sign(
        self,
        media: bytes,
        *,
        binding: C2PABinding,
        assertion_codes: Sequence[str],
    ) -> tuple[bytes, Mapping[str, Any]]: ...

    def attest_receipt(
        self, receipt: Mapping[str, Any], *, binding: C2PABinding
    ) -> Mapping[str, Any]: ...


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("media provenance data must be finite JSON") from exc
    if len(encoded) > _MAX_RECEIPT_BYTES:
        raise ValueError("media provenance receipt exceeds the 128 KiB bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_text(value: object, label: str, limit: int = 256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    text = unicodedata.normalize("NFKC", value).strip()
    if not text or len(text) > limit or _CONTROL_RE.search(text):
        raise ValueError(f"{label} is invalid")
    return text


def _token(value: object, label: str) -> str:
    text = _safe_text(value, label, 128).lower()
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _identity(value: object, label: str) -> str:
    text = _safe_text(value, label, 256)
    if not _IDENTITY_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _digest(value: object, label: str) -> str:
    text = _safe_text(value, label, 71).lower()
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text.removeprefix("sha256:")


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _timestamp(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{label} must be a timestamp")
    stamp = float(value)
    if not math.isfinite(stamp) or stamp <= 0 or stamp > 100_000_000_000.0:
        raise ValueError(f"{label} must be a timestamp")
    return stamp


def _enum(value: object, enum_type: type[Enum], label: str) -> str:
    raw = value.value if isinstance(value, enum_type) else value
    try:
        return str(enum_type(raw).value)
    except (TypeError, ValueError) as exc:
        choices = ", ".join(sorted(str(item.value) for item in enum_type))
        raise ValueError(f"{label} must be one of: {choices}") from exc


def _asset_id(value: object) -> str:
    text = _safe_text(value, "asset_id", 36)
    if not _ASSET_RE.fullmatch(text):
        raise ValueError("asset_id must be an exact Model Risk asset id")
    return text


def _standard(value: object) -> str:
    text = _safe_text(value, "standard", 32).lower()
    if text != "c2pa" and not text.startswith("c2pa/"):
        raise ValueError("standard must identify C2PA")
    if not re.fullmatch(r"c2pa(?:/[0-9]+(?:\.[0-9]+)*)?", text):
        raise ValueError("standard must identify a bounded C2PA version")
    return text


def _actor(actor: MediaProvenanceActor) -> tuple[str, str]:
    if not isinstance(actor, MediaProvenanceActor):
        raise TypeError("actor must be a MediaProvenanceActor")
    kind = _enum(actor.kind, ActorKind, "actor kind")
    principal = _safe_text(actor.principal, "actor principal", 4_096)
    prefix = "user:" if kind == ActorKind.HUMAN.value else "system:"
    if not principal.startswith(prefix) or len(principal) <= len(prefix):
        raise ValueError(f"{kind} actor principal must start with {prefix}")
    return kind, principal


def _actor_ref(principal: str, tenant_ref: str) -> str:
    return "ACT-" + hashlib.sha256(f"{tenant_ref}\x00{principal}".encode()).hexdigest()[:24]


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise MediaProvenanceStateError(
            "media provenance operations require an explicit tenant"
        )
    return "TEN-" + hashlib.sha256(tenant.encode()).hexdigest()[:24]


def enabled() -> bool:
    """Return true only for explicit ``[ai_media_provenance] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_media_provenance")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise MediaProvenanceConfigError(
            "AI media provenance is disabled; set "
            "[ai_media_provenance] enable = true"
        )


def _configured_verification_adapter() -> tuple[str, str] | None:
    """Return the closed adapter name and independently approved tool digest."""

    try:
        from .config import load_config

        config = load_config()
    except Exception:
        raise MediaProvenanceConfigError(
            "AI media provenance configuration is unavailable"
        ) from None
    if not isinstance(config, Mapping):
        raise MediaProvenanceConfigError(
            "AI media provenance configuration is malformed"
        )
    section = config.get("ai_media_provenance")
    if not isinstance(section, Mapping):
        return None
    selected = section.get("verification_adapter")
    if selected is None:
        return None
    if selected != "c2patool":
        raise MediaProvenanceConfigError(
            "ai_media_provenance.verification_adapter must be exactly c2patool"
        )
    executable_sha256 = section.get("c2patool_executable_sha256")
    if not isinstance(executable_sha256, str) or re.fullmatch(
        r"[0-9a-f]{64}", executable_sha256
    ) is None:
        raise MediaProvenanceConfigError(
            "ai_media_provenance.c2patool_executable_sha256 must be an exact "
            "lowercase SHA-256 digest when c2patool verification is selected"
        )
    return selected, executable_sha256


def _assertions(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("assertion_codes must be an array")
    if not 1 <= len(value) <= _MAX_ASSERTIONS:
        raise ValueError("assertion_codes must contain 1 through 64 items")
    result = tuple(sorted({_token(item, "assertion code") for item in value}))
    if len(result) != len(value):
        raise ValueError("assertion_codes must be unique")
    return result


def _media(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("media must be bytes")
    data = bytes(value)
    if not data or len(data) > _MAX_MEDIA_BYTES:
        raise ValueError("media must contain 1 byte through 64 MiB")
    return data


def _normalize_receipt(
    value: Mapping[str, Any],
    *,
    expected_operation: ProvenanceOperation | str | None = None,
) -> NormalizedC2PAReceipt:
    if not isinstance(value, Mapping) or set(value) != _RECEIPT_FIELDS:
        raise ValueError("C2PA adapter receipt has unexpected or missing fields")
    payload = {key: value[key] for key in sorted(_RECEIPT_FIELDS - {"receipt_sha256"})}
    receipt_sha = _digest(value.get("receipt_sha256"), "receipt_sha256")
    if _sha256(payload) != receipt_sha:
        raise ValueError("C2PA adapter receipt digest does not match its payload")
    operation = _enum(value.get("operation"), ProvenanceOperation, "operation")
    if expected_operation is not None:
        expected = _enum(expected_operation, ProvenanceOperation, "expected operation")
        if operation != expected:
            raise ValueError(f"C2PA adapter receipt operation must be {expected}")
    media_kind = _enum(value.get("media_kind"), MediaKind, "media_kind")
    source_digest = _digest(value.get("source_content_sha256"), "source_content_sha256")
    content_digest = _digest(value.get("content_sha256"), "content_sha256")
    if operation == ProvenanceOperation.VERIFICATION.value and source_digest != content_digest:
        raise ValueError("verification receipt content digests must match")
    return NormalizedC2PAReceipt(
        operation=operation,
        adapter_id=_token(value.get("adapter_id"), "adapter_id"),
        adapter_version=_identity(value.get("adapter_version"), "adapter_version"),
        standard=_standard(value.get("standard")),
        receipt_id=_identity(value.get("receipt_id"), "receipt_id"),
        observed_at=_timestamp(value.get("observed_at"), "observed_at"),
        media_kind=media_kind,
        source_content_sha256=source_digest,
        content_sha256=content_digest,
        asset_id=_asset_id(value.get("asset_id")),
        asset_revision=_positive_int(value.get("asset_revision"), "asset_revision"),
        asset_version_digest=_digest(
            value.get("asset_version_digest"), "asset_version_digest"
        ),
        deployment_id=_identity(value.get("deployment_id"), "deployment_id"),
        deployment_revision=_positive_int(
            value.get("deployment_revision"), "deployment_revision"
        ),
        deployment_artifact_digest=_digest(
            value.get("deployment_artifact_digest"),
            "deployment_artifact_digest",
        ),
        context_id=_identity(value.get("context_id"), "context_id"),
        context_revision=_positive_int(value.get("context_revision"), "context_revision"),
        context_digest=_digest(value.get("context_digest"), "context_digest"),
        manifest_sha256=_digest(value.get("manifest_sha256"), "manifest_sha256"),
        claim_generator=_safe_text(value.get("claim_generator"), "claim_generator", 256),
        signing_time=_timestamp(value.get("signing_time"), "signing_time"),
        validation_state=_enum(
            value.get("validation_state"), ValidationState, "validation_state"
        ),
        assertion_codes=_assertions(value.get("assertion_codes")),
        trust_chain_state=_enum(
            value.get("trust_chain_state"), TrustChainState, "trust_chain_state"
        ),
        receipt_sha256=receipt_sha,
    )


def normalize_c2pa_receipt(
    receipt: Mapping[str, Any],
) -> NormalizedC2PAReceipt:
    """Validate the closed envelope and digest, without asserting cryptographic validity."""

    return _normalize_receipt(receipt)


def _adapter_identity(adapter: object) -> tuple[str, str]:
    try:
        adapter_id = _token(adapter.adapter_id, "adapter_id")  # type: ignore[attr-defined]
        adapter_version = _identity(
            adapter.adapter_version, "adapter_version"  # type: ignore[attr-defined]
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise MediaProvenanceUnavailable("C2PA adapter identity is unavailable") from exc
    return adapter_id, adapter_version


def _adapter_available(adapter: object | None) -> bool:
    if adapter is None:
        return False
    try:
        return bool(adapter.is_available())  # type: ignore[attr-defined]
    except Exception:
        return False


def _default_deployment_lookup(deployment_id: str) -> Mapping[str, Any] | None:
    from . import model_risk_assurance

    for deployment in model_risk_assurance.list_deployments():
        if deployment.get("deployment_id") == deployment_id:
            return deployment
    return None


def _payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in _IMMUTABLE_FIELDS}


def _state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "payload_sha256": record.get("payload_sha256"),
        "recorded_by_kind": record.get("recorded_by_kind"),
        "recorded_by": record.get("recorded_by"),
        "status": record.get("status"),
        "release": record.get("release"),
    }


class MediaProvenanceService:
    """Govern C2PA adapter receipts without pretending to implement C2PA."""

    def __init__(
        self,
        *,
        records: GovernedRecordStore | None = None,
        verifier: C2PAVerifier | None = None,
        signer: C2PASigner | None = None,
        asset_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        deployment_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        context_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        clock: Callable[[], float] | None = None,
        enforce_feature: bool = True,
    ) -> None:
        for lookup, label in (
            (asset_lookup, "asset_lookup"),
            (deployment_lookup, "deployment_lookup"),
            (context_lookup, "context_lookup"),
            (clock, "clock"),
        ):
            if lookup is not None and not callable(lookup):
                raise ValueError(f"{label} must be callable")
        if not isinstance(enforce_feature, bool):
            raise ValueError("enforce_feature must be a boolean")
        self._records = records or _RECORDS
        self._verifier = verifier
        self._signer = signer
        self._asset_lookup = asset_lookup
        self._deployment_lookup = deployment_lookup
        self._context_lookup = context_lookup
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        _ = self._records.backend_kind
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._records.authoritative_time
        return _timestamp(source(), "authority time")

    def capability_status(self) -> dict[str, Any]:
        """Report adapter reality; absence is unsupported, never simulated support."""

        verification_configured = self._verifier is not None
        signing_configured = self._signer is not None
        verification_available = _adapter_available(self._verifier)
        signing_available = _adapter_available(self._signer)

        def capability(
            adapter: C2PAVerifier | C2PASigner | None,
            *,
            configured: bool,
            available: bool,
        ) -> dict[str, Any]:
            adapter_id: str | None = None
            adapter_version: str | None = None
            if adapter is not None:
                try:
                    adapter_id = _token(adapter.adapter_id, "adapter_id")
                except (AttributeError, TypeError, ValueError):
                    pass
                if available:
                    try:
                        adapter_id, adapter_version = _adapter_identity(adapter)
                    except MediaProvenanceUnavailable:
                        available = False
            return {
                "configured": configured,
                "available": available,
                "status": (
                    "available"
                    if available
                    else "unavailable" if configured else "unsupported"
                ),
                "adapter_id": adapter_id,
                "adapter_version": adapter_version,
            }

        return {
            "enabled": enabled() if self._enforce_feature else True,
            "standard": "C2PA",
            "implementation": "external_adapter_required",
            "verification": capability(
                self._verifier,
                configured=verification_configured,
                available=verification_available,
            ),
            "signing": capability(
                self._signer,
                configured=signing_configured,
                available=signing_available,
            ),
            "limitations": list(STANDARDS_LIMITATIONS),
        }

    def _require_adapter(self, operation: str) -> C2PAVerifier | C2PASigner:
        adapter = (
            self._verifier
            if operation == ProvenanceOperation.VERIFICATION.value
            else self._signer
        )
        if adapter is None:
            raise MediaProvenanceUnavailable(
                f"C2PA {operation} is unsupported without an explicit real adapter"
            )
        if not _adapter_available(adapter):
            raise MediaProvenanceUnavailable(f"configured C2PA {operation} adapter is unavailable")
        _adapter_identity(adapter)
        return adapter

    def _asset_binding(self, asset_id: object) -> dict[str, Any]:
        asset = _asset_id(asset_id)
        lookup = self._asset_lookup
        if lookup is None:
            from . import model_risk_assurance

            lookup = model_risk_assurance.get_observation
        try:
            row = lookup(asset)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise MediaProvenanceBindingError("Model Risk asset lookup failed") from exc
        if not isinstance(row, Mapping):
            raise MediaProvenanceBindingError("Model Risk asset does not exist")
        try:
            bound = {
                "asset_id": _asset_id(row.get("asset_id")),
                "asset_revision": _positive_int(row.get("revision"), "asset revision"),
                "asset_version_digest": _digest(
                    row.get("version_digest"), "asset version_digest"
                ),
            }
        except (TypeError, ValueError) as exc:
            raise MediaProvenanceBindingError("Model Risk asset binding is malformed") from exc
        if bound["asset_id"] != asset:
            raise MediaProvenanceBindingError("Model Risk asset lookup changed identity")
        return bound

    def _deployment_binding(
        self,
        deployment_id: object,
        *,
        asset: Mapping[str, Any],
        require_current_artifact: bool = True,
    ) -> dict[str, Any]:
        identity = _identity(deployment_id, "deployment_id")
        lookup = self._deployment_lookup or _default_deployment_lookup
        try:
            row = lookup(identity)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise MediaProvenanceBindingError("Model Risk deployment lookup failed") from exc
        if not isinstance(row, Mapping):
            raise MediaProvenanceBindingError("Model Risk deployment does not exist")
        try:
            bound = {
                "deployment_id": _identity(row.get("deployment_id"), "deployment_id"),
                "deployment_revision": _positive_int(
                    row.get("revision"), "deployment revision"
                ),
                "deployment_artifact_digest": _digest(
                    row.get("artifact_digest"), "deployment artifact_digest"
                ),
                "asset_id": _asset_id(row.get("asset_id")),
            }
        except (TypeError, ValueError) as exc:
            raise MediaProvenanceBindingError("Model Risk deployment binding is malformed") from exc
        if bound["deployment_id"] != identity:
            raise MediaProvenanceBindingError("Model Risk deployment lookup changed identity")
        if bound["asset_id"] != asset["asset_id"]:
            raise MediaProvenanceBindingError("deployment belongs to a different asset")
        if row.get("status") != "deployed":
            raise MediaProvenanceBindingError("Model Risk deployment is not deployed")
        if (
            require_current_artifact
            and bound["deployment_artifact_digest"] != asset["asset_version_digest"]
        ):
            raise MediaProvenanceBindingError("deployment is not bound to the current asset version")
        return bound

    def _context_binding(
        self, context_id: object, *, deployment: Mapping[str, Any]
    ) -> dict[str, Any]:
        identity = _identity(context_id, "context_id")
        if self._context_lookup is None:
            raise MediaProvenanceBindingError(
                "a current release-context authority lookup is required"
            )
        try:
            row = self._context_lookup(identity)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise MediaProvenanceBindingError("release-context lookup failed") from exc
        if not isinstance(row, Mapping):
            raise MediaProvenanceBindingError("release context does not exist")
        try:
            bound = {
                "context_id": _identity(row.get("context_id"), "context_id"),
                "context_revision": _positive_int(
                    row.get("revision"), "context revision"
                ),
                "context_digest": _digest(row.get("context_digest"), "context_digest"),
                "deployment_id": _identity(
                    row.get("deployment_id"), "context deployment_id"
                ),
            }
        except (TypeError, ValueError) as exc:
            raise MediaProvenanceBindingError("release-context binding is malformed") from exc
        if bound["context_id"] != identity:
            raise MediaProvenanceBindingError("release-context lookup changed identity")
        if bound["deployment_id"] != deployment["deployment_id"]:
            raise MediaProvenanceBindingError("context belongs to a different deployment")
        if row.get("status") != "active":
            raise MediaProvenanceBindingError("release context is not active")
        return bound

    def _binding(
        self,
        *,
        media_kind: object,
        source_content_sha256: object,
        asset_id: object,
        deployment_id: object,
        context_id: object,
        require_current_artifact: bool = True,
    ) -> C2PABinding:
        asset = self._asset_binding(asset_id)
        deployment = self._deployment_binding(
            deployment_id,
            asset=asset,
            require_current_artifact=require_current_artifact,
        )
        context = self._context_binding(context_id, deployment=deployment)
        return C2PABinding(
            media_kind=_enum(media_kind, MediaKind, "media_kind"),
            source_content_sha256=_digest(
                source_content_sha256, "source_content_sha256"
            ),
            asset_id=asset["asset_id"],
            asset_revision=asset["asset_revision"],
            asset_version_digest=asset["asset_version_digest"],
            deployment_id=deployment["deployment_id"],
            deployment_revision=deployment["deployment_revision"],
            deployment_artifact_digest=deployment["deployment_artifact_digest"],
            context_id=context["context_id"],
            context_revision=context["context_revision"],
            context_digest=context["context_digest"],
        )

    def _binding_from_receipt(self, receipt: NormalizedC2PAReceipt) -> C2PABinding:
        return self._binding(
            media_kind=receipt.media_kind,
            source_content_sha256=receipt.source_content_sha256,
            asset_id=receipt.asset_id,
            deployment_id=receipt.deployment_id,
            context_id=receipt.context_id,
        )

    @staticmethod
    def _require_receipt_binding(
        receipt: NormalizedC2PAReceipt,
        binding: C2PABinding,
        *,
        expected_content_sha256: str | None = None,
    ) -> None:
        fields = (
            "media_kind",
            "source_content_sha256",
            "asset_id",
            "asset_revision",
            "asset_version_digest",
            "deployment_id",
            "deployment_revision",
            "deployment_artifact_digest",
            "context_id",
            "context_revision",
            "context_digest",
        )
        if any(getattr(receipt, field) != getattr(binding, field) for field in fields):
            raise MediaProvenanceBindingError(
                "C2PA adapter receipt does not match current exact authority"
            )
        if expected_content_sha256 is not None and (
            receipt.content_sha256 != expected_content_sha256
        ):
            raise MediaProvenanceBindingError(
                "C2PA adapter receipt does not bind the exact media bytes"
            )

    @staticmethod
    def _require_adapter_receipt(
        receipt: NormalizedC2PAReceipt, adapter: object
    ) -> None:
        adapter_id, adapter_version = _adapter_identity(adapter)
        if (
            receipt.adapter_id != adapter_id
            or receipt.adapter_version != adapter_version
        ):
            raise MediaProvenanceUnavailable(
                "C2PA receipt identity does not match the configured adapter"
            )

    def _binding_state(self, record: Mapping[str, Any]) -> tuple[bool, list[str], C2PABinding]:
        current = self._binding(
            media_kind=record["media_kind"],
            source_content_sha256=record["source_content_sha256"],
            asset_id=record["asset_id"],
            deployment_id=record["deployment_id"],
            context_id=record["context_id"],
            require_current_artifact=False,
        )
        reasons: list[str] = []
        for field in (
            "asset_revision",
            "asset_version_digest",
            "deployment_revision",
            "deployment_artifact_digest",
            "context_revision",
            "context_digest",
        ):
            if record[field] != getattr(current, field):
                reasons.append(f"{field}_changed")
        return not reasons, reasons, current

    def _validate_release(self, value: object) -> dict[str, Any] | None:
        if value is None:
            return None
        if not isinstance(value, Mapping) or set(value) != _RELEASE_FIELDS:
            raise MediaProvenanceStateError("stored release record is malformed")
        try:
            prepared_at = _timestamp(value.get("prepared_at"), "prepared_at")
            purpose = _token(value.get("purpose_code"), "purpose_code")
            preparation_evidence = _digest(
                value.get("preparation_evidence_sha256"),
                "preparation_evidence_sha256",
            )
            prepared_kind, prepared_by = _actor(
                MediaProvenanceActor(ActorKind.HUMAN, value.get("prepared_by"))
            )
            if prepared_kind != ActorKind.HUMAN.value:
                raise ValueError("preparer must be human")
            outcome = value.get("outcome")
            reviewed_at = value.get("reviewed_at")
            review_evidence = value.get("review_evidence_sha256")
            reviewed_by = value.get("reviewed_by")
            if outcome is None:
                if any(item is not None for item in (reviewed_at, review_evidence, reviewed_by)):
                    raise ValueError("pending release contains review fields")
                normalized_outcome = None
                normalized_reviewed_at = None
                normalized_review_evidence = None
                normalized_reviewer = None
            else:
                normalized_outcome = _enum(outcome, ReleaseOutcome, "release outcome")
                normalized_reviewed_at = _timestamp(reviewed_at, "reviewed_at")
                normalized_review_evidence = _digest(
                    review_evidence, "review_evidence_sha256"
                )
                _, normalized_reviewer = _actor(
                    MediaProvenanceActor(ActorKind.HUMAN, reviewed_by)
                )
                if normalized_reviewer == prepared_by:
                    raise ValueError("release review violates four-eyes")
        except (TypeError, ValueError) as exc:
            raise MediaProvenanceStateError("stored release record is malformed") from exc
        return {
            "prepared_at": prepared_at,
            "purpose_code": purpose,
            "preparation_evidence_sha256": preparation_evidence,
            "prepared_by": prepared_by,
            "reviewed_at": normalized_reviewed_at,
            "outcome": normalized_outcome,
            "review_evidence_sha256": normalized_review_evidence,
            "reviewed_by": normalized_reviewer,
        }

    def _validate_record(self, record: Mapping[str, Any], tenant_ref: str) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            raise MediaProvenanceStateError("stored media provenance is not an object")
        if (set(record) - _RECORD_FIELDS - _STORE_METADATA) or (
            _RECORD_FIELDS - set(record)
        ):
            raise MediaProvenanceStateError("stored media provenance shape is malformed")
        try:
            record_id = _safe_text(record.get("id"), "record id", 36)
            if not _RECORD_ID_RE.fullmatch(record_id):
                raise ValueError("record id is invalid")
            stored_tenant = _safe_text(record.get("tenant_ref"), "tenant_ref", 28)
            if not _TENANT_REF_RE.fullmatch(stored_tenant) or stored_tenant != tenant_ref:
                raise ValueError("tenant binding is invalid")
            if record.get("schema") != PROVENANCE_RECORD_SCHEMA:
                raise ValueError("record schema is unsupported")
            _positive_int(record.get("revision"), "revision")
            _timestamp(record.get("created_at"), "created_at")
            _timestamp(record.get("updated_at"), "updated_at")
            operation = _enum(
                record.get("operation"), ProvenanceOperation, "operation"
            )
            _token(record.get("adapter_id"), "adapter_id")
            _identity(record.get("adapter_version"), "adapter_version")
            _standard(record.get("standard"))
            observed_at = _timestamp(record.get("observed_at"), "observed_at")
            _enum(record.get("media_kind"), MediaKind, "media_kind")
            for field in (
                "source_content_sha256",
                "content_sha256",
                "asset_version_digest",
                "deployment_artifact_digest",
                "context_digest",
                "manifest_sha256",
                "receipt_id_sha256",
                "receipt_sha256",
                "payload_sha256",
                "state_sha256",
            ):
                _digest(record.get(field), field)
            _asset_id(record.get("asset_id"))
            _positive_int(record.get("asset_revision"), "asset_revision")
            _identity(record.get("deployment_id"), "deployment_id")
            _positive_int(record.get("deployment_revision"), "deployment_revision")
            _identity(record.get("context_id"), "context_id")
            _positive_int(record.get("context_revision"), "context_revision")
            _safe_text(record.get("claim_generator"), "claim_generator", 256)
            signing_time = _timestamp(record.get("signing_time"), "signing_time")
            _enum(record.get("validation_state"), ValidationState, "validation_state")
            assertions = _assertions(record.get("assertion_codes"))
            _enum(record.get("trust_chain_state"), TrustChainState, "trust_chain_state")
            actor_kind, actor_name = _actor(
                MediaProvenanceActor(
                    record.get("recorded_by_kind"), record.get("recorded_by")
                )
            )
            status = _token(record.get("status"), "status")
            release = self._validate_release(record.get("release"))
            if (
                operation == ProvenanceOperation.VERIFICATION.value
                and record.get("source_content_sha256") != record.get("content_sha256")
            ):
                raise ValueError("verification content digest binding is inconsistent")
            if signing_time > observed_at + _MAX_FUTURE_SKEW_SECONDS:
                raise ValueError("signing time is after the observation")
            if status == "observed" and release is not None:
                raise ValueError("observed record cannot contain a release")
            if status == "release_pending" and (
                release is None or release["outcome"] is not None
            ):
                raise ValueError("pending release lifecycle is inconsistent")
            outcomes = {
                ReleaseOutcome.APPROVED.value: "release_approved",
                ReleaseOutcome.REJECTED.value: "release_rejected",
                ReleaseOutcome.NEEDS_REMEDIATION.value: "release_needs_remediation",
            }
            if status not in {"observed", "release_pending", *outcomes.values()}:
                raise ValueError("record status is unsupported")
            if status in outcomes.values() and (
                release is None or outcomes.get(release["outcome"]) != status
            ):
                raise ValueError("reviewed release lifecycle is inconsistent")
            if status == "release_approved" and (
                record.get("validation_state") != ValidationState.VALID.value
                or record.get("trust_chain_state") != TrustChainState.TRUSTED.value
            ):
                raise ValueError("approved release lacks valid and trusted provenance")
        except MediaProvenanceStateError:
            raise
        except (TypeError, ValueError) as exc:
            raise MediaProvenanceStateError("stored media provenance is malformed") from exc
        if _sha256(_payload(record)) != record.get("payload_sha256"):
            raise MediaProvenanceStateError("stored provenance payload digest is malformed")
        if _sha256(_state(record)) != record.get("state_sha256"):
            raise MediaProvenanceStateError("stored provenance state digest is malformed")
        normalized = dict(record)
        normalized["assertion_codes"] = list(assertions)
        normalized["recorded_by_kind"] = actor_kind
        normalized["recorded_by"] = actor_name
        normalized["release"] = release
        return normalized

    def _public(self, record: Mapping[str, Any]) -> dict[str, Any]:
        current, stale_reasons, binding = self._binding_state(record)
        release = record["release"]
        return {
            "schema": SAFE_EXPORT_SCHEMA,
            "provenance_id": record["id"],
            "revision": record["revision"],
            "operation": record["operation"],
            "adapter": {
                "id": record["adapter_id"],
                "version": record["adapter_version"],
            },
            "adapter_reported_standard": record["standard"],
            "media_kind": record["media_kind"],
            "source_content_sha256": record["source_content_sha256"],
            "content_sha256": record["content_sha256"],
            "asset_binding": {
                "asset_id": record["asset_id"],
                "revision": record["asset_revision"],
                "version_digest": record["asset_version_digest"],
            },
            "deployment_binding": {
                "deployment_id": record["deployment_id"],
                "revision": record["deployment_revision"],
                "artifact_digest": record["deployment_artifact_digest"],
            },
            "context_binding": {
                "context_id": record["context_id"],
                "revision": record["context_revision"],
                "context_digest": record["context_digest"],
            },
            "manifest_sha256": record["manifest_sha256"],
            "claim_generator": record["claim_generator"],
            "signing_time": record["signing_time"],
            "observed_at": record["observed_at"],
            "adapter_reported_validation_state": record["validation_state"],
            "adapter_reported_trust_chain_state": record["trust_chain_state"],
            "coverage": {
                "assertion_codes": list(record["assertion_codes"]),
                "assertion_count": len(record["assertion_codes"]),
                "content_digest_only": True,
                "media_bytes_persisted": False,
            },
            "receipt_sha256": record["receipt_sha256"],
            "payload_sha256": record["payload_sha256"],
            "recorded_by_kind": record["recorded_by_kind"],
            "recorded_by_ref": _actor_ref(record["recorded_by"], record["tenant_ref"]),
            "status": record["status"],
            "release": (
                None
                if release is None
                else {
                    "prepared_at": release["prepared_at"],
                    "purpose_code": release["purpose_code"],
                    "preparation_evidence_sha256": release[
                        "preparation_evidence_sha256"
                    ],
                    "prepared_by_ref": _actor_ref(
                        release["prepared_by"], record["tenant_ref"]
                    ),
                    "reviewed_at": release["reviewed_at"],
                    "outcome": release["outcome"],
                    "review_evidence_sha256": release[
                        "review_evidence_sha256"
                    ],
                    "reviewed_by_ref": (
                        None
                        if release["reviewed_by"] is None
                        else _actor_ref(release["reviewed_by"], record["tenant_ref"])
                    ),
                }
            ),
            "binding_current": current,
            "stale_reasons": stale_reasons,
            "current_authority": {
                "asset_revision": binding.asset_revision,
                "asset_version_digest": binding.asset_version_digest,
                "deployment_revision": binding.deployment_revision,
                "deployment_artifact_digest": binding.deployment_artifact_digest,
                "context_revision": binding.context_revision,
                "context_digest": binding.context_digest,
            },
            "certification_claim": False,
            "limitations": list(STANDARDS_LIMITATIONS),
        }

    def _admit(
        self,
        receipt: NormalizedC2PAReceipt,
        *,
        actor: MediaProvenanceActor,
        tenant_ref: str,
    ) -> dict[str, Any]:
        actor_kind, actor_name = _actor(actor)
        now = self._now()
        if receipt.observed_at > now + _MAX_FUTURE_SKEW_SECONDS:
            raise ValueError("observed_at is too far in the future")
        if receipt.signing_time > receipt.observed_at + _MAX_FUTURE_SKEW_SECONDS:
            raise ValueError("signing_time is after the observation")
        identity_material = (
            f"{tenant_ref}\x00{receipt.operation}\x00{receipt.adapter_id}"
            f"\x00{receipt.receipt_id}"
        )
        identity_sha = hashlib.sha256(identity_material.encode()).hexdigest()
        record_id = f"AMP-{identity_sha[:32]}"
        receipt_id_sha = hashlib.sha256(
            f"{tenant_ref}\x00{receipt.receipt_id}".encode()
        ).hexdigest()
        payload = {
            "schema": PROVENANCE_RECORD_SCHEMA,
            "tenant_ref": tenant_ref,
            "operation": receipt.operation,
            "adapter_id": receipt.adapter_id,
            "adapter_version": receipt.adapter_version,
            "standard": receipt.standard,
            "observed_at": receipt.observed_at,
            "media_kind": receipt.media_kind,
            "source_content_sha256": receipt.source_content_sha256,
            "content_sha256": receipt.content_sha256,
            "asset_id": receipt.asset_id,
            "asset_revision": receipt.asset_revision,
            "asset_version_digest": receipt.asset_version_digest,
            "deployment_id": receipt.deployment_id,
            "deployment_revision": receipt.deployment_revision,
            "deployment_artifact_digest": receipt.deployment_artifact_digest,
            "context_id": receipt.context_id,
            "context_revision": receipt.context_revision,
            "context_digest": receipt.context_digest,
            "manifest_sha256": receipt.manifest_sha256,
            "claim_generator": receipt.claim_generator,
            "signing_time": receipt.signing_time,
            "validation_state": receipt.validation_state,
            "assertion_codes": list(receipt.assertion_codes),
            "trust_chain_state": receipt.trust_chain_state,
            "receipt_id_sha256": receipt_id_sha,
            "receipt_sha256": receipt.receipt_sha256,
        }
        payload_sha = _sha256(payload)
        current = self._records.get(record_id)
        if current is not None:
            validated = self._validate_record(current, tenant_ref)
            if validated["payload_sha256"] != payload_sha:
                raise MediaProvenanceIdempotencyConflict(
                    "C2PA receipt identity was already used for different content"
                )
            return self._public(validated)
        record = {
            "id": record_id,
            **payload,
            "payload_sha256": payload_sha,
            "recorded_by_kind": actor_kind,
            "recorded_by": actor_name,
            "status": "observed",
            "release": None,
        }
        record["state_sha256"] = _sha256(_state(record))
        try:
            saved = self._records.create(
                record,
                action="admit_media_provenance",
                actor=actor_name,
                max_records=_MAX_RECORDS,
            )
        except RecordConflict as exc:
            concurrent = self._records.get(record_id)
            if concurrent is None:
                raise
            validated = self._validate_record(concurrent, tenant_ref)
            if validated["payload_sha256"] != payload_sha:
                raise MediaProvenanceIdempotencyConflict(
                    "C2PA receipt identity was concurrently reused"
                ) from exc
            saved = validated
        return self._public(self._validate_record(saved, tenant_ref))

    def verify_media(
        self,
        media: bytes,
        *,
        media_kind: MediaKind | str,
        asset_id: str,
        deployment_id: str,
        context_id: str,
        actor: MediaProvenanceActor,
    ) -> dict[str, Any]:
        """Transiently verify exact bytes through the configured real adapter."""

        tenant_ref = self._require_active()
        adapter = self._require_adapter(ProvenanceOperation.VERIFICATION.value)
        data = _media(media)
        content_sha = hashlib.sha256(data).hexdigest()
        binding = self._binding(
            media_kind=media_kind,
            source_content_sha256=content_sha,
            asset_id=asset_id,
            deployment_id=deployment_id,
            context_id=context_id,
        )
        try:
            raw = adapter.verify(data, binding=binding)  # type: ignore[union-attr]
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise MediaProvenanceUnavailable("C2PA verification adapter failed") from exc
        receipt = _normalize_receipt(
            raw, expected_operation=ProvenanceOperation.VERIFICATION
        )
        self._require_adapter_receipt(receipt, adapter)
        self._require_receipt_binding(
            receipt, binding, expected_content_sha256=content_sha
        )
        return self._admit(receipt, actor=actor, tenant_ref=tenant_ref)

    def ingest_verification_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        actor: MediaProvenanceActor,
    ) -> dict[str, Any]:
        """Admit a detached receipt only after the real adapter attests it."""

        tenant_ref = self._require_active()
        adapter = self._require_adapter(ProvenanceOperation.VERIFICATION.value)
        provisional = _normalize_receipt(
            receipt, expected_operation=ProvenanceOperation.VERIFICATION
        )
        binding = self._binding_from_receipt(provisional)
        self._require_receipt_binding(provisional, binding)
        try:
            attested = adapter.attest_receipt(receipt, binding=binding)  # type: ignore[union-attr]
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise MediaProvenanceUnavailable(
                "C2PA verifier could not authenticate the detached receipt"
            ) from exc
        normalized = _normalize_receipt(
            attested, expected_operation=ProvenanceOperation.VERIFICATION
        )
        if normalized != provisional:
            raise MediaProvenanceUnavailable(
                "C2PA adapter attestation changed the normalized receipt"
            )
        self._require_adapter_receipt(normalized, adapter)
        return self._admit(normalized, actor=actor, tenant_ref=tenant_ref)

    def sign_media(
        self,
        media: bytes,
        *,
        media_kind: MediaKind | str,
        asset_id: str,
        deployment_id: str,
        context_id: str,
        assertion_codes: Sequence[str],
        actor: MediaProvenanceActor,
    ) -> SignedMediaResult:
        """Sign transient bytes through a real adapter and store only digests."""

        tenant_ref = self._require_active()
        adapter = self._require_adapter(ProvenanceOperation.SIGNING.value)
        data = _media(media)
        requested_assertions = _assertions(assertion_codes)
        source_sha = hashlib.sha256(data).hexdigest()
        binding = self._binding(
            media_kind=media_kind,
            source_content_sha256=source_sha,
            asset_id=asset_id,
            deployment_id=deployment_id,
            context_id=context_id,
        )
        try:
            result = adapter.sign(  # type: ignore[union-attr]
                data,
                binding=binding,
                assertion_codes=requested_assertions,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise MediaProvenanceUnavailable("C2PA signing adapter failed") from exc
        if not isinstance(result, tuple) or len(result) != 2:
            raise MediaProvenanceUnavailable(
                "C2PA signing adapter returned an invalid result"
            )
        signed_media = _media(result[0])
        receipt = _normalize_receipt(
            result[1], expected_operation=ProvenanceOperation.SIGNING
        )
        self._require_adapter_receipt(receipt, adapter)
        self._require_receipt_binding(
            receipt,
            binding,
            expected_content_sha256=hashlib.sha256(signed_media).hexdigest(),
        )
        if not set(requested_assertions).issubset(receipt.assertion_codes):
            raise MediaProvenanceUnavailable(
                "C2PA signer omitted a requested assertion from its receipt"
            )
        record = self._admit(receipt, actor=actor, tenant_ref=tenant_ref)
        return SignedMediaResult(media=signed_media, record=record)

    def ingest_signing_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        actor: MediaProvenanceActor,
    ) -> dict[str, Any]:
        """Admit a detached signing receipt only after signer attestation."""

        tenant_ref = self._require_active()
        adapter = self._require_adapter(ProvenanceOperation.SIGNING.value)
        provisional = _normalize_receipt(
            receipt, expected_operation=ProvenanceOperation.SIGNING
        )
        binding = self._binding_from_receipt(provisional)
        self._require_receipt_binding(provisional, binding)
        try:
            attested = adapter.attest_receipt(receipt, binding=binding)  # type: ignore[union-attr]
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise MediaProvenanceUnavailable(
                "C2PA signer could not authenticate the detached receipt"
            ) from exc
        normalized = _normalize_receipt(
            attested, expected_operation=ProvenanceOperation.SIGNING
        )
        if normalized != provisional:
            raise MediaProvenanceUnavailable(
                "C2PA signer attestation changed the normalized receipt"
            )
        self._require_adapter_receipt(normalized, adapter)
        return self._admit(normalized, actor=actor, tenant_ref=tenant_ref)

    def get_record(self, provenance_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        identity = _safe_text(provenance_id, "provenance_id", 36)
        if not _RECORD_ID_RE.fullmatch(identity):
            raise ValueError("provenance_id is invalid")
        row = self._records.get(identity)
        if row is None:
            return None
        return self._public(self._validate_record(row, tenant_ref))

    def list_records(self, *, asset_id: str | None = None) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        asset = None if asset_id is None else _asset_id(asset_id)
        rows = self._records.list(limit=_MAX_RECORDS + 1)
        if len(rows) > _MAX_RECORDS:
            raise MediaProvenanceStateError("media provenance namespace exceeds its bound")
        validated = [self._validate_record(row, tenant_ref) for row in rows]
        if asset is not None:
            validated = [row for row in validated if row["asset_id"] == asset]
        return [
            self._public(row)
            for row in sorted(validated, key=lambda item: (item["observed_at"], item["id"]))
        ]

    def release_references(self, *, limit: int = 200) -> list[dict[str, Any]]:
        """Release references this workspace's media records already use.

        Newest use first.  Only stored, integrity-checked records of the
        active tenant are read; the release-context authority is not consulted,
        so a listed reference is a suggestion that checking or signing still
        resolves and binds exactly as before.
        """

        tenant_ref = self._require_active()
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_REFERENCE_LIST
        ):
            raise ValueError(f"limit must be between 1 and {_MAX_REFERENCE_LIST}")
        rows = self._records.list(limit=_MAX_RECORDS + 1)
        if len(rows) > _MAX_RECORDS:
            raise MediaProvenanceStateError("media provenance namespace exceeds its bound")
        used: dict[str, dict[str, Any]] = {}
        for row in rows:
            record = self._validate_record(row, tenant_ref)
            entry = used.setdefault(
                record["context_id"],
                {"last_used_at": 0.0, "deployment_ids": set(), "record_count": 0},
            )
            entry["last_used_at"] = max(entry["last_used_at"], float(record["observed_at"]))
            entry["deployment_ids"].add(record["deployment_id"])
            entry["record_count"] += 1
        ordered = sorted(used.items(), key=lambda item: (-item[1]["last_used_at"], item[0]))
        return [
            {
                "context_id": context_id,
                "last_used_at": entry["last_used_at"],
                "deployment_ids": sorted(entry["deployment_ids"]),
                "record_count": entry["record_count"],
            }
            for context_id, entry in ordered[:limit]
        ]

    def prepare_release_record(
        self,
        provenance_id: str,
        *,
        expected_revision: int,
        purpose_code: str,
        evidence_sha256: str,
        actor: MediaProvenanceActor,
    ) -> dict[str, Any]:
        """CAS-prepare a release record by an authenticated human."""

        tenant_ref = self._require_active()
        identity = _safe_text(provenance_id, "provenance_id", 36)
        if not _RECORD_ID_RE.fullmatch(identity):
            raise ValueError("provenance_id is invalid")
        expected = _positive_int(expected_revision, "expected_revision")
        kind, preparer = _actor(actor)
        if kind != ActorKind.HUMAN.value:
            raise ValueError("release preparation requires a human actor")
        purpose = _token(purpose_code, "purpose_code")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        raw = self._records.get(identity)
        if raw is None:
            raise MediaProvenanceStateError("media provenance record does not exist")
        current = self._validate_record(raw, tenant_ref)
        fresh, _, _ = self._binding_state(current)
        if not fresh:
            raise MediaProvenanceStateError("stale provenance cannot be prepared for release")
        if current["status"] != "observed":
            raise MediaProvenanceStateError("release record already exists")
        if (
            current["validation_state"] != ValidationState.VALID.value
            or current["trust_chain_state"] != TrustChainState.TRUSTED.value
        ):
            raise MediaProvenanceStateError(
                "release requires adapter-reported valid and trusted provenance"
            )
        prepared_at = self._now()

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_record(row, tenant_ref)
            if validated["status"] != "observed":
                raise MediaProvenanceStateError("release record already exists")
            row["status"] = "release_pending"
            row["release"] = {
                "prepared_at": prepared_at,
                "purpose_code": purpose,
                "preparation_evidence_sha256": evidence,
                "prepared_by": preparer,
                "reviewed_at": None,
                "outcome": None,
                "review_evidence_sha256": None,
                "reviewed_by": None,
            }
            row["state_sha256"] = _sha256(_state(row))

        saved = self._records.update(
            identity,
            mutate,
            expected_revision=expected,
            action="prepare_media_provenance_release",
            actor=preparer,
        )
        if saved is None:
            raise MediaProvenanceStateError("media provenance record disappeared")
        return self._public(self._validate_record(saved, tenant_ref))

    def review_release_record(
        self,
        provenance_id: str,
        *,
        expected_revision: int,
        outcome: ReleaseOutcome | str,
        evidence_sha256: str,
        actor: MediaProvenanceActor,
    ) -> dict[str, Any]:
        """CAS-review a prepared release by a different authenticated human."""

        tenant_ref = self._require_active()
        identity = _safe_text(provenance_id, "provenance_id", 36)
        if not _RECORD_ID_RE.fullmatch(identity):
            raise ValueError("provenance_id is invalid")
        expected = _positive_int(expected_revision, "expected_revision")
        kind, reviewer = _actor(actor)
        if kind != ActorKind.HUMAN.value:
            raise ValueError("release review requires a human actor")
        decision = _enum(outcome, ReleaseOutcome, "release outcome")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        raw = self._records.get(identity)
        if raw is None:
            raise MediaProvenanceStateError("media provenance record does not exist")
        current = self._validate_record(raw, tenant_ref)
        fresh, _, _ = self._binding_state(current)
        if not fresh:
            raise MediaProvenanceStateError("stale provenance cannot be reviewed for release")
        if current["status"] != "release_pending" or current["release"] is None:
            raise MediaProvenanceStateError("release is not pending review")
        if current["release"]["prepared_by"] == reviewer:
            raise MediaProvenanceStateError(
                "four-eyes release review requires a different human"
            )
        reviewed_at = self._now()

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_record(row, tenant_ref)
            release = validated["release"]
            if validated["status"] != "release_pending" or release is None:
                raise MediaProvenanceStateError("release is not pending review")
            if release["prepared_by"] == reviewer:
                raise MediaProvenanceStateError(
                    "four-eyes release review requires a different human"
                )
            row["status"] = {
                ReleaseOutcome.APPROVED.value: "release_approved",
                ReleaseOutcome.REJECTED.value: "release_rejected",
                ReleaseOutcome.NEEDS_REMEDIATION.value: "release_needs_remediation",
            }[decision]
            row["release"] = {
                **release,
                "reviewed_at": reviewed_at,
                "outcome": decision,
                "review_evidence_sha256": evidence,
                "reviewed_by": reviewer,
            }
            row["state_sha256"] = _sha256(_state(row))

        saved = self._records.update(
            identity,
            mutate,
            expected_revision=expected,
            action="review_media_provenance_release",
            actor=reviewer,
        )
        if saved is None:
            raise MediaProvenanceStateError("media provenance record disappeared")
        return self._public(self._validate_record(saved, tenant_ref))

    def export_record(self, provenance_id: str) -> dict[str, Any]:
        """Return a safe digest-only projection with explicit limitations."""

        record = self.get_record(provenance_id)
        if record is None:
            raise MediaProvenanceStateError("media provenance record does not exist")
        return record


default_service = MediaProvenanceService()


def configured_media_provenance() -> MediaProvenanceService:
    """Build the explicitly selected verifier; never infer signing custody."""

    require_enabled()
    configured = _configured_verification_adapter()
    if configured is None:
        return default_service
    _selected, executable_sha256 = configured
    from .ai_media_provenance_c2pa import C2PAToolVerifier

    return MediaProvenanceService(
        verifier=C2PAToolVerifier(
            expected_executable_sha256=executable_sha256,
        )
    )


__all__ = [
    "ADAPTER_RECEIPT_SCHEMA",
    "ActorKind",
    "C2PABinding",
    "C2PASigner",
    "C2PAVerifier",
    "MediaKind",
    "MediaProvenanceActor",
    "MediaProvenanceBindingError",
    "MediaProvenanceConfigError",
    "MediaProvenanceError",
    "MediaProvenanceIdempotencyConflict",
    "MediaProvenanceService",
    "MediaProvenanceStateError",
    "MediaProvenanceUnavailable",
    "NormalizedC2PAReceipt",
    "PROVENANCE_RECORD_SCHEMA",
    "ProvenanceOperation",
    "ReleaseOutcome",
    "SAFE_EXPORT_SCHEMA",
    "STANDARDS_LIMITATIONS",
    "SignedMediaResult",
    "TrustChainState",
    "ValidationState",
    "configured_media_provenance",
    "default_service",
    "enabled",
    "normalize_c2pa_receipt",
    "require_enabled",
]
