"""Device-bound protocol and durable runtime for native consent clients.

This module is the platform-neutral security boundary used by the iOS/tvOS,
Android/Fire TV, Roku, Tizen, and webOS adapters shipped under
``sdks/consent-native``.  It deliberately does not embed a tenant-wide bearer
credential in an application binary.  An operator first binds an application
to one existing public-consent *service* client, an injected platform
attestation authority admits an installation's Ed25519 public key, and every
subsequent operation is signed by that device key.

The signed body contains the exact tenant, application, platform, device,
public-client revision/digest, publication, policy, configuration, profile,
monotonic counter, request id, operation, and bounded payload.  Replays are
idempotent only when every signed byte is identical.  Application, device,
public-client, profile, publication, or policy drift fails closed.

The server-side :class:`NativeConsentGateway` is intentionally backend-neutral:
its injected handler maps closed operations onto Lightwork's existing consent
preference, publishing, identity-pairing, and consumer-rights authorities.
Handlers must use the signed request id as their downstream idempotency key.
This allows a crash after downstream commit but before gateway receipt commit
to replay safely.

IAB TCF/GPP strings are transported only as opaque, digest-bound values from an
injected certified CMP adapter.  This code does not claim IAB certification or
reinterpret those strings.  GPC and Do-Not-Sell/Share are explicit boolean
privacy floors and can never grant consent.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from . import consent_storage
from .constant_time import text_equals
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
APPLICATION_SCHEMA = "lightwork.native-consent-application.v1"
ATTESTATION_SCHEMA = "lightwork.native-consent-attestation.v1"
ENVELOPE_SCHEMA = "lightwork.native-consent-envelope.v1"
RECEIPT_SCHEMA = "lightwork.native-consent-receipt.v1"
AUDIT_SCHEMA = "lightwork.native-consent-audit.v1"

PLATFORMS = frozenset({"android", "fireos", "ios", "roku", "tizen", "tvos", "webos"})
OPERATIONS = frozenset(
    {
        "bootstrap_profile",
        "configuration",
        "current_preferences",
        "link_profile",
        "privacy_signals",
        "record_preferences",
        "revoke_profile",
        "rights_request",
    }
)
RIGHTS = frozenset(
    {
        "access",
        "erasure",
        "objection",
        "opt_out",
        "portability",
        "rectification",
        "restriction",
    }
)
ACTIONS = frozenset({"deny", "grant", "revoke", "withdraw"})

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_APP_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,254}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")
_LOCALE_RE = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}\Z")
_COUNTRY_RE = re.compile(r"[A-Z]{2}\Z")
_REGION_RE = re.compile(r"(?:[A-Z]{2}-[A-Z0-9]{1,3})?\Z")
_WIRE_RE = re.compile(r"[A-Za-z0-9._~+\-/=]{1,8192}\Z")

_MAX_JSON_BYTES = 256 * 1024
_MAX_RESULT_BYTES = 512 * 1024
_MAX_PAYLOAD_BYTES = 128 * 1024
_MAX_CHOICES = 128
_MAX_LOCALES = 64
_MAX_LOCALIZED_STRINGS = 256
_MAX_PENDING_MESSAGES = 512
_MAX_ATTESTATION_BYTES = 64 * 1024
_MAX_CLOCK_SKEW_SECONDS = 120.0
_MAX_ENVELOPE_TTL_SECONDS = 300.0
_MAX_COUNTER_JUMP = 10_000
# A signed request is claimed only while ``issued_at <= now + skew`` and
# ``expires_at >= now``, and its lifetime is capped. A claim older than this
# therefore belongs to an envelope that has expired: without the claim row it
# is refused as outside its freshness window, and its counter is behind the
# device's. Attestation nonces have no such horizon (the evidence timestamps
# around a nonce are not signed), so nonce rows are kept.
_REQUEST_REPLAY_HORIZON_SECONDS = _MAX_CLOCK_SKEW_SECONDS + _MAX_ENVELOPE_TTL_SECONDS
_MAX_DEVICE_ATTESTATION_SECONDS = 31 * 24 * 60 * 60

_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "application_ref",
        "application_authority_sha256",
        "tenant_sha256",
        "device_id",
        "device_revision",
        "request_id",
        "request_sha256",
        "operation",
        "result",
        "result_sha256",
        "publication_sha256",
        "configuration_sha256",
        "policy_sha256",
        "key_id",
        "key_revision",
        "completed_at",
    }
)


class NativeConsentError(RuntimeError):
    """Base error for the native consent boundary."""


class NativeConsentValidationError(NativeConsentError, ValueError):
    """An input is outside the closed native protocol."""


class NativeConsentDenied(NativeConsentError):
    """Attestation, authority, signature, or revocation denied the request."""


class NativeConsentConflict(NativeConsentError):
    """A CAS, replay, idempotency, or authoritative binding changed."""


class NativeConsentIntegrityError(NativeConsentError):
    """Stored or signed evidence failed its integrity contract."""


class NativeConsentCapacityError(NativeConsentError):
    """A bounded durable queue or registry reached its configured capacity."""


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise NativeConsentValidationError("native consent data must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise NativeConsentValidationError("native consent data exceeds its byte bound")
    return encoded


def _loads(value: object, label: str, *, maximum: int = _MAX_JSON_BYTES) -> Any:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise NativeConsentIntegrityError(f"stored {label} exceeds its byte bound")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise NativeConsentIntegrityError(f"stored {label} is invalid") from exc


def _sha256(value: object, *, maximum: int = _MAX_JSON_BYTES) -> str:
    return hashlib.sha256(_canonical(value, maximum=maximum)).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and text_equals(left, right)


def _ref(value: object, label: str, pattern: re.Pattern[str] = _REF_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise NativeConsentValidationError(f"{label} must be a bounded opaque reference")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise NativeConsentValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _positive_int(value: object, label: str, *, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise NativeConsentValidationError(f"{label} is outside its integer bound")
    return value


def _revision(value: object, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**31 - 1:
        raise NativeConsentValidationError(f"{label} is outside its revision bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NativeConsentValidationError(f"{label} must be a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or not 0 < result < 100_000_000_000.0:
        raise NativeConsentValidationError(f"{label} must be a finite timestamp")
    return result


def _wire_timestamp(value: object, label: str) -> int:
    """Return an integer epoch second for cross-language signed JSON.

    Python and ECMAScript intentionally serialize some floating-point values
    differently. Native protocol timestamps therefore use integer seconds so
    Swift, Kotlin, BrightScript, JavaScript, and the Python verifier sign the
    same bytes. Integral floats are accepted at the Python boundary because
    Pydantic materializes JSON integers annotated as ``float`` that way.
    """

    result = _timestamp(value, label)
    if not result.is_integer():
        raise NativeConsentValidationError(f"{label} must use integer epoch seconds")
    return int(result)


def _platform(value: object) -> str:
    if not isinstance(value, str) or value not in PLATFORMS:
        raise NativeConsentValidationError("platform is unsupported")
    return value


def _require_attestation_material(material: object, expected_sha256: str) -> bytes:
    if not isinstance(material, bytes) or not 1 <= len(material) <= _MAX_ATTESTATION_BYTES:
        raise NativeConsentDenied("attestation material digest did not verify")
    if not _same(hashlib.sha256(material).hexdigest(), expected_sha256):
        raise NativeConsentDenied("attestation material digest did not verify")
    return material


def _locale(value: object) -> str:
    if not isinstance(value, str) or not _LOCALE_RE.fullmatch(value):
        raise NativeConsentValidationError("locale is invalid")
    return value


def _profile_digest(payload: Mapping[str, Any], *, required: bool) -> str | None:
    value = payload.get("profile_credential_sha256")
    if value is None and not required:
        return None
    return _digest(value, "profile_credential_sha256")


def _closed_mapping(
    value: object,
    label: str,
    *,
    allowed: frozenset[str],
    required: frozenset[str] = frozenset(),
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise NativeConsentValidationError(f"{label} must be an object")
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(allowed):
        raise NativeConsentValidationError(f"{label} has unknown or missing fields")
    return value


@dataclass(frozen=True)
class NativeApplicationAuthority:
    """Exact snapshot of one operator-approved native application."""

    application_ref: str
    tenant_id: str
    property_id: str
    application_id: str
    platform: str
    public_client_credential_sha256: str
    public_client_revision: int
    public_client_record_sha256: str
    property_revision: int
    property_sha256: str
    publication_sha256: str
    publication_bundle_sha256: str
    configuration_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    standards_contract_sha256: str
    minimum_sdk_version: int
    default_locale: str
    locales: tuple[str, ...]

    def normalized(self) -> dict[str, Any]:
        try:
            tenant = canonical_tenant_id(self.tenant_id)
        except (TypeError, ValueError) as exc:
            raise NativeConsentValidationError("tenant authority is invalid") from exc
        if tenant != self.tenant_id:
            raise NativeConsentValidationError("tenant authority is not canonical")
        platform = _platform(self.platform)
        application_id = _ref(self.application_id, "application_id", _APP_ID_RE)
        locales = tuple(_locale(item) for item in self.locales)
        if not 1 <= len(locales) <= _MAX_LOCALES or len(set(locales)) != len(locales):
            raise NativeConsentValidationError("application locales are invalid")
        default_locale = _locale(self.default_locale)
        if default_locale not in locales:
            raise NativeConsentValidationError("default locale is absent from application locales")
        value = {
            "schema": APPLICATION_SCHEMA,
            "application_ref": _ref(self.application_ref, "application_ref"),
            "tenant_id": tenant,
            "property_id": _ref(self.property_id, "property_id"),
            "application_id": application_id,
            "platform": platform,
            "public_client_credential_sha256": _digest(
                self.public_client_credential_sha256,
                "public_client_credential_sha256",
            ),
            "public_client_revision": _positive_int(
                self.public_client_revision,
                "public_client_revision",
            ),
            "public_client_record_sha256": _digest(
                self.public_client_record_sha256,
                "public_client_record_sha256",
            ),
            "property_revision": _positive_int(self.property_revision, "property_revision"),
            "property_sha256": _digest(self.property_sha256, "property_sha256"),
            "publication_sha256": _digest(self.publication_sha256, "publication_sha256"),
            "publication_bundle_sha256": _digest(
                self.publication_bundle_sha256,
                "publication_bundle_sha256",
            ),
            "configuration_sha256": _digest(
                self.configuration_sha256,
                "configuration_sha256",
            ),
            "policy_id": _ref(self.policy_id, "policy_id"),
            "policy_version": _positive_int(self.policy_version, "policy_version"),
            "policy_sha256": _digest(self.policy_sha256, "policy_sha256"),
            "standards_contract_sha256": _digest(
                self.standards_contract_sha256,
                "standards_contract_sha256",
            ),
            "minimum_sdk_version": _positive_int(
                self.minimum_sdk_version,
                "minimum_sdk_version",
                maximum=1_000_000,
            ),
            "default_locale": default_locale,
            "locales": list(locales),
        }
        return value

    @property
    def authority_sha256(self) -> str:
        return _sha256(self.normalized())


@dataclass(frozen=True)
class NativeEnrollmentEvidence:
    """Attestation request; only digests and the device public key persist."""

    application_ref: str
    tenant_id: str
    application_id: str
    platform: str
    install_subject_sha256: str
    public_key_hex: str
    attestation_nonce: str
    attestation_evidence_sha256: str
    issued_at: float
    expires_at: float
    sdk_version: int | None = None

    def normalized(self) -> dict[str, Any]:
        try:
            tenant = canonical_tenant_id(self.tenant_id)
        except (TypeError, ValueError) as exc:
            raise NativeConsentValidationError("enrollment tenant is invalid") from exc
        public_key = _digest(self.public_key_hex, "public_key_hex")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        except (ImportError, TypeError, ValueError) as exc:
            raise NativeConsentValidationError("device public key is not Ed25519") from exc
        issued = _timestamp(self.issued_at, "attestation issued_at")
        expires = _timestamp(self.expires_at, "attestation expires_at")
        if expires <= issued or expires - issued > _MAX_ENVELOPE_TTL_SECONDS:
            raise NativeConsentValidationError("attestation freshness window is invalid")
        result = {
            "schema": ATTESTATION_SCHEMA,
            "application_ref": _ref(self.application_ref, "application_ref"),
            "tenant_id": tenant,
            "application_id": _ref(self.application_id, "application_id", _APP_ID_RE),
            "platform": _platform(self.platform),
            "install_subject_sha256": _digest(
                self.install_subject_sha256,
                "install_subject_sha256",
            ),
            "public_key_hex": public_key,
            "attestation_nonce": _ref(self.attestation_nonce, "attestation_nonce"),
            "attestation_evidence_sha256": _digest(
                self.attestation_evidence_sha256,
                "attestation_evidence_sha256",
            ),
            "issued_at": issued,
            "expires_at": expires,
        }
        if self.sdk_version is not None:
            result["sdk_version"] = _positive_int(
                self.sdk_version,
                "attested sdk_version",
                maximum=1_000_000,
            )
        return result


@dataclass(frozen=True)
class VerifiedNativeAttestation:
    """Ephemeral decision returned by an independently injected verifier."""

    authority: str
    application_ref: str
    tenant_id: str
    application_id: str
    platform: str
    install_subject_sha256: str
    public_key_hex: str
    attestation_nonce: str
    attestation_evidence_sha256: str
    verified_at: float
    valid_until: float
    verdict: str
    sdk_version: int | None = None

    def normalized(self) -> dict[str, Any]:
        if self.verdict != "allow":
            raise NativeConsentDenied("platform attestation did not allow enrollment")
        try:
            tenant = canonical_tenant_id(self.tenant_id)
        except (TypeError, ValueError) as exc:
            raise NativeConsentValidationError("attestation tenant is invalid") from exc
        verified_at = _timestamp(self.verified_at, "verified_at")
        valid_until = _timestamp(self.valid_until, "valid_until")
        if (
            valid_until <= verified_at
            or valid_until - verified_at > _MAX_DEVICE_ATTESTATION_SECONDS
        ):
            raise NativeConsentDenied("platform attestation validity is outside its bound")
        result = {
            "authority": _ref(self.authority, "attestation authority"),
            "application_ref": _ref(self.application_ref, "application_ref"),
            "tenant_id": tenant,
            "application_id": _ref(self.application_id, "application_id", _APP_ID_RE),
            "platform": _platform(self.platform),
            "install_subject_sha256": _digest(
                self.install_subject_sha256,
                "install_subject_sha256",
            ),
            "public_key_hex": _digest(self.public_key_hex, "public_key_hex"),
            "attestation_nonce": _ref(self.attestation_nonce, "attestation_nonce"),
            "attestation_evidence_sha256": _digest(
                self.attestation_evidence_sha256,
                "attestation_evidence_sha256",
            ),
            "verified_at": verified_at,
            "valid_until": valid_until,
            "verdict": self.verdict,
        }
        if self.sdk_version is not None:
            result["sdk_version"] = _positive_int(
                self.sdk_version,
                "verified sdk_version",
                maximum=1_000_000,
            )
        return result


class NativeAttestationVerifier(Protocol):
    def verify(
        self,
        evidence: NativeEnrollmentEvidence,
        attestation_material: bytes,
    ) -> VerifiedNativeAttestation: ...


@dataclass(frozen=True)
class NativeDeviceAuthority:
    device_id: str
    application_ref: str
    application_authority_sha256: str
    tenant_id: str
    application_id: str
    platform: str
    install_subject_sha256: str
    public_key_hex: str
    key_revision: int
    sdk_version: int
    revision: int
    attestation_authority: str
    attestation_evidence_sha256: str
    attestation_valid_until: float
    created_at: float


def _normalize_choices(value: object) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise NativeConsentValidationError("choices must be a sequence")
    choices = tuple(value)
    if not 1 <= len(choices) <= _MAX_CHOICES:
        raise NativeConsentValidationError("choices count is outside its bound")
    result: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for item in choices:
        row = _closed_mapping(
            item,
            "choice",
            allowed=frozenset({"purpose_id", "action", "channel", "vendor_id", "expires_at"}),
            required=frozenset({"purpose_id", "action"}),
        )
        action = row["action"]
        if not isinstance(action, str) or action not in ACTIONS:
            raise NativeConsentValidationError("choice action is unsupported")
        expires = row.get("expires_at")
        if expires is not None:
            expires = _wire_timestamp(expires, "choice expires_at")
            if action in {"revoke", "withdraw"}:
                raise NativeConsentValidationError("negative lifecycle choices cannot expire")
        normalized = {
            "purpose_id": _ref(row["purpose_id"], "purpose_id"),
            "action": action,
            "channel": _ref(row.get("channel", "all"), "channel"),
            "vendor_id": _ref(row.get("vendor_id", "all"), "vendor_id"),
            "expires_at": expires,
        }
        identity = (
            normalized["purpose_id"],
            normalized["channel"],
            normalized["vendor_id"],
        )
        if identity in identities:
            raise NativeConsentValidationError("choice scope is duplicated")
        identities.add(identity)
        result.append(normalized)
    result.sort(key=lambda row: (row["purpose_id"], row["channel"], row["vendor_id"]))
    return result


def _normalize_signals(value: object) -> dict[str, Any]:
    row = _closed_mapping(
        value,
        "privacy signals",
        allowed=frozenset(
            {
                "gpc",
                "do_not_sell_or_share",
                "tcf_string",
                "tcf_string_sha256",
                "gpp_string",
                "gpp_string_sha256",
                "standards_contract_sha256",
                "purposes",
            }
        ),
        required=frozenset({"gpc", "do_not_sell_or_share", "standards_contract_sha256", "purposes"}),
    )
    gpc = row["gpc"]
    dns = row["do_not_sell_or_share"]
    if type(gpc) is not bool or type(dns) is not bool:
        raise NativeConsentValidationError("privacy signal flags must be booleans")
    purposes_raw = row["purposes"]
    if isinstance(purposes_raw, (str, bytes)) or not isinstance(purposes_raw, Sequence):
        raise NativeConsentValidationError("privacy signal purposes must be a sequence")
    purposes = tuple(_ref(item, "privacy signal purpose") for item in purposes_raw)
    if not 1 <= len(purposes) <= _MAX_CHOICES or len(set(purposes)) != len(purposes):
        raise NativeConsentValidationError("privacy signal purposes are invalid")
    result: dict[str, Any] = {
        "gpc": gpc,
        "do_not_sell_or_share": dns,
        "standards_contract_sha256": _digest(
            row["standards_contract_sha256"],
            "standards_contract_sha256",
        ),
        "purposes": sorted(purposes),
    }
    for name in ("tcf", "gpp"):
        wire = row.get(f"{name}_string")
        digest = row.get(f"{name}_string_sha256")
        if (wire is None) != (digest is None):
            raise NativeConsentValidationError(f"{name.upper()} string and digest must appear together")
        if wire is not None:
            if not isinstance(wire, str) or not _WIRE_RE.fullmatch(wire):
                raise NativeConsentValidationError(f"{name.upper()} string is outside its opaque wire bound")
            expected = hashlib.sha256(wire.encode("ascii")).hexdigest()
            if not _same(expected, _digest(digest, f"{name}_string_sha256")):
                raise NativeConsentValidationError(f"{name.upper()} string digest does not verify")
            result[f"{name}_string"] = wire
            result[f"{name}_string_sha256"] = expected
    if not (gpc or dns or "tcf_string" in result or "gpp_string" in result):
        raise NativeConsentValidationError("at least one privacy signal is required")
    return result


def normalize_operation_payload(operation: str, payload: object) -> dict[str, Any]:
    """Validate one closed SDK operation before it is signed or executed."""

    if operation not in OPERATIONS:
        raise NativeConsentValidationError("native operation is unsupported")
    if operation == "configuration":
        row = _closed_mapping(payload, "configuration payload", allowed=frozenset())
        return dict(row)
    if operation == "bootstrap_profile":
        row = _closed_mapping(
            payload,
            "bootstrap payload",
            allowed=frozenset({"subject_sha256", "profile_credential_sha256", "idempotency_key"}),
            required=frozenset({"subject_sha256", "profile_credential_sha256", "idempotency_key"}),
        )
        return {
            "subject_sha256": _digest(row["subject_sha256"], "subject_sha256"),
            "profile_credential_sha256": _digest(
                row["profile_credential_sha256"],
                "profile_credential_sha256",
            ),
            "idempotency_key": _ref(row["idempotency_key"], "idempotency_key"),
        }
    if operation == "current_preferences":
        row = _closed_mapping(
            payload,
            "current preferences payload",
            allowed=frozenset({"profile_credential_sha256"}),
            required=frozenset({"profile_credential_sha256"}),
        )
        return {"profile_credential_sha256": _profile_digest(row, required=True)}
    if operation == "record_preferences":
        row = _closed_mapping(
            payload,
            "preference payload",
            allowed=frozenset(
                {"profile_credential_sha256", "expected_revision", "idempotency_key", "choices"}
            ),
            required=frozenset(
                {"profile_credential_sha256", "expected_revision", "idempotency_key", "choices"}
            ),
        )
        return {
            "profile_credential_sha256": _profile_digest(row, required=True),
            "expected_revision": _revision(row["expected_revision"], "expected_revision", allow_zero=True),
            "idempotency_key": _ref(row["idempotency_key"], "idempotency_key"),
            "choices": _normalize_choices(row["choices"]),
        }
    if operation == "privacy_signals":
        row = _closed_mapping(
            payload,
            "privacy signal payload",
            allowed=frozenset(
                {
                    "profile_credential_sha256",
                    "expected_revision",
                    "idempotency_key",
                    "signals",
                }
            ),
            required=frozenset(
                {
                    "profile_credential_sha256",
                    "expected_revision",
                    "idempotency_key",
                    "signals",
                }
            ),
        )
        return {
            "profile_credential_sha256": _profile_digest(row, required=True),
            "expected_revision": _revision(row["expected_revision"], "expected_revision", allow_zero=True),
            "idempotency_key": _ref(row["idempotency_key"], "idempotency_key"),
            "signals": _normalize_signals(row["signals"]),
        }
    if operation == "link_profile":
        row = _closed_mapping(
            payload,
            "profile link payload",
            allowed=frozenset(
                {
                    "profile_credential_sha256",
                    "target_profile_credential_sha256",
                    "pairing_authorization_sha256",
                    "scope",
                    "idempotency_key",
                }
            ),
            required=frozenset(
                {
                    "profile_credential_sha256",
                    "target_profile_credential_sha256",
                    "pairing_authorization_sha256",
                    "scope",
                    "idempotency_key",
                }
            ),
        )
        scope = row["scope"]
        if scope not in {"device", "household"}:
            raise NativeConsentValidationError("profile link scope is unsupported")
        source = _profile_digest(row, required=True)
        target = _digest(
            row["target_profile_credential_sha256"],
            "target_profile_credential_sha256",
        )
        if _same(source, target):
            raise NativeConsentValidationError("profile link must name a distinct target")
        return {
            "profile_credential_sha256": source,
            "target_profile_credential_sha256": target,
            "pairing_authorization_sha256": _digest(
                row["pairing_authorization_sha256"],
                "pairing_authorization_sha256",
            ),
            "scope": scope,
            "idempotency_key": _ref(row["idempotency_key"], "idempotency_key"),
        }
    if operation == "rights_request":
        row = _closed_mapping(
            payload,
            "rights request payload",
            allowed=frozenset(
                {"profile_credential_sha256", "rights", "expected_revision", "idempotency_key"}
            ),
            required=frozenset(
                {"profile_credential_sha256", "rights", "expected_revision", "idempotency_key"}
            ),
        )
        rights_raw = row["rights"]
        if isinstance(rights_raw, (str, bytes)) or not isinstance(rights_raw, Sequence):
            raise NativeConsentValidationError("rights must be a sequence")
        rights = tuple(rights_raw)
        if (
            not 1 <= len(rights) <= len(RIGHTS)
            or any(not isinstance(item, str) or item not in RIGHTS for item in rights)
            or len(set(rights)) != len(rights)
        ):
            raise NativeConsentValidationError("rights request contains unsupported values")
        expected = row["expected_revision"]
        if type(expected) is not int or expected != 0:
            raise NativeConsentValidationError("new rights requests require expected_revision 0")
        return {
            "profile_credential_sha256": _profile_digest(row, required=True),
            "rights": sorted(rights),
            "expected_revision": 0,
            "idempotency_key": _ref(row["idempotency_key"], "idempotency_key"),
        }
    row = _closed_mapping(
        payload,
        "profile revocation payload",
        allowed=frozenset({"profile_credential_sha256", "evidence_sha256", "idempotency_key"}),
        required=frozenset({"profile_credential_sha256", "evidence_sha256", "idempotency_key"}),
    )
    return {
        "profile_credential_sha256": _profile_digest(row, required=True),
        "evidence_sha256": _digest(row["evidence_sha256"], "evidence_sha256"),
        "idempotency_key": _ref(row["idempotency_key"], "idempotency_key"),
    }


@dataclass(frozen=True)
class NativeRequestEnvelope:
    schema: str
    application_ref: str
    application_authority_sha256: str
    tenant_id: str
    application_id: str
    platform: str
    device_id: str
    device_revision: int
    key_revision: int
    sdk_version: int
    public_client_revision: int
    public_client_record_sha256: str
    publication_sha256: str
    publication_bundle_sha256: str
    configuration_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    standards_contract_sha256: str
    request_id: str
    counter: int
    issued_at: float
    expires_at: float
    operation: str
    payload: Mapping[str, Any]
    signature_hex: str

    def signing_body(self) -> dict[str, Any]:
        if self.schema != ENVELOPE_SCHEMA:
            raise NativeConsentValidationError("native envelope schema is unsupported")
        issued = _wire_timestamp(self.issued_at, "issued_at")
        expires = _wire_timestamp(self.expires_at, "expires_at")
        if expires <= issued or expires - issued > _MAX_ENVELOPE_TTL_SECONDS:
            raise NativeConsentValidationError("native request freshness window is invalid")
        operation = self.operation
        payload = normalize_operation_payload(operation, self.payload)
        result = {
            "schema": ENVELOPE_SCHEMA,
            "application_ref": _ref(self.application_ref, "application_ref"),
            "application_authority_sha256": _digest(
                self.application_authority_sha256,
                "application_authority_sha256",
            ),
            "tenant_id": canonical_tenant_id(self.tenant_id),
            "application_id": _ref(self.application_id, "application_id", _APP_ID_RE),
            "platform": _platform(self.platform),
            "device_id": _ref(self.device_id, "device_id"),
            "device_revision": _positive_int(self.device_revision, "device_revision"),
            "key_revision": _positive_int(self.key_revision, "key_revision"),
            "sdk_version": _positive_int(self.sdk_version, "sdk_version", maximum=1_000_000),
            "public_client_revision": _positive_int(
                self.public_client_revision,
                "public_client_revision",
            ),
            "public_client_record_sha256": _digest(
                self.public_client_record_sha256,
                "public_client_record_sha256",
            ),
            "publication_sha256": _digest(self.publication_sha256, "publication_sha256"),
            "publication_bundle_sha256": _digest(
                self.publication_bundle_sha256,
                "publication_bundle_sha256",
            ),
            "configuration_sha256": _digest(
                self.configuration_sha256,
                "configuration_sha256",
            ),
            "policy_id": _ref(self.policy_id, "policy_id"),
            "policy_version": _positive_int(self.policy_version, "policy_version"),
            "policy_sha256": _digest(self.policy_sha256, "policy_sha256"),
            "standards_contract_sha256": _digest(
                self.standards_contract_sha256,
                "standards_contract_sha256",
            ),
            "request_id": _ref(self.request_id, "request_id"),
            "counter": _positive_int(self.counter, "counter", maximum=2**63 - 1),
            "issued_at": issued,
            "expires_at": expires,
            "operation": operation,
            "payload": payload,
        }
        _canonical(result, maximum=_MAX_PAYLOAD_BYTES)
        return result

    @property
    def request_sha256(self) -> str:
        return _sha256(self.signing_body(), maximum=_MAX_PAYLOAD_BYTES)

    def verify(self, public_key_hex: str) -> None:
        public_key = _digest(public_key_hex, "device public key")
        if not isinstance(self.signature_hex, str) or not _SIGNATURE_RE.fullmatch(
            self.signature_hex
        ):
            raise NativeConsentDenied("native request signature is invalid")
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
                bytes.fromhex(self.signature_hex),
                _canonical(self.signing_body(), maximum=_MAX_PAYLOAD_BYTES),
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise NativeConsentDenied("native request signature did not verify") from exc


class NativeEnvelopeSigner(Protocol):
    def sign(self, body: bytes) -> bytes: ...


class NativeReceiptSigner(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def key_revision(self) -> int: ...

    def sign(self, body: bytes) -> bytes: ...


@dataclass(frozen=True)
class NativeResponseReceipt:
    payload: Mapping[str, Any]
    signature_hex: str

    def normalized(self) -> dict[str, Any]:
        """Validate the closed signed receipt and return detached JSON data."""

        row = _closed_mapping(
            self.payload,
            "native receipt",
            allowed=_RECEIPT_FIELDS,
            required=_RECEIPT_FIELDS,
        )
        if row["schema"] != RECEIPT_SCHEMA:
            raise NativeConsentIntegrityError("native receipt schema is unsupported")
        operation = row["operation"]
        if not isinstance(operation, str) or operation not in OPERATIONS:
            raise NativeConsentIntegrityError("native receipt operation is unsupported")
        result = row["result"]
        if not isinstance(result, Mapping) or not all(isinstance(key, str) for key in result):
            raise NativeConsentIntegrityError("native receipt result is invalid")
        try:
            detached_result = _loads(
                _canonical(dict(result), maximum=_MAX_RESULT_BYTES).decode("ascii"),
                "native receipt result",
                maximum=_MAX_RESULT_BYTES,
            )
            result_sha = _digest(row["result_sha256"], "receipt result_sha256")
            if not _same(
                _sha256(detached_result, maximum=_MAX_RESULT_BYTES),
                result_sha,
            ):
                raise NativeConsentIntegrityError("native receipt result digest changed")
            normalized = {
                "schema": RECEIPT_SCHEMA,
                "application_ref": _ref(row["application_ref"], "receipt application_ref"),
                "application_authority_sha256": _digest(
                    row["application_authority_sha256"],
                    "receipt application_authority_sha256",
                ),
                "tenant_sha256": _digest(row["tenant_sha256"], "receipt tenant_sha256"),
                "device_id": _ref(row["device_id"], "receipt device_id"),
                "device_revision": _positive_int(
                    row["device_revision"],
                    "receipt device_revision",
                ),
                "request_id": _ref(row["request_id"], "receipt request_id"),
                "request_sha256": _digest(
                    row["request_sha256"],
                    "receipt request_sha256",
                ),
                "operation": operation,
                "result": detached_result,
                "result_sha256": result_sha,
                "publication_sha256": _digest(
                    row["publication_sha256"],
                    "receipt publication_sha256",
                ),
                "configuration_sha256": _digest(
                    row["configuration_sha256"],
                    "receipt configuration_sha256",
                ),
                "policy_sha256": _digest(row["policy_sha256"], "receipt policy_sha256"),
                "key_id": _ref(row["key_id"], "receipt key_id"),
                "key_revision": _positive_int(
                    row["key_revision"],
                    "receipt key_revision",
                ),
                "completed_at": _wire_timestamp(
                    row["completed_at"],
                    "receipt completed_at",
                ),
            }
            _canonical(normalized, maximum=_MAX_RESULT_BYTES)
            return normalized
        except NativeConsentValidationError as exc:
            raise NativeConsentIntegrityError("native receipt is invalid") from exc

    def verify(self, trusted_public_keys: Mapping[str, str]) -> bool:
        try:
            body = self.normalized()
        except (NativeConsentError, TypeError, ValueError):
            return False
        key_id = body["key_id"]
        key_revision = body["key_revision"]
        public_hex = trusted_public_keys.get(f"{key_id}:{key_revision}")
        # Revision one may use the historical unversioned map key. Rotated
        # keys must be explicitly versioned so an old key ID cannot silently
        # acquire authority over new receipts.
        if public_hex is None and key_revision == 1:
            public_hex = trusted_public_keys.get(key_id)
        if not isinstance(public_hex, str) or not _PUBLIC_KEY_RE.fullmatch(public_hex):
            return False
        if not isinstance(self.signature_hex, str) or not _SIGNATURE_RE.fullmatch(
            self.signature_hex
        ):
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
                bytes.fromhex(self.signature_hex),
                _canonical(body, maximum=_MAX_RESULT_BYTES),
            )
        except (InvalidSignature, TypeError, ValueError):
            return False
        return True


def build_envelope(
    authority: NativeApplicationAuthority,
    device: NativeDeviceAuthority,
    *,
    request_id: str,
    counter: int,
    operation: str,
    payload: Mapping[str, Any],
    signer: NativeEnvelopeSigner,
    issued_at: float | None = None,
    ttl_seconds: float = 120.0,
) -> NativeRequestEnvelope:
    """Build and sign one exact native request for secure platform adapters."""

    authority.normalized()
    if (
        device.application_ref != authority.application_ref
        or device.application_authority_sha256 != authority.authority_sha256
        or device.tenant_id != authority.tenant_id
        or device.application_id != authority.application_id
        or device.platform != authority.platform
    ):
        raise NativeConsentConflict("device authority is not bound to this application")
    raw_now = _timestamp(issued_at if issued_at is not None else time.time(), "issued_at")
    now = int(math.floor(raw_now))
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
        raise NativeConsentValidationError("ttl_seconds must be numeric")
    ttl = float(ttl_seconds)
    if (
        not math.isfinite(ttl)
        or not ttl.is_integer()
        or not 1 <= ttl <= _MAX_ENVELOPE_TTL_SECONDS
    ):
        raise NativeConsentValidationError("ttl_seconds is outside its bound")
    unsigned = NativeRequestEnvelope(
        schema=ENVELOPE_SCHEMA,
        application_ref=authority.application_ref,
        application_authority_sha256=authority.authority_sha256,
        tenant_id=authority.tenant_id,
        application_id=authority.application_id,
        platform=authority.platform,
        device_id=device.device_id,
        device_revision=device.revision,
        key_revision=device.key_revision,
        sdk_version=device.sdk_version,
        public_client_revision=authority.public_client_revision,
        public_client_record_sha256=authority.public_client_record_sha256,
        publication_sha256=authority.publication_sha256,
        publication_bundle_sha256=authority.publication_bundle_sha256,
        configuration_sha256=authority.configuration_sha256,
        policy_id=authority.policy_id,
        policy_version=authority.policy_version,
        policy_sha256=authority.policy_sha256,
        standards_contract_sha256=authority.standards_contract_sha256,
        request_id=_ref(request_id, "request_id"),
        counter=_positive_int(counter, "counter", maximum=2**63 - 1),
        issued_at=now,
        expires_at=now + int(ttl),
        operation=operation,
        payload=normalize_operation_payload(operation, payload),
        signature_hex="0" * 128,
    )
    signature = signer.sign(_canonical(unsigned.signing_body(), maximum=_MAX_PAYLOAD_BYTES))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise NativeConsentValidationError("native signer must return a 64-byte Ed25519 signature")
    return NativeRequestEnvelope(**{**asdict(unsigned), "signature_hex": signature.hex()})


def localized_ui_contract(
    *,
    locale: str,
    direction: str,
    strings: Mapping[str, str],
    required_keys: Sequence[str],
    content_revision: int,
    content_sha256: str,
) -> dict[str, Any]:
    """Validate a native, accessibility-safe localized rendering contract.

    Strings are plain text.  HTML, JavaScript URLs, inline event handlers, and
    CSS are rejected so each native adapter owns accessible platform widgets.
    """

    normalized_locale = _locale(locale)
    if direction not in {"ltr", "rtl"}:
        raise NativeConsentValidationError("localized direction is unsupported")
    if not isinstance(strings, Mapping) or not 1 <= len(strings) <= _MAX_LOCALIZED_STRINGS:
        raise NativeConsentValidationError("localized strings are outside their count bound")
    normalized: dict[str, str] = {}
    for key, value in strings.items():
        ref = _ref(key, "localized string key")
        if not isinstance(value, str) or not 1 <= len(value) <= 4_096:
            raise NativeConsentValidationError("localized string value is outside its bound")
        lowered = value.casefold()
        if any(token in lowered for token in ("<script", "javascript:", "onerror=", "onclick=")):
            raise NativeConsentValidationError("localized strings must be inert plain text")
        normalized[ref] = value
    required = tuple(_ref(item, "required localized key") for item in required_keys)
    if not 1 <= len(required) <= _MAX_LOCALIZED_STRINGS or not set(required).issubset(normalized):
        raise NativeConsentValidationError("localized contract is missing required strings")
    body = {
        "schema": "lightwork.native-consent-localized-ui.v1",
        "locale": normalized_locale,
        "direction": direction,
        "content_revision": _positive_int(content_revision, "content_revision"),
        "content_sha256": _digest(content_sha256, "content_sha256"),
        "required_keys": sorted(set(required)),
        "strings": dict(sorted(normalized.items())),
        "rendering": {
            "native_controls_only": True,
            "supports_dynamic_type": True,
            "supports_screen_reader": True,
            "supports_focus_navigation": True,
            "html_allowed": False,
        },
    }
    return {**body, "contract_sha256": _sha256(body)}


class NativeConsentDeviceRegistry:
    """Private, CAS- and hash-chain-protected application/device authority."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        max_devices: int = 100_000,
        max_requests: int = 1_000_000,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self.max_devices = _positive_int(max_devices, "max_devices", maximum=10_000_000)
        self.max_requests = _positive_int(max_requests, "max_requests", maximum=100_000_000)
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    @contextlib.contextmanager
    def _connect(self):
        with consent_storage.authority_connection(
            self.path, ensure_directory=ensure_private_directory,
            ensure_file=ensure_private_file,
        ) as connection:
            yield connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS native_consent_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS native_consent_apps(
                    application_ref TEXT PRIMARY KEY,
                    authority_json TEXT NOT NULL,
                    authority_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    revision INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS native_consent_devices(
                    device_id TEXT PRIMARY KEY,
                    application_ref TEXT NOT NULL,
                    application_authority_sha256 TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    application_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    install_subject_sha256 TEXT NOT NULL,
                    public_key_hex TEXT NOT NULL,
                    key_revision INTEGER NOT NULL,
                    sdk_version INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    attestation_authority TEXT NOT NULL,
                    attestation_evidence_sha256 TEXT NOT NULL,
                    attestation_valid_until REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    last_counter INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(application_ref, install_subject_sha256),
                    UNIQUE(application_ref, public_key_hex),
                    FOREIGN KEY(application_ref) REFERENCES native_consent_apps(application_ref)
                );
                CREATE TABLE IF NOT EXISTS native_consent_nonces(
                    application_ref TEXT NOT NULL,
                    nonce_sha256 TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    used_at REAL NOT NULL,
                    PRIMARY KEY(application_ref, nonce_sha256)
                );
                CREATE TABLE IF NOT EXISTS native_consent_requests(
                    device_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','complete')),
                    result_json TEXT,
                    result_sha256 TEXT,
                    receipt_json TEXT,
                    signature_hex TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(device_id, request_id),
                    UNIQUE(device_id, counter),
                    FOREIGN KEY(device_id) REFERENCES native_consent_devices(device_id)
                );
                CREATE TABLE IF NOT EXISTS native_consent_audit(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL,
                    previous_sha256 TEXT,
                    event_sha256 TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS native_consent_audit_no_update
                BEFORE UPDATE ON native_consent_audit
                BEGIN SELECT RAISE(ABORT, 'native consent audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS native_consent_audit_no_delete
                BEFORE DELETE ON native_consent_audit
                BEGIN SELECT RAISE(ABORT, 'native consent audit is immutable'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO native_consent_meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM native_consent_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise NativeConsentIntegrityError("unsupported native consent registry schema")

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        subject_ref: str,
        evidence_sha256: str,
        occurred_at: float,
    ) -> str:
        prior = connection.execute(
            "SELECT event_sha256 FROM native_consent_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = str(prior["event_sha256"]) if prior is not None else None
        body = {
            "schema": AUDIT_SCHEMA,
            "event_type": _ref(event_type, "audit event type"),
            "subject_ref": _ref(subject_ref, "audit subject"),
            "evidence_sha256": _digest(evidence_sha256, "audit evidence_sha256"),
            "occurred_at": _timestamp(occurred_at, "audit occurred_at"),
            "previous_sha256": previous,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO native_consent_audit(event_json,previous_sha256,event_sha256) "
            "VALUES(?,?,?)",
            (_canonical(body).decode("ascii"), previous, event_sha),
        )
        return event_sha

    @staticmethod
    def _authority_from_row(row: sqlite3.Row) -> NativeApplicationAuthority:
        raw = _loads(row["authority_json"], "application authority")
        if not isinstance(raw, Mapping):
            raise NativeConsentIntegrityError("stored application authority is invalid")
        fields = dict(raw)
        fields.pop("schema", None)
        fields["locales"] = tuple(fields.get("locales", ()))
        try:
            authority = NativeApplicationAuthority(**fields)
        except TypeError as exc:
            raise NativeConsentIntegrityError("stored application authority fields changed") from exc
        if not _same(authority.authority_sha256, row["authority_sha256"]):
            raise NativeConsentIntegrityError("stored application authority changed")
        return authority

    @staticmethod
    def _device_from_row(row: sqlite3.Row) -> NativeDeviceAuthority:
        return NativeDeviceAuthority(
            device_id=str(row["device_id"]),
            application_ref=str(row["application_ref"]),
            application_authority_sha256=str(row["application_authority_sha256"]),
            tenant_id=str(row["tenant_id"]),
            application_id=str(row["application_id"]),
            platform=str(row["platform"]),
            install_subject_sha256=str(row["install_subject_sha256"]),
            public_key_hex=str(row["public_key_hex"]),
            key_revision=int(row["key_revision"]),
            sdk_version=int(row["sdk_version"]),
            revision=int(row["revision"]),
            attestation_authority=str(row["attestation_authority"]),
            attestation_evidence_sha256=str(row["attestation_evidence_sha256"]),
            attestation_valid_until=float(row["attestation_valid_until"]),
            created_at=float(row["created_at"]),
        )

    def register_application(
        self,
        authority: NativeApplicationAuthority,
        *,
        expected_revision: int,
    ) -> dict[str, Any]:
        value = authority.normalized()
        expected = _revision(expected_revision, "expected_revision", allow_zero=True)
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT revision,authority_sha256,status FROM native_consent_apps "
                    "WHERE application_ref=?",
                    (authority.application_ref,),
                ).fetchone()
                current = int(row["revision"]) if row is not None else 0
                if current != expected:
                    raise NativeConsentConflict("application authority revision changed")
                if row is not None and row["status"] == "revoked":
                    raise NativeConsentDenied("revoked application cannot be rebound")
                next_revision = current + 1
                if row is None:
                    connection.execute(
                        "INSERT INTO native_consent_apps(application_ref,authority_json,"
                        "authority_sha256,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                        (
                            authority.application_ref,
                            _canonical(value).decode("ascii"),
                            authority.authority_sha256,
                            "active",
                            next_revision,
                            now,
                            now,
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE native_consent_apps SET authority_json=?,authority_sha256=?,"
                        "revision=?,updated_at=? WHERE application_ref=? AND revision=?",
                        (
                            _canonical(value).decode("ascii"),
                            authority.authority_sha256,
                            next_revision,
                            now,
                            authority.application_ref,
                            current,
                        ),
                    )
                self._append_audit(
                    connection,
                    event_type="application.registered",
                    subject_ref=authority.application_ref,
                    evidence_sha256=authority.authority_sha256,
                    occurred_at=now,
                )
                connection.execute("COMMIT")
                return {
                    "application_ref": authority.application_ref,
                    "revision": next_revision,
                    "authority_sha256": authority.authority_sha256,
                    "status": "active",
                }
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def get_application(self, application_ref: str) -> tuple[NativeApplicationAuthority, int]:
        ref = _ref(application_ref, "application_ref")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM native_consent_apps WHERE application_ref=?",
                (ref,),
            ).fetchone()
        if row is None or row["status"] != "active":
            raise NativeConsentDenied("native application authority is unavailable")
        return self._authority_from_row(row), int(row["revision"])

    def enroll_device(
        self,
        evidence: NativeEnrollmentEvidence,
        *,
        verifier: NativeAttestationVerifier,
        attestation_material: bytes,
        sdk_version: int,
    ) -> NativeDeviceAuthority:
        request = evidence.normalized()
        _require_attestation_material(
            attestation_material,
            request["attestation_evidence_sha256"],
        )
        version = _positive_int(sdk_version, "sdk_version", maximum=1_000_000)
        if "sdk_version" in request and request["sdk_version"] != version:
            raise NativeConsentDenied("enrollment SDK version was rebound")
        authority, _application_revision = self.get_application(evidence.application_ref)
        if (
            request["tenant_id"] != authority.tenant_id
            or request["application_id"] != authority.application_id
            or request["platform"] != authority.platform
            or version < authority.minimum_sdk_version
        ):
            raise NativeConsentDenied("enrollment is outside the application authority")
        verified = verifier.verify(evidence, attestation_material)
        if not isinstance(verified, VerifiedNativeAttestation):
            raise NativeConsentDenied("attestation verifier returned an invalid decision")
        attestation = verified.normalized()
        for key in (
            "application_ref",
            "tenant_id",
            "application_id",
            "platform",
            "install_subject_sha256",
            "public_key_hex",
            "attestation_nonce",
            "attestation_evidence_sha256",
        ):
            if not _same(str(attestation[key]), str(request[key])):
                raise NativeConsentDenied("attestation decision was rebound")
        if "sdk_version" in request and attestation.get("sdk_version") != version:
            raise NativeConsentDenied("attestation decision did not bind the SDK version")
        now = _timestamp(self._clock(), "clock")
        if (
            request["issued_at"] > now + _MAX_CLOCK_SKEW_SECONDS
            or request["expires_at"] < now
            or attestation["verified_at"] > now + _MAX_CLOCK_SKEW_SECONDS
            or attestation["valid_until"] <= now
        ):
            raise NativeConsentDenied("attestation is not current")
        nonce_sha = hashlib.sha256(request["attestation_nonce"].encode("utf-8")).hexdigest()
        device_id = "CP-DEV-" + hashlib.sha256(
            f"{authority.application_ref}\0{request['public_key_hex']}".encode()
        ).hexdigest()[:32]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                nonce = connection.execute(
                    "SELECT evidence_sha256 FROM native_consent_nonces "
                    "WHERE application_ref=? AND nonce_sha256=?",
                    (authority.application_ref, nonce_sha),
                ).fetchone()
                if nonce is not None:
                    raise NativeConsentConflict("attestation nonce was already consumed")
                count = connection.execute(
                    "SELECT COUNT(*) AS count FROM native_consent_devices"
                ).fetchone()
                if count is None or int(count["count"]) >= self.max_devices:
                    raise NativeConsentCapacityError("native device registry reached its bound")
                conflict = connection.execute(
                    "SELECT device_id FROM native_consent_devices WHERE "
                    "application_ref=? AND (install_subject_sha256=? OR public_key_hex=?)",
                    (
                        authority.application_ref,
                        request["install_subject_sha256"],
                        request["public_key_hex"],
                    ),
                ).fetchone()
                if conflict is not None:
                    raise NativeConsentConflict("installation is already enrolled")
                connection.execute(
                    "INSERT INTO native_consent_nonces(application_ref,nonce_sha256,"
                    "evidence_sha256,used_at) VALUES(?,?,?,?)",
                    (
                        authority.application_ref,
                        nonce_sha,
                        request["attestation_evidence_sha256"],
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO native_consent_devices(device_id,application_ref,"
                    "application_authority_sha256,tenant_id,application_id,platform,"
                    "install_subject_sha256,public_key_hex,key_revision,sdk_version,revision,"
                    "attestation_authority,attestation_evidence_sha256,"
                    "attestation_valid_until,status,last_counter,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        device_id,
                        authority.application_ref,
                        authority.authority_sha256,
                        authority.tenant_id,
                        authority.application_id,
                        authority.platform,
                        request["install_subject_sha256"],
                        request["public_key_hex"],
                        1,
                        version,
                        1,
                        attestation["authority"],
                        request["attestation_evidence_sha256"],
                        attestation["valid_until"],
                        "active",
                        0,
                        now,
                        now,
                    ),
                )
                self._append_audit(
                    connection,
                    event_type="device.enrolled",
                    subject_ref=device_id,
                    evidence_sha256=request["attestation_evidence_sha256"],
                    occurred_at=now,
                )
                row = connection.execute(
                    "SELECT * FROM native_consent_devices WHERE device_id=?",
                    (device_id,),
                ).fetchone()
                connection.execute("COMMIT")
                if row is None:
                    raise NativeConsentIntegrityError("device enrollment was not persisted")
                return self._device_from_row(row)
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def revoke_device(
        self,
        device_id: str,
        *,
        expected_revision: int,
        evidence_sha256: str,
    ) -> dict[str, Any]:
        device = _ref(device_id, "device_id")
        expected = _positive_int(expected_revision, "expected_revision")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                updated = connection.execute(
                    "UPDATE native_consent_devices SET status='revoked',revision=revision+1,"
                    "updated_at=? WHERE device_id=? AND revision=? AND status='active'",
                    (now, device, expected),
                )
                if updated.rowcount != 1:
                    raise NativeConsentConflict("device authority revision changed")
                self._append_audit(
                    connection,
                    event_type="device.revoked",
                    subject_ref=device,
                    evidence_sha256=evidence,
                    occurred_at=now,
                )
                connection.execute("COMMIT")
                return {"device_id": device, "revision": expected + 1, "status": "revoked"}
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def rotate_device_key(
        self,
        device_id: str,
        evidence: NativeEnrollmentEvidence,
        *,
        verifier: NativeAttestationVerifier,
        attestation_material: bytes,
        expected_revision: int,
    ) -> NativeDeviceAuthority:
        """Replace a key only under fresh platform attestation and exact CAS."""

        device_ref = _ref(device_id, "device_id")
        expected = _positive_int(expected_revision, "expected_revision")
        request = evidence.normalized()
        _require_attestation_material(
            attestation_material,
            request["attestation_evidence_sha256"],
        )
        verified = verifier.verify(evidence, attestation_material)
        if not isinstance(verified, VerifiedNativeAttestation):
            raise NativeConsentDenied("attestation verifier returned an invalid decision")
        decision = verified.normalized()
        now = _timestamp(self._clock(), "clock")
        if (
            request["issued_at"] > now + _MAX_CLOCK_SKEW_SECONDS
            or request["expires_at"] < now
            or decision["verified_at"] > now + _MAX_CLOCK_SKEW_SECONDS
            or decision["valid_until"] <= now
        ):
            raise NativeConsentDenied("rotation attestation is not current")
        for key in (
            "public_key_hex",
            "attestation_nonce",
            "attestation_evidence_sha256",
        ):
            if not _same(str(request[key]), str(decision[key])):
                raise NativeConsentDenied("rotation attestation decision was rebound")
        nonce_sha = hashlib.sha256(request["attestation_nonce"].encode()).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM native_consent_devices WHERE device_id=?",
                    (device_ref,),
                ).fetchone()
                if row is None or row["status"] != "active" or int(row["revision"]) != expected:
                    raise NativeConsentConflict("device authority revision changed")
                for key, stored in (
                    ("application_ref", row["application_ref"]),
                    ("tenant_id", row["tenant_id"]),
                    ("application_id", row["application_id"]),
                    ("platform", row["platform"]),
                    ("install_subject_sha256", row["install_subject_sha256"]),
                ):
                    if not _same(str(request[key]), str(stored)) or not _same(
                        str(decision[key]), str(stored)
                    ):
                        raise NativeConsentDenied("rotation attestation was rebound")
                if _same(row["public_key_hex"], request["public_key_hex"]):
                    raise NativeConsentConflict("rotation requires a new public key")
                prior_nonce = connection.execute(
                    "SELECT 1 FROM native_consent_nonces WHERE application_ref=? AND nonce_sha256=?",
                    (row["application_ref"], nonce_sha),
                ).fetchone()
                if prior_nonce is not None:
                    raise NativeConsentConflict("attestation nonce was already consumed")
                connection.execute(
                    "INSERT INTO native_consent_nonces(application_ref,nonce_sha256,"
                    "evidence_sha256,used_at) VALUES(?,?,?,?)",
                    (
                        row["application_ref"],
                        nonce_sha,
                        request["attestation_evidence_sha256"],
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE native_consent_devices SET public_key_hex=?,key_revision=key_revision+1,"
                    "revision=revision+1,attestation_authority=?,attestation_evidence_sha256=?,"
                    "attestation_valid_until=?,updated_at=? WHERE device_id=? AND revision=?",
                    (
                        request["public_key_hex"],
                        decision["authority"],
                        request["attestation_evidence_sha256"],
                        decision["valid_until"],
                        now,
                        device_ref,
                        expected,
                    ),
                )
                self._append_audit(
                    connection,
                    event_type="device.key_rotated",
                    subject_ref=device_ref,
                    evidence_sha256=request["attestation_evidence_sha256"],
                    occurred_at=now,
                )
                current = connection.execute(
                    "SELECT * FROM native_consent_devices WHERE device_id=?",
                    (device_ref,),
                ).fetchone()
                connection.execute("COMMIT")
                if current is None:
                    raise NativeConsentIntegrityError("rotated device is unavailable")
                return self._device_from_row(current)
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def refresh_device_authority(
        self,
        device_id: str,
        evidence: NativeEnrollmentEvidence,
        *,
        verifier: NativeAttestationVerifier,
        attestation_material: bytes,
        expected_revision: int,
        admitted_sdk_version: int | None = None,
    ) -> NativeDeviceAuthority:
        """Rebind one attested installation to the current application authority.

        This transition never rotates the device key or resets its monotonic
        counter. A version change is admitted only when the evidence and the
        independent verifier decision both explicitly bind that exact version.
        """

        device_ref = _ref(device_id, "device_id")
        expected = _positive_int(expected_revision, "expected_revision")
        request = evidence.normalized()
        _require_attestation_material(
            attestation_material,
            request["attestation_evidence_sha256"],
        )
        bound_sdk: int | None = None
        if admitted_sdk_version is not None:
            bound_sdk = _positive_int(
                admitted_sdk_version,
                "admitted_sdk_version",
                maximum=1_000_000,
            )
            if request.get("sdk_version") != bound_sdk:
                raise NativeConsentDenied("refresh evidence did not bind the SDK version")
        elif "sdk_version" in request:
            raise NativeConsentDenied("refresh SDK version was not explicitly admitted")

        # Reject obviously rebound applications before invoking an external
        # attestation verifier; the authority is re-read under the write lock.
        preliminary, _revision = self.get_application(evidence.application_ref)
        if (
            request["tenant_id"] != preliminary.tenant_id
            or request["application_id"] != preliminary.application_id
            or request["platform"] != preliminary.platform
        ):
            raise NativeConsentDenied("refresh is outside the application authority")
        verified = verifier.verify(evidence, attestation_material)
        if not isinstance(verified, VerifiedNativeAttestation):
            raise NativeConsentDenied("attestation verifier returned an invalid decision")
        decision = verified.normalized()
        for key in (
            "application_ref",
            "tenant_id",
            "application_id",
            "platform",
            "install_subject_sha256",
            "public_key_hex",
            "attestation_nonce",
            "attestation_evidence_sha256",
        ):
            if not _same(str(decision[key]), str(request[key])):
                raise NativeConsentDenied("refresh attestation decision was rebound")
        if bound_sdk is not None and decision.get("sdk_version") != bound_sdk:
            raise NativeConsentDenied("refresh verifier did not bind the SDK version")
        if bound_sdk is None and "sdk_version" in decision:
            raise NativeConsentDenied("refresh verifier introduced an unrequested SDK version")

        now = _timestamp(self._clock(), "clock")
        if (
            request["issued_at"] > now + _MAX_CLOCK_SKEW_SECONDS
            or request["expires_at"] < now
            or decision["verified_at"] > now + _MAX_CLOCK_SKEW_SECONDS
            or decision["valid_until"] <= now
        ):
            raise NativeConsentDenied("refresh attestation is not current")
        nonce_sha = hashlib.sha256(request["attestation_nonce"].encode("utf-8")).hexdigest()

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM native_consent_devices WHERE device_id=?",
                    (device_ref,),
                ).fetchone()
                app_row = connection.execute(
                    "SELECT * FROM native_consent_apps WHERE application_ref=?",
                    (request["application_ref"],),
                ).fetchone()
                if (
                    row is None
                    or row["status"] != "active"
                    or int(row["revision"]) != expected
                ):
                    raise NativeConsentConflict("device authority revision changed")
                if app_row is None or app_row["status"] != "active":
                    raise NativeConsentDenied("native application authority is unavailable")
                authority = self._authority_from_row(app_row)
                exact = (
                    (request["application_ref"], row["application_ref"]),
                    (request["application_ref"], authority.application_ref),
                    (request["tenant_id"], row["tenant_id"]),
                    (request["tenant_id"], authority.tenant_id),
                    (request["application_id"], row["application_id"]),
                    (request["application_id"], authority.application_id),
                    (request["platform"], row["platform"]),
                    (request["platform"], authority.platform),
                    (request["install_subject_sha256"], row["install_subject_sha256"]),
                    (request["public_key_hex"], row["public_key_hex"]),
                    (decision["application_ref"], row["application_ref"]),
                    (decision["tenant_id"], row["tenant_id"]),
                    (decision["application_id"], row["application_id"]),
                    (decision["platform"], row["platform"]),
                    (decision["install_subject_sha256"], row["install_subject_sha256"]),
                    (decision["public_key_hex"], row["public_key_hex"]),
                )
                if any(not _same(str(left), str(right)) for left, right in exact):
                    raise NativeConsentDenied("refresh installation authority was rebound")
                current_sdk = int(row["sdk_version"])
                next_sdk = current_sdk if bound_sdk is None else bound_sdk
                if next_sdk < current_sdk or next_sdk < authority.minimum_sdk_version:
                    raise NativeConsentDenied("refresh SDK version is no longer admitted")
                prior_nonce = connection.execute(
                    "SELECT 1 FROM native_consent_nonces WHERE application_ref=? "
                    "AND nonce_sha256=?",
                    (authority.application_ref, nonce_sha),
                ).fetchone()
                if prior_nonce is not None:
                    raise NativeConsentConflict("attestation nonce was already consumed")
                connection.execute(
                    "INSERT INTO native_consent_nonces(application_ref,nonce_sha256,"
                    "evidence_sha256,used_at) VALUES(?,?,?,?)",
                    (
                        authority.application_ref,
                        nonce_sha,
                        request["attestation_evidence_sha256"],
                        now,
                    ),
                )
                updated = connection.execute(
                    "UPDATE native_consent_devices SET application_authority_sha256=?,"
                    "sdk_version=?,revision=revision+1,attestation_authority=?,"
                    "attestation_evidence_sha256=?,attestation_valid_until=?,updated_at=? "
                    "WHERE device_id=? AND revision=? AND status='active'",
                    (
                        authority.authority_sha256,
                        next_sdk,
                        decision["authority"],
                        request["attestation_evidence_sha256"],
                        decision["valid_until"],
                        now,
                        device_ref,
                        expected,
                    ),
                )
                if updated.rowcount != 1:
                    raise NativeConsentConflict("device authority revision changed")
                self._append_audit(
                    connection,
                    event_type="device.authority_refreshed",
                    subject_ref=device_ref,
                    evidence_sha256=_sha256(
                        {
                            "application_authority_sha256": authority.authority_sha256,
                            "attestation_authority": decision["authority"],
                            "attestation_evidence_sha256": request[
                                "attestation_evidence_sha256"
                            ],
                            "attestation_nonce_sha256": nonce_sha,
                            "attestation_valid_until": decision["valid_until"],
                            "device_id": device_ref,
                            "from_revision": expected,
                            "public_key_sha256": hashlib.sha256(
                                request["public_key_hex"].encode("ascii")
                            ).hexdigest(),
                            "sdk_version": next_sdk,
                            "to_revision": expected + 1,
                        }
                    ),
                    occurred_at=now,
                )
                current = connection.execute(
                    "SELECT * FROM native_consent_devices WHERE device_id=?",
                    (device_ref,),
                ).fetchone()
                connection.execute("COMMIT")
                if current is None:
                    raise NativeConsentIntegrityError("refreshed device is unavailable")
                return self._device_from_row(current)
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def claim_request(
        self,
        envelope: NativeRequestEnvelope,
        *,
        client_authority_resolver: Callable[[str], object],
    ) -> tuple[NativeApplicationAuthority, NativeDeviceAuthority, NativeResponseReceipt | None]:
        """Authenticate, replay-check, and durably claim one signed request."""

        body = envelope.signing_body()
        request_sha = envelope.request_sha256
        now = _timestamp(self._clock(), "clock")
        if body["issued_at"] > now + _MAX_CLOCK_SKEW_SECONDS:
            raise NativeConsentDenied("native request is outside its freshness window")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                device_row = connection.execute(
                    "SELECT * FROM native_consent_devices WHERE device_id=?",
                    (envelope.device_id,),
                ).fetchone()
                app_row = connection.execute(
                    "SELECT * FROM native_consent_apps WHERE application_ref=?",
                    (envelope.application_ref,),
                ).fetchone()
                if (
                    device_row is None
                    or app_row is None
                    or device_row["status"] != "active"
                    or app_row["status"] != "active"
                ):
                    raise NativeConsentDenied("native device authority is unavailable")
                authority = self._authority_from_row(app_row)
                device = self._device_from_row(device_row)
                if device.attestation_valid_until <= now:
                    raise NativeConsentDenied("device attestation expired")
                exact_pairs = (
                    (envelope.application_ref, authority.application_ref),
                    (envelope.application_authority_sha256, authority.authority_sha256),
                    (device.application_ref, authority.application_ref),
                    (device.application_authority_sha256, authority.authority_sha256),
                    (envelope.tenant_id, authority.tenant_id),
                    (device.tenant_id, authority.tenant_id),
                    (envelope.application_id, authority.application_id),
                    (device.application_id, authority.application_id),
                    (envelope.platform, authority.platform),
                    (device.platform, authority.platform),
                    (envelope.device_id, device.device_id),
                    (envelope.public_client_record_sha256, authority.public_client_record_sha256),
                    (envelope.publication_sha256, authority.publication_sha256),
                    (envelope.publication_bundle_sha256, authority.publication_bundle_sha256),
                    (envelope.configuration_sha256, authority.configuration_sha256),
                    (envelope.policy_id, authority.policy_id),
                    (envelope.policy_sha256, authority.policy_sha256),
                    (envelope.standards_contract_sha256, authority.standards_contract_sha256),
                )
                if any(not _same(left, right) for left, right in exact_pairs) or any(
                    left != right
                    for left, right in (
                        (envelope.device_revision, device.revision),
                        (envelope.key_revision, device.key_revision),
                        (envelope.sdk_version, device.sdk_version),
                        (envelope.public_client_revision, authority.public_client_revision),
                        (envelope.policy_version, authority.policy_version),
                    )
                ):
                    raise NativeConsentConflict("native request authority changed")
                if device.sdk_version < authority.minimum_sdk_version:
                    raise NativeConsentDenied("native SDK version is no longer admitted")
                envelope.verify(device.public_key_hex)
                current_client = client_authority_resolver(
                    authority.public_client_credential_sha256
                )
                client_pairs = {
                    "credential_sha256": authority.public_client_credential_sha256,
                    "tenant_id": authority.tenant_id,
                    "property_id": authority.property_id,
                    "client_kind": "service",
                    "service_client_id": authority.application_ref,
                    "target_bundle_id": authority.application_id,
                    "target_platform": authority.platform,
                    "revision": authority.public_client_revision,
                    "record_sha256": authority.public_client_record_sha256,
                    "property_revision": authority.property_revision,
                    "property_sha256": authority.property_sha256,
                    "publication_sha256": authority.publication_sha256,
                    "bundle_sha256": authority.publication_bundle_sha256,
                    "policy_id": authority.policy_id,
                    "policy_version": authority.policy_version,
                    "policy_sha256": authority.policy_sha256,
                }
                for name, expected in client_pairs.items():
                    actual = (
                        current_client.get(name)
                        if isinstance(current_client, Mapping)
                        else getattr(current_client, name, None)
                    )
                    if actual != expected:
                        raise NativeConsentConflict("public client authority changed")
                prior = connection.execute(
                    "SELECT * FROM native_consent_requests WHERE device_id=? AND request_id=?",
                    (device.device_id, envelope.request_id),
                ).fetchone()
                if prior is not None:
                    if not _same(prior["request_sha256"], request_sha):
                        raise NativeConsentConflict("request id was rebound to different content")
                    if prior["status"] == "complete":
                        payload = _loads(
                            prior["receipt_json"],
                            "native receipt",
                            maximum=_MAX_RESULT_BYTES,
                        )
                        if not isinstance(payload, Mapping) or not isinstance(
                            prior["signature_hex"], str
                        ):
                            raise NativeConsentIntegrityError("stored native receipt is invalid")
                        connection.execute("COMMIT")
                        return authority, device, NativeResponseReceipt(
                            payload=dict(payload),
                            signature_hex=str(prior["signature_hex"]),
                        )
                    if body["expires_at"] < now:
                        raise NativeConsentDenied("native request is outside its freshness window")
                    connection.execute("COMMIT")
                    return authority, device, None
                if body["expires_at"] < now:
                    raise NativeConsentDenied("native request is outside its freshness window")
                count = connection.execute(
                    "SELECT COUNT(*) AS count FROM native_consent_requests"
                ).fetchone()
                if count is not None and int(count["count"]) >= self.max_requests:
                    # Reclaim room only when the bound is reached, so stored
                    # receipts stay available to retries for as long as they fit.
                    connection.execute(
                        "DELETE FROM native_consent_requests WHERE created_at < ?",
                        (now - _REQUEST_REPLAY_HORIZON_SECONDS,),
                    )
                    count = connection.execute(
                        "SELECT COUNT(*) AS count FROM native_consent_requests"
                    ).fetchone()
                if count is None or int(count["count"]) >= self.max_requests:
                    raise NativeConsentCapacityError("native request registry reached its bound")
                last_counter = int(device_row["last_counter"])
                if not last_counter < envelope.counter <= last_counter + _MAX_COUNTER_JUMP:
                    raise NativeConsentConflict("native request counter is stale or jumped its bound")
                connection.execute(
                    "INSERT INTO native_consent_requests(device_id,request_id,request_sha256,"
                    "counter,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (
                        device.device_id,
                        envelope.request_id,
                        request_sha,
                        envelope.counter,
                        "pending",
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE native_consent_devices SET last_counter=?,updated_at=? WHERE device_id=?",
                    (envelope.counter, now, device.device_id),
                )
                self._append_audit(
                    connection,
                    event_type="request.claimed",
                    subject_ref=envelope.request_id,
                    evidence_sha256=request_sha,
                    occurred_at=now,
                )
                connection.execute("COMMIT")
                return authority, device, None
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def complete_request(
        self,
        envelope: NativeRequestEnvelope,
        result: Mapping[str, Any],
        *,
        signer: NativeReceiptSigner,
    ) -> NativeResponseReceipt:
        safe_result = dict(result)
        result_json = _canonical(safe_result, maximum=_MAX_RESULT_BYTES).decode("ascii")
        result_sha = hashlib.sha256(result_json.encode("ascii")).hexdigest()
        now = int(math.floor(_timestamp(self._clock(), "clock")))
        key_id = _ref(signer.key_id, "receipt key id")
        key_revision = _positive_int(signer.key_revision, "receipt key revision")
        body = {
            "schema": RECEIPT_SCHEMA,
            "application_ref": envelope.application_ref,
            "application_authority_sha256": envelope.application_authority_sha256,
            "tenant_sha256": hashlib.sha256(envelope.tenant_id.encode()).hexdigest(),
            "device_id": envelope.device_id,
            "device_revision": envelope.device_revision,
            "request_id": envelope.request_id,
            "request_sha256": envelope.request_sha256,
            "operation": envelope.operation,
            "result": safe_result,
            "result_sha256": result_sha,
            "publication_sha256": envelope.publication_sha256,
            "configuration_sha256": envelope.configuration_sha256,
            "policy_sha256": envelope.policy_sha256,
            "key_id": key_id,
            "key_revision": key_revision,
            "completed_at": now,
        }
        encoded = _canonical(body, maximum=_MAX_RESULT_BYTES)
        signature = signer.sign(encoded)
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise NativeConsentIntegrityError("receipt signer returned an invalid signature")
        receipt = NativeResponseReceipt(payload=body, signature_hex=signature.hex())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT request_sha256,status,receipt_json,signature_hex "
                    "FROM native_consent_requests WHERE device_id=? AND request_id=?",
                    (envelope.device_id, envelope.request_id),
                ).fetchone()
                if row is None or not _same(row["request_sha256"], envelope.request_sha256):
                    raise NativeConsentConflict("native request claim is unavailable")
                if row["status"] == "complete":
                    stored = _loads(row["receipt_json"], "native receipt", maximum=_MAX_RESULT_BYTES)
                    if not isinstance(stored, Mapping) or not isinstance(row["signature_hex"], str):
                        raise NativeConsentIntegrityError("stored native receipt is invalid")
                    connection.execute("COMMIT")
                    return NativeResponseReceipt(dict(stored), str(row["signature_hex"]))
                connection.execute(
                    "UPDATE native_consent_requests SET status='complete',result_json=?,"
                    "result_sha256=?,receipt_json=?,signature_hex=?,updated_at=? "
                    "WHERE device_id=? AND request_id=? AND status='pending'",
                    (
                        result_json,
                        result_sha,
                        encoded.decode("ascii"),
                        receipt.signature_hex,
                        now,
                        envelope.device_id,
                        envelope.request_id,
                    ),
                )
                self._append_audit(
                    connection,
                    event_type="request.completed",
                    subject_ref=envelope.request_id,
                    evidence_sha256=result_sha,
                    occurred_at=now,
                )
                connection.execute("COMMIT")
                return receipt
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def verify_integrity(self) -> dict[str, Any]:
        previous: str | None = None
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence,event_json,previous_sha256,event_sha256 "
                "FROM native_consent_audit ORDER BY sequence"
            ).fetchall()
        for row in rows:
            body = _loads(row["event_json"], "native audit event")
            if (
                not isinstance(body, Mapping)
                or body.get("previous_sha256") != previous
                or row["previous_sha256"] != previous
                or not _same(_sha256(body), row["event_sha256"])
            ):
                raise NativeConsentIntegrityError("native consent audit chain changed")
            previous = str(row["event_sha256"])
        return {
            "schema": "lightwork.native-consent-integrity.v1",
            "valid": True,
            "events": len(rows),
            "head_sha256": previous,
        }


class NativeOperationHandler(Protocol):
    def __call__(
        self,
        authority: NativeApplicationAuthority,
        device: NativeDeviceAuthority,
        operation: str,
        payload: Mapping[str, Any],
        request_id: str,
    ) -> Mapping[str, Any]: ...


class NativeConsentGateway:
    """Authenticate and execute closed operations against existing authorities."""

    def __init__(
        self,
        registry: NativeConsentDeviceRegistry,
        *,
        client_authority_resolver: Callable[[str], object],
        handler: NativeOperationHandler,
        receipt_signer: NativeReceiptSigner,
    ) -> None:
        self.registry = registry
        self.client_authority_resolver = client_authority_resolver
        self.handler = handler
        self.receipt_signer = receipt_signer

    def dispatch(self, envelope: NativeRequestEnvelope) -> NativeResponseReceipt:
        authority, device, replay = self.registry.claim_request(
            envelope,
            client_authority_resolver=self.client_authority_resolver,
        )
        if replay is not None:
            return replay
        result = self.handler(
            authority,
            device,
            envelope.operation,
            envelope.signing_body()["payload"],
            envelope.request_id,
        )
        if not isinstance(result, Mapping):
            raise NativeConsentIntegrityError("native operation handler returned invalid data")
        return self.registry.complete_request(envelope, result, signer=self.receipt_signer)


class NativeOfflineQueue:
    """Bounded durable queue shared by adapter conformance tests and thin hosts.

    Platform adapters may use Keychain/Keystore/IndexedDB/roRegistry for their
    transport implementation, but must preserve these state transitions and
    bounds.  Only already-signed envelopes are persisted; no raw subject,
    profile capability, bearer credential, or attestation token is accepted.
    """

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        max_messages: int = _MAX_PENDING_MESSAGES,
        max_attempts: int = 8,
        retry_base_seconds: float = 2.0,
        retry_max_seconds: float = 300.0,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self.max_messages = _positive_int(max_messages, "max_messages", maximum=10_000)
        self.max_attempts = _positive_int(max_attempts, "max_attempts", maximum=32)
        self.retry_base_seconds = float(retry_base_seconds)
        self.retry_max_seconds = float(retry_max_seconds)
        if (
            not math.isfinite(self.retry_base_seconds)
            or not math.isfinite(self.retry_max_seconds)
            or not 0.1 <= self.retry_base_seconds <= self.retry_max_seconds <= 86_400
        ):
            raise NativeConsentValidationError("offline retry bounds are invalid")
        ensure_private_directory(self.path.parent)
        self._initialize()

    @contextlib.contextmanager
    def _connect(self):
        with consent_storage.authority_connection(
            self.path, ensure_directory=ensure_private_directory,
            ensure_file=ensure_private_file, foreign_keys=False,
        ) as connection:
            yield connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS native_offline_queue(
                    request_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','dead_letter')),
                    next_attempt_at REAL NOT NULL,
                    last_error_sha256 TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )

    def enqueue(self, envelope: NativeRequestEnvelope) -> dict[str, Any]:
        body = {**envelope.signing_body(), "signature_hex": envelope.signature_hex}
        encoded = _canonical(body, maximum=_MAX_PAYLOAD_BYTES).decode("ascii")
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                prior = connection.execute(
                    "SELECT request_sha256,state FROM native_offline_queue WHERE request_id=?",
                    (envelope.request_id,),
                ).fetchone()
                if prior is not None:
                    if not _same(prior["request_sha256"], envelope.request_sha256):
                        raise NativeConsentConflict("offline request id was rebound")
                    connection.execute("COMMIT")
                    return {"request_id": envelope.request_id, "status": str(prior["state"])}
                count = connection.execute(
                    "SELECT COUNT(*) AS count FROM native_offline_queue WHERE state='pending'"
                ).fetchone()
                if count is None or int(count["count"]) >= self.max_messages:
                    raise NativeConsentCapacityError("offline queue reached its bound")
                connection.execute(
                    "INSERT INTO native_offline_queue(request_id,device_id,request_sha256,"
                    "envelope_json,attempts,state,next_attempt_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,0,'pending',?,?,?)",
                    (
                        envelope.request_id,
                        envelope.device_id,
                        envelope.request_sha256,
                        encoded,
                        now,
                        now,
                        now,
                    ),
                )
                connection.execute("COMMIT")
                return {"request_id": envelope.request_id, "status": "pending"}
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def due(self, *, limit: int = 32) -> tuple[NativeRequestEnvelope, ...]:
        bounded = _positive_int(limit, "limit", maximum=128)
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT envelope_json FROM native_offline_queue WHERE state='pending' "
                "AND next_attempt_at<=? ORDER BY created_at,request_id LIMIT ?",
                (now, bounded),
            ).fetchall()
        result: list[NativeRequestEnvelope] = []
        for row in rows:
            raw = _loads(row["envelope_json"], "offline envelope", maximum=_MAX_PAYLOAD_BYTES)
            if not isinstance(raw, Mapping):
                raise NativeConsentIntegrityError("stored offline envelope is invalid")
            try:
                result.append(NativeRequestEnvelope(**dict(raw)))
            except TypeError as exc:
                raise NativeConsentIntegrityError("stored offline envelope fields changed") from exc
        return tuple(result)

    def retry(self, request_id: str, error_evidence: bytes) -> dict[str, Any]:
        ref = _ref(request_id, "request_id")
        if not isinstance(error_evidence, bytes) or not 1 <= len(error_evidence) <= 4_096:
            raise NativeConsentValidationError("retry evidence is outside its byte bound")
        error_sha = hashlib.sha256(error_evidence).hexdigest()
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT attempts,state FROM native_offline_queue WHERE request_id=?",
                    (ref,),
                ).fetchone()
                if row is None or row["state"] != "pending":
                    raise NativeConsentConflict("offline request is not retryable")
                attempts = int(row["attempts"]) + 1
                state = "dead_letter" if attempts >= self.max_attempts else "pending"
                delay = min(
                    self.retry_max_seconds,
                    self.retry_base_seconds * (2 ** min(attempts - 1, 20)),
                )
                connection.execute(
                    "UPDATE native_offline_queue SET attempts=?,state=?,next_attempt_at=?,"
                    "last_error_sha256=?,updated_at=? WHERE request_id=?",
                    (attempts, state, now + delay, error_sha, now, ref),
                )
                connection.execute("COMMIT")
                return {
                    "request_id": ref,
                    "state": state,
                    "attempts": attempts,
                    "next_attempt_at": now + delay,
                    "error_sha256": error_sha,
                }
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def renew_expired(
        self,
        request_id: str,
        authority: NativeApplicationAuthority,
        device: NativeDeviceAuthority,
        *,
        new_request_id: str,
        counter: int,
        signer: NativeEnvelopeSigner,
        ttl_seconds: float = 120.0,
    ) -> NativeRequestEnvelope:
        """Re-sign an expired offline operation without retaining a bearer secret.

        The downstream idempotency key inside the normalized operation payload
        is preserved.  A new envelope request id and counter are mandatory so a
        delivery-unknown retry cannot rebind a gateway claim.  Mutating backend
        handlers must in turn preserve that downstream idempotency key.
        """

        ref = _ref(request_id, "request_id")
        replacement_ref = _ref(new_request_id, "new_request_id")
        if _same(ref, replacement_ref):
            raise NativeConsentValidationError("renewal requires a new request id")
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT envelope_json,state,attempts,updated_at FROM native_offline_queue "
                "WHERE request_id=?",
                (ref,),
            ).fetchone()
        if row is None or row["state"] != "pending":
            raise NativeConsentConflict("offline request is not renewable")
        raw = _loads(row["envelope_json"], "offline envelope", maximum=_MAX_PAYLOAD_BYTES)
        if not isinstance(raw, Mapping):
            raise NativeConsentIntegrityError("stored offline envelope is invalid")
        try:
            prior = NativeRequestEnvelope(**dict(raw))
        except TypeError as exc:
            raise NativeConsentIntegrityError("stored offline envelope fields changed") from exc
        if prior.expires_at >= now:
            raise NativeConsentConflict("offline request has not expired")
        if (
            prior.application_ref != authority.application_ref
            or prior.device_id != device.device_id
            or prior.application_authority_sha256 != authority.authority_sha256
        ):
            raise NativeConsentConflict("offline request authority changed")
        replacement = build_envelope(
            authority,
            device,
            request_id=replacement_ref,
            counter=counter,
            operation=prior.operation,
            payload=prior.payload,
            signer=signer,
            issued_at=now,
            ttl_seconds=ttl_seconds,
        )
        replacement_value = {
            **replacement.signing_body(),
            "signature_hex": replacement.signature_hex,
        }
        encoded = _canonical(replacement_value, maximum=_MAX_PAYLOAD_BYTES).decode("ascii")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    "SELECT request_sha256,state,attempts,updated_at "
                    "FROM native_offline_queue WHERE request_id=?",
                    (ref,),
                ).fetchone()
                if (
                    current is None
                    or current["state"] != "pending"
                    or not _same(current["request_sha256"], prior.request_sha256)
                    or int(current["attempts"]) != int(row["attempts"])
                    or float(current["updated_at"]) != float(row["updated_at"])
                ):
                    raise NativeConsentConflict("offline request changed during renewal")
                collision = connection.execute(
                    "SELECT 1 FROM native_offline_queue WHERE request_id=?",
                    (replacement_ref,),
                ).fetchone()
                if collision is not None:
                    raise NativeConsentConflict("replacement request id already exists")
                connection.execute(
                    "INSERT INTO native_offline_queue(request_id,device_id,request_sha256,"
                    "envelope_json,attempts,state,next_attempt_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,0,'pending',?,?,?)",
                    (
                        replacement.request_id,
                        replacement.device_id,
                        replacement.request_sha256,
                        encoded,
                        now,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "DELETE FROM native_offline_queue WHERE request_id=?",
                    (ref,),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return replacement

    def acknowledge(
        self,
        receipt: NativeResponseReceipt,
        *,
        trusted_public_keys: Mapping[str, str],
    ) -> None:
        """Delete a queued request only after a trusted, exact receipt verifies."""

        if not receipt.verify(trusted_public_keys):
            raise NativeConsentDenied("offline receipt signature did not verify")
        body = receipt.normalized()
        request_id = body["request_id"]
        request_sha = body["request_sha256"]
        device_id = body["device_id"]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT request_sha256,device_id FROM native_offline_queue WHERE request_id=?",
                    (request_id,),
                ).fetchone()
                if (
                    row is None
                    or not _same(row["request_sha256"], request_sha)
                    or not _same(row["device_id"], device_id)
                ):
                    raise NativeConsentConflict("receipt is not bound to an offline request")
                connection.execute(
                    "DELETE FROM native_offline_queue WHERE request_id=?",
                    (request_id,),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def revoke_device(self, device_id: str) -> int:
        """Delete all queued operations when local device authority is revoked."""

        device = _ref(device_id, "device_id")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                removed = connection.execute(
                    "DELETE FROM native_offline_queue WHERE device_id=?",
                    (device,),
                ).rowcount
                connection.execute("COMMIT")
                return int(removed)
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise


__all__ = [
    "APPLICATION_SCHEMA",
    "ATTESTATION_SCHEMA",
    "AUDIT_SCHEMA",
    "ENVELOPE_SCHEMA",
    "OPERATIONS",
    "PLATFORMS",
    "RECEIPT_SCHEMA",
    "NativeApplicationAuthority",
    "NativeAttestationVerifier",
    "NativeConsentCapacityError",
    "NativeConsentConflict",
    "NativeConsentDenied",
    "NativeConsentDeviceRegistry",
    "NativeConsentError",
    "NativeConsentGateway",
    "NativeConsentIntegrityError",
    "NativeConsentValidationError",
    "NativeDeviceAuthority",
    "NativeEnrollmentEvidence",
    "NativeEnvelopeSigner",
    "NativeOfflineQueue",
    "NativeOperationHandler",
    "NativeReceiptSigner",
    "NativeRequestEnvelope",
    "NativeResponseReceipt",
    "VerifiedNativeAttestation",
    "build_envelope",
    "localized_ui_contract",
    "normalize_operation_payload",
]
