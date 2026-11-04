"""Trust and transport seams for the bounded AI benchmark exchange.

The core benchmark service deliberately has no network client.  This module
adds two independently injectable boundaries without changing that default:

* an immutable, versioned Ed25519 trust-root set whose verifier is directly
  compatible with ``AIBenchmarkExchangeService(signature_verifier=...)``; and
* an explicitly enabled HTTPS coordinator client that accepts only an already
  exported, four-eyes-approved contribution packet plus literal per-call
  consent.

The coordinator URL and path cannot be selected by a contribution or caller.
The request schema is closed and contains no tenant identifier or raw record.
There are no background jobs, automatic contributions, automatic retries, or
cross-tenant pooling in this module.  An ambiguous write can only be retried by
calling ``submit`` again with the exact same idempotency key and payload.

Signature verification proves payload integrity against an operator-pinned
key.  Coordinator submission proves neither cohort inclusion nor anonymity,
differential privacy, methodology quality, or population representativeness.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from .ai_benchmark_exchange import (
    CONTRIBUTION_EXPORT_SCHEMA,
    METHODOLOGY_NOTICE,
    PRIVACY_NOTICE,
    SUPPORTED_GEOGRAPHIES,
    SUPPORTED_INDUSTRIES,
    SUPPORTED_METRICS,
    SUPPORTED_MODALITIES,
    SUPPORTED_ORG_SIZES,
)

TRUST_ROOT_SCHEMA = "lightwork.ai-benchmark-ed25519-trust-roots.v1"
COORDINATOR_SUBMISSION_SCHEMA = "lightwork.ai-benchmark-coordinator-submission.v1"
COORDINATOR_RECEIPT_SCHEMA = "lightwork.ai-benchmark-coordinator-receipt.v1"
COORDINATOR_SUBMISSION_PATH = "/v1/benchmark/contributions"

_MAX_TRUST_KEYS = 64
_MAX_CANONICAL_BYTES = 256 * 1024
_MAX_REQUEST_BYTES = 256 * 1024
_MIN_REQUEST_BYTES = 1024
_MAX_RESPONSE_BYTES = 1024 * 1024
_MIN_RESPONSE_BYTES = 1024
_MAX_TIMEOUT_SECONDS = 60.0
_MIN_TIMEOUT_SECONDS = 1.0
_MAX_IDEMPOTENCY_KEY = 128
_MAX_EVIDENCE_BINDINGS = 32
_MAX_LIMITATIONS = 8
_MAX_COUNT = 1_000_000_000_000

_KEY_ID_RE = re.compile(r"KEY-[0-9a-f]{32}\Z")
_PUBLIC_KEY_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_HEX_SIGNATURE_RE = re.compile(r"[0-9a-fA-F]{128}\Z")
_ENCODED_SIGNATURE_RE = re.compile(r"[A-Za-z0-9+/_=-]{64,128}\Z")
_PSEUDONYMOUS_ID_RE = re.compile(r"BXC-[0-9a-f]{32}\Z")
_EVIDENCE_ID_RE = re.compile(r"MRE-[0-9a-f]{32}\Z")
_RECEIPT_ID_RE = re.compile(r"BCR-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")

_TRUST_DOCUMENT_FIELDS = frozenset({"schema", "version", "keys"})
_TRUST_KEY_FIELDS = frozenset({"key_id", "public_key_hex", "introduced_in", "revoked_in"})
_TRUST_KEY_REQUIRED_FIELDS = frozenset({"key_id", "public_key_hex", "introduced_in"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "value"})
_EXPORT_FIELDS = frozenset(
    {
        "schema",
        "pseudonymous_contribution_id",
        "version",
        "metric_code",
        "numerator",
        "denominator",
        "period",
        "cohort",
        "evidence_bindings",
        "content_sha256",
        "authority_sha256",
        "approval",
        "methodology",
        "privacy",
        "limitations",
        "packet_sha256",
    }
)
_PERIOD_FIELDS = frozenset({"start", "end"})
_COHORT_FIELDS = frozenset(
    {"industry_code", "geography_code", "organization_size_code", "model_modality_code"}
)
_EVIDENCE_FIELDS = frozenset({"evidence_id", "digest"})
_APPROVAL_FIELDS = frozenset(
    {"voluntary_opt_in", "human_approved", "four_eyes", "evidence_current"}
)
_METHODOLOGY_FIELDS = frozenset({"aggregation_level", "calculation", "sampling_basis"})
_PRIVACY_FIELDS = frozenset(
    {
        "raw_records_included",
        "tenant_identity_included",
        "customer_identifiers_included",
        "anonymity_claim",
        "differential_privacy_claim",
        "privacy_budget_accounting",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "receipt_id",
        "idempotency_key",
        "packet_sha256",
        "accepted_at",
    }
)


class BenchmarkExchangeTransportError(RuntimeError):
    """Base error for the optional trust and coordinator seam."""


class BenchmarkTrustRootError(BenchmarkExchangeTransportError):
    """An operator-supplied trust-root document is invalid or regressive."""


class BenchmarkCoordinatorConfigError(BenchmarkExchangeTransportError):
    """The opt-in coordinator client has unsafe or incomplete configuration."""


class BenchmarkCoordinatorDisabled(BenchmarkCoordinatorConfigError):
    """Coordinator egress was not explicitly enabled."""


class BenchmarkCoordinatorConsentError(BenchmarkExchangeTransportError):
    """A caller did not provide literal consent for the exact export packet."""


class BenchmarkCoordinatorProtocolError(BenchmarkExchangeTransportError):
    """A local packet or coordinator response violated the closed protocol."""


class BenchmarkCoordinatorDefinitiveTransportError(BenchmarkExchangeTransportError):
    """A request was blocked before any remote delivery could occur."""


class BenchmarkCoordinatorAmbiguousDelivery(BenchmarkExchangeTransportError):
    """Delivery may have occurred; only an exact idempotent retry is safe."""

    retryable = True


class BenchmarkCoordinatorIdempotencyConflict(BenchmarkExchangeTransportError):
    """An idempotency key was rebound to different canonical content."""


def _closed(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BenchmarkCoordinatorProtocolError(f"{label} has unexpected or missing fields")
    return value


def _canonical(value: object, *, maximum: int = _MAX_CANONICAL_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise BenchmarkCoordinatorProtocolError("benchmark payload is not finite JSON") from None
    if len(encoded) > maximum:
        raise BenchmarkCoordinatorProtocolError("benchmark payload exceeds its byte bound")
    return encoded


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object) -> str:
    return _sha256_bytes(_canonical(value))


def _strict_json(body: bytes, *, maximum: int, label: str) -> Any:
    if not isinstance(body, bytes) or not body or len(body) > maximum:
        raise BenchmarkCoordinatorProtocolError(f"{label} exceeds its byte bound")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    try:
        return json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise BenchmarkCoordinatorProtocolError(f"{label} is malformed JSON") from None


def _positive_integer(value: object, label: str, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise BenchmarkCoordinatorProtocolError(f"{label} must be a positive integer")
    return value


def _bounded_count(value: object, label: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= _MAX_COUNT:
        raise BenchmarkCoordinatorProtocolError(f"{label} is outside its integer bound")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise BenchmarkCoordinatorProtocolError(f"{label} must be a lowercase SHA-256")
    return value


def _canonical_date(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise BenchmarkCoordinatorProtocolError(f"{label} must be a canonical ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise BenchmarkCoordinatorProtocolError(f"{label} must be a canonical ISO date") from None
    if parsed.isoformat() != value:
        raise BenchmarkCoordinatorProtocolError(f"{label} must be a canonical ISO date")
    return value


@dataclass(frozen=True)
class Ed25519TrustKey:
    """One opaque key-id binding in a versioned operator trust document."""

    key_id: str
    public_key_hex: str = field(repr=False)
    introduced_in: int = 1
    revoked_in: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.fullmatch(self.key_id):
            raise BenchmarkTrustRootError("trust key_id is invalid")
        if not isinstance(self.public_key_hex, str) or not _PUBLIC_KEY_RE.fullmatch(
            self.public_key_hex
        ):
            raise BenchmarkTrustRootError("trust public key must be 32-byte hex")
        public_hex = self.public_key_hex.lower()
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        except (TypeError, ValueError):
            raise BenchmarkTrustRootError("trust public key is invalid") from None
        introduced = self.introduced_in
        if (
            isinstance(introduced, bool)
            or not isinstance(introduced, int)
            or introduced < 1
            or introduced > 2**31 - 1
        ):
            raise BenchmarkTrustRootError("trust introduced_in is invalid")
        revoked = self.revoked_in
        if revoked is not None and (
            isinstance(revoked, bool)
            or not isinstance(revoked, int)
            or revoked <= introduced
            or revoked > 2**31 - 1
        ):
            raise BenchmarkTrustRootError("trust revoked_in is invalid")
        object.__setattr__(self, "public_key_hex", public_hex)

    def active_at(self, version: int) -> bool:
        return self.introduced_in <= version and (
            self.revoked_in is None or version < self.revoked_in
        )


@dataclass(frozen=True)
class VersionedEd25519TrustRoots:
    """Immutable key-id-selected trust roots with monotonic rotation support."""

    version: int
    keys: tuple[Ed25519TrustKey, ...]

    def __post_init__(self) -> None:
        version = self.version
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or not 1 <= version <= 2**31 - 1
        ):
            raise BenchmarkTrustRootError("trust-root version is invalid")
        if isinstance(self.keys, (str, bytes)) or not isinstance(self.keys, Sequence):
            raise BenchmarkTrustRootError("trust-root keys must be a bounded sequence")
        keys = tuple(self.keys)
        if not 1 <= len(keys) <= _MAX_TRUST_KEYS:
            raise BenchmarkTrustRootError("trust-root key count is invalid")
        if not all(isinstance(item, Ed25519TrustKey) for item in keys):
            raise BenchmarkTrustRootError("trust-root entries must be Ed25519TrustKey")
        identities = [item.key_id for item in keys]
        if len(set(identities)) != len(identities):
            raise BenchmarkTrustRootError("trust-root key ids must be unique")
        if any(item.introduced_in > version for item in keys):
            raise BenchmarkTrustRootError("trust-root contains a future key")
        object.__setattr__(self, "keys", tuple(sorted(keys, key=lambda item: item.key_id)))

    @classmethod
    def from_document(cls, document: object) -> VersionedEd25519TrustRoots:
        if not isinstance(document, Mapping) or set(document) != _TRUST_DOCUMENT_FIELDS:
            raise BenchmarkTrustRootError("trust-root document shape is invalid")
        if document.get("schema") != TRUST_ROOT_SCHEMA:
            raise BenchmarkTrustRootError("trust-root document schema is unsupported")
        version = document.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise BenchmarkTrustRootError("trust-root version is invalid")
        raw_keys = document.get("keys")
        if isinstance(raw_keys, (str, bytes)) or not isinstance(raw_keys, Sequence):
            raise BenchmarkTrustRootError("trust-root keys must be a bounded sequence")
        keys: list[Ed25519TrustKey] = []
        for raw in raw_keys:
            if (
                not isinstance(raw, Mapping)
                or set(raw) - _TRUST_KEY_FIELDS
                or _TRUST_KEY_REQUIRED_FIELDS - set(raw)
            ):
                raise BenchmarkTrustRootError("trust-root key shape is invalid")
            keys.append(
                Ed25519TrustKey(
                    key_id=raw["key_id"],
                    public_key_hex=raw["public_key_hex"],
                    introduced_in=raw["introduced_in"],
                    revoked_in=raw.get("revoked_in"),
                )
            )
        return cls(version=version, keys=tuple(keys))

    def as_document(self) -> dict[str, Any]:
        return {
            "schema": TRUST_ROOT_SCHEMA,
            "version": self.version,
            "keys": [
                {
                    "key_id": item.key_id,
                    "public_key_hex": item.public_key_hex,
                    "introduced_in": item.introduced_in,
                    "revoked_in": item.revoked_in,
                }
                for item in self.keys
            ],
        }

    def advance(
        self,
        *,
        version: int,
        additions: Sequence[Ed25519TrustKey] = (),
        revocations: Sequence[str] = (),
    ) -> VersionedEd25519TrustRoots:
        """Return a monotonic trust snapshot; prior bindings cannot be rewritten."""

        if isinstance(version, bool) or not isinstance(version, int) or version <= self.version:
            raise BenchmarkTrustRootError("trust-root version must advance monotonically")
        if isinstance(additions, (str, bytes)) or not isinstance(additions, Sequence):
            raise BenchmarkTrustRootError("trust-root additions are invalid")
        if isinstance(revocations, (str, bytes)) or not isinstance(revocations, Sequence):
            raise BenchmarkTrustRootError("trust-root revocations are invalid")
        current = {item.key_id: item for item in self.keys}
        for key_id in revocations:
            item = current.get(key_id)
            if item is None or not item.active_at(self.version):
                raise BenchmarkTrustRootError("only a known active key can be revoked")
            current[key_id] = replace(item, revoked_in=version)
        for item in additions:
            if not isinstance(item, Ed25519TrustKey) or item.introduced_in != version:
                raise BenchmarkTrustRootError("new keys must be introduced at the new version")
            if item.key_id in current:
                raise BenchmarkTrustRootError("trust-root key binding cannot be replaced")
            current[item.key_id] = item
        return VersionedEd25519TrustRoots(version=version, keys=tuple(current.values()))

    def _selected_key(self, key_id: str) -> Ed25519TrustKey | None:
        for item in self.keys:
            if hmac.compare_digest(item.key_id, key_id):
                return item if item.active_at(self.version) else None
        return None

    def verify(self, payload: bytes, signature: Mapping[str, str]) -> bool:
        """Verify one canonical report body against its named active Ed25519 key."""

        if not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_CANONICAL_BYTES:
            return False
        try:
            loaded = _strict_json(
                payload,
                maximum=_MAX_CANONICAL_BYTES,
                label="signed cohort-report payload",
            )
            if not isinstance(loaded, Mapping) or _canonical(loaded) != payload:
                return False
        except BenchmarkCoordinatorProtocolError:
            return False
        if not isinstance(signature, Mapping) or set(signature) != _SIGNATURE_FIELDS:
            return False
        if signature.get("algorithm") != "Ed25519":
            return False
        key_id = signature.get("key_id")
        value = signature.get("value")
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            return False
        if not isinstance(value, str):
            return False
        key = self._selected_key(key_id)
        if key is None:
            return False
        signature_bytes = _signature_bytes(value)
        if signature_bytes is None:
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
            public_key.verify(signature_bytes, payload)
        except (InvalidSignature, TypeError, ValueError):
            return False
        return True

    def __call__(self, payload: bytes, signature: Mapping[str, str]) -> bool:
        return self.verify(payload, signature)


def _signature_bytes(value: str) -> bytes | None:
    if _HEX_SIGNATURE_RE.fullmatch(value):
        return bytes.fromhex(value)
    if not _ENCODED_SIGNATURE_RE.fullmatch(value):
        return None
    try:
        if "-" in value or "_" in value:
            padding = "=" * ((4 - len(value) % 4) % 4)
            decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        else:
            decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    return decoded if len(decoded) == 64 else None


@dataclass(frozen=True)
class CoordinatorTransportLimits:
    timeout_seconds: float = 15.0
    max_request_bytes: int = 128 * 1024
    max_response_bytes: int = 128 * 1024

    def __post_init__(self) -> None:
        timeout = self.timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not _MIN_TIMEOUT_SECONDS <= float(timeout) <= _MAX_TIMEOUT_SECONDS
        ):
            raise BenchmarkCoordinatorConfigError("coordinator timeout is invalid")
        if (
            isinstance(self.max_request_bytes, bool)
            or not isinstance(self.max_request_bytes, int)
            or not _MIN_REQUEST_BYTES <= self.max_request_bytes <= _MAX_REQUEST_BYTES
        ):
            raise BenchmarkCoordinatorConfigError("coordinator request bound is invalid")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not _MIN_RESPONSE_BYTES <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise BenchmarkCoordinatorConfigError("coordinator response bound is invalid")
        object.__setattr__(self, "timeout_seconds", float(timeout))


@dataclass(frozen=True, repr=False)
class CoordinatorHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise BenchmarkCoordinatorProtocolError("coordinator status is invalid")
        if not isinstance(self.headers, Mapping):
            raise BenchmarkCoordinatorProtocolError("coordinator headers are invalid")
        if not isinstance(self.body, bytes):
            raise BenchmarkCoordinatorProtocolError("coordinator body must be bytes")


class CoordinatorHTTPTransport(Protocol):
    """Injectable one-shot HTTP seam. Implementations must not follow redirects."""

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
        allow_redirects: bool,
        max_response_bytes: int,
    ) -> CoordinatorHTTPResponse: ...


class _PinnedCoordinatorHTTPTransport:
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
        allow_redirects: bool,
        max_response_bytes: int,
    ) -> CoordinatorHTTPResponse:
        if allow_redirects:
            raise BenchmarkCoordinatorConfigError("coordinator redirects must be disabled")
        from .enterprise import enterprise_egress_denial
        from .tools._ssrf import BlockedHost, safe_client

        if enterprise_egress_denial(url, tool="ai_benchmark_exchange.coordinator"):
            raise BenchmarkCoordinatorDefinitiveTransportError(
                "coordinator egress is denied by enterprise policy"
            )
        try:
            with safe_client(url, timeout=timeout) as client:
                with client.stream(
                    "POST",
                    url,
                    headers=dict(headers),
                    content=body,
                ) as response:
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise BenchmarkCoordinatorProtocolError(
                                "coordinator Content-Length is invalid"
                            ) from None
                        if declared_size < 0 or declared_size > max_response_bytes:
                            raise BenchmarkCoordinatorProtocolError(
                                "coordinator response exceeds its byte bound"
                            )
                    chunks: list[bytes] = []
                    observed = 0
                    for chunk in response.iter_bytes():
                        observed += len(chunk)
                        if observed > max_response_bytes:
                            raise BenchmarkCoordinatorProtocolError(
                                "coordinator response exceeds its byte bound"
                            )
                        chunks.append(chunk)
                    selected_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {
                            "content-length",
                            "content-type",
                            "content-encoding",
                            "location",
                            "retry-after",
                        }
                    }
                    return CoordinatorHTTPResponse(
                        status_code=int(response.status_code),
                        headers=selected_headers,
                        body=b"".join(chunks),
                    )
        except BlockedHost:
            raise BenchmarkCoordinatorDefinitiveTransportError(
                "coordinator destination failed SSRF validation"
            ) from None


@dataclass
class _SubmissionAttempt:
    request_sha256: str
    state: str
    receipt: dict[str, Any] | None = None


class BenchmarkCoordinatorClient:
    """Default-off, single-origin client for explicit approved exports only."""

    def __init__(
        self,
        *,
        coordinator_origin: str,
        enabled: bool = False,
        transport: CoordinatorHTTPTransport | None = None,
        limits: CoordinatorTransportLimits | None = None,
    ) -> None:
        if not isinstance(enabled, bool):
            raise BenchmarkCoordinatorConfigError("coordinator enabled must be boolean")
        self._origin = _coordinator_origin(coordinator_origin)
        self._url = self._origin + COORDINATOR_SUBMISSION_PATH
        self._enabled = enabled
        self._transport = transport or _PinnedCoordinatorHTTPTransport()
        if not hasattr(self._transport, "post") or not callable(self._transport.post):
            raise BenchmarkCoordinatorConfigError("coordinator transport is invalid")
        self._limits = limits or CoordinatorTransportLimits()
        if not isinstance(self._limits, CoordinatorTransportLimits):
            raise BenchmarkCoordinatorConfigError("coordinator limits are invalid")
        self._attempts: dict[str, _SubmissionAttempt] = {}
        self._lock = threading.RLock()

    @property
    def coordinator_origin(self) -> str:
        return self._origin

    @property
    def submission_url(self) -> str:
        return self._url

    def submit(
        self,
        export_package: Mapping[str, Any],
        *,
        explicit_consent: bool,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if not self._enabled:
            raise BenchmarkCoordinatorDisabled("benchmark coordinator transport is disabled")
        if explicit_consent is not True:
            raise BenchmarkCoordinatorConsentError(
                "literal consent is required for this exact export package"
            )
        operation = _idempotency_key(idempotency_key)
        contribution = _validate_export_package(export_package)
        envelope = {
            "schema": COORDINATOR_SUBMISSION_SCHEMA,
            "explicit_consent": True,
            "idempotency_key": operation,
            "contribution": contribution,
        }
        request_body = _canonical(envelope, maximum=self._limits.max_request_bytes)
        request_digest = _sha256_bytes(request_body)
        packet_digest = contribution["packet_sha256"]

        with self._lock:
            existing = self._attempts.get(operation)
            if existing is not None:
                if not hmac.compare_digest(existing.request_sha256, request_digest):
                    raise BenchmarkCoordinatorIdempotencyConflict(
                        "coordinator idempotency key is bound to different content"
                    )
                if existing.receipt is not None:
                    return copy.deepcopy(existing.receipt)
                if existing.state == "in_flight":
                    raise BenchmarkCoordinatorAmbiguousDelivery(
                        "an identical coordinator submission is already in flight"
                    )
                existing.state = "in_flight"
            else:
                self._attempts[operation] = _SubmissionAttempt(
                    request_sha256=request_digest,
                    state="in_flight",
                )

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Content-Length": str(len(request_body)),
            "Idempotency-Key": operation,
            "X-Lightwork-Packet-SHA256": packet_digest,
            "X-Lightwork-Explicit-Consent": "true",
        }
        try:
            response = self._transport.post(
                self._url,
                headers=headers,
                body=request_body,
                timeout=self._limits.timeout_seconds,
                allow_redirects=False,
                max_response_bytes=self._limits.max_response_bytes,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except BenchmarkCoordinatorDefinitiveTransportError:
            self._mark_attempt(operation, request_digest, "failed")
            raise
        except Exception:
            self._mark_attempt(operation, request_digest, "ambiguous")
            raise BenchmarkCoordinatorAmbiguousDelivery(
                "coordinator delivery is ambiguous; retry only the exact idempotency key and payload"
            ) from None

        try:
            receipt = self._validate_response(
                response,
                idempotency_key=operation,
                packet_sha256=packet_digest,
            )
        except BenchmarkCoordinatorAmbiguousDelivery:
            self._mark_attempt(operation, request_digest, "ambiguous")
            raise
        except BenchmarkExchangeTransportError:
            self._mark_attempt(operation, request_digest, "failed")
            raise
        with self._lock:
            attempt = self._attempts.get(operation)
            if attempt is None or not hmac.compare_digest(attempt.request_sha256, request_digest):
                raise BenchmarkCoordinatorIdempotencyConflict(
                    "coordinator attempt authority changed"
                )
            attempt.state = "delivered"
            attempt.receipt = copy.deepcopy(receipt)
        return receipt

    def _mark_attempt(self, key: str, request_digest: str, state: str) -> None:
        with self._lock:
            attempt = self._attempts.get(key)
            if attempt is not None and hmac.compare_digest(attempt.request_sha256, request_digest):
                attempt.state = state

    def _validate_response(
        self,
        response: object,
        *,
        idempotency_key: str,
        packet_sha256: str,
    ) -> dict[str, Any]:
        if not isinstance(response, CoordinatorHTTPResponse):
            raise BenchmarkCoordinatorProtocolError(
                "coordinator transport returned an untyped response"
            )
        if len(response.body) > self._limits.max_response_bytes:
            raise BenchmarkCoordinatorProtocolError("coordinator response exceeds its byte bound")
        declared = _header(response.headers, "content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError:
                raise BenchmarkCoordinatorProtocolError(
                    "coordinator Content-Length is invalid"
                ) from None
            if (
                declared_size < 0
                or declared_size > self._limits.max_response_bytes
                or declared_size != len(response.body)
            ):
                raise BenchmarkCoordinatorProtocolError(
                    "coordinator Content-Length does not match its bounded body"
                )
        status = response.status_code
        if 300 <= status < 400:
            raise BenchmarkCoordinatorProtocolError("coordinator redirect was rejected")
        if status in {408, 425, 429, 500, 502, 503, 504}:
            raise BenchmarkCoordinatorAmbiguousDelivery(
                "coordinator returned an ambiguous retryable status; reuse the exact request"
            )
        if status == 409:
            raise BenchmarkCoordinatorIdempotencyConflict(
                "coordinator rejected the idempotency binding"
            )
        if not 200 <= status < 300:
            raise BenchmarkCoordinatorProtocolError("coordinator rejected the submission")
        content_type = _header(response.headers, "content-type")
        if (
            not isinstance(content_type, str)
            or content_type.split(";", 1)[0].strip().lower() != "application/json"
        ):
            raise BenchmarkCoordinatorProtocolError(
                "coordinator response Content-Type must be application/json"
            )
        encoding = _header(response.headers, "content-encoding")
        if encoding is not None and encoding.strip().lower() not in {"", "identity"}:
            raise BenchmarkCoordinatorProtocolError(
                "coordinator response content encoding is unsupported"
            )
        raw = _strict_json(
            response.body,
            maximum=self._limits.max_response_bytes,
            label="coordinator response",
        )
        return _validate_receipt(
            raw,
            idempotency_key=idempotency_key,
            packet_sha256=packet_sha256,
        )


def _coordinator_origin(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise BenchmarkCoordinatorConfigError("coordinator origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise BenchmarkCoordinatorConfigError("coordinator origin is invalid") from None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise BenchmarkCoordinatorConfigError("coordinator must be an HTTPS origin")
    host = parsed.hostname.lower()
    if (
        host == "localhost"
        or host.endswith((".localhost", ".localdomain"))
        or host.endswith(".")
        or any(ord(char) > 127 for char in host)
    ):
        raise BenchmarkCoordinatorConfigError("coordinator host is invalid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
            raise BenchmarkCoordinatorConfigError("coordinator host is invalid") from None
        rendered_host = host
    else:
        if not address.is_global:
            raise BenchmarkCoordinatorConfigError("coordinator host must be public")
        rendered_host = f"[{host}]" if address.version == 6 else host
    return urlunsplit(("https", rendered_host, "", "", ""))


def validated_coordinator_origin(value: object) -> str:
    """Validate and normalize one operator-pinned public HTTPS origin."""

    return _coordinator_origin(value)


def _idempotency_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_IDEMPOTENCY_KEY
        or not _IDEMPOTENCY_RE.fullmatch(value)
    ):
        raise BenchmarkCoordinatorProtocolError("coordinator idempotency key is invalid")
    return value


def _validate_export_package(value: object) -> dict[str, Any]:
    row = _closed(value, _EXPORT_FIELDS, "benchmark export package")
    if row["schema"] != CONTRIBUTION_EXPORT_SCHEMA:
        raise BenchmarkCoordinatorProtocolError("benchmark export schema is unsupported")
    contribution_id = row["pseudonymous_contribution_id"]
    if not isinstance(contribution_id, str) or not _PSEUDONYMOUS_ID_RE.fullmatch(contribution_id):
        raise BenchmarkCoordinatorProtocolError("pseudonymous contribution id is invalid")
    version = _positive_integer(row["version"], "contribution version", maximum=50)
    metric_code = row["metric_code"]
    if not isinstance(metric_code, str) or metric_code not in SUPPORTED_METRICS:
        raise BenchmarkCoordinatorProtocolError("benchmark metric is unsupported")
    numerator = _bounded_count(row["numerator"], "numerator", minimum=0)
    denominator = _bounded_count(row["denominator"], "denominator", minimum=1)
    if numerator > denominator:
        raise BenchmarkCoordinatorProtocolError("benchmark numerator exceeds denominator")

    period_row = _closed(row["period"], _PERIOD_FIELDS, "benchmark period")
    period = {
        "start": _canonical_date(period_row["start"], "period.start"),
        "end": _canonical_date(period_row["end"], "period.end"),
    }
    if period["start"] > period["end"]:
        raise BenchmarkCoordinatorProtocolError("benchmark period is reversed")
    cohort_row = _closed(row["cohort"], _COHORT_FIELDS, "benchmark cohort")
    cohort = {
        "industry_code": _closed_choice(
            cohort_row["industry_code"], SUPPORTED_INDUSTRIES, "industry"
        ),
        "geography_code": _closed_choice(
            cohort_row["geography_code"], SUPPORTED_GEOGRAPHIES, "geography"
        ),
        "organization_size_code": _closed_choice(
            cohort_row["organization_size_code"], SUPPORTED_ORG_SIZES, "organization size"
        ),
        "model_modality_code": _closed_choice(
            cohort_row["model_modality_code"], SUPPORTED_MODALITIES, "model modality"
        ),
    }

    raw_evidence = row["evidence_bindings"]
    if (
        isinstance(raw_evidence, (str, bytes))
        or not isinstance(raw_evidence, Sequence)
        or not 1 <= len(raw_evidence) <= _MAX_EVIDENCE_BINDINGS
    ):
        raise BenchmarkCoordinatorProtocolError("evidence bindings are invalid")
    evidence: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_evidence:
        binding = _closed(raw, _EVIDENCE_FIELDS, "evidence binding")
        evidence_id = binding["evidence_id"]
        if not isinstance(evidence_id, str) or not _EVIDENCE_ID_RE.fullmatch(evidence_id):
            raise BenchmarkCoordinatorProtocolError("evidence id is invalid")
        if evidence_id in seen:
            raise BenchmarkCoordinatorProtocolError("evidence ids must be unique")
        seen.add(evidence_id)
        evidence.append(
            {
                "evidence_id": evidence_id,
                "digest": _digest(binding["digest"], "evidence digest"),
            }
        )
    if evidence != sorted(evidence, key=lambda item: item["evidence_id"]):
        raise BenchmarkCoordinatorProtocolError("evidence bindings are not canonical")

    approval_row = _closed(row["approval"], _APPROVAL_FIELDS, "benchmark approval")
    approval = {
        "voluntary_opt_in": approval_row["voluntary_opt_in"],
        "human_approved": approval_row["human_approved"],
        "four_eyes": approval_row["four_eyes"],
        "evidence_current": approval_row["evidence_current"],
    }
    if any(value is not True for value in approval.values()):
        raise BenchmarkCoordinatorConsentError(
            "export package lacks current voluntary four-eyes approval"
        )
    methodology_row = _closed(row["methodology"], _METHODOLOGY_FIELDS, "benchmark methodology")
    methodology = {
        "aggregation_level": methodology_row["aggregation_level"],
        "calculation": methodology_row["calculation"],
        "sampling_basis": methodology_row["sampling_basis"],
    }
    if methodology != {
        "aggregation_level": "organization",
        "calculation": "bounded_numerator_divided_by_denominator",
        "sampling_basis": "voluntary_opt_in",
    }:
        raise BenchmarkCoordinatorProtocolError("benchmark methodology is not canonical")
    privacy_row = _closed(row["privacy"], _PRIVACY_FIELDS, "benchmark privacy")
    privacy = {
        "raw_records_included": privacy_row["raw_records_included"],
        "tenant_identity_included": privacy_row["tenant_identity_included"],
        "customer_identifiers_included": privacy_row["customer_identifiers_included"],
        "anonymity_claim": privacy_row["anonymity_claim"],
        "differential_privacy_claim": privacy_row["differential_privacy_claim"],
        "privacy_budget_accounting": privacy_row["privacy_budget_accounting"],
    }
    if privacy != {
        "raw_records_included": False,
        "tenant_identity_included": False,
        "customer_identifiers_included": False,
        "anonymity_claim": False,
        "differential_privacy_claim": False,
        "privacy_budget_accounting": "unsupported",
    }:
        raise BenchmarkCoordinatorProtocolError("benchmark privacy boundary is invalid")
    limitations = row["limitations"]
    if (
        not isinstance(limitations, list)
        or len(limitations) > _MAX_LIMITATIONS
        or limitations != [METHODOLOGY_NOTICE, PRIVACY_NOTICE]
    ):
        raise BenchmarkCoordinatorProtocolError("benchmark limitations are not canonical")

    packet = {
        "schema": CONTRIBUTION_EXPORT_SCHEMA,
        "pseudonymous_contribution_id": contribution_id,
        "version": version,
        "metric_code": metric_code,
        "numerator": numerator,
        "denominator": denominator,
        "period": period,
        "cohort": cohort,
        "evidence_bindings": evidence,
        "content_sha256": _digest(row["content_sha256"], "content digest"),
        "authority_sha256": _digest(row["authority_sha256"], "authority digest"),
        "approval": approval,
        "methodology": methodology,
        "privacy": privacy,
        "limitations": list(limitations),
    }
    packet_sha256 = _digest(row["packet_sha256"], "packet digest")
    if not hmac.compare_digest(packet_sha256, _sha256(packet)):
        raise BenchmarkCoordinatorProtocolError("benchmark packet digest is invalid")
    return {**packet, "packet_sha256": packet_sha256}


def _closed_choice(value: object, choices: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise BenchmarkCoordinatorProtocolError(f"benchmark {label} is unsupported")
    return value


def _header(headers: Mapping[str, str], name: str) -> str | None:
    values: list[str] = []
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise BenchmarkCoordinatorProtocolError("coordinator headers are malformed")
        if key.lower() == name.lower():
            values.append(value)
    if len(values) > 1:
        raise BenchmarkCoordinatorProtocolError("coordinator repeated a security header")
    return values[0] if values else None


def _validate_receipt(
    value: object,
    *,
    idempotency_key: str,
    packet_sha256: str,
) -> dict[str, Any]:
    row = _closed(value, _RECEIPT_FIELDS, "coordinator receipt")
    if row["schema"] != COORDINATOR_RECEIPT_SCHEMA:
        raise BenchmarkCoordinatorProtocolError("coordinator receipt schema is unsupported")
    if row["status"] not in {"accepted", "duplicate"}:
        raise BenchmarkCoordinatorProtocolError("coordinator receipt status is invalid")
    receipt_id = row["receipt_id"]
    if not isinstance(receipt_id, str) or not _RECEIPT_ID_RE.fullmatch(receipt_id):
        raise BenchmarkCoordinatorProtocolError("coordinator receipt id is invalid")
    if row["idempotency_key"] != idempotency_key:
        raise BenchmarkCoordinatorIdempotencyConflict(
            "coordinator receipt idempotency key does not match"
        )
    observed_packet = _digest(row["packet_sha256"], "receipt packet digest")
    if not hmac.compare_digest(observed_packet, packet_sha256):
        raise BenchmarkCoordinatorIdempotencyConflict(
            "coordinator receipt packet digest does not match"
        )
    accepted_at = row["accepted_at"]
    if (
        isinstance(accepted_at, bool)
        or not isinstance(accepted_at, (int, float))
        or not math.isfinite(float(accepted_at))
        or float(accepted_at) <= 0
        or float(accepted_at) > 100_000_000_000.0
    ):
        raise BenchmarkCoordinatorProtocolError("coordinator receipt timestamp is invalid")
    return {
        "schema": COORDINATOR_RECEIPT_SCHEMA,
        "status": row["status"],
        "receipt_id": receipt_id,
        "idempotency_key": idempotency_key,
        "packet_sha256": packet_sha256,
        "accepted_at": float(accepted_at),
        "limitations": {
            "cohort_inclusion_verified": False,
            "anonymity_verified": False,
            "differential_privacy_verified": False,
        },
    }


__all__ = [
    "BenchmarkCoordinatorAmbiguousDelivery",
    "BenchmarkCoordinatorClient",
    "BenchmarkCoordinatorConfigError",
    "BenchmarkCoordinatorConsentError",
    "BenchmarkCoordinatorDefinitiveTransportError",
    "BenchmarkCoordinatorDisabled",
    "BenchmarkCoordinatorIdempotencyConflict",
    "BenchmarkCoordinatorProtocolError",
    "BenchmarkExchangeTransportError",
    "BenchmarkTrustRootError",
    "COORDINATOR_RECEIPT_SCHEMA",
    "COORDINATOR_SUBMISSION_PATH",
    "COORDINATOR_SUBMISSION_SCHEMA",
    "CoordinatorHTTPResponse",
    "CoordinatorHTTPTransport",
    "CoordinatorTransportLimits",
    "Ed25519TrustKey",
    "TRUST_ROOT_SCHEMA",
    "VersionedEd25519TrustRoots",
    "validated_coordinator_origin",
]
