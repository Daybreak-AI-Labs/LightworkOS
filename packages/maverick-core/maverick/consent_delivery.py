"""Durable, tenant-safe consent/preference change delivery.

This module is an outbound delivery *authority*, not evidence of live external
delivery.  It provides explicit destination enrollment, a durable SQLite
outbox, per-profile ordering, CAS leases, bounded retries/dead-letter/replay,
key-ID rotation/revocation, canonical signed envelopes, and an injectable HTTP
transport seam.  The default transport uses the repository's DNS-pinned SSRF
guard and never follows redirects.

Opaque identifiers, bounded consent choices, digests, and an HTTPS origin are
retained. Ordinary signing keys and future subscriptions use sealed records in
the existing metadata authority; plaintext keys are never stored or returned.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import sqlite3
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from . import consent_storage
from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
CHANGE_SCHEMA = "lightwork.consent-delivery-change.v1"
ENVELOPE_SCHEMA = "lightwork.consent-delivery-envelope.v1"
AUDIT_SCHEMA = "lightwork.consent-delivery-audit.v1"
DELIVERY_PATH = "/v1/consent-preference-events"

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ERROR_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
_SIGNATURE_RE = re.compile(r"v1=[A-Za-z0-9_-]{2,683}\Z")

_MAX_JSON_BYTES = 64 * 1024
_MAX_CHOICES = 128
_MAX_DESTINATIONS_PER_ENQUEUE = 64
_MAX_DESTINATIONS_PER_TENANT = 1000
_MAX_PENDING_PER_TENANT = 100_000
_MAX_CLAIM_LIMIT = 100
_MAX_AUDIT_LIMIT = 500
_MAX_RESPONSE_BYTES = 4096
_MAX_SIGNATURE_BYTES = 512
_MAX_LEASE_SECONDS = 3600.0
_MAX_RETRY_AFTER_SECONDS = 86_400.0
_MAX_RETENTION_SECONDS = 5 * 365 * 24 * 3600

_ACTIONS = frozenset({"grant", "deny", "revoke", "withdraw"})
_EVENT_KINDS = frozenset(
    {
        "preferences_changed",
        "privacy_signal_observed",
        "profile_linked",
        "profile_erased",
    }
)
_DESTINATION_STATES = frozenset({"active", "suspended", "revoked"})
_MESSAGE_STATES = frozenset(
    {"queued", "leased", "delivered", "dead_letter", "cancelled"}
)
_RETRY_ERROR_CODES = frozenset(
    {
        "transport_error",
        "timeout",
        "rate_limited",
        "remote_unavailable",
        "authentication_rejected",
        "contract_rejected",
        "unexpected_status",
        "delivery_unconfirmed",
    }
)
_PROHIBITED_KEYS = frozenset(
    {
        "secret",
        "secret_key",
        "private_key",
        "key_material",
        "credential",
        "password",
        "token",
        "cookie",
        "email",
        "ip_address",
    }
)


class ConsentDeliveryError(RuntimeError):
    """Base error for consent delivery."""


class ConsentDeliveryConfigError(ConsentDeliveryError):
    """Delivery is disabled or configured unsafely."""


class ConsentDeliveryValidationError(ConsentDeliveryError, ValueError):
    """Input is outside the closed delivery contract."""


class ConsentDeliveryConflict(ConsentDeliveryError):
    """A revision, state, or uniqueness precondition failed."""


class ConsentDeliveryIdempotencyConflict(ConsentDeliveryError):
    """An idempotency key was rebound to different content."""


class ConsentDeliveryNotFound(ConsentDeliveryError):
    """A tenant-scoped delivery resource does not exist."""


class ConsentDeliveryLeaseLost(ConsentDeliveryError):
    """A delivery lease expired, was reclaimed, or failed CAS validation."""


class ConsentDeliveryRevoked(ConsentDeliveryError):
    """The destination or signing key no longer authorizes a send."""


class ConsentDeliveryTransportError(ConsentDeliveryError):
    """The transport failed without exposing response content."""


def enabled() -> bool:
    """Require both consent authority and delivery to be explicitly enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    consent = config.get("consent_preferences")
    delivery = consent.get("delivery") if isinstance(consent, Mapping) else None
    return (
        isinstance(consent, Mapping)
        and consent.get("enable") is True
        and isinstance(delivery, Mapping)
        and delivery.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless both configuration gates are explicitly true."""

    if not enabled():
        raise ConsentDeliveryConfigError(
            "consent delivery is disabled; explicitly enable consent_preferences "
            "and consent_preferences.delivery"
        )


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentDeliveryValidationError(
            "delivery data must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ConsentDeliveryValidationError("delivery data exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _opaque(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _REF_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ConsentDeliveryValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    if _CONTROL_RE.search(value):
        raise ConsentDeliveryValidationError(f"{label} contains control characters")
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise ConsentDeliveryValidationError("tenant_id is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ConsentDeliveryValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def delivery_retry_settings(
    config: Mapping[str, Any] | None = None,
) -> tuple[int, int, float, float]:
    """``(default tries, most tries, base wait, longest wait)`` for new destinations.

    ``[consent_preferences.delivery] max_attempts`` is the default number of
    tries and a cap: a destination can ask for fewer, never more, and existing
    destinations are held to it when messages are retried. The two waits are
    only defaults for destinations that do not choose their own. Unset keeps
    the historical 6 tries (up to 20 on request), 5 seconds and 1 hour.
    """
    if config is None:
        from .config import load_config

        config = load_config() or {}
    consent = config.get("consent_preferences") if isinstance(config, Mapping) else None
    section = consent.get("delivery") if isinstance(consent, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    default_attempts, most_attempts = 6, 20
    base, longest = 5.0, 3600.0
    try:
        if "max_attempts" in section:
            default_attempts = most_attempts = _positive_int(
                section["max_attempts"], "delivery max_attempts", maximum=20
            )
        if "retry_base_seconds" in section:
            base = _positive_float(
                section["retry_base_seconds"], "delivery retry_base_seconds", maximum=3_600.0
            )
        if "retry_max_seconds" in section:
            longest = _positive_float(
                section["retry_max_seconds"], "delivery retry_max_seconds",
                maximum=_MAX_RETRY_AFTER_SECONDS,
            )
    except ConsentDeliveryValidationError as exc:
        raise ConsentDeliveryConfigError(str(exc)) from exc
    return default_attempts, most_attempts, base, max(base, longest)


def _positive_int(value: object, label: str, *, maximum: int = 2**31 - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise ConsentDeliveryValidationError(
            f"{label} must be an integer between 1 and {maximum}"
        )
    return value


def _revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**31:
        raise ConsentDeliveryValidationError(
            "expected_revision must be a non-negative integer"
        )
    return value


def _finite_time(value: object, label: str, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise ConsentDeliveryValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return float(value)


def _positive_float(value: object, label: str, *, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= maximum
    ):
        raise ConsentDeliveryValidationError(
            f"{label} must be positive and no greater than {maximum:g}"
        )
    return float(value)


def _loads(value: object, label: str) -> Any:
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ConsentDeliveryError(f"stored {label} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ConsentDeliveryError(f"stored {label} is invalid") from exc


def _normalize_origin(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048 or _CONTROL_RE.search(value):
        raise ConsentDeliveryValidationError("destination origin is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ConsentDeliveryValidationError("destination origin is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ConsentDeliveryValidationError(
            "destination must be an exact credential-free HTTPS origin"
        )
    hostname = parsed.hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConsentDeliveryValidationError(
            "destination hostname is invalid"
        ) from exc
    if not hostname or hostname == "localhost":
        raise ConsentDeliveryValidationError("destination hostname is not public")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise ConsentDeliveryValidationError(
                "destination IP is not a public address"
            )
    if port is not None and not 1 <= port <= 65535:
        raise ConsentDeliveryValidationError("destination port is invalid")
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != 443:
        rendered_host += f":{port}"
    return f"https://{rendered_host}"


def _validate_public_origin(origin: str) -> None:
    try:
        from .enterprise import enterprise_egress_denial
        from .tools import _ssrf
    except ImportError as exc:
        raise ConsentDeliveryConfigError(
            "Destination safety checks are unavailable"
        ) from exc
    if _ssrf.allow_private():
        raise ConsentDeliveryConfigError(
            "Consent delivery cannot run while private-network browsing is enabled"
        )
    if enterprise_egress_denial(origin, tool="consent_delivery"):
        raise ConsentDeliveryConfigError(
            "Destination is not on the approved outbound hosts list"
        )
    host = urllib.parse.urlsplit(origin).hostname or ""
    try:
        _ssrf.resolve_pinned_ip(host, require_public=True)
    except Exception as exc:
        raise ConsentDeliveryConfigError(
            "destination failed SSRF-safe public resolution"
        ) from exc


def _closed_tuple(value: object, label: str, *, maximum: int) -> tuple[Any, ...]:
    if not isinstance(value, tuple) or not 1 <= len(value) <= maximum:
        raise ConsentDeliveryValidationError(
            f"{label} must be an immutable tuple with 1 to {maximum} entries"
        )
    return value


@dataclass(frozen=True)
class DeliveryPreferenceChoice:
    """One bounded preference decision included in a change envelope."""

    purpose_id: str
    action: str
    channel: str = "all"
    vendor_id: str = "all"

    def normalized(self) -> dict[str, str]:
        if self.action not in _ACTIONS:
            raise ConsentDeliveryValidationError("preference action is invalid")
        return {
            "purpose_id": _opaque(self.purpose_id, "purpose_id"),
            "action": self.action,
            "channel": _opaque(self.channel, "channel"),
            "vendor_id": _opaque(self.vendor_id, "vendor_id"),
        }


@dataclass(frozen=True)
class ConsentChange:
    """Pseudonymous change payload accepted by the delivery authority."""

    event_id: str
    event_kind: str
    profile_id: str
    profile_revision: int
    receipt_id: str
    receipt_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    choices: tuple[DeliveryPreferenceChoice, ...]
    occurred_at: float

    def normalized(self) -> dict[str, Any]:
        if self.event_kind not in _EVENT_KINDS:
            raise ConsentDeliveryValidationError("event_kind is invalid")
        raw_choices = _closed_tuple(
            self.choices,
            "choices",
            maximum=_MAX_CHOICES,
        )
        choices = tuple(choice.normalized() for choice in raw_choices)
        keys = [
            (item["purpose_id"], item["channel"], item["vendor_id"])
            for item in choices
        ]
        if len(set(keys)) != len(keys):
            raise ConsentDeliveryValidationError(
                "choices contains duplicate purpose/channel/vendor entries"
            )
        return {
            "schema": CHANGE_SCHEMA,
            "event_id": _opaque(self.event_id, "event_id"),
            "event_kind": self.event_kind,
            "profile_id": _opaque(self.profile_id, "profile_id"),
            "profile_revision": _positive_int(
                self.profile_revision,
                "profile_revision",
            ),
            "receipt_id": _opaque(self.receipt_id, "receipt_id"),
            "receipt_sha256": _digest(self.receipt_sha256, "receipt_sha256"),
            "policy_id": _opaque(self.policy_id, "policy_id"),
            "policy_version": _positive_int(self.policy_version, "policy_version"),
            "policy_sha256": _digest(self.policy_sha256, "policy_sha256"),
            "choices": sorted(
                choices,
                key=lambda item: (
                    item["purpose_id"],
                    item["channel"],
                    item["vendor_id"],
                ),
            ),
            "occurred_at": _finite_time(self.occurred_at, "occurred_at"),
        }


@dataclass(frozen=True)
class DeliveryClaim:
    """A CAS-bound outbox lease; safe to pass between worker components."""

    tenant_id: str
    message_id: str
    destination_id: str
    origin: str
    profile_id: str
    profile_sequence: int
    event_id: str
    payload: Mapping[str, Any]
    payload_sha256: str
    attempt: int
    lease_owner: str
    lease_token: str
    lease_until: float
    message_revision: int
    destination_revision: int
    signing_key_id: str


@dataclass(frozen=True, repr=False)
class SignedDeliveryRequest:
    """Canonical signed request containing no key material."""

    tenant_id: str
    message_id: str
    destination_id: str
    url: str
    body: bytes
    headers: tuple[tuple[str, str], ...]
    key_id: str
    body_sha256: str
    authorization_sha256: str

    def header_map(self) -> dict[str, str]:
        return dict(self.headers)


@dataclass(frozen=True)
class DeliveryResponse:
    """Bounded response metadata; response content is never retained."""

    status_code: int
    retry_after_seconds: float | None = None
    response_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise ConsentDeliveryTransportError("delivery status is invalid")
        if self.retry_after_seconds is not None:
            retry = self.retry_after_seconds
            if (
                isinstance(retry, bool)
                or not isinstance(retry, (int, float))
                or not math.isfinite(float(retry))
                or not 0 <= float(retry) <= _MAX_RETRY_AFTER_SECONDS
            ):
                raise ConsentDeliveryTransportError("Retry-After is invalid")
        if self.response_sha256 is not None:
            _digest(self.response_sha256, "response_sha256")


class DeliverySigner(Protocol):
    """Key-custody seam. Implementations resolve key material outside SQLite."""

    def sign(self, key_id: str, payload: bytes) -> bytes: ...


class DeliveryTransport(Protocol):
    """One-shot redirect-free HTTP transport seam."""

    def post(
        self,
        request: SignedDeliveryRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> DeliveryResponse: ...


def _validated_request_headers(request: SignedDeliveryRequest) -> dict[str, str]:
    """Fail closed on a forged or mutated request at the network boundary."""

    if not isinstance(request, SignedDeliveryRequest):
        raise ConsentDeliveryTransportError(
            "delivery transport requires a signed request"
        )
    try:
        tenant = _tenant_id(request.tenant_id)
        message = _opaque(request.message_id, "request message_id")
        destination = _opaque(request.destination_id, "request destination_id")
        key_id = _opaque(request.key_id, "request key_id")
        body_sha256 = _digest(request.body_sha256, "request body_sha256")
        authorization_sha256 = _digest(
            request.authorization_sha256,
            "request authorization_sha256",
        )
        if not isinstance(request.body, bytes) or not 1 <= len(request.body) <= _MAX_JSON_BYTES:
            raise ConsentDeliveryTransportError("delivery body is invalid")
        try:
            envelope = json.loads(request.body.decode("ascii"))
        except (UnicodeError, ValueError) as exc:
            raise ConsentDeliveryTransportError(
                "delivery body is not canonical JSON"
            ) from exc
        if not isinstance(envelope, dict) or _canonical(envelope) != request.body:
            raise ConsentDeliveryTransportError(
                "delivery body is not canonical JSON"
            )
        expected_envelope_keys = {
            "schema",
            "tenant_id",
            "message_id",
            "destination_id",
            "profile_id",
            "profile_sequence",
            "event_id",
            "event",
            "event_sha256",
            "attempt",
            "destination_revision",
            "signing_key_id",
        }
        if set(envelope) != expected_envelope_keys or any(
            (
                envelope.get("schema") != ENVELOPE_SCHEMA,
                envelope.get("tenant_id") != tenant,
                envelope.get("message_id") != message,
                envelope.get("destination_id") != destination,
                envelope.get("signing_key_id") != key_id,
            )
        ):
            raise ConsentDeliveryTransportError(
                "delivery envelope binding is invalid"
            )
        event = envelope.get("event")
        event_sha256 = _digest(envelope.get("event_sha256"), "event_sha256")
        if not isinstance(event, dict) or not hmac.compare_digest(
            hashlib.sha256(_canonical(event)).hexdigest(),
            event_sha256,
        ):
            raise ConsentDeliveryTransportError(
                "delivery event binding is invalid"
            )
        computed_body_sha256 = hashlib.sha256(request.body).hexdigest()
        if not hmac.compare_digest(computed_body_sha256, body_sha256):
            raise ConsentDeliveryTransportError("delivery body digest changed")
        expected_names = (
            "Content-Type",
            "X-Lightwork-Delivery-Id",
            "X-Lightwork-Key-Id",
            "X-Lightwork-Body-SHA256",
            "X-Lightwork-Signature",
        )
        if (
            not isinstance(request.headers, tuple)
            or len(request.headers) != len(expected_names)
            or any(
                not isinstance(header, tuple)
                or len(header) != 2
                or not all(isinstance(item, str) for item in header)
                for header in request.headers
            )
            or tuple(header[0] for header in request.headers) != expected_names
        ):
            raise ConsentDeliveryTransportError("delivery headers are invalid")
        headers = request.header_map()
        if (
            headers["Content-Type"] != "application/json"
            or headers["X-Lightwork-Delivery-Id"] != message
            or headers["X-Lightwork-Key-Id"] != key_id
            or headers["X-Lightwork-Body-SHA256"] != body_sha256
            or not _SIGNATURE_RE.fullmatch(headers["X-Lightwork-Signature"])
        ):
            raise ConsentDeliveryTransportError(
                "delivery header binding is invalid"
            )
        origin = request.url.removesuffix(DELIVERY_PATH)
        if request.url != _normalize_origin(origin) + DELIVERY_PATH:
            raise ConsentDeliveryTransportError(
                "delivery URL is not the fixed endpoint"
            )
        computed_authorization = _sha256(
            {
                "body_sha256": body_sha256,
                "headers": list(request.headers),
                "url": request.url,
            }
        )
        if not hmac.compare_digest(computed_authorization, authorization_sha256):
            raise ConsentDeliveryTransportError(
                "delivery authorization binding changed"
            )
        return headers
    except ConsentDeliveryTransportError:
        raise
    except ConsentDeliveryValidationError as exc:
        raise ConsentDeliveryTransportError(
            "signed delivery request failed validation"
        ) from exc


class HTTPSConsentDeliveryTransport:
    """Real DNS-pinned HTTPS transport; tests should inject a fake transport."""

    def __init__(self, *, before_effect=None):
        self._before_effect = before_effect

    def post(
        self,
        request: SignedDeliveryRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> DeliveryResponse:
        timeout = _positive_float(timeout_seconds, "timeout_seconds", maximum=60.0)
        maximum = _positive_int(
            max_response_bytes,
            "max_response_bytes",
            maximum=_MAX_RESPONSE_BYTES,
        )
        headers = _validated_request_headers(request)
        try:
            from .enterprise import enterprise_egress_denial
            from .tools._ssrf import allow_private, safe_client
        except ImportError as exc:
            raise ConsentDeliveryTransportError(
                "Destination safety checks are unavailable"
            ) from exc
        if allow_private():
            raise ConsentDeliveryTransportError(
                "Consent delivery cannot run while private-network browsing is enabled"
            )
        if enterprise_egress_denial(request.url, tool="consent_delivery"):
            raise ConsentDeliveryTransportError(
                "Destination is not on the approved outbound hosts list"
            )

        try:
            with safe_client(request.url, timeout=timeout, require_public=True) as client:
                from .authority_effects import authority_effect_fence
                with authority_effect_fence() if self._before_effect else contextlib.nullcontext():
                    if self._before_effect is not None:
                        self._before_effect(request)
                    return self._post(client, request, headers, maximum)
        except (ConsentDeliveryTransportError, ConsentDeliveryRevoked):
            raise
        except Exception as exc:
            raise ConsentDeliveryTransportError(
                "consent delivery transport failed or was blocked"
            ) from exc

    @staticmethod
    def _post(client, request, headers, maximum):
        with client.stream(
            "POST",
            request.url,
            headers=headers,
            content=request.body,
        ) as response:
            declared = response.headers.get("content-length")
            if declared is not None:
                try:
                    declared_length = int(declared)
                except ValueError:
                    raise ConsentDeliveryTransportError(
                        "delivery response Content-Length is invalid"
                    ) from None
                if declared_length < 0 or declared_length > maximum:
                    raise ConsentDeliveryTransportError(
                        "delivery response exceeds its byte bound"
                    )
            digest = hashlib.sha256()
            observed = 0
            for chunk in response.iter_bytes():
                observed += len(chunk)
                if observed > maximum:
                    raise ConsentDeliveryTransportError(
                        "delivery response exceeds its byte bound"
                    )
                digest.update(chunk)
            retry_after: float | None = None
            raw_retry = response.headers.get("retry-after")
            if raw_retry is not None:
                try:
                    candidate = float(raw_retry)
                except ValueError:
                    candidate = -1.0
                if 0 <= candidate <= _MAX_RETRY_AFTER_SECONDS:
                    retry_after = candidate
            return DeliveryResponse(
                status_code=int(response.status_code),
                retry_after_seconds=retry_after,
                response_sha256=digest.hexdigest(),
            )


class ConsentDeliveryStore:
    """SQLite outbox and subscription authority scoped by explicit tenant IDs."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        config_gate: Callable[[], bool] | None = None,
        origin_validator: Callable[[str], None] = _validate_public_origin,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self._id_factory = id_factory or (
            lambda prefix: f"{prefix}-{secrets.token_urlsafe(18)}"
        )
        self._config_gate = config_gate or enabled
        self._origin_validator = origin_validator
        self._require_enabled()
        self._initialize()

    def _require_enabled(self) -> None:
        try:
            allowed = self._config_gate()
        except Exception as exc:
            raise ConsentDeliveryConfigError("consent delivery gate failed") from exc
        if allowed is not True:
            raise ConsentDeliveryConfigError("consent delivery is disabled")

    def _new_id(self, prefix: str) -> str:
        return _opaque(self._id_factory(prefix), f"{prefix} identifier")

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception as exc:
            raise ConsentDeliveryConfigError("delivery clock failed") from exc
        parsed = _finite_time(value, "current time")
        assert parsed is not None
        return parsed

    @staticmethod
    def _tenant(value: object) -> str:
        return _tenant_id(value)

    @staticmethod
    def _idempotency(value: object) -> tuple[str, str]:
        raw = _opaque(value, "idempotency_key", _IDEMPOTENCY_RE)
        return raw, hashlib.sha256(raw.encode("ascii")).hexdigest()

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
                CREATE TABLE IF NOT EXISTS delivery_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS delivery_destinations (
                    tenant TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','suspended','revoked')),
                    active_key_id TEXT,
                    revision INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    base_backoff_seconds REAL NOT NULL,
                    max_backoff_seconds REAL NOT NULL,
                    default_retention_seconds INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    revoked_at REAL,
                    PRIMARY KEY (tenant, destination_id)
                );
                CREATE TABLE IF NOT EXISTS delivery_destination_keys (
                    tenant TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','retired','revoked')),
                    introduced_at REAL NOT NULL,
                    retired_at REAL,
                    revoked_at REAL,
                    PRIMARY KEY (tenant, destination_id, key_id),
                    FOREIGN KEY (tenant, destination_id)
                        REFERENCES delivery_destinations(tenant, destination_id)
                );
                CREATE TABLE IF NOT EXISTS delivery_profile_sequences (
                    tenant TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    last_sequence INTEGER NOT NULL,
                    PRIMARY KEY (tenant, profile_id)
                );
                CREATE TABLE IF NOT EXISTS delivery_messages (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    profile_sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(
                        state IN ('queued','leased','delivered','dead_letter','cancelled')
                    ),
                    attempts INTEGER NOT NULL,
                    next_attempt_at REAL NOT NULL,
                    lease_owner TEXT,
                    lease_token TEXT,
                    lease_until REAL,
                    destination_revision INTEGER,
                    signing_key_id TEXT,
                    revision INTEGER NOT NULL,
                    retention_until REAL NOT NULL,
                    last_error_code TEXT,
                    acknowledgement_sha256 TEXT,
                    delivered_at REAL,
                    cancelled_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE (tenant, message_id),
                    UNIQUE (tenant, destination_id, profile_id, profile_sequence),
                    FOREIGN KEY (tenant, destination_id)
                        REFERENCES delivery_destinations(tenant, destination_id)
                );
                CREATE INDEX IF NOT EXISTS delivery_messages_due
                    ON delivery_messages(tenant, state, next_attempt_at, sequence);
                CREATE INDEX IF NOT EXISTS delivery_messages_ordering
                    ON delivery_messages(
                        tenant, destination_id, profile_id, profile_sequence, state
                    );
                CREATE TABLE IF NOT EXISTS delivery_idempotency (
                    tenant TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, namespace, key_sha256)
                );
                CREATE TABLE IF NOT EXISTS delivery_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    details_sha256 TEXT NOT NULL,
                    previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE (tenant, event_id)
                );
                CREATE INDEX IF NOT EXISTS delivery_audit_tenant
                    ON delivery_audit(tenant, sequence);

                CREATE TRIGGER IF NOT EXISTS delivery_idempotency_no_update
                    BEFORE UPDATE ON delivery_idempotency
                    BEGIN SELECT RAISE(ABORT, 'delivery idempotency is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS delivery_idempotency_no_delete
                    BEFORE DELETE ON delivery_idempotency
                    BEGIN SELECT RAISE(ABORT, 'delivery idempotency is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS delivery_audit_no_update
                    BEFORE UPDATE ON delivery_audit
                    BEGIN SELECT RAISE(ABORT, 'delivery audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS delivery_audit_no_delete
                    BEFORE DELETE ON delivery_audit
                    BEGIN SELECT RAISE(ABORT, 'delivery audit is immutable'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO delivery_meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM delivery_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise ConsentDeliveryError("unsupported consent delivery schema")

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            connection.execute("ROLLBACK")

    @staticmethod
    def _idempotent_result(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256,result_json FROM delivery_idempotency "
            "WHERE tenant=? AND namespace=? AND key_sha256=?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not text_equals(str(row["request_sha256"]), request_sha256):
            raise ConsentDeliveryIdempotencyConflict(
                "idempotency key was already used for different delivery content"
            )
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise ConsentDeliveryError("stored idempotency result is invalid")
        return result

    @staticmethod
    def _save_idempotency(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
        result: Mapping[str, Any],
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO delivery_idempotency(tenant,namespace,key_sha256,"
            "request_sha256,result_json,created_at) VALUES(?,?,?,?,?,?)",
            (
                tenant,
                namespace,
                key_sha256,
                request_sha256,
                _canonical(dict(result)).decode("ascii"),
                now,
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        event_type: str,
        subject_id: str,
        details: Mapping[str, Any],
        now: float,
    ) -> str:
        event = _opaque(event_type, "audit event_type")
        subject = _opaque(subject_id, "audit subject_id")
        event_id = self._new_id("CD-AUD")
        detail_value = dict(details)
        details_sha256 = _sha256(detail_value)
        previous = connection.execute(
            "SELECT event_sha256 FROM delivery_audit WHERE tenant=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        previous_sha256 = None if previous is None else str(previous["event_sha256"])
        body = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant,
            "event_id": event_id,
            "event_type": event,
            "subject_id": subject,
            "details_sha256": details_sha256,
            "previous_event_sha256": previous_sha256,
            "created_at": now,
        }
        event_sha256 = _sha256(body)
        connection.execute(
            "INSERT INTO delivery_audit(tenant,event_id,event_type,subject_id,"
            "details_json,details_sha256,previous_event_sha256,event_sha256,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                event_id,
                event,
                subject,
                _canonical(detail_value).decode("ascii"),
                details_sha256,
                previous_sha256,
                event_sha256,
                now,
            ),
        )
        return event_sha256

    def enroll_destination(
        self,
        tenant_id: str,
        *,
        destination_id: str,
        origin: str,
        signing_key_id: str,
        idempotency_key: str,
        max_attempts: int | None = None,
        base_backoff_seconds: float | None = None,
        max_backoff_seconds: float | None = None,
        default_retention_seconds: int = 30 * 24 * 3600,
    ) -> dict[str, Any]:
        """Explicitly enroll one public HTTPS origin and external key ID.

        Omitted retry values take the installation defaults
        (:func:`delivery_retry_settings`); a requested number of tries above
        the installation's most tries is lowered to it.
        """

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        destination = _opaque(destination_id, "destination_id")
        normalized_origin = _normalize_origin(origin)
        key_id = _opaque(signing_key_id, "signing_key_id")
        _, key_sha256 = self._idempotency(idempotency_key)
        default_attempts, most_attempts, default_base, default_longest = (
            delivery_retry_settings()
        )
        if max_attempts is None:
            max_attempts = default_attempts
        if base_backoff_seconds is None:
            base_backoff_seconds = default_base
        if max_backoff_seconds is None:
            max_backoff_seconds = max(default_longest, float(base_backoff_seconds))
        attempts = min(
            _positive_int(max_attempts, "max_attempts", maximum=20), most_attempts
        )
        base_backoff = _positive_float(
            base_backoff_seconds,
            "base_backoff_seconds",
            maximum=_MAX_RETRY_AFTER_SECONDS,
        )
        max_backoff = _positive_float(
            max_backoff_seconds,
            "max_backoff_seconds",
            maximum=_MAX_RETRY_AFTER_SECONDS,
        )
        if max_backoff < base_backoff:
            raise ConsentDeliveryValidationError(
                "max_backoff_seconds must be at least base_backoff_seconds"
            )
        retention = _positive_int(
            default_retention_seconds,
            "default_retention_seconds",
            maximum=_MAX_RETENTION_SECONDS,
        )
        try:
            self._origin_validator(normalized_origin)
        except ConsentDeliveryConfigError:
            raise
        except Exception as exc:
            raise ConsentDeliveryConfigError(
                "destination failed SSRF-safe enrollment validation"
            ) from exc
        request = {
            "destination_id": destination,
            "origin": normalized_origin,
            "signing_key_id": key_id,
            "max_attempts": attempts,
            "base_backoff_seconds": base_backoff,
            "max_backoff_seconds": max_backoff,
            "default_retention_seconds": retention,
        }
        request_sha256 = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            try:
                self._begin(connection)
                prior = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="enroll_destination",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.execute("COMMIT")
                    return prior
                existing = connection.execute(
                    "SELECT 1 FROM delivery_destinations WHERE tenant=? AND destination_id=?",
                    (tenant, destination),
                ).fetchone()
                if existing is not None:
                    raise ConsentDeliveryConflict("destination_id is already enrolled")
                count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM delivery_destinations WHERE tenant=?",
                        (tenant,),
                    ).fetchone()[0]
                )
                if count >= _MAX_DESTINATIONS_PER_TENANT:
                    raise ConsentDeliveryConflict("tenant destination bound is exhausted")
                connection.execute(
                    "INSERT INTO delivery_destinations(tenant,destination_id,origin,status,"
                    "active_key_id,revision,max_attempts,base_backoff_seconds,"
                    "max_backoff_seconds,default_retention_seconds,created_at,updated_at) "
                    "VALUES(?,?,?,'active',?,1,?,?,?,?,?,?)",
                    (
                        tenant,
                        destination,
                        normalized_origin,
                        key_id,
                        attempts,
                        base_backoff,
                        max_backoff,
                        retention,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO delivery_destination_keys(tenant,destination_id,key_id,"
                    "status,introduced_at) VALUES(?,?,?,'active',?)",
                    (tenant, destination, key_id, now),
                )
                result = {
                    "destination_id": destination,
                    "origin": normalized_origin,
                    "status": "active",
                    "active_key_id": key_id,
                    "revision": 1,
                    "created_at": now,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="destination_enrolled",
                    subject_id=destination,
                    details={
                        "origin_sha256": hashlib.sha256(
                            normalized_origin.encode("ascii")
                        ).hexdigest(),
                        "key_id": key_id,
                        "revision": 1,
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="enroll_destination",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback(connection)
                raise

    def rotate_signing_key(
        self,
        tenant_id: str,
        destination_id: str,
        *,
        new_key_id: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Activate a new external key ID and invalidate outstanding leases."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        destination = _opaque(destination_id, "destination_id")
        key_id = _opaque(new_key_id, "new_key_id")
        expected = _revision(expected_revision)
        _, key_sha256 = self._idempotency(idempotency_key)
        request = {
            "destination_id": destination,
            "new_key_id": key_id,
            "expected_revision": expected,
        }
        request_sha256 = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            try:
                self._begin(connection)
                prior = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="rotate_key",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.execute("COMMIT")
                    return prior
                row = connection.execute(
                    "SELECT * FROM delivery_destinations WHERE tenant=? AND destination_id=?",
                    (tenant, destination),
                ).fetchone()
                if row is None:
                    raise ConsentDeliveryNotFound("destination does not exist")
                if row["status"] == "revoked":
                    raise ConsentDeliveryRevoked("destination is permanently revoked")
                if int(row["revision"]) != expected:
                    raise ConsentDeliveryConflict("destination revision changed")
                reused = connection.execute(
                    "SELECT 1 FROM delivery_destination_keys WHERE tenant=? "
                    "AND destination_id=? AND key_id=?",
                    (tenant, destination, key_id),
                ).fetchone()
                if reused is not None:
                    raise ConsentDeliveryConflict("signing key IDs cannot be reused")
                old_key = row["active_key_id"]
                if old_key is not None:
                    connection.execute(
                        "UPDATE delivery_destination_keys SET status='retired',retired_at=? "
                        "WHERE tenant=? AND destination_id=? AND key_id=? AND status='active'",
                        (now, tenant, destination, old_key),
                    )
                connection.execute(
                    "INSERT INTO delivery_destination_keys(tenant,destination_id,key_id,"
                    "status,introduced_at) VALUES(?,?,?,'active',?)",
                    (tenant, destination, key_id, now),
                )
                new_revision = expected + 1
                updated = connection.execute(
                    "UPDATE delivery_destinations SET active_key_id=?,status='active',"
                    "revision=?,updated_at=? WHERE tenant=? AND destination_id=? "
                    "AND revision=? AND status!='revoked'",
                    (
                        key_id,
                        new_revision,
                        now,
                        tenant,
                        destination,
                        expected,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConsentDeliveryConflict("destination revision changed")
                connection.execute(
                    "UPDATE delivery_messages SET state='queued',lease_owner=NULL,"
                    "lease_token=NULL,lease_until=NULL,destination_revision=NULL,"
                    "signing_key_id=NULL,revision=revision+1,updated_at=? "
                    "WHERE tenant=? AND destination_id=? AND state='leased'",
                    (now, tenant, destination),
                )
                result = {
                    "destination_id": destination,
                    "previous_key_id": old_key,
                    "active_key_id": key_id,
                    "status": "active",
                    "revision": new_revision,
                    "rotated_at": now,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="signing_key_rotated",
                    subject_id=destination,
                    details={
                        "previous_key_id": old_key,
                        "active_key_id": key_id,
                        "revision": new_revision,
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="rotate_key",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback(connection)
                raise

    def revoke_signing_key(
        self,
        tenant_id: str,
        destination_id: str,
        *,
        key_id: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Revoke a key ID; revoking the active key suspends all sends."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        destination = _opaque(destination_id, "destination_id")
        key = _opaque(key_id, "key_id")
        expected = _revision(expected_revision)
        _, key_sha256 = self._idempotency(idempotency_key)
        request = {
            "destination_id": destination,
            "key_id": key,
            "expected_revision": expected,
        }
        request_sha256 = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            try:
                self._begin(connection)
                prior = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="revoke_key",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.execute("COMMIT")
                    return prior
                destination_row = connection.execute(
                    "SELECT * FROM delivery_destinations WHERE tenant=? AND destination_id=?",
                    (tenant, destination),
                ).fetchone()
                if destination_row is None:
                    raise ConsentDeliveryNotFound("destination does not exist")
                if int(destination_row["revision"]) != expected:
                    raise ConsentDeliveryConflict("destination revision changed")
                key_row = connection.execute(
                    "SELECT status FROM delivery_destination_keys WHERE tenant=? "
                    "AND destination_id=? AND key_id=?",
                    (tenant, destination, key),
                ).fetchone()
                if key_row is None:
                    raise ConsentDeliveryNotFound("signing key ID does not exist")
                if key_row["status"] == "revoked":
                    raise ConsentDeliveryConflict("signing key is already revoked")
                connection.execute(
                    "UPDATE delivery_destination_keys SET status='revoked',revoked_at=? "
                    "WHERE tenant=? AND destination_id=? AND key_id=?",
                    (now, tenant, destination, key),
                )
                was_active = destination_row["active_key_id"] == key
                new_revision = expected + 1
                status = "suspended" if was_active else str(destination_row["status"])
                active_key = None if was_active else destination_row["active_key_id"]
                connection.execute(
                    "UPDATE delivery_destinations SET status=?,active_key_id=?,revision=?,"
                    "updated_at=? WHERE tenant=? AND destination_id=? AND revision=?",
                    (
                        status,
                        active_key,
                        new_revision,
                        now,
                        tenant,
                        destination,
                        expected,
                    ),
                )
                # Every key revocation advances the destination revision. Release
                # all leases bound to the previous revision, even when the
                # revoked key was already retired, so ordering does not stall
                # until lease expiry and no stale authorization can be used.
                connection.execute(
                    "UPDATE delivery_messages SET state='queued',lease_owner=NULL,"
                    "lease_token=NULL,lease_until=NULL,destination_revision=NULL,"
                    "signing_key_id=NULL,revision=revision+1,updated_at=? "
                    "WHERE tenant=? AND destination_id=? AND state='leased'",
                    (now, tenant, destination),
                )
                result = {
                    "destination_id": destination,
                    "key_id": key,
                    "key_status": "revoked",
                    "destination_status": status,
                    "active_key_id": active_key,
                    "revision": new_revision,
                    "revoked_at": now,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="signing_key_revoked",
                    subject_id=destination,
                    details={
                        "key_id": key,
                        "was_active": was_active,
                        "destination_status": status,
                        "revision": new_revision,
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="revoke_key",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback(connection)
                raise

    def revoke_destination(
        self,
        tenant_id: str,
        destination_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Permanently revoke a destination and cancel every unsent message."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        destination = _opaque(destination_id, "destination_id")
        expected = _revision(expected_revision)
        _, key_sha256 = self._idempotency(idempotency_key)
        request = {
            "destination_id": destination,
            "expected_revision": expected,
        }
        request_sha256 = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            try:
                self._begin(connection)
                prior = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="revoke_destination",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.execute("COMMIT")
                    return prior
                row = connection.execute(
                    "SELECT status,revision FROM delivery_destinations "
                    "WHERE tenant=? AND destination_id=?",
                    (tenant, destination),
                ).fetchone()
                if row is None:
                    raise ConsentDeliveryNotFound("destination does not exist")
                if int(row["revision"]) != expected:
                    raise ConsentDeliveryConflict("destination revision changed")
                if row["status"] == "revoked":
                    raise ConsentDeliveryConflict("destination is already revoked")
                new_revision = expected + 1
                connection.execute(
                    "UPDATE delivery_destinations SET status='revoked',active_key_id=NULL,"
                    "revision=?,updated_at=?,revoked_at=? WHERE tenant=? "
                    "AND destination_id=? AND revision=?",
                    (new_revision, now, now, tenant, destination, expected),
                )
                connection.execute(
                    "UPDATE delivery_destination_keys SET status='revoked',revoked_at=? "
                    "WHERE tenant=? AND destination_id=? AND status!='revoked'",
                    (now, tenant, destination),
                )
                cancelled = connection.execute(
                    "UPDATE delivery_messages SET state='cancelled',lease_owner=NULL,"
                    "lease_token=NULL,lease_until=NULL,destination_revision=NULL,"
                    "signing_key_id=NULL,cancelled_at=?,revision=revision+1,updated_at=? "
                    "WHERE tenant=? AND destination_id=? "
                    "AND state IN ('queued','leased','dead_letter')",
                    (now, now, tenant, destination),
                ).rowcount
                result = {
                    "destination_id": destination,
                    "status": "revoked",
                    "revision": new_revision,
                    "cancelled_messages": int(cancelled),
                    "revoked_at": now,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="destination_revoked",
                    subject_id=destination,
                    details={
                        "revision": new_revision,
                        "cancelled_messages": int(cancelled),
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="revoke_destination",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback(connection)
                raise

    def enqueue_change(
        self,
        tenant_id: str,
        change: ConsentChange,
        *,
        destination_ids: tuple[str, ...],
        idempotency_key: str,
        retention_until: float | None = None,
    ) -> dict[str, Any]:
        """Atomically fan one change out with one sequence per tenant/profile."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        if not isinstance(change, ConsentChange):
            raise ConsentDeliveryValidationError("change must be a ConsentChange")
        payload = change.normalized()
        payload_bytes = _canonical(payload)
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        raw_destinations = _closed_tuple(
            destination_ids,
            "destination_ids",
            maximum=_MAX_DESTINATIONS_PER_ENQUEUE,
        )
        destinations = tuple(
            sorted(_opaque(item, "destination_id") for item in raw_destinations)
        )
        if len(set(destinations)) != len(destinations):
            raise ConsentDeliveryValidationError("destination_ids contains duplicates")
        _, key_sha256 = self._idempotency(idempotency_key)
        now = self._now()
        explicit_retention = _finite_time(
            retention_until,
            "retention_until",
            allow_none=True,
        )
        if explicit_retention is not None:
            if explicit_retention <= now:
                raise ConsentDeliveryValidationError("retention_until must be in the future")
            if explicit_retention - now > _MAX_RETENTION_SECONDS:
                raise ConsentDeliveryValidationError("retention_until is too far in the future")
        request = {
            "payload_sha256": payload_sha256,
            "destination_ids": list(destinations),
            "retention_until": explicit_retention,
        }
        request_sha256 = _sha256(request)
        with self._connect() as connection:
            try:
                self._begin(connection)
                prior = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="enqueue_change",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.execute("COMMIT")
                    return prior
                pending = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM delivery_messages WHERE tenant=? "
                        "AND state IN ('queued','leased','dead_letter')",
                        (tenant,),
                    ).fetchone()[0]
                )
                if pending + len(destinations) > _MAX_PENDING_PER_TENANT:
                    raise ConsentDeliveryConflict("tenant pending-delivery bound is exhausted")
                placeholders = ",".join("?" for _ in destinations)
                destination_rows = connection.execute(
                    "SELECT * FROM delivery_destinations WHERE tenant=? "
                    f"AND destination_id IN ({placeholders})",
                    (tenant, *destinations),
                ).fetchall()
                by_id = {str(row["destination_id"]): row for row in destination_rows}
                if set(by_id) != set(destinations):
                    raise ConsentDeliveryNotFound("one or more destinations do not exist")
                for destination in destinations:
                    row = by_id[destination]
                    if row["status"] != "active" or row["active_key_id"] is None:
                        raise ConsentDeliveryRevoked(
                            "destination is not active with an authorized key"
                        )
                sequence_row = connection.execute(
                    "SELECT last_sequence FROM delivery_profile_sequences "
                    "WHERE tenant=? AND profile_id=?",
                    (tenant, payload["profile_id"]),
                ).fetchone()
                profile_sequence = (
                    1 if sequence_row is None else int(sequence_row["last_sequence"]) + 1
                )
                if sequence_row is None:
                    connection.execute(
                        "INSERT INTO delivery_profile_sequences(tenant,profile_id,last_sequence) "
                        "VALUES(?,?,?)",
                        (tenant, payload["profile_id"], profile_sequence),
                    )
                else:
                    connection.execute(
                        "UPDATE delivery_profile_sequences SET last_sequence=? "
                        "WHERE tenant=? AND profile_id=? AND last_sequence=?",
                        (
                            profile_sequence,
                            tenant,
                            payload["profile_id"],
                            profile_sequence - 1,
                        ),
                    )
                messages: list[dict[str, Any]] = []
                for destination in destinations:
                    row = by_id[destination]
                    message_id = self._new_id("CD-MSG")
                    effective_retention = explicit_retention or (
                        now + int(row["default_retention_seconds"])
                    )
                    connection.execute(
                        "INSERT INTO delivery_messages(tenant,message_id,destination_id,"
                        "profile_id,profile_sequence,event_id,payload_json,payload_sha256,"
                        "state,attempts,next_attempt_at,revision,retention_until,created_at,"
                        "updated_at) VALUES(?,?,?,?,?,?,?,?, 'queued',0,?,1,?,?,?)",
                        (
                            tenant,
                            message_id,
                            destination,
                            payload["profile_id"],
                            profile_sequence,
                            payload["event_id"],
                            payload_bytes.decode("ascii"),
                            payload_sha256,
                            now,
                            effective_retention,
                            now,
                            now,
                        ),
                    )
                    messages.append(
                        {
                            "message_id": message_id,
                            "destination_id": destination,
                            "retention_until": effective_retention,
                        }
                    )
                result = {
                    "event_id": payload["event_id"],
                    "profile_id": payload["profile_id"],
                    "profile_sequence": profile_sequence,
                    "payload_sha256": payload_sha256,
                    "messages": messages,
                    "enqueued_at": now,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="change_enqueued",
                    subject_id=payload["event_id"],
                    details={
                        "profile_id": payload["profile_id"],
                        "profile_sequence": profile_sequence,
                        "payload_sha256": payload_sha256,
                        "destination_ids_sha256": _sha256(list(destinations)),
                        "message_count": len(messages),
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="enqueue_change",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback(connection)
                raise

    def _recover_expired(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        now: float,
        limit: int = 1000,
    ) -> int:
        most_attempts = delivery_retry_settings()[1]
        rows = connection.execute(
            "SELECT m.*,d.status AS destination_status,d.max_attempts "
            "FROM delivery_messages m JOIN delivery_destinations d "
            "ON d.tenant=m.tenant AND d.destination_id=m.destination_id "
            "WHERE m.tenant=? AND m.state='leased' AND m.lease_until<=? "
            "ORDER BY m.sequence LIMIT ?",
            (tenant, now, limit),
        ).fetchall()
        for row in rows:
            if row["destination_status"] == "revoked" or float(
                row["retention_until"]
            ) <= now:
                state = "cancelled"
                error_code = "lease_expired_cancelled"
            elif row["last_error_code"] == "delivery_unconfirmed":
                state = "dead_letter"
                error_code = "delivery_unconfirmed"
            elif int(row["attempts"]) >= min(int(row["max_attempts"]), most_attempts):
                state = "dead_letter"
                error_code = "lease_expired_max_attempts"
            else:
                state = "queued"
                error_code = "lease_expired"
            updated = connection.execute(
                "UPDATE delivery_messages SET state=?,lease_owner=NULL,lease_token=NULL,"
                "lease_until=NULL,destination_revision=NULL,signing_key_id=NULL,"
                "last_error_code=?,cancelled_at=CASE WHEN ?='cancelled' THEN ? ELSE "
                "cancelled_at END,revision=revision+1,updated_at=? "
                "WHERE tenant=? AND message_id=? AND state='leased' AND revision=?",
                (
                    state,
                    error_code,
                    state,
                    now,
                    now,
                    tenant,
                    row["message_id"],
                    row["revision"],
                ),
            )
            if updated.rowcount == 1:
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="lease_recovered",
                    subject_id=str(row["message_id"]),
                    details={
                        "outcome": state,
                        "attempts": int(row["attempts"]),
                    },
                    now=now,
                )
        return len(rows)

    def claim(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 60.0,
        destination_ids: tuple[str, ...] | None = None,
    ) -> tuple[DeliveryClaim, ...]:
        """CAS-claim due messages while preserving destination/profile order."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        worker = _opaque(worker_id, "worker_id")
        bounded_limit = _positive_int(limit, "limit", maximum=_MAX_CLAIM_LIMIT)
        lease = _positive_float(
            lease_seconds,
            "lease_seconds",
            maximum=_MAX_LEASE_SECONDS,
        )
        now = self._now()
        lease_until = now + lease
        selected = None if destination_ids is None else _closed_tuple(destination_ids, "destination_ids", maximum=64)
        if selected is not None:
            selected = tuple(_opaque(value, "destination_id") for value in selected)
        selection_sql = "" if selected is None else " AND m.destination_id IN (" + ",".join("?" for _ in selected) + ")"
        with self._connect() as connection:
            try:
                self._begin(connection)
                self._recover_expired(connection, tenant=tenant, now=now)
                expired = connection.execute(
                    "SELECT message_id,revision FROM delivery_messages WHERE tenant=? "
                    "AND state='queued' AND retention_until<=? LIMIT 1000",
                    (tenant, now),
                ).fetchall()
                for row in expired:
                    updated = connection.execute(
                        "UPDATE delivery_messages SET state='cancelled',cancelled_at=?,"
                        "last_error_code='retention_expired',revision=revision+1,updated_at=? "
                        "WHERE tenant=? AND message_id=? AND state='queued' AND revision=?",
                        (now, now, tenant, row["message_id"], row["revision"]),
                    )
                    if updated.rowcount == 1:
                        self._audit(
                            connection,
                            tenant=tenant,
                            event_type="message_cancelled",
                            subject_id=str(row["message_id"]),
                            details={"reason": "retention_expired"},
                            now=now,
                        )
                rows = connection.execute(
                    """
                    SELECT m.*,d.origin,d.revision AS current_destination_revision,
                           d.active_key_id,k.status AS key_status
                    FROM delivery_messages m
                    JOIN delivery_destinations d
                      ON d.tenant=m.tenant AND d.destination_id=m.destination_id
                    JOIN delivery_destination_keys k
                      ON k.tenant=d.tenant AND k.destination_id=d.destination_id
                     AND k.key_id=d.active_key_id
                    WHERE m.tenant=? AND m.state='queued' AND m.next_attempt_at<=?
                      AND m.retention_until>?
                      AND d.status='active' AND d.active_key_id IS NOT NULL
                      AND k.status='active'
                      AND NOT EXISTS (
                          SELECT 1 FROM delivery_messages earlier
                          WHERE earlier.tenant=m.tenant
                            AND earlier.destination_id=m.destination_id
                            AND earlier.profile_id=m.profile_id
                            AND earlier.profile_sequence<m.profile_sequence
                            AND earlier.state IN ('queued','leased','dead_letter')
                      )
                    """ + selection_sql + """
                    ORDER BY m.sequence
                    LIMIT ?
                    """,
                    (tenant, now, now, *(selected or ()), bounded_limit),
                ).fetchall()
                claims: list[DeliveryClaim] = []
                for row in rows:
                    token = self._new_id("CD-LEASE")
                    next_revision = int(row["revision"]) + 1
                    updated = connection.execute(
                        "UPDATE delivery_messages SET state='leased',attempts=attempts+1,"
                        "lease_owner=?,lease_token=?,lease_until=?,destination_revision=?,"
                        "signing_key_id=?,revision=?,updated_at=? WHERE tenant=? "
                        "AND message_id=? AND state='queued' AND revision=?",
                        (
                            worker,
                            token,
                            lease_until,
                            row["current_destination_revision"],
                            row["active_key_id"],
                            next_revision,
                            now,
                            tenant,
                            row["message_id"],
                            row["revision"],
                        ),
                    )
                    if updated.rowcount != 1:
                        continue
                    payload = _loads(row["payload_json"], "delivery payload")
                    if not isinstance(payload, dict):
                        raise ConsentDeliveryError("stored delivery payload is invalid")
                    if not text_equals(
                        hashlib.sha256(_canonical(payload)).hexdigest(),
                        str(row["payload_sha256"]),
                    ):
                        raise ConsentDeliveryError("stored delivery payload digest changed")
                    claim = DeliveryClaim(
                        tenant_id=tenant,
                        message_id=str(row["message_id"]),
                        destination_id=str(row["destination_id"]),
                        origin=str(row["origin"]),
                        profile_id=str(row["profile_id"]),
                        profile_sequence=int(row["profile_sequence"]),
                        event_id=str(row["event_id"]),
                        payload=payload,
                        payload_sha256=str(row["payload_sha256"]),
                        attempt=int(row["attempts"]) + 1,
                        lease_owner=worker,
                        lease_token=token,
                        lease_until=lease_until,
                        message_revision=next_revision,
                        destination_revision=int(row["current_destination_revision"]),
                        signing_key_id=str(row["active_key_id"]),
                    )
                    claims.append(claim)
                    self._audit(
                        connection,
                        tenant=tenant,
                        event_type="message_claimed",
                        subject_id=claim.message_id,
                        details={
                            "destination_id": claim.destination_id,
                            "profile_sequence": claim.profile_sequence,
                            "attempt": claim.attempt,
                            "key_id": claim.signing_key_id,
                            "lease_until": lease_until,
                        },
                        now=now,
                    )
                connection.execute("COMMIT")
                return tuple(claims)
            except BaseException:
                self._rollback(connection)
                raise

    def _claim_row(
        self,
        connection: sqlite3.Connection,
        claim: DeliveryClaim,
        *,
        now: float,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        if not isinstance(claim, DeliveryClaim):
            raise ConsentDeliveryValidationError("claim must be a DeliveryClaim")
        row = connection.execute(
            "SELECT * FROM delivery_messages WHERE tenant=? AND message_id=?",
            (claim.tenant_id, claim.message_id),
        ).fetchone()
        if row is None:
            raise ConsentDeliveryNotFound("delivery message does not exist")
        if (
            row["state"] != "leased"
            or row["lease_token"] != claim.lease_token
            or int(row["revision"]) != claim.message_revision
            or row["lease_owner"] != claim.lease_owner
            or row["lease_until"] is None
            or float(row["lease_until"]) <= now
        ):
            raise ConsentDeliveryLeaseLost("delivery lease no longer authorizes work")
        destination = connection.execute(
            "SELECT * FROM delivery_destinations WHERE tenant=? AND destination_id=?",
            (claim.tenant_id, claim.destination_id),
        ).fetchone()
        if destination is None:
            raise ConsentDeliveryNotFound("destination does not exist")
        if (
            destination["status"] != "active"
            or destination["active_key_id"] != claim.signing_key_id
            or int(destination["revision"]) != claim.destination_revision
        ):
            raise ConsentDeliveryRevoked(
                "destination or signing authority changed after claim"
            )
        key = connection.execute(
            "SELECT status FROM delivery_destination_keys WHERE tenant=? "
            "AND destination_id=? AND key_id=?",
            (claim.tenant_id, claim.destination_id, claim.signing_key_id),
        ).fetchone()
        if key is None or key["status"] != "active":
            raise ConsentDeliveryRevoked("signing key is not active")
        return row, destination

    def authorize_claim(self, claim: DeliveryClaim) -> None:
        """Re-check a claim immediately before signing or transport I/O."""

        self._require_enabled()
        now = self._now()
        with self._connect() as connection:
            row, destination = self._claim_row(connection, claim, now=now)
            if row["payload_sha256"] != claim.payload_sha256:
                raise ConsentDeliveryLeaseLost("claim payload binding changed")
            if destination["origin"] != claim.origin:
                raise ConsentDeliveryRevoked("destination origin changed")

    def build_signed_request(
        self,
        claim: DeliveryClaim,
        signer: DeliverySigner,
    ) -> SignedDeliveryRequest:
        """Create and sign the canonical envelope without retaining key material."""

        self.authorize_claim(claim)
        if not hasattr(signer, "sign") or not callable(signer.sign):
            raise ConsentDeliveryConfigError("delivery signer is invalid")
        envelope = {
            "schema": ENVELOPE_SCHEMA,
            "tenant_id": claim.tenant_id,
            "message_id": claim.message_id,
            "destination_id": claim.destination_id,
            "profile_id": claim.profile_id,
            "profile_sequence": claim.profile_sequence,
            "event_id": claim.event_id,
            "event": dict(claim.payload),
            "event_sha256": claim.payload_sha256,
            "attempt": claim.attempt,
            "destination_revision": claim.destination_revision,
            "signing_key_id": claim.signing_key_id,
        }
        body = _canonical(envelope)
        body_sha256 = hashlib.sha256(body).hexdigest()
        signing_input = (
            b"lightwork.consent-delivery.v1\n"
            + claim.signing_key_id.encode("ascii")
            + b"\n"
            + body
        )
        try:
            signature = signer.sign(claim.signing_key_id, signing_input)
        except Exception as exc:
            raise ConsentDeliveryConfigError("delivery signing failed") from exc
        if (
            not isinstance(signature, bytes)
            or not 1 <= len(signature) <= _MAX_SIGNATURE_BYTES
        ):
            raise ConsentDeliveryConfigError("delivery signer returned invalid bytes")
        encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        headers = (
            ("Content-Type", "application/json"),
            ("X-Lightwork-Delivery-Id", claim.message_id),
            ("X-Lightwork-Key-Id", claim.signing_key_id),
            ("X-Lightwork-Body-SHA256", body_sha256),
            ("X-Lightwork-Signature", f"v1={encoded_signature}"),
        )
        authorization_sha256 = _sha256(
            {
                "body_sha256": body_sha256,
                "headers": list(headers),
                "url": claim.origin + DELIVERY_PATH,
            }
        )
        return SignedDeliveryRequest(
            tenant_id=claim.tenant_id,
            message_id=claim.message_id,
            destination_id=claim.destination_id,
            url=claim.origin + DELIVERY_PATH,
            body=body,
            headers=headers,
            key_id=claim.signing_key_id,
            body_sha256=body_sha256,
            authorization_sha256=authorization_sha256,
        )

    def acknowledge(
        self,
        claim: DeliveryClaim,
        *,
        response_sha256: str,
    ) -> dict[str, Any]:
        """Idempotently acknowledge one exact lease and response digest."""

        self._require_enabled()
        if not isinstance(claim, DeliveryClaim):
            raise ConsentDeliveryValidationError("claim must be a DeliveryClaim")
        response_digest = _digest(response_sha256, "response_sha256")
        now = self._now()
        acknowledgement_sha256 = _sha256(
            {
                "message_id": claim.message_id,
                "lease_token": claim.lease_token,
                "response_sha256": response_digest,
            }
        )
        with self._connect() as connection:
            try:
                self._begin(connection)
                existing = connection.execute(
                    "SELECT state,lease_token,acknowledgement_sha256,delivered_at "
                    "FROM delivery_messages WHERE tenant=? AND message_id=?",
                    (claim.tenant_id, claim.message_id),
                ).fetchone()
                if existing is None:
                    raise ConsentDeliveryNotFound("delivery message does not exist")
                if existing["state"] == "delivered":
                    if (
                        existing["lease_token"] == claim.lease_token
                        and text_equals(
                            str(existing["acknowledgement_sha256"]),
                            acknowledgement_sha256,
                        )
                    ):
                        connection.execute("COMMIT")
                        return {
                            "message_id": claim.message_id,
                            "state": "delivered",
                            "acknowledgement_sha256": acknowledgement_sha256,
                            "delivered_at": float(existing["delivered_at"]),
                        }
                    raise ConsentDeliveryConflict(
                        "message was acknowledged by a different lease or response"
                    )
                self._claim_row(connection, claim, now=now)
                updated = connection.execute(
                    "UPDATE delivery_messages SET state='delivered',lease_owner=NULL,"
                    "lease_until=NULL,acknowledgement_sha256=?,delivered_at=?,"
                    "revision=revision+1,updated_at=? WHERE tenant=? AND message_id=? "
                    "AND state='leased' AND lease_token=? AND revision=?",
                    (
                        acknowledgement_sha256,
                        now,
                        now,
                        claim.tenant_id,
                        claim.message_id,
                        claim.lease_token,
                        claim.message_revision,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConsentDeliveryLeaseLost("acknowledgement CAS failed")
                self._audit(
                    connection,
                    tenant=claim.tenant_id,
                    event_type="delivery_acknowledged",
                    subject_id=claim.message_id,
                    details={
                        "destination_id": claim.destination_id,
                        "attempt": claim.attempt,
                        "acknowledgement_sha256": acknowledgement_sha256,
                    },
                    now=now,
                )
                connection.execute("COMMIT")
                return {
                    "message_id": claim.message_id,
                    "state": "delivered",
                    "acknowledgement_sha256": acknowledgement_sha256,
                    "delivered_at": now,
                }
            except BaseException:
                self._rollback(connection)
                raise

    def fail_claim(
        self,
        claim: DeliveryClaim,
        *,
        error_code: str,
        retry_after_seconds: float | None = None,
        permanent: bool = False,
    ) -> dict[str, Any]:
        """Schedule bounded backoff or atomically dead-letter an exact lease."""

        self._require_enabled()
        if error_code not in _RETRY_ERROR_CODES or not _ERROR_CODE_RE.fullmatch(error_code):
            raise ConsentDeliveryValidationError("error_code is not in the safe taxonomy")
        if not isinstance(permanent, bool):
            raise ConsentDeliveryValidationError("permanent must be boolean")
        retry_after: float | None = None
        if retry_after_seconds is not None:
            if (
                isinstance(retry_after_seconds, bool)
                or not isinstance(retry_after_seconds, (int, float))
                or not math.isfinite(float(retry_after_seconds))
                or not 0 <= float(retry_after_seconds) <= _MAX_RETRY_AFTER_SECONDS
            ):
                raise ConsentDeliveryValidationError("retry_after_seconds is invalid")
            retry_after = float(retry_after_seconds)
        now = self._now()
        most_attempts = delivery_retry_settings()[1]
        with self._connect() as connection:
            try:
                self._begin(connection)
                row, destination = self._claim_row(connection, claim, now=now)
                attempts = int(row["attempts"])
                dead_letter = permanent or attempts >= min(
                    int(destination["max_attempts"]), most_attempts
                )
                if dead_letter:
                    state = "dead_letter"
                    next_attempt_at = float(row["next_attempt_at"])
                    event_type = "message_dead_lettered"
                else:
                    exponent = min(max(attempts - 1, 0), 20)
                    computed = min(
                        float(destination["base_backoff_seconds"]) * (2**exponent),
                        float(destination["max_backoff_seconds"]),
                    )
                    delay = computed if retry_after is None else min(
                        retry_after,
                        float(destination["max_backoff_seconds"]),
                    )
                    state = "queued"
                    next_attempt_at = now + delay
                    event_type = "retry_scheduled"
                updated = connection.execute(
                    "UPDATE delivery_messages SET state=?,next_attempt_at=?,"
                    "lease_owner=NULL,lease_token=NULL,lease_until=NULL,"
                    "destination_revision=NULL,signing_key_id=NULL,last_error_code=?,"
                    "revision=revision+1,updated_at=? WHERE tenant=? AND message_id=? "
                    "AND state='leased' AND lease_token=? AND revision=?",
                    (
                        state,
                        next_attempt_at,
                        error_code,
                        now,
                        claim.tenant_id,
                        claim.message_id,
                        claim.lease_token,
                        claim.message_revision,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConsentDeliveryLeaseLost("failure CAS failed")
                self._audit(
                    connection,
                    tenant=claim.tenant_id,
                    event_type=event_type,
                    subject_id=claim.message_id,
                    details={
                        "destination_id": claim.destination_id,
                        "attempt": attempts,
                        "error_code": error_code,
                        "next_attempt_at": next_attempt_at,
                    },
                    now=now,
                )
                connection.execute("COMMIT")
                return {
                    "message_id": claim.message_id,
                    "state": state,
                    "attempts": attempts,
                    "next_attempt_at": next_attempt_at,
                    "error_code": error_code,
                }
            except BaseException:
                self._rollback(connection)
                raise

    def release_invalidated_claim(self, claim: DeliveryClaim) -> dict[str, Any]:
        """Release a claim invalidated by rotation/revocation without sending."""

        self._require_enabled()
        if not isinstance(claim, DeliveryClaim):
            raise ConsentDeliveryValidationError("claim must be a DeliveryClaim")
        now = self._now()
        with self._connect() as connection:
            try:
                self._begin(connection)
                row = connection.execute(
                    "SELECT state,lease_token,revision,last_error_code FROM delivery_messages "
                    "WHERE tenant=? AND message_id=?",
                    (claim.tenant_id, claim.message_id),
                ).fetchone()
                if row is None:
                    raise ConsentDeliveryNotFound("delivery message does not exist")
                if (
                    row["state"] != "leased"
                    or row["lease_token"] != claim.lease_token
                    or int(row["revision"]) != claim.message_revision
                ):
                    raise ConsentDeliveryLeaseLost("delivery claim was already invalidated")
                destination = connection.execute(
                    "SELECT status,active_key_id,revision FROM delivery_destinations "
                    "WHERE tenant=? AND destination_id=?",
                    (claim.tenant_id, claim.destination_id),
                ).fetchone()
                if destination is None or destination["status"] == "revoked":
                    state = "cancelled"
                    cancelled_at: float | None = now
                else:
                    state = "dead_letter" if row["last_error_code"] == "delivery_unconfirmed" else "queued"
                    cancelled_at = None
                connection.execute(
                    "UPDATE delivery_messages SET state=?,lease_owner=NULL,lease_token=NULL,"
                    "lease_until=NULL,destination_revision=NULL,signing_key_id=NULL,"
                    "cancelled_at=?,last_error_code=CASE WHEN last_error_code='delivery_unconfirmed' "
                    "THEN last_error_code ELSE 'authorization_changed' END,"
                    "revision=revision+1,updated_at=? WHERE tenant=? AND message_id=? "
                    "AND state='leased' AND lease_token=? AND revision=?",
                    (
                        state,
                        cancelled_at,
                        now,
                        claim.tenant_id,
                        claim.message_id,
                        claim.lease_token,
                        claim.message_revision,
                    ),
                )
                self._audit(
                    connection,
                    tenant=claim.tenant_id,
                    event_type="claim_invalidated",
                    subject_id=claim.message_id,
                    details={"outcome": state, "reason": "authorization_changed"},
                    now=now,
                )
                connection.execute("COMMIT")
                return {"message_id": claim.message_id, "state": state}
            except BaseException:
                self._rollback(connection)
                raise

    def replay_dead_letter(
        self,
        tenant_id: str,
        message_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        retention_until: float | None = None,
    ) -> dict[str, Any]:
        """Explicitly replay one dead letter with reset attempts and fresh CAS."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        message = _opaque(message_id, "message_id")
        expected = _revision(expected_revision)
        _, key_sha256 = self._idempotency(idempotency_key)
        now = self._now()
        requested_retention = _finite_time(
            retention_until,
            "retention_until",
            allow_none=True,
        )
        if requested_retention is not None and (
            requested_retention <= now
            or requested_retention - now > _MAX_RETENTION_SECONDS
        ):
            raise ConsentDeliveryValidationError("replay retention is invalid")
        request = {
            "message_id": message,
            "expected_revision": expected,
            "retention_until": requested_retention,
        }
        request_sha256 = _sha256(request)
        with self._connect() as connection:
            try:
                self._begin(connection)
                prior = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="replay_dead_letter",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.execute("COMMIT")
                    return prior
                row = connection.execute(
                    "SELECT m.*,d.status AS destination_status,d.active_key_id "
                    "FROM delivery_messages m JOIN delivery_destinations d "
                    "ON d.tenant=m.tenant AND d.destination_id=m.destination_id "
                    "WHERE m.tenant=? AND m.message_id=?",
                    (tenant, message),
                ).fetchone()
                if row is None:
                    raise ConsentDeliveryNotFound("delivery message does not exist")
                if row["state"] != "dead_letter":
                    raise ConsentDeliveryConflict("message is not a dead letter")
                if row["last_error_code"] == "delivery_unconfirmed":
                    raise ConsentDeliveryConflict("The receiving system must confirm this update before it can be sent again.")
                if int(row["revision"]) != expected:
                    raise ConsentDeliveryConflict("message revision changed")
                if row["destination_status"] != "active" or row["active_key_id"] is None:
                    raise ConsentDeliveryRevoked("destination cannot accept replay")
                effective_retention = requested_retention or float(row["retention_until"])
                if effective_retention <= now:
                    raise ConsentDeliveryConflict(
                        "dead letter retention expired; provide a reviewed future retention"
                    )
                new_revision = expected + 1
                updated = connection.execute(
                    "UPDATE delivery_messages SET state='queued',attempts=0,"
                    "next_attempt_at=?,lease_owner=NULL,lease_token=NULL,lease_until=NULL,"
                    "destination_revision=NULL,signing_key_id=NULL,last_error_code=NULL,"
                    "retention_until=?,revision=?,updated_at=? WHERE tenant=? "
                    "AND message_id=? AND state='dead_letter' AND revision=?",
                    (
                        now,
                        effective_retention,
                        new_revision,
                        now,
                        tenant,
                        message,
                        expected,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConsentDeliveryConflict("dead-letter replay CAS failed")
                result = {
                    "message_id": message,
                    "state": "queued",
                    "attempts": 0,
                    "revision": new_revision,
                    "retention_until": effective_retention,
                    "replayed_at": now,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="dead_letter_replayed",
                    subject_id=message,
                    details={
                        "revision": new_revision,
                        "retention_until": effective_retention,
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="replay_dead_letter",
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback(connection)
                raise

    def destination(self, tenant_id: str, destination_id: str) -> dict[str, Any]:
        """Read one tenant-scoped destination and key-ID metadata."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        destination = _opaque(destination_id, "destination_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM delivery_destinations WHERE tenant=? AND destination_id=?",
                (tenant, destination),
            ).fetchone()
            if row is None:
                raise ConsentDeliveryNotFound("destination does not exist")
            keys = connection.execute(
                "SELECT key_id,status,introduced_at,retired_at,revoked_at "
                "FROM delivery_destination_keys WHERE tenant=? AND destination_id=? "
                "ORDER BY introduced_at,key_id",
                (tenant, destination),
            ).fetchall()
            return {
                "destination_id": destination,
                "origin": str(row["origin"]),
                "status": str(row["status"]),
                "active_key_id": row["active_key_id"],
                "revision": int(row["revision"]),
                "max_attempts": int(row["max_attempts"]),
                "base_backoff_seconds": float(row["base_backoff_seconds"]),
                "max_backoff_seconds": float(row["max_backoff_seconds"]),
                "default_retention_seconds": int(row["default_retention_seconds"]),
                "created_at": float(row["created_at"]),
                "updated_at": float(row["updated_at"]),
                "revoked_at": row["revoked_at"],
                "keys": [dict(key) for key in keys],
            }

    def list_destinations(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List one tenant's destinations and key-ID metadata, newest first."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        bounded = _positive_int(limit, "limit", maximum=_MAX_AUDIT_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT destination_id FROM delivery_destinations WHERE tenant=? "
                "ORDER BY created_at DESC,destination_id LIMIT ?",
                (tenant, bounded + 1),
            ).fetchall()
        items = [
            self.destination(tenant, str(row["destination_id"]))
            for row in rows[:bounded]
        ]
        return {"items": items, "truncated": len(rows) > bounded}

    def message(self, tenant_id: str, message_id: str) -> dict[str, Any]:
        """Read safe queue metadata without returning the consent payload."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        message = _opaque(message_id, "message_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT message_id,destination_id,profile_id,profile_sequence,event_id,"
                "payload_sha256,state,attempts,next_attempt_at,lease_owner,lease_until,"
                "signing_key_id,revision,retention_until,last_error_code,"
                "acknowledgement_sha256,delivered_at,cancelled_at,created_at,updated_at "
                "FROM delivery_messages WHERE tenant=? AND message_id=?",
                (tenant, message),
            ).fetchone()
            if row is None:
                raise ConsentDeliveryNotFound("delivery message does not exist")
            return dict(row)

    def counts(self, tenant_id: str) -> dict[str, int]:
        self._require_enabled()
        tenant = self._tenant(tenant_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT state,COUNT(*) AS count FROM delivery_messages "
                "WHERE tenant=? GROUP BY state",
                (tenant,),
            ).fetchall()
        result = dict.fromkeys(sorted(_MESSAGE_STATES), 0)
        result.update({str(row["state"]): int(row["count"]) for row in rows})
        result["pending"] = (
            result["queued"] + result["leased"] + result["dead_letter"]
        )
        return result

    def list_dead_letters(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self._require_enabled()
        tenant = self._tenant(tenant_id)
        bounded = _positive_int(limit, "limit", maximum=_MAX_AUDIT_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT message_id,destination_id,profile_id,profile_sequence,event_id,"
                "payload_sha256,attempts,revision,retention_until,last_error_code,updated_at "
                "FROM delivery_messages WHERE tenant=? AND state='dead_letter' "
                "ORDER BY sequence LIMIT ?",
                (tenant, bounded),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_audit(
        self,
        tenant_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self._require_enabled()
        tenant = self._tenant(tenant_id)
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or after_sequence < 0
        ):
            raise ConsentDeliveryValidationError("after_sequence is invalid")
        bounded = _positive_int(limit, "limit", maximum=_MAX_AUDIT_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM delivery_audit WHERE tenant=? AND sequence>? "
                "ORDER BY sequence LIMIT ?",
                (tenant, after_sequence, bounded),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            details = _loads(row["details_json"], "audit details")
            if not isinstance(details, dict) or not text_equals(
                _sha256(details),
                str(row["details_sha256"]),
            ):
                raise ConsentDeliveryError("stored audit details changed")
            result.append(
                {
                    "sequence": int(row["sequence"]),
                    "event_id": str(row["event_id"]),
                    "event_type": str(row["event_type"]),
                    "subject_id": str(row["subject_id"]),
                    "details": details,
                    "details_sha256": str(row["details_sha256"]),
                    "previous_event_sha256": row["previous_event_sha256"],
                    "event_sha256": str(row["event_sha256"]),
                    "created_at": float(row["created_at"]),
                }
            )
        return result

    def verify_audit_chain(self, tenant_id: str) -> dict[str, Any]:
        self._require_enabled()
        tenant = self._tenant(tenant_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM delivery_audit WHERE tenant=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        previous: str | None = None
        for row in rows:
            if row["previous_event_sha256"] != previous:
                raise ConsentDeliveryError("delivery audit chain is broken")
            details = _loads(row["details_json"], "audit details")
            if not isinstance(details, dict) or not text_equals(
                _sha256(details),
                str(row["details_sha256"]),
            ):
                raise ConsentDeliveryError("delivery audit details changed")
            body = {
                "schema": AUDIT_SCHEMA,
                "tenant_id": tenant,
                "event_id": str(row["event_id"]),
                "event_type": str(row["event_type"]),
                "subject_id": str(row["subject_id"]),
                "details_sha256": str(row["details_sha256"]),
                "previous_event_sha256": previous,
                "created_at": float(row["created_at"]),
            }
            computed = _sha256(body)
            if not text_equals(computed, str(row["event_sha256"])):
                raise ConsentDeliveryError("delivery audit event digest changed")
            previous = computed
        return {
            "tenant_id": tenant,
            "events": len(rows),
            "head_sha256": previous,
            "valid": True,
        }

    def retention_due(self, tenant_id: str, *, at: float | None = None) -> dict[str, int]:
        self._require_enabled()
        tenant = self._tenant(tenant_id)
        cutoff = self._now() if at is None else float(
            _finite_time(at, "retention cutoff")
        )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT state,COUNT(*) AS count FROM delivery_messages "
                "WHERE tenant=? AND retention_until<=? GROUP BY state",
                (tenant, cutoff),
            ).fetchall()
        result = dict.fromkeys(sorted(_MESSAGE_STATES), 0)
        result.update({str(row["state"]): int(row["count"]) for row in rows})
        return result

    def purge_terminal(
        self,
        tenant_id: str,
        *,
        at: float | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Delete expired delivered/cancelled payloads; dead letters require review."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        cutoff = self._now() if at is None else float(
            _finite_time(at, "retention cutoff")
        )
        bounded = _positive_int(limit, "limit", maximum=5000)
        now = self._now()
        with self._connect() as connection:
            try:
                self._begin(connection)
                rows = connection.execute(
                    "SELECT message_id FROM delivery_messages WHERE tenant=? "
                    "AND state IN ('delivered','cancelled') AND retention_until<=? "
                    "ORDER BY sequence LIMIT ?",
                    (tenant, cutoff, bounded),
                ).fetchall()
                message_ids = [str(row["message_id"]) for row in rows]
                for message in message_ids:
                    connection.execute(
                        "DELETE FROM delivery_messages WHERE tenant=? AND message_id=? "
                        "AND state IN ('delivered','cancelled') AND retention_until<=?",
                        (tenant, message, cutoff),
                    )
                if message_ids:
                    self._audit(
                        connection,
                        tenant=tenant,
                        event_type="terminal_payloads_purged",
                        subject_id="retention",
                        details={
                            "count": len(message_ids),
                            "message_ids_sha256": _sha256(message_ids),
                            "cutoff": cutoff,
                        },
                        now=now,
                    )
                connection.execute("COMMIT")
                return {"purged": len(message_ids), "cutoff": cutoff}
            except BaseException:
                self._rollback(connection)
                raise

    def managed_record(self, tenant_id: str, kind: str, reference: str) -> dict | None:
        """Read one exact sealed key/subscription; no credential is public."""
        from . import crypto_at_rest
        tenant, ref = self._tenant(tenant_id), _opaque(reference, "reference")
        if kind not in {"key", "subscription"}:
            raise ConsentDeliveryValidationError("managed record kind is invalid")
        key = "managed." + _sha256(tenant) + "." + kind + "." + _sha256(ref)
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM delivery_meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        try:
            if not crypto_at_rest.is_sealed_str(row["value"]):
                raise ValueError
            record = json.loads(crypto_at_rest.unseal_from_str(row["value"]))
            if (record["tenant"] != tenant or record["kind"] != kind or record["reference"] != ref
                    or not isinstance(record["revision"], int) or record["revision"] < 1):
                raise ValueError
            return record
        except (ValueError, TypeError, KeyError, crypto_at_rest.EncryptionUnavailable) as exc:
            raise ConsentDeliveryConfigError("Saved delivery setup could not be verified.") from exc

    def managed_save(self, tenant_id: str, kind: str, reference: str, material: dict,
                     *, expected_revision: int, idempotency_key: str, before_effect=None) -> dict:
        """Existing sealed metadata + immutable receipt; no parallel journal."""
        from . import crypto_at_rest
        tenant, ref = self._tenant(tenant_id), _opaque(reference, "reference")
        if kind not in {"key", "subscription"} or not isinstance(material, dict):
            raise ConsentDeliveryValidationError("managed delivery setup is invalid")
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
            raise ConsentDeliveryValidationError("setup revision is invalid")
        request = {"kind": kind, "reference": ref, "material": material, "expected_revision": expected_revision}
        request_hash = _sha256(request)
        _raw, operation = self._idempotency(idempotency_key)
        key = "managed." + _sha256(tenant) + "." + kind + "." + _sha256(ref)
        with self._connect() as connection:
            try:
                self._begin(connection)
                prior = self._idempotent_result(connection, tenant=tenant, namespace="managed."+kind,
                    key_sha256=operation, request_sha256=request_hash)
                if prior is not None:
                    connection.execute("COMMIT")
                    return prior
                row = connection.execute("SELECT value FROM delivery_meta WHERE key=?", (key,)).fetchone()
                if row is not None and not crypto_at_rest.is_sealed_str(row["value"]):
                    raise ConsentDeliveryConfigError("Saved setup could not be verified.")
                previous = None if row is None else json.loads(crypto_at_rest.unseal_from_str(row["value"]))
                if previous is not None and (previous["tenant"], previous["kind"], previous["reference"]) != (tenant, kind, ref):
                    raise ConsentDeliveryConfigError("Saved setup could not be verified.")
                revision = 0 if previous is None else previous["revision"]
                if revision != expected_revision or (kind == "key" and revision):
                    raise ConsentDeliveryConflict("Saved setup changed. Review its current edition again.")
                if before_effect is not None:
                    before_effect()
                now = self._now()
                record = {"tenant": tenant, "kind": kind, "reference": ref, "revision": revision+1, "material": material}
                sealed = crypto_at_rest.seal_to_str(_canonical(record).decode("ascii"))
                if not crypto_at_rest.is_sealed_str(sealed):
                    raise ConsentDeliveryConfigError("Delivery setup could not be protected.")
                connection.execute("INSERT INTO delivery_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, sealed))
                result = {"kind": kind, "reference": ref, "revision": revision+1, "saved": True}
                self._audit(connection, tenant=tenant, event_type="managed_setup_saved", subject_id=ref,
                    details={"kind": kind, "revision": revision+1}, now=now)
                self._save_idempotency(connection, tenant=tenant, namespace="managed."+kind,
                    key_sha256=operation, request_sha256=request_hash, result=result, now=now)
                if before_effect is not None:
                    before_effect()
                connection.execute("COMMIT")
                return result
            except BaseException:
                self._rollback(connection)
                raise

    def managed_original(self, tenant_id: str, request: dict, idempotency_key: str) -> dict | None:
        tenant = self._tenant(tenant_id)
        _raw, operation = self._idempotency(idempotency_key)
        with self._connect() as connection:
            return self._idempotent_result(connection, tenant=tenant, namespace="managed."+request["kind"],
                key_sha256=operation, request_sha256=_sha256(request))

    def managed_keys(self, tenant_id: str) -> list[dict]:
        """Named choices only; secrets never enter the public inventory."""
        from . import crypto_at_rest
        tenant = self._tenant(tenant_id)
        prefix = "managed." + _sha256(tenant) + ".key."
        with self._connect() as connection:
            rows = connection.execute("SELECT value FROM delivery_meta WHERE key LIKE ? ORDER BY key LIMIT 1001", (prefix+"%",)).fetchall()
        if len(rows) > 1000:
            raise ConsentDeliveryConfigError("Saved signing keys exceed the supported inventory bound.")
        result = []
        for row in rows:
            record = json.loads(crypto_at_rest.unseal_from_str(row["value"]))
            current = self.managed_record(tenant, "key", record["reference"])
            if current is None:
                raise ConsentDeliveryConfigError("Saved signing key changed during the read.")
            result.append({"key_id": current["reference"], "label": current["material"]["label"], "saved": True})
        return result

    def mark_managed_send(self, claim: DeliveryClaim) -> None:
        """Before physical send, persist uncertainty so a crash never replays."""
        with self._connect() as connection:
            try:
                self._begin(connection)
                self._claim_row(connection, claim, now=self._now())
                connection.execute("UPDATE delivery_messages SET last_error_code='delivery_unconfirmed' WHERE tenant=? AND message_id=?", (claim.tenant_id, claim.message_id))
                connection.execute("COMMIT")
            except BaseException:
                self._rollback(connection)
                raise

    def privacy_posture(self, tenant_id: str) -> dict[str, Any]:
        """Inspect retained JSON keys and schema columns without returning values."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM delivery_messages WHERE tenant=?",
                (tenant,),
            ).fetchall()
            columns: list[str] = []
            for table in (
                "delivery_destinations",
                "delivery_destination_keys",
                "delivery_messages",
            ):
                columns.extend(
                    str(row["name"]).lower()
                    for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
                )
        retained_keys: set[str] = set()

        def inspect(value: object) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    retained_keys.add(str(key).lower())
                    inspect(nested)
            elif isinstance(value, list):
                for nested in value:
                    inspect(nested)

        for row in rows:
            inspect(_loads(row["payload_json"], "delivery payload"))
        prohibited = sorted(retained_keys & _PROHIBITED_KEYS)
        prohibited_columns = sorted(set(columns) & _PROHIBITED_KEYS)
        return {
            "tenant_id": tenant,
            "payloads_inspected": len(rows),
            "retained_keys": tuple(sorted(retained_keys)),
            "prohibited_payload_keys": tuple(prohibited),
            "prohibited_schema_columns": tuple(prohibited_columns),
            "key_material_persisted": False,
            "managed_key_custody": "sealed metadata; never plaintext",
            "privacy_check_passed": not prohibited and not prohibited_columns,
        }


class ConsentDeliveryDispatcher:
    """One bounded network-dispatch cycle over the durable delivery authority."""

    def __init__(
        self,
        store: ConsentDeliveryStore,
        *,
        signer: DeliverySigner,
        transport: DeliveryTransport | None = None,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        before_effect=None,
        hold_unknown: bool = False,
    ) -> None:
        if not isinstance(store, ConsentDeliveryStore):
            raise ConsentDeliveryConfigError("store must be a ConsentDeliveryStore")
        if not hasattr(signer, "sign") or not callable(signer.sign):
            raise ConsentDeliveryConfigError("signer is invalid")
        self._before_effect = before_effect
        self._hold_unknown = hold_unknown
        self._active_claim = None
        selected_transport = transport or HTTPSConsentDeliveryTransport(
            before_effect=self._physical_boundary if before_effect is not None or hold_unknown else None)
        if not hasattr(selected_transport, "post") or not callable(selected_transport.post):
            raise ConsentDeliveryConfigError("transport is invalid")
        self._store = store
        self._signer = signer
        self._transport = selected_transport
        self._timeout = _positive_float(
            timeout_seconds,
            "timeout_seconds",
            maximum=60.0,
        )
        self._max_response_bytes = _positive_int(
            max_response_bytes,
            "max_response_bytes",
            maximum=_MAX_RESPONSE_BYTES,
        )

    def _physical_boundary(self, request):
        claim = self._active_claim
        if claim is None or (request.tenant_id, request.message_id, request.destination_id, request.key_id) != (
                claim.tenant_id, claim.message_id, claim.destination_id, claim.signing_key_id):
            raise ConsentDeliveryRevoked("The reviewed delivery source changed.")
        if self._before_effect is not None:
            self._before_effect(claim)
        self._store.authorize_claim(claim)
        if self._hold_unknown:
            self._store.mark_managed_send(claim)

    def _record_failure(
        self,
        result: dict[str, int],
        claim: DeliveryClaim,
        *,
        error_code: str,
        retry_after_seconds: float | None = None,
        permanent: bool = False,
    ) -> dict[str, Any] | None:
        """Transition a claim without crashing on a concurrent revocation."""

        try:
            return self._store.fail_claim(
                claim,
                error_code=error_code,
                retry_after_seconds=retry_after_seconds,
                permanent=permanent,
            )
        except (ConsentDeliveryLeaseLost, ConsentDeliveryRevoked):
            result["authorization_invalidated"] += 1
            return None

    def _release_invalidated(
        self,
        result: dict[str, int],
        claim: DeliveryClaim,
    ) -> None:
        try:
            self._store.release_invalidated_claim(claim)
        except (ConsentDeliveryLeaseLost, ConsentDeliveryRevoked):
            pass
        result["authorization_invalidated"] += 1

    def deliver_once(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 60.0,
        destination_ids: tuple[str, ...] | None = None,
    ) -> dict[str, int]:
        """Claim, sign, reauthorize, send, and transition a bounded batch."""

        claims = self._store.claim(
            tenant_id,
            worker_id=worker_id,
            limit=limit,
            lease_seconds=lease_seconds,
            destination_ids=destination_ids,
        )
        result = {
            "claimed": len(claims),
            "delivered": 0,
            "retry_scheduled": 0,
            "dead_lettered": 0,
            "authorization_invalidated": 0,
        }
        for claim in claims:
            try:
                if self._before_effect is not None:
                    self._before_effect(claim)
                request = self._store.build_signed_request(claim, self._signer)
                # A signer may rotate/revoke external custody while it works.
                # Re-check after signing and immediately before transport I/O.
                self._store.authorize_claim(claim)
            except ConsentDeliveryRevoked:
                self._release_invalidated(result, claim)
                continue
            except ConsentDeliveryLeaseLost:
                result["authorization_invalidated"] += 1
                continue
            except ConsentDeliveryConfigError:
                failure = self._record_failure(
                    result,
                    claim,
                    error_code="authentication_rejected",
                    permanent=True,
                )
                if failure is not None:
                    result["dead_lettered"] += int(
                        failure["state"] == "dead_letter"
                    )
                continue
            try:
                self._active_claim = claim
                self._physical_boundary(request)
                response = self._transport.post(
                    request,
                    timeout_seconds=self._timeout,
                    max_response_bytes=self._max_response_bytes,
                )
                if self._before_effect is not None:
                    self._before_effect(claim)
            except (ConsentDeliveryRevoked, ConsentDeliveryLeaseLost):
                self._release_invalidated(result, claim)
                continue
            except Exception:
                failure = self._record_failure(
                    result,
                    claim,
                    error_code="delivery_unconfirmed" if self._hold_unknown else "transport_error",
                    permanent=self._hold_unknown,
                )
                if failure is not None:
                    result["retry_scheduled"] += int(failure["state"] == "queued")
                    result["dead_lettered"] += int(
                        failure["state"] == "dead_letter"
                    )
                continue
            if not isinstance(response, DeliveryResponse):
                failure = self._record_failure(
                    result,
                    claim,
                    error_code="delivery_unconfirmed" if self._hold_unknown else "contract_rejected",
                    permanent=True,
                )
                if failure is not None:
                    result["dead_lettered"] += int(
                        failure["state"] == "dead_letter"
                    )
                continue
            status = response.status_code
            response_sha256 = response.response_sha256 or hashlib.sha256(b"").hexdigest()
            if 200 <= status < 300:
                try:
                    self._store.acknowledge(
                        claim,
                        response_sha256=response_sha256,
                    )
                except (ConsentDeliveryLeaseLost, ConsentDeliveryRevoked):
                    result["authorization_invalidated"] += 1
                else:
                    result["delivered"] += 1
            elif status in {408, 425, 429} or 500 <= status < 600:
                code = "delivery_unconfirmed" if self._hold_unknown else (
                    "rate_limited" if status == 429 else "remote_unavailable")
                failure = self._record_failure(
                    result,
                    claim,
                    error_code=code,
                    retry_after_seconds=response.retry_after_seconds,
                    permanent=self._hold_unknown,
                )
                if failure is not None:
                    result["retry_scheduled"] += int(failure["state"] == "queued")
                    result["dead_lettered"] += int(
                        failure["state"] == "dead_letter"
                    )
            else:
                code = (
                    "authentication_rejected"
                    if status in {401, 403}
                    else "contract_rejected"
                )
                failure = self._record_failure(
                    result,
                    claim,
                    error_code=code,
                    permanent=True,
                )
                if failure is not None:
                    result["dead_lettered"] += int(
                        failure["state"] == "dead_letter"
                    )
        return result
