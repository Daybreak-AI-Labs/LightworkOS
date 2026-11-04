"""Bounded reference clients for machine-authenticated AI discovery sensors.

The server-side control plane admits only a closed, non-identifying
observation. This module supplies two small reference normalizers plus the
exact Ed25519 request-envelope builder used by the external sensor ingress.

Raw host names and OAuth/browser source events are processed transiently. The
returned payload contains a caller-supplied source-event digest and closed
taxonomy codes, never a URL, IP address, user id, account id, token, prompt, or
content body. The module does not claim that these reference clients discover
all AI use in an estate.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from .external_identity import envelope_message

_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\Z")
_SENSOR_ID_RE = re.compile(r"DSN-[0-9a-f]{32}\Z")
_AGENT_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,126}[a-z0-9])?\Z")
_MAX_CONTEXT_CODES = 16
_MAX_BODY_BYTES = 64 * 1024
_DEPLOYMENT_TYPES = frozenset(
    {"embedded", "hosted_api", "managed_cloud", "saas", "self_hosted", "unknown"}
)
_PROHIBITED_TOKENS = frozenset(
    {
        "access_token",
        "browsing_history",
        "content",
        "credential",
        "email",
        "ip",
        "ip_address",
        "password",
        "payload",
        "prompt",
        "raw_url",
        "refresh_token",
        "secret",
        "token",
        "uri",
        "url",
        "user_id",
        "username",
    }
)

# Deliberately closed and conservative. Deployments can inject a reviewed
# replacement mapping; suffix matching is label-boundary aware.
DEFAULT_AI_HOSTS: Mapping[str, tuple[str, str, str]] = {
    "api.anthropic.com": ("anthropic", "claude", "anthropic"),
    "claude.ai": ("anthropic", "claude", "anthropic"),
    "api.openai.com": ("openai", "openai_api", "openai"),
    "chatgpt.com": ("openai", "chatgpt", "openai"),
    "copilot.microsoft.com": ("microsoft", "copilot", "microsoft"),
    "gemini.google.com": ("google", "gemini", "google"),
    "generativelanguage.googleapis.com": ("google", "gemini_api", "google"),
    "huggingface.co": ("hugging_face", "hugging_face_hub", "hugging_face"),
}


class DiscoverySensorClientError(ValueError):
    """A raw event or signing binding is unsafe or malformed."""


class Ed25519RequestSigner(Protocol):
    """Minimal signer interface; private key material stays with the caller."""

    def __call__(self, message: bytes) -> bytes: ...


@dataclass(frozen=True)
class SensorBinding:
    tenant_ref: str
    agent_id: str
    sensor_id: str
    sensor_revision: int
    config_sha256: str


@dataclass(frozen=True)
class NormalizedSensorEvent:
    event_sha256: str
    observed_at: float
    ai_service_code: str
    ai_product_code: str
    provider_code: str
    domain_category: str
    deployment_type: str
    environment_code: str
    context_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SignedObservationRequest:
    path: str
    body: bytes
    headers: Mapping[str, str]


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
        raise DiscoverySensorClientError("sensor request must be finite JSON") from exc
    if len(encoded) > _MAX_BODY_BYTES:
        raise DiscoverySensorClientError("sensor request exceeds the body limit")
    return encoded


def _digest(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(text):
        raise DiscoverySensorClientError(f"{label} must be a SHA-256 digest")
    return text.removeprefix("sha256:")


def _token(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _TOKEN_RE.fullmatch(text) or text in _PROHIBITED_TOKENS:
        raise DiscoverySensorClientError(f"{label} is invalid")
    return text


def _deployment_type(value: object) -> str:
    token = _token(value, "deployment_type")
    if token not in _DEPLOYMENT_TYPES:
        raise DiscoverySensorClientError("deployment_type is invalid")
    return token


def _timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DiscoverySensorClientError("observed_at must be a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise DiscoverySensorClientError("observed_at must be a finite timestamp")
    return result


def _contexts(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)) or len(values) > _MAX_CONTEXT_CODES:
        raise DiscoverySensorClientError("context_codes must be a bounded sequence")
    normalized = tuple(sorted(_token(item, "context_code") for item in values))
    if len(set(normalized)) != len(normalized):
        raise DiscoverySensorClientError("context_codes must not contain duplicates")
    return normalized


def _hostname(value: object) -> str:
    text = str(value or "").strip().rstrip(".").lower()
    if (
        not text
        or len(text) > 253
        or any(char in text for char in "/\\:@?#")
        or any(char.isspace() for char in text)
    ):
        raise DiscoverySensorClientError("hostname must not contain URL or identity data")
    try:
        ascii_host = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DiscoverySensorClientError("hostname is invalid") from exc
    labels = ascii_host.split(".")
    if (
        len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        )
    ):
        raise DiscoverySensorClientError("hostname is invalid")
    return ascii_host


def _validated_hosts(
    values: Mapping[str, tuple[str, str, str]],
) -> tuple[tuple[str, tuple[str, str, str]], ...]:
    if not isinstance(values, Mapping) or not 1 <= len(values) <= 256:
        raise DiscoverySensorClientError("AI host registry must be a bounded mapping")
    rows: list[tuple[str, tuple[str, str, str]]] = []
    for raw_host, raw_codes in values.items():
        host = _hostname(raw_host)
        if not isinstance(raw_codes, tuple) or len(raw_codes) != 3:
            raise DiscoverySensorClientError("AI host registry entry is invalid")
        codes = (
            _token(raw_codes[0], "ai_service_code"),
            _token(raw_codes[1], "ai_product_code"),
            _token(raw_codes[2], "provider_code"),
        )
        rows.append((host, codes))
    return tuple(sorted(rows, key=lambda item: (-len(item[0]), item[0])))


def normalize_network_egress(
    *,
    hostname: str,
    source_event_sha256: str,
    observed_at: float,
    environment_code: str,
    deployment_type: str = "hosted_api",
    context_codes: Sequence[str] = (),
    ai_hosts: Mapping[str, tuple[str, str, str]] = DEFAULT_AI_HOSTS,
) -> NormalizedSensorEvent | None:
    """Normalize one known AI-host egress event; unknown hosts return None."""

    host = _hostname(hostname)
    codes = next(
        (
            value
            for suffix, value in _validated_hosts(ai_hosts)
            if host == suffix or host.endswith("." + suffix)
        ),
        None,
    )
    if codes is None:
        return None
    return NormalizedSensorEvent(
        event_sha256=_digest(source_event_sha256, "source_event_sha256"),
        observed_at=_timestamp(observed_at),
        ai_service_code=codes[0],
        ai_product_code=codes[1],
        provider_code=codes[2],
        domain_category="network_egress",
        deployment_type=_deployment_type(deployment_type),
        environment_code=_token(environment_code, "environment_code"),
        context_codes=_contexts(context_codes),
    )


def normalize_browser_oauth(
    *,
    source_event_sha256: str,
    observed_at: float,
    provider_code: str,
    ai_product_code: str,
    environment_code: str,
    oauth_grant: bool,
    deployment_type: str = "saas",
    context_codes: Sequence[str] = (),
) -> NormalizedSensorEvent:
    """Normalize a browser-origin or OAuth-grant detector's closed event."""

    return NormalizedSensorEvent(
        event_sha256=_digest(source_event_sha256, "source_event_sha256"),
        observed_at=_timestamp(observed_at),
        ai_service_code=_token(provider_code, "provider_code"),
        ai_product_code=_token(ai_product_code, "ai_product_code"),
        provider_code=_token(provider_code, "provider_code"),
        domain_category="oauth_grant" if oauth_grant else "browser_extension",
        deployment_type=_deployment_type(deployment_type),
        environment_code=_token(environment_code, "environment_code"),
        context_codes=_contexts(context_codes),
    )


def normalize_identity_audit(
    *,
    source_event_sha256: str,
    observed_at: float,
    ai_service_code: str,
    ai_product_code: str,
    provider_code: str,
    environment_code: str,
    deployment_type: str = "saas",
    context_codes: Sequence[str] = (),
) -> NormalizedSensorEvent:
    """Normalize one reviewed identity-audit observation.

    Identity-provider audit records (Okta System Log, Entra audit/sign-in, and
    Google Workspace Reports) often contain people, client identifiers, and
    provider-specific payloads. Their adapters must reduce those records to
    this closed event before the durable discovery spool sees them. The
    identity provider is the *source* of the signal, not the reported AI
    provider; callers therefore supply reviewed AI taxonomy codes only.

    This function deliberately has no raw-event parameter. It cannot retain
    or accidentally serialize provider payloads, identities, tokens, URLs, or
    application identifiers.
    """

    return NormalizedSensorEvent(
        event_sha256=_digest(source_event_sha256, "source_event_sha256"),
        observed_at=_timestamp(observed_at),
        ai_service_code=_token(ai_service_code, "ai_service_code"),
        ai_product_code=_token(ai_product_code, "ai_product_code"),
        provider_code=_token(provider_code, "provider_code"),
        domain_category="identity_directory",
        deployment_type=_deployment_type(deployment_type),
        environment_code=_token(environment_code, "environment_code"),
        context_codes=_contexts(context_codes),
    )


class SignedDiscoverySensorClient:
    """Build byte-exact signed requests; sending remains caller-controlled."""

    def __init__(
        self,
        binding: SensorBinding,
        *,
        signer: Ed25519RequestSigner,
        clock: Callable[[], float] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(binding, SensorBinding):
            raise TypeError("binding must be a SensorBinding")
        tenant = str(binding.tenant_ref or "")
        if not tenant or len(tenant.encode("utf-8")) > 256:
            raise DiscoverySensorClientError("tenant_ref is invalid")
        agent_id = str(binding.agent_id or "").strip().lower()
        if not _AGENT_ID_RE.fullmatch(agent_id):
            raise DiscoverySensorClientError("agent_id is invalid")
        if not _SENSOR_ID_RE.fullmatch(str(binding.sensor_id or "")):
            raise DiscoverySensorClientError("sensor_id is invalid")
        if (
            isinstance(binding.sensor_revision, bool)
            or not isinstance(binding.sensor_revision, int)
            or binding.sensor_revision < 1
        ):
            raise DiscoverySensorClientError("sensor_revision is invalid")
        self._binding = SensorBinding(
            tenant_ref=tenant,
            agent_id=agent_id,
            sensor_id=binding.sensor_id,
            sensor_revision=binding.sensor_revision,
            config_sha256=_digest(binding.config_sha256, "config_sha256"),
        )
        if not callable(signer):
            raise TypeError("signer must be callable")
        self._signer = signer
        self._clock = clock or time.time
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(24))

    def build(self, event: NormalizedSensorEvent) -> SignedObservationRequest:
        if not isinstance(event, NormalizedSensorEvent):
            raise TypeError("event must be a NormalizedSensorEvent")
        payload = {
            "tenant_ref": self._binding.tenant_ref,
            "sensor_revision": self._binding.sensor_revision,
            "config_sha256": self._binding.config_sha256,
            "event_sha256": _digest(event.event_sha256, "event_sha256"),
            "observed_at": _timestamp(event.observed_at),
            "ai_service_code": _token(event.ai_service_code, "ai_service_code"),
            "ai_product_code": _token(event.ai_product_code, "ai_product_code"),
            "provider_code": _token(event.provider_code, "provider_code"),
            "domain_category": _token(event.domain_category, "domain_category"),
            "deployment_type": _deployment_type(event.deployment_type),
            "environment_code": _token(event.environment_code, "environment_code"),
            "context_codes": list(_contexts(event.context_codes)),
        }
        body = _canonical(payload)
        timestamp = str(int(float(self._clock())))
        nonce = str(self._nonce_factory() or "")
        if (
            not nonce
            or len(nonce.encode("utf-8", "replace")) > 256
            or any(char.isspace() for char in nonce)
        ):
            raise DiscoverySensorClientError("nonce_factory returned an invalid nonce")
        signature = self._signer(
            envelope_message(self._binding.agent_id, timestamp, nonce, body)
        )
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise DiscoverySensorClientError(
                "signer must return a 64-byte Ed25519 signature"
            )
        return SignedObservationRequest(
            path=(
                "/api/v1/external/discovery-sensors/"
                f"{self._binding.sensor_id}/observations"
            ),
            body=body,
            headers={
                "Content-Type": "application/json",
                "X-Lightwork-Agent-Id": self._binding.agent_id,
                "X-Maverick-Timestamp": timestamp,
                "X-Lightwork-Nonce": nonce,
                "X-Lightwork-Request-Signature": signature.hex(),
            },
        )


def safe_request_digest(request: SignedObservationRequest) -> str:
    """Return a log-safe request digest without exposing body or signature."""

    if not isinstance(request, SignedObservationRequest):
        raise TypeError("request must be a SignedObservationRequest")
    return hashlib.sha256(request.body).hexdigest()


__all__ = [
    "DEFAULT_AI_HOSTS",
    "DiscoverySensorClientError",
    "Ed25519RequestSigner",
    "NormalizedSensorEvent",
    "SensorBinding",
    "SignedDiscoverySensorClient",
    "SignedObservationRequest",
    "normalize_browser_oauth",
    "normalize_identity_audit",
    "normalize_network_egress",
    "safe_request_digest",
]
