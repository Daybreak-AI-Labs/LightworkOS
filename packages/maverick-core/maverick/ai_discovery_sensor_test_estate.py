"""Local, no-network acceptance estate for discovery sensor agents.

The harness exercises the same detached Ed25519 envelope emitted by
``ai_discovery_sensor_agents`` while making no production, customer, or
enterprise-completeness claim.  It is intentionally consent-gated and stores
only the closed normalized observation plus digest-only key-ceremony records.
It is suitable for deterministic retry, recovery, rotation, revocation,
privacy, concurrency, and bounded-scale tests.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from .ai_discovery_sensor_agents import TransportResponse
from .ai_discovery_sensor_clients import SignedObservationRequest
from .external_identity import envelope_message

_SENSOR_ID_RE = re.compile(r"DSN-[0-9a-f]{32}\Z")
_NORMALIZED_REQUEST_FIELDS = frozenset(
    {
        "tenant_ref",
        "sensor_revision",
        "config_sha256",
        "event_sha256",
        "observed_at",
        "ai_service_code",
        "ai_product_code",
        "provider_code",
        "domain_category",
        "deployment_type",
        "environment_code",
        "context_codes",
    }
)
_PROHIBITED_FIELDS = frozenset(
    {
        "access_token",
        "account_id",
        "browser_history",
        "content",
        "cookie",
        "credential",
        "email",
        "hostname",
        "ip",
        "ip_address",
        "password",
        "prompt",
        "raw_event",
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


class ConsentingTestEstateError(ValueError):
    """The local estate definition or lifecycle operation is invalid."""


@dataclass(frozen=True)
class _SensorAuthority:
    agent_id: str
    sensor_id: str
    tenant_ref: str
    sensor_revision: int
    config_sha256: str
    domain_category: str
    active_public_keys: tuple[bytes, ...]
    revoked: bool = False


class ConsentingDiscoveryTestEstate:
    """Thread-safe, in-process signed-ingress acceptance harness."""

    def __init__(
        self,
        *,
        consent_acknowledged: bool,
        consent_reference: str,
        coverage_limitations: tuple[str, ...],
        clock: Callable[[], float] | None = None,
    ) -> None:
        if consent_acknowledged is not True:
            raise ConsentingTestEstateError("test estate requires explicit consent")
        if not isinstance(consent_reference, str) or not consent_reference.strip():
            raise ConsentingTestEstateError("consent_reference is required")
        if not coverage_limitations or any(
            not isinstance(item, str) or not item.strip() for item in coverage_limitations
        ):
            raise ConsentingTestEstateError("coverage_limitations are required")
        self._consent_digest = hashlib.sha256(
            consent_reference.strip().encode("utf-8")
        ).hexdigest()
        self._limitations = tuple(coverage_limitations)
        self._clock = clock or time.time
        self._authorities: dict[str, _SensorAuthority] = {}
        self._nonces: set[tuple[str, str]] = set()
        self._observations: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._ceremony: list[dict[str, Any]] = []
        self._outage_remaining = 0
        self._requests = 0
        self._lock = threading.RLock()

    @staticmethod
    def _public_key_bytes(public_key: object) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if isinstance(public_key, Ed25519PublicKey):
            raw = public_key.public_bytes_raw()
        elif isinstance(public_key, bytes):
            raw = public_key
        else:
            raise ConsentingTestEstateError("public key must be Ed25519 bytes")
        if len(raw) != 32:
            raise ConsentingTestEstateError("public key must be 32 bytes")
        return raw

    def register_sensor(
        self,
        *,
        agent_id: str,
        sensor_id: str,
        tenant_ref: str,
        sensor_revision: int,
        config_sha256: str,
        domain_category: str,
        public_key: object,
    ) -> None:
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ConsentingTestEstateError("agent_id is required")
        if not _SENSOR_ID_RE.fullmatch(str(sensor_id)):
            raise ConsentingTestEstateError("sensor_id is invalid")
        if not isinstance(tenant_ref, str) or not tenant_ref:
            raise ConsentingTestEstateError("tenant_ref is required")
        if (
            isinstance(sensor_revision, bool)
            or not isinstance(sensor_revision, int)
            or sensor_revision < 1
        ):
            raise ConsentingTestEstateError("sensor_revision is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", str(config_sha256)):
            raise ConsentingTestEstateError("config_sha256 is invalid")
        if domain_category not in {"network_egress", "browser_extension", "oauth_grant"}:
            raise ConsentingTestEstateError("domain_category is invalid")
        raw_key = self._public_key_bytes(public_key)
        with self._lock:
            if agent_id in self._authorities:
                raise ConsentingTestEstateError("agent_id is already registered")
            self._authorities[agent_id] = _SensorAuthority(
                agent_id=agent_id,
                sensor_id=sensor_id,
                tenant_ref=tenant_ref,
                sensor_revision=sensor_revision,
                config_sha256=config_sha256,
                domain_category=domain_category,
                active_public_keys=(raw_key,),
            )
            self._record_ceremony("register", agent_id, raw_key)

    def rotate_key(
        self, agent_id: str, public_key: object, *, overlap_previous: bool = False
    ) -> None:
        raw_key = self._public_key_bytes(public_key)
        with self._lock:
            authority = self._authorities.get(agent_id)
            if authority is None:
                raise ConsentingTestEstateError("agent_id is not registered")
            keys = (
                (raw_key, *authority.active_public_keys)
                if overlap_previous
                else (raw_key,)
            )
            self._authorities[agent_id] = replace(
                authority,
                active_public_keys=tuple(dict.fromkeys(keys)),
                revoked=False,
            )
            self._record_ceremony("rotate_overlap" if overlap_previous else "rotate", agent_id, raw_key)

    def retire_previous_keys(self, agent_id: str) -> None:
        with self._lock:
            authority = self._authorities.get(agent_id)
            if authority is None:
                raise ConsentingTestEstateError("agent_id is not registered")
            newest = authority.active_public_keys[:1]
            self._authorities[agent_id] = replace(
                authority, active_public_keys=newest
            )
            self._record_ceremony("retire_previous", agent_id, newest[0])

    def revoke_sensor(self, agent_id: str) -> None:
        with self._lock:
            authority = self._authorities.get(agent_id)
            if authority is None:
                raise ConsentingTestEstateError("agent_id is not registered")
            self._authorities[agent_id] = replace(authority, revoked=True)
            self._record_ceremony("revoke", agent_id, authority.active_public_keys[0])

    def restore_sensor(self, agent_id: str) -> None:
        with self._lock:
            authority = self._authorities.get(agent_id)
            if authority is None:
                raise ConsentingTestEstateError("agent_id is not registered")
            self._authorities[agent_id] = replace(authority, revoked=False)
            self._record_ceremony("restore", agent_id, authority.active_public_keys[0])

    def simulate_outage(self, request_count: int) -> None:
        if isinstance(request_count, bool) or not isinstance(request_count, int) or request_count < 0:
            raise ConsentingTestEstateError("outage request count is invalid")
        with self._lock:
            self._outage_remaining = request_count

    def _record_ceremony(self, action: str, agent_id: str, public_key: bytes) -> None:
        self._ceremony.append(
            {
                "sequence": len(self._ceremony) + 1,
                "action": action,
                "agent_id_sha256": hashlib.sha256(agent_id.encode("utf-8")).hexdigest(),
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "recorded_at": float(self._clock()),
            }
        )

    def send(self, request: SignedObservationRequest) -> TransportResponse:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        with self._lock:
            self._requests += 1
            if self._outage_remaining:
                self._outage_remaining -= 1
                return TransportResponse(503, retry_after_seconds=0.0)
            agent_id = request.headers.get("X-Lightwork-Agent-Id", "")
            authority = self._authorities.get(agent_id)
            if authority is None or authority.revoked:
                return TransportResponse(401)
            if request.path != (
                f"/api/v1/external/discovery-sensors/{authority.sensor_id}/observations"
            ):
                return TransportResponse(403)
            timestamp = request.headers.get("X-Maverick-Timestamp", "")
            nonce = request.headers.get("X-Lightwork-Nonce", "")
            signature_hex = request.headers.get("X-Lightwork-Request-Signature", "")
            try:
                parsed_timestamp = float(timestamp)
                signature = bytes.fromhex(signature_hex)
            except (TypeError, ValueError):
                return TransportResponse(401)
            if (
                not math.isfinite(parsed_timestamp)
                or abs(float(self._clock()) - parsed_timestamp) > 360.0
                or not nonce
                or len(signature) != 64
            ):
                return TransportResponse(401)
            message = envelope_message(agent_id, timestamp, nonce, request.body)
            verified = False
            for raw_key in authority.active_public_keys:
                try:
                    Ed25519PublicKey.from_public_bytes(raw_key).verify(signature, message)
                    verified = True
                    break
                except (InvalidSignature, ValueError):
                    continue
            if not verified or (agent_id, nonce) in self._nonces:
                return TransportResponse(401)
            try:
                payload = json.loads(request.body)
            except (UnicodeError, ValueError):
                return TransportResponse(422)
            if not isinstance(payload, dict) or set(payload) != _NORMALIZED_REQUEST_FIELDS:
                return TransportResponse(422)
            lowered_fields = {str(key).lower() for key in payload}
            if lowered_fields.intersection(_PROHIBITED_FIELDS):
                return TransportResponse(422)
            if (
                payload["tenant_ref"] != authority.tenant_ref
                or payload["sensor_revision"] != authority.sensor_revision
                or payload["config_sha256"] != authority.config_sha256
                or payload["domain_category"] != authority.domain_category
            ):
                return TransportResponse(409)
            self._nonces.add((agent_id, nonce))
            # Idempotency is scoped to the authenticated tenant and sensor.
            # The same source-system digest can legitimately occur in another
            # tenant or sensor and must not collapse across those boundaries.
            observation_key = (
                authority.tenant_ref,
                authority.sensor_id,
                payload["event_sha256"],
            )
            self._observations.setdefault(observation_key, payload)
            return TransportResponse(201)

    def acceptance_report(self) -> dict[str, Any]:
        with self._lock:
            fields: set[str] = set()
            for payload in self._observations.values():
                fields.update(str(key).lower() for key in payload)
            prohibited = tuple(sorted(fields.intersection(_PROHIBITED_FIELDS)))
            return {
                "consent_reference_sha256": self._consent_digest,
                "requests_received": self._requests,
                "unique_observations": len(self._observations),
                "key_ceremony_events": len(self._ceremony),
                "raw_source_persisted": False,
                "prohibited_fields_found": prohibited,
                "privacy_check_passed": not prohibited,
                "coverage_complete": False,
                "coverage_limitations": self._limitations,
            }

    def ceremony_records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(item) for item in self._ceremony)


__all__ = ["ConsentingDiscoveryTestEstate", "ConsentingTestEstateError"]
