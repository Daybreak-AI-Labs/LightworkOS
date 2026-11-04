"""Privacy-preserving control plane for AI discovery sensor observations.

This module governs *ingestion contracts* for independently deployed discovery
sensors.  It does not contain a browser extension, network interceptor, OAuth
crawler, identity connector, data-catalog connector, or SaaS scanner, and it
does not make a complete-discovery claim.

Only an explicitly enabled, tenant-scoped deployment may register sensors.
Sensor configurations require compare-and-swap and approval by a second human.
Configuration changes and revocation requests stop ingestion immediately until
the relevant four-eyes decision is complete.  Approved sensors may submit only
a closed normalized observation containing taxonomy codes, timestamps, and
SHA-256 digests.  There is intentionally no field for URLs, browsing history,
prompts, content, user identities, IP addresses, credentials, access tokens,
secrets, or provider payloads.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

SENSOR_SCHEMA = "lightwork.ai-discovery-sensor.v1"
OBSERVATION_SCHEMA = "lightwork.ai-discovery-observation.v1"
AGGREGATE_SCHEMA = "lightwork.ai-discovery-aggregate.v1"

SENSOR_TYPES = frozenset(
    {
        "browser_extension",
        "network_egress",
        "oauth_grant",
        "saas_posture",
        "identity_directory",
        "data_catalog",
    }
)
DEPLOYMENT_TYPES = frozenset(
    {"embedded", "hosted_api", "managed_cloud", "saas", "self_hosted", "unknown"}
)

DISCOVERY_LIMIT_NOTICE = (
    "Normalized sensor observations only. This output does not establish complete "
    "AI discovery, identify a person, reproduce source activity, or verify a live "
    "provider integration."
)

_SENSORS = GovernedRecordStore(
    "ai_discovery_sensor_identities", "DSN", "ai_discovery_sensor_identity"
)
_OBSERVATIONS = GovernedRecordStore(
    "ai_discovery_sensor_observations", "DSO", "ai_discovery_sensor_observation"
)

_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\Z")
_HUMAN_RE = re.compile(r"user:[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SENSOR_ID_RE = re.compile(r"DSN-[0-9a-f]{32}\Z")
_OBSERVATION_ID_RE = re.compile(r"DSO-[0-9a-f]{32}\Z")

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

_MAX_SENSORS = 2_000
_MAX_OBSERVATIONS = 10_000
_MAX_LIST = 500
_MAX_CONTEXT_CODES = 16
_MAX_AGGREGATE_FINDINGS = 1_000
_MAX_JSON_BYTES = 64 * 1024
_MAX_FUTURE_SKEW_SECONDS = 300
_MIN_TTL_SECONDS = 300
_MAX_TTL_SECONDS = 90 * 24 * 60 * 60

_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_SENSOR_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "sensor_name",
        "sensor_type",
        "configuration",
        "status",
        "revocation",
        "registration_sha256",
        "state_sha256",
    }
)
_CONFIGURATION_FIELDS = frozenset(
    {
        "sensor_revision",
        "config_sha256",
        "prepared_by",
        "prepared_at",
        "approval",
    }
)
_APPROVAL_FIELDS = frozenset(
    {"approved_by", "approved_at", "sensor_revision", "config_sha256"}
)
_REVOCATION_FIELDS = frozenset(
    {"reason_code", "requested_by", "requested_at", "approval"}
)
_REVOCATION_APPROVAL_FIELDS = frozenset({"approved_by", "approved_at"})
_OBSERVATION_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "sensor_binding",
        "event_sha256",
        "observed_at",
        "expires_at",
        "normalized",
        "payload_sha256",
        "received_at",
        "state_sha256",
    }
)
_SENSOR_BINDING_FIELDS = frozenset(
    {"sensor_id", "sensor_revision", "config_sha256", "sensor_type"}
)
_NORMALIZED_FIELDS = frozenset(
    {
        "ai_service_code",
        "ai_product_code",
        "provider_code",
        "domain_category",
        "deployment_type",
        "environment_code",
        "context_codes",
    }
)


class AIDiscoverySensorsError(RuntimeError):
    """Base error for the discovery-sensor control plane."""


class AIDiscoverySensorsConfigError(AIDiscoverySensorsError):
    """The default-off feature is unavailable."""


class AIDiscoverySensorsStateError(AIDiscoverySensorsError):
    """Persisted state is malformed, inconsistent, or over its bound."""


class AIDiscoverySensorsApprovalError(AIDiscoverySensorsError):
    """A four-eyes sensor lifecycle decision is invalid."""


class AIDiscoverySensorsBindingError(AIDiscoverySensorsError):
    """An observation is not bound to the exact approved sensor authority."""


class AIDiscoverySensorsIdempotencyConflict(AIDiscoverySensorsError):
    """A stable identity or event digest was reused with different content."""


@dataclass(frozen=True)
class SensorActor:
    """Authenticated human principal for sensor lifecycle mutations."""

    principal: str


@dataclass(frozen=True)
class NormalizedDiscoveryObservation:
    """Closed, non-identifying observation accepted from an approved sensor."""

    event_sha256: str
    observed_at: float
    ai_service_code: str
    ai_product_code: str
    provider_code: str
    domain_category: str
    deployment_type: str
    environment_code: str
    context_codes: Sequence[str] = ()


def enabled() -> bool:
    """Return true only for explicit ``[ai_discovery_sensors] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_discovery_sensors")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise AIDiscoverySensorsConfigError(
            "AI discovery sensors are disabled; set "
            "[ai_discovery_sensors] enable = true"
        )


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
        raise ValueError("discovery-sensor data must be finite JSON") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("discovery-sensor data exceeds the 64 KiB bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value.strip()):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value.strip().lower().removeprefix("sha256:")


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a finite non-negative timestamp")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{label} must be a finite non-negative timestamp")
    return parsed


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an opaque lowercase taxonomy code")
    token = value.strip()
    if not _TOKEN_RE.fullmatch(token) or token in _PROHIBITED_TOKENS:
        raise ValueError(f"{label} must be a non-sensitive opaque lowercase taxonomy code")
    return token


def _human(actor: SensorActor) -> str:
    if not isinstance(actor, SensorActor):
        raise TypeError("actor must be a SensorActor")
    principal = actor.principal.strip() if isinstance(actor.principal, str) else ""
    if not _HUMAN_RE.fullmatch(principal):
        raise ValueError("sensor lifecycle actor must be an authenticated user principal")
    return principal


def _sensor_type(value: object) -> str:
    parsed = _token(value, "sensor_type")
    if parsed not in SENSOR_TYPES:
        raise ValueError("sensor_type is not supported")
    return parsed


def _deployment_type(value: object) -> str:
    parsed = _token(value, "deployment_type")
    if parsed not in DEPLOYMENT_TYPES:
        raise ValueError("deployment_type is not supported")
    return parsed


def _closed(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} must use the closed schema")
    return value


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise AIDiscoverySensorsStateError(
            "AI discovery sensor operations require an explicit tenant"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _sensor_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(record[key]) for key in sorted(_SENSOR_FIELDS - {"state_sha256"})}


def _observation_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(record[key])
        for key in sorted(_OBSERVATION_FIELDS - {"state_sha256"})
    }


def _record_body(
    value: Mapping[str, Any], fields: frozenset[str], label: str
) -> Mapping[str, Any]:
    unknown = set(value) - fields - _STORE_METADATA
    missing = fields - set(value)
    if unknown or missing:
        raise AIDiscoverySensorsStateError(f"persisted {label} uses an invalid schema")
    return value


def _validated_configuration(value: object) -> dict[str, Any]:
    configuration = dict(_closed(value, _CONFIGURATION_FIELDS, "configuration"))
    sensor_revision = _positive_integer(
        configuration["sensor_revision"], "sensor_revision"
    )
    config_digest = _digest(configuration["config_sha256"], "config_sha256")
    prepared_by = _human(SensorActor(str(configuration["prepared_by"])))
    prepared_at = _timestamp(configuration["prepared_at"], "prepared_at")
    approval_value = configuration["approval"]
    approval: dict[str, Any] | None = None
    if approval_value is not None:
        approval = dict(_closed(approval_value, _APPROVAL_FIELDS, "approval"))
        approval["approved_by"] = _human(SensorActor(str(approval["approved_by"])))
        approval["approved_at"] = _timestamp(approval["approved_at"], "approved_at")
        approval["sensor_revision"] = _positive_integer(
            approval["sensor_revision"], "approved sensor_revision"
        )
        approval["config_sha256"] = _digest(
            approval["config_sha256"], "approved config_sha256"
        )
        if approval["approved_by"] == prepared_by:
            raise ValueError("sensor approval violates four-eyes")
        if approval["approved_at"] < prepared_at:
            raise ValueError("sensor approval predates its preparation")
        if (
            approval["sensor_revision"] != sensor_revision
            or approval["config_sha256"] != config_digest
        ):
            raise ValueError("sensor approval is stale")
    configuration.update(
        {
            "sensor_revision": sensor_revision,
            "config_sha256": config_digest,
            "prepared_by": prepared_by,
            "prepared_at": prepared_at,
            "approval": approval,
        }
    )
    return configuration


def _validated_revocation(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    revocation = dict(_closed(value, _REVOCATION_FIELDS, "revocation"))
    revocation["reason_code"] = _token(
        revocation["reason_code"], "revocation reason_code"
    )
    revocation["requested_by"] = _human(
        SensorActor(str(revocation["requested_by"]))
    )
    revocation["requested_at"] = _timestamp(
        revocation["requested_at"], "revocation requested_at"
    )
    approval_value = revocation["approval"]
    approval: dict[str, Any] | None = None
    if approval_value is not None:
        approval = dict(
            _closed(
                approval_value,
                _REVOCATION_APPROVAL_FIELDS,
                "revocation approval",
            )
        )
        approval["approved_by"] = _human(SensorActor(str(approval["approved_by"])))
        approval["approved_at"] = _timestamp(
            approval["approved_at"], "revocation approved_at"
        )
        if approval["approved_by"] == revocation["requested_by"]:
            raise ValueError("sensor revocation violates four-eyes")
        if approval["approved_at"] < revocation["requested_at"]:
            raise ValueError("sensor revocation approval predates its request")
    revocation["approval"] = approval
    return revocation


def _validate_sensor(record: object, *, tenant_ref: str) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise AIDiscoverySensorsStateError("persisted sensor is not an object")
    row = dict(_record_body(record, _SENSOR_FIELDS, "sensor"))
    try:
        if row["schema"] != SENSOR_SCHEMA or row["tenant_ref"] != tenant_ref:
            raise ValueError("sensor authority changed")
        sensor_id = str(row["id"])
        if not _SENSOR_ID_RE.fullmatch(sensor_id):
            raise ValueError("sensor id is invalid")
        name = _token(row["sensor_name"], "sensor_name")
        kind = _sensor_type(row["sensor_type"])
        configuration = _validated_configuration(row["configuration"])
        approval = configuration["approval"]
        status = row["status"]
        if status not in {"pending_approval", "active", "revocation_pending", "revoked"}:
            raise ValueError("sensor status is invalid")
        revocation = _validated_revocation(row["revocation"])
        if status == "active" and (approval is None or revocation is not None):
            raise ValueError("active sensor authority is incomplete")
        if status == "pending_approval" and (approval is not None or revocation is not None):
            raise ValueError("pending sensor state is inconsistent")
        if status == "revocation_pending" and (
            approval is None or revocation is None or revocation["approval"] is not None
        ):
            raise ValueError("pending revocation state is inconsistent")
        if status == "revoked" and (
            approval is None or revocation is None or revocation["approval"] is None
        ):
            raise ValueError("revoked sensor state is inconsistent")
        registration_sha = _digest(
            row["registration_sha256"], "registration_sha256"
        )
        state_sha = _digest(row["state_sha256"], "state_sha256")
        expected_id = "DSN-" + _sha256(
            {"tenant_ref": tenant_ref, "sensor_type": kind, "sensor_name": name}
        )[:32]
        if sensor_id != expected_id:
            raise ValueError("sensor identity digest does not match")
        if registration_sha != _sha256(
            {"tenant_ref": tenant_ref, "sensor_type": kind, "sensor_name": name}
        ):
            raise ValueError("sensor registration digest does not match")
        row.update(
            {
                "sensor_name": name,
                "sensor_type": kind,
                "configuration": configuration,
                "status": status,
                "revocation": revocation,
                "registration_sha256": registration_sha,
            }
        )
        if state_sha != _sha256(_sensor_state(row)):
            raise ValueError("sensor state digest does not match")
    except (KeyError, TypeError, ValueError) as exc:
        raise AIDiscoverySensorsStateError("persisted sensor state is invalid") from exc
    return row


def _validate_normalized(value: object) -> dict[str, Any]:
    row = dict(_closed(value, _NORMALIZED_FIELDS, "normalized observation"))
    row["ai_service_code"] = _token(row["ai_service_code"], "ai_service_code")
    row["ai_product_code"] = _token(row["ai_product_code"], "ai_product_code")
    row["provider_code"] = _token(row["provider_code"], "provider_code")
    row["domain_category"] = _token(row["domain_category"], "domain_category")
    row["deployment_type"] = _deployment_type(row["deployment_type"])
    row["environment_code"] = _token(row["environment_code"], "environment_code")
    contexts = row["context_codes"]
    if (
        not isinstance(contexts, Sequence)
        or isinstance(contexts, (str, bytes, bytearray))
        or len(contexts) > _MAX_CONTEXT_CODES
    ):
        raise ValueError("context_codes must be a bounded list")
    normalized_contexts = [_token(item, "context_code") for item in contexts]
    if len(set(normalized_contexts)) != len(normalized_contexts):
        raise ValueError("context_codes must not contain duplicates")
    row["context_codes"] = sorted(normalized_contexts)
    return row


def _validate_observation(record: object, *, tenant_ref: str) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise AIDiscoverySensorsStateError("persisted observation is not an object")
    row = dict(_record_body(record, _OBSERVATION_FIELDS, "observation"))
    try:
        if row["schema"] != OBSERVATION_SCHEMA or row["tenant_ref"] != tenant_ref:
            raise ValueError("observation authority changed")
        observation_id = str(row["id"])
        if not _OBSERVATION_ID_RE.fullmatch(observation_id):
            raise ValueError("observation id is invalid")
        binding = dict(
            _closed(row["sensor_binding"], _SENSOR_BINDING_FIELDS, "sensor_binding")
        )
        if not _SENSOR_ID_RE.fullmatch(str(binding["sensor_id"])):
            raise ValueError("bound sensor id is invalid")
        binding["sensor_revision"] = _positive_integer(
            binding["sensor_revision"], "bound sensor_revision"
        )
        binding["config_sha256"] = _digest(
            binding["config_sha256"], "bound config_sha256"
        )
        binding["sensor_type"] = _sensor_type(binding["sensor_type"])
        event_sha = _digest(row["event_sha256"], "event_sha256")
        observed_at = _timestamp(row["observed_at"], "observed_at")
        expires_at = _timestamp(row["expires_at"], "expires_at")
        received_at = _timestamp(row["received_at"], "received_at")
        if expires_at <= observed_at:
            raise ValueError("observation expiry is invalid")
        validity_float = expires_at - observed_at
        validity = int(round(validity_float))
        if (
            abs(validity_float - validity) > 1e-6
            or not _MIN_TTL_SECONDS <= validity <= _MAX_TTL_SECONDS
        ):
            raise ValueError("observation TTL is outside the governed bound")
        normalized = _validate_normalized(row["normalized"])
        payload_sha = _digest(row["payload_sha256"], "payload_sha256")
        state_sha = _digest(row["state_sha256"], "state_sha256")
        payload = {
            "schema": OBSERVATION_SCHEMA,
            "tenant_ref": tenant_ref,
            "sensor_binding": binding,
            "event_sha256": event_sha,
            "observed_at": observed_at,
            "expires_at": expires_at,
            "normalized": normalized,
        }
        if payload_sha != _sha256(payload):
            raise ValueError("observation payload digest does not match")
        expected_id = "DSO-" + _sha256(
            {"sensor_id": binding["sensor_id"], "event_sha256": event_sha}
        )[:32]
        if observation_id != expected_id:
            raise ValueError("observation identity digest does not match")
        row.update(
            {
                "sensor_binding": binding,
                "event_sha256": event_sha,
                "observed_at": observed_at,
                "expires_at": expires_at,
                "normalized": normalized,
                "payload_sha256": payload_sha,
                "received_at": received_at,
            }
        )
        if state_sha != _sha256(_observation_state(row)):
            raise ValueError("observation state digest does not match")
    except (KeyError, TypeError, ValueError) as exc:
        raise AIDiscoverySensorsStateError(
            "persisted discovery observation is invalid"
        ) from exc
    return row


def _sensor_public(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sensor_id": row["id"],
        "sensor_name": row["sensor_name"],
        "sensor_type": row["sensor_type"],
        "status": row["status"],
        "sensor_revision": row["configuration"]["sensor_revision"],
        "config_sha256": row["configuration"]["config_sha256"],
        "prepared_by": row["configuration"]["prepared_by"],
        "prepared_at": row["configuration"]["prepared_at"],
        "approved_by": (
            row["configuration"]["approval"]["approved_by"]
            if row["configuration"]["approval"] is not None
            else None
        ),
        "revocation": copy.deepcopy(row["revocation"]),
        "revision": row["revision"],
    }


class DiscoverySensorService:
    """Govern sensor identities and admit privacy-safe normalized observations."""

    def __init__(
        self,
        *,
        sensors: GovernedRecordStore | None = None,
        observations: GovernedRecordStore | None = None,
        clock: Callable[[], float] | None = None,
        observation_ttl_seconds: int = 30 * 24 * 60 * 60,
        enforce_feature: bool = True,
    ) -> None:
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        if isinstance(observation_ttl_seconds, bool) or not isinstance(
            observation_ttl_seconds, int
        ):
            raise ValueError("observation_ttl_seconds must be an integer")
        if not _MIN_TTL_SECONDS <= observation_ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError(
                f"observation_ttl_seconds must be {_MIN_TTL_SECONDS} through "
                f"{_MAX_TTL_SECONDS}"
            )
        if not isinstance(enforce_feature, bool):
            raise ValueError("enforce_feature must be a boolean")
        self._sensors = sensors or _SENSORS
        self._observations = observations or _OBSERVATIONS
        self._clock = clock
        self._ttl = observation_ttl_seconds
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        if self._sensors.backend_kind != self._observations.backend_kind:
            raise AIDiscoverySensorsStateError(
                "sensor identities and observations use different backends"
            )
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._observations.authoritative_time
        return _timestamp(source(), "authority time")

    def _bounded_sensors(self, tenant_ref: str) -> list[dict[str, Any]]:
        rows = self._sensors.list(limit=_MAX_SENSORS + 1)
        if len(rows) > _MAX_SENSORS:
            raise AIDiscoverySensorsStateError("sensor namespace exceeds its bound")
        return [_validate_sensor(row, tenant_ref=tenant_ref) for row in rows]

    def _bounded_observations(self, tenant_ref: str) -> list[dict[str, Any]]:
        rows = self._observations.list(limit=_MAX_OBSERVATIONS + 1)
        if len(rows) > _MAX_OBSERVATIONS:
            raise AIDiscoverySensorsStateError("observation namespace exceeds its bound")
        return [_validate_observation(row, tenant_ref=tenant_ref) for row in rows]

    def register_sensor(
        self,
        *,
        sensor_name: str,
        sensor_type: str,
        config_sha256: str,
        actor: SensorActor,
    ) -> dict[str, Any]:
        """Register one stable named identity in pending-approval state."""

        tenant_ref = self._require_active()
        name = _token(sensor_name, "sensor_name")
        kind = _sensor_type(sensor_type)
        config_digest = _digest(config_sha256, "config_sha256")
        principal = _human(actor)
        now = self._now()
        registration = {
            "tenant_ref": tenant_ref,
            "sensor_type": kind,
            "sensor_name": name,
        }
        registration_sha = _sha256(registration)
        sensor_id = "DSN-" + registration_sha[:32]
        existing = self._sensors.get(sensor_id)
        if existing is not None:
            current = _validate_sensor(existing, tenant_ref=tenant_ref)
            if current["configuration"]["config_sha256"] != config_digest:
                raise AIDiscoverySensorsIdempotencyConflict(
                    "sensor identity is already registered with different configuration"
                )
            return _sensor_public(current)
        record: dict[str, Any] = {
            "id": sensor_id,
            "schema": SENSOR_SCHEMA,
            "tenant_ref": tenant_ref,
            "sensor_name": name,
            "sensor_type": kind,
            "configuration": {
                "sensor_revision": 1,
                "config_sha256": config_digest,
                "prepared_by": principal,
                "prepared_at": now,
                "approval": None,
            },
            "status": "pending_approval",
            "revocation": None,
            "registration_sha256": registration_sha,
        }
        record["state_sha256"] = _sha256(_sensor_state(record))
        try:
            saved = self._sensors.create(
                record,
                action="register_ai_discovery_sensor",
                actor=principal,
                max_records=_MAX_SENSORS,
            )
        except RecordConflict as exc:
            concurrent = self._sensors.get(sensor_id)
            if concurrent is None:
                raise
            current = _validate_sensor(concurrent, tenant_ref=tenant_ref)
            if current["configuration"]["config_sha256"] != config_digest:
                raise AIDiscoverySensorsIdempotencyConflict(
                    "sensor identity was concurrently registered differently"
                ) from exc
            saved = current
        return _sensor_public(_validate_sensor(saved, tenant_ref=tenant_ref))

    def approve_sensor(
        self, sensor_id: str, *, expected_revision: int, actor: SensorActor
    ) -> dict[str, Any]:
        """Four-eyes approve the current pending sensor configuration."""

        tenant_ref = self._require_active()
        identity = str(sensor_id or "")
        if not _SENSOR_ID_RE.fullmatch(identity):
            raise ValueError("sensor_id is invalid")
        expected = _positive_integer(expected_revision, "expected_revision")
        principal = _human(actor)
        current = self._sensors.get(identity)
        if current is None:
            raise AIDiscoverySensorsStateError("sensor does not exist")
        validated = _validate_sensor(current, tenant_ref=tenant_ref)
        if validated["status"] != "pending_approval":
            raise AIDiscoverySensorsApprovalError("sensor is not pending approval")
        if validated["configuration"]["prepared_by"] == principal:
            raise AIDiscoverySensorsApprovalError(
                "sensor approval requires a different human than the preparer"
            )
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            configuration = row["configuration"]
            configuration["approval"] = {
                "approved_by": principal,
                "approved_at": now,
                "sensor_revision": configuration["sensor_revision"],
                "config_sha256": configuration["config_sha256"],
            }
            row["status"] = "active"
            row["state_sha256"] = _sha256(_sensor_state(row))

        saved = self._sensors.update(
            identity,
            mutate,
            expected_revision=expected,
            action="approve_ai_discovery_sensor",
            actor=principal,
        )
        if saved is None:
            raise AIDiscoverySensorsStateError("sensor disappeared")
        return _sensor_public(_validate_sensor(saved, tenant_ref=tenant_ref))

    def prepare_sensor_configuration(
        self,
        sensor_id: str,
        *,
        config_sha256: str,
        expected_revision: int,
        actor: SensorActor,
    ) -> dict[str, Any]:
        """CAS-stage a new configuration; ingestion stops until approval."""

        tenant_ref = self._require_active()
        identity = str(sensor_id or "")
        if not _SENSOR_ID_RE.fullmatch(identity):
            raise ValueError("sensor_id is invalid")
        digest = _digest(config_sha256, "config_sha256")
        expected = _positive_integer(expected_revision, "expected_revision")
        principal = _human(actor)
        current = self._sensors.get(identity)
        if current is None:
            raise AIDiscoverySensorsStateError("sensor does not exist")
        validated = _validate_sensor(current, tenant_ref=tenant_ref)
        if validated["status"] != "active":
            raise AIDiscoverySensorsStateError("only an active sensor can be updated")
        if validated["configuration"]["config_sha256"] == digest:
            raise ValueError("new sensor configuration must change its digest")
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            row["configuration"] = {
                "sensor_revision": row["configuration"]["sensor_revision"] + 1,
                "config_sha256": digest,
                "prepared_by": principal,
                "prepared_at": now,
                "approval": None,
            }
            row["status"] = "pending_approval"
            row["state_sha256"] = _sha256(_sensor_state(row))

        saved = self._sensors.update(
            identity,
            mutate,
            expected_revision=expected,
            action="prepare_ai_discovery_sensor_configuration",
            actor=principal,
        )
        if saved is None:
            raise AIDiscoverySensorsStateError("sensor disappeared")
        return _sensor_public(_validate_sensor(saved, tenant_ref=tenant_ref))

    def request_sensor_revocation(
        self,
        sensor_id: str,
        *,
        reason_code: str,
        expected_revision: int,
        actor: SensorActor,
    ) -> dict[str, Any]:
        """Immediately stop ingestion and stage a four-eyes revocation."""

        tenant_ref = self._require_active()
        identity = str(sensor_id or "")
        if not _SENSOR_ID_RE.fullmatch(identity):
            raise ValueError("sensor_id is invalid")
        reason = _token(reason_code, "reason_code")
        expected = _positive_integer(expected_revision, "expected_revision")
        principal = _human(actor)
        current = self._sensors.get(identity)
        if current is None:
            raise AIDiscoverySensorsStateError("sensor does not exist")
        validated = _validate_sensor(current, tenant_ref=tenant_ref)
        if validated["status"] != "active":
            raise AIDiscoverySensorsStateError("only an active sensor can be revoked")
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            row["status"] = "revocation_pending"
            row["revocation"] = {
                "reason_code": reason,
                "requested_by": principal,
                "requested_at": now,
                "approval": None,
            }
            row["state_sha256"] = _sha256(_sensor_state(row))

        saved = self._sensors.update(
            identity,
            mutate,
            expected_revision=expected,
            action="request_ai_discovery_sensor_revocation",
            actor=principal,
        )
        if saved is None:
            raise AIDiscoverySensorsStateError("sensor disappeared")
        return _sensor_public(_validate_sensor(saved, tenant_ref=tenant_ref))

    def approve_sensor_revocation(
        self, sensor_id: str, *, expected_revision: int, actor: SensorActor
    ) -> dict[str, Any]:
        """Four-eyes approve a pending sensor revocation."""

        tenant_ref = self._require_active()
        identity = str(sensor_id or "")
        if not _SENSOR_ID_RE.fullmatch(identity):
            raise ValueError("sensor_id is invalid")
        expected = _positive_integer(expected_revision, "expected_revision")
        principal = _human(actor)
        current = self._sensors.get(identity)
        if current is None:
            raise AIDiscoverySensorsStateError("sensor does not exist")
        validated = _validate_sensor(current, tenant_ref=tenant_ref)
        if validated["status"] != "revocation_pending":
            raise AIDiscoverySensorsApprovalError("sensor revocation is not pending")
        if validated["revocation"]["requested_by"] == principal:
            raise AIDiscoverySensorsApprovalError(
                "sensor revocation approval requires a different human"
            )
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            row["revocation"]["approval"] = {
                "approved_by": principal,
                "approved_at": now,
            }
            row["status"] = "revoked"
            row["state_sha256"] = _sha256(_sensor_state(row))

        saved = self._sensors.update(
            identity,
            mutate,
            expected_revision=expected,
            action="approve_ai_discovery_sensor_revocation",
            actor=principal,
        )
        if saved is None:
            raise AIDiscoverySensorsStateError("sensor disappeared")
        return _sensor_public(_validate_sensor(saved, tenant_ref=tenant_ref))

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        identity = str(sensor_id or "")
        if not _SENSOR_ID_RE.fullmatch(identity):
            raise ValueError("sensor_id is invalid")
        row = self._sensors.get(identity)
        return None if row is None else _sensor_public(_validate_sensor(row, tenant_ref=tenant_ref))

    def list_sensors(self, *, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
        rows = self._bounded_sensors(tenant_ref)
        return [_sensor_public(row) for row in sorted(rows, key=lambda item: item["id"])[:limit]]

    def ingest_observation(
        self,
        sensor_id: str,
        *,
        sensor_revision: int,
        config_sha256: str,
        observation: NormalizedDiscoveryObservation,
    ) -> dict[str, Any]:
        """Idempotently ingest one exact closed observation from an approved sensor."""

        if not isinstance(observation, NormalizedDiscoveryObservation):
            raise TypeError("observation must be a NormalizedDiscoveryObservation")
        tenant_ref = self._require_active()
        identity = str(sensor_id or "")
        if not _SENSOR_ID_RE.fullmatch(identity):
            raise ValueError("sensor_id is invalid")
        revision = _positive_integer(sensor_revision, "sensor_revision")
        config_digest = _digest(config_sha256, "config_sha256")
        sensor_row = self._sensors.get(identity)
        if sensor_row is None:
            raise AIDiscoverySensorsBindingError("sensor does not exist")
        sensor = _validate_sensor(sensor_row, tenant_ref=tenant_ref)
        if sensor["status"] != "active":
            raise AIDiscoverySensorsBindingError("sensor is not currently approved")
        configuration = sensor["configuration"]
        if (
            configuration["approval"] is None
            or configuration["sensor_revision"] != revision
            or configuration["config_sha256"] != config_digest
        ):
            raise AIDiscoverySensorsBindingError(
                "observation does not match the exact approved sensor configuration"
            )
        now = self._now()
        observed_at = _timestamp(observation.observed_at, "observed_at")
        if observed_at > now + _MAX_FUTURE_SKEW_SECONDS:
            raise ValueError("observed_at is too far in the future")
        event_sha = _digest(observation.event_sha256, "event_sha256")
        normalized = _validate_normalized(
            {
                "ai_service_code": observation.ai_service_code,
                "ai_product_code": observation.ai_product_code,
                "provider_code": observation.provider_code,
                "domain_category": observation.domain_category,
                "deployment_type": observation.deployment_type,
                "environment_code": observation.environment_code,
                "context_codes": observation.context_codes,
            }
        )
        binding = {
            "sensor_id": identity,
            "sensor_revision": revision,
            "config_sha256": config_digest,
            "sensor_type": sensor["sensor_type"],
        }
        payload = {
            "schema": OBSERVATION_SCHEMA,
            "tenant_ref": tenant_ref,
            "sensor_binding": binding,
            "event_sha256": event_sha,
            "observed_at": observed_at,
            "expires_at": observed_at + self._ttl,
            "normalized": normalized,
        }
        payload_sha = _sha256(payload)
        observation_id = "DSO-" + _sha256(
            {"sensor_id": identity, "event_sha256": event_sha}
        )[:32]
        existing = self._observations.get(observation_id)
        if existing is not None:
            current = _validate_observation(existing, tenant_ref=tenant_ref)
            if current["payload_sha256"] != payload_sha:
                raise AIDiscoverySensorsIdempotencyConflict(
                    "event digest was already used for a different observation"
                )
            return self._observation_public(current, sensor=sensor, now=now)
        record: dict[str, Any] = {
            "id": observation_id,
            **payload,
            "payload_sha256": payload_sha,
            "received_at": now,
        }
        record["state_sha256"] = _sha256(_observation_state(record))
        try:
            saved = self._observations.create(
                record,
                action="ingest_ai_discovery_observation",
                actor=identity,
                max_records=_MAX_OBSERVATIONS,
            )
        except RecordConflict as exc:
            concurrent = self._observations.get(observation_id)
            if concurrent is None:
                raise
            current = _validate_observation(concurrent, tenant_ref=tenant_ref)
            if current["payload_sha256"] != payload_sha:
                raise AIDiscoverySensorsIdempotencyConflict(
                    "event digest was concurrently reused differently"
                ) from exc
            saved = current
        return self._observation_public(
            _validate_observation(saved, tenant_ref=tenant_ref), sensor=sensor, now=now
        )

    @staticmethod
    def _observation_public(
        row: Mapping[str, Any], *, sensor: Mapping[str, Any] | None, now: float
    ) -> dict[str, Any]:
        reasons: list[str] = []
        if now > row["expires_at"]:
            reasons.append("observation_expired")
        if sensor is None:
            reasons.append("sensor_unavailable")
        else:
            binding = row["sensor_binding"]
            if sensor["status"] != "active":
                reasons.append("sensor_not_active")
            configuration = sensor["configuration"]
            if (
                binding["sensor_revision"] != configuration["sensor_revision"]
                or binding["config_sha256"] != configuration["config_sha256"]
            ):
                reasons.append("sensor_authority_changed")
        return {
            "observation_id": row["id"],
            "sensor_binding": copy.deepcopy(row["sensor_binding"]),
            "event_sha256": row["event_sha256"],
            "observed_at": row["observed_at"],
            "expires_at": row["expires_at"],
            "normalized": copy.deepcopy(row["normalized"]),
            "payload_sha256": row["payload_sha256"],
            "current": not reasons,
            "stale_reasons": reasons,
            "revision": row["revision"],
            "notice": DISCOVERY_LIMIT_NOTICE,
        }

    def get_observation(self, observation_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        identity = str(observation_id or "")
        if not _OBSERVATION_ID_RE.fullmatch(identity):
            raise ValueError("observation_id is invalid")
        row = self._observations.get(identity)
        if row is None:
            return None
        observation = _validate_observation(row, tenant_ref=tenant_ref)
        sensor_row = self._sensors.get(observation["sensor_binding"]["sensor_id"])
        sensor = (
            None
            if sensor_row is None
            else _validate_sensor(sensor_row, tenant_ref=tenant_ref)
        )
        return self._observation_public(observation, sensor=sensor, now=self._now())

    def list_observations(self, *, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
        sensors = {row["id"]: row for row in self._bounded_sensors(tenant_ref)}
        now = self._now()
        rows = sorted(
            self._bounded_observations(tenant_ref),
            key=lambda item: (item["observed_at"], item["id"]),
            reverse=True,
        )[:limit]
        return [
            self._observation_public(
                row, sensor=sensors.get(row["sensor_binding"]["sensor_id"]), now=now
            )
            for row in rows
        ]

    def aggregate_findings(self) -> dict[str, Any]:
        """Return bounded non-identifying counts for later inventory reconciliation."""

        tenant_ref = self._require_active()
        sensors = {row["id"]: row for row in self._bounded_sensors(tenant_ref)}
        observations = self._bounded_observations(tenant_ref)
        now = self._now()
        grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
        current_sensor_types: set[str] = set()
        stale_count = 0
        for row in observations:
            sensor = sensors.get(row["sensor_binding"]["sensor_id"])
            projected = self._observation_public(row, sensor=sensor, now=now)
            if not projected["current"]:
                stale_count += 1
                continue
            normalized = row["normalized"]
            current_sensor_types.add(row["sensor_binding"]["sensor_type"])
            key = (
                normalized["ai_service_code"],
                normalized["ai_product_code"],
                normalized["provider_code"],
                normalized["domain_category"],
                normalized["deployment_type"],
                normalized["environment_code"],
                tuple(normalized["context_codes"]),
            )
            finding = grouped.setdefault(
                key,
                {
                    "ai_service_code": key[0],
                    "ai_product_code": key[1],
                    "provider_code": key[2],
                    "domain_category": key[3],
                    "deployment_type": key[4],
                    "environment_code": key[5],
                    "context_codes": list(key[6]),
                    "current_observation_count": 0,
                    "first_observed_at": row["observed_at"],
                    "last_observed_at": row["observed_at"],
                    "sensor_types": set(),
                },
            )
            finding["current_observation_count"] += 1
            finding["first_observed_at"] = min(
                finding["first_observed_at"], row["observed_at"]
            )
            finding["last_observed_at"] = max(
                finding["last_observed_at"], row["observed_at"]
            )
            finding["sensor_types"].add(row["sensor_binding"]["sensor_type"])
        if len(grouped) > _MAX_AGGREGATE_FINDINGS:
            raise AIDiscoverySensorsStateError("aggregate finding bound exceeded")
        findings: list[dict[str, Any]] = []
        for key in sorted(grouped):
            finding = grouped[key]
            finding["sensor_types"] = sorted(finding["sensor_types"])
            finding["finding_sha256"] = _sha256(finding)
            findings.append(finding)
        return {
            "schema": AGGREGATE_SCHEMA,
            "generated_at": now,
            "findings": findings,
            "current_observation_count": sum(
                item["current_observation_count"] for item in findings
            ),
            "stale_observation_count": stale_count,
            "observed_sensor_types": sorted(current_sensor_types),
            "supported_sensor_types": sorted(SENSOR_TYPES),
            "complete_discovery_assessed": False,
            "identifies_people": False,
            "notice": DISCOVERY_LIMIT_NOTICE,
        }


def default_service() -> DiscoverySensorService:
    """Return the process-default governed discovery-sensor service."""

    return DiscoverySensorService()


__all__ = [
    "AGGREGATE_SCHEMA",
    "AIDiscoverySensorsApprovalError",
    "AIDiscoverySensorsBindingError",
    "AIDiscoverySensorsConfigError",
    "AIDiscoverySensorsError",
    "AIDiscoverySensorsIdempotencyConflict",
    "AIDiscoverySensorsStateError",
    "DEPLOYMENT_TYPES",
    "DISCOVERY_LIMIT_NOTICE",
    "DiscoverySensorService",
    "NormalizedDiscoveryObservation",
    "OBSERVATION_SCHEMA",
    "SENSOR_SCHEMA",
    "SENSOR_TYPES",
    "SensorActor",
    "default_service",
    "enabled",
    "require_enabled",
]
