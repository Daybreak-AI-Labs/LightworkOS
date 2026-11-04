"""Governed volunteered profile preferences and progressive prompt journeys.

This core authority stores only closed boolean/select values from an exact,
approved publication snapshot.  Public writes derive tenant and profile scope
from a frozen server-constructed :class:`PublicProfileAuthority`; they never
accept caller-authored tenant or actor fields.  Administrative writes derive
their actor from an authenticated runtime principal.

The module performs no network or live-traffic operation and makes no customer
or accessibility acceptance claim.  It is default-off unless both exact gates
are true::

    [consent_preferences]
    enable = true
    [consent_preferences.profile_data]
    enable = true
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import consent_storage
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.consent-profile-data-audit.v1"
EXPORT_SCHEMA = "lightwork.consent-profile-data-export.v1"

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_DEFINITIONS = 256
_MAX_STAGES = 64
_MIN_RETENTION_SECONDS = 24 * 60 * 60
_MAX_RETENTION_SECONDS = 5 * 365 * 24 * 60 * 60
_MAX_EXPIRY_SECONDS = 2 * 365 * 24 * 60 * 60

VALUE_TYPES = frozenset({"boolean", "single_select", "multi_select"})
CATALOG_STATES = frozenset({"pending_approval", "published"})
JOURNEY_STATES = frozenset({"draft", "approved", "active", "paused", "killed", "rolled_back"})
CONDITION_SOURCES = frozenset({"preference", "purpose"})
CONDITION_OPERATORS = frozenset({"equals", "contains"})
PURPOSE_SIGNALS = frozenset({"grant", "deny"})
PROMPT_OUTCOMES = frozenset({"completed", "dismissed"})


class ConsentProfileDataError(RuntimeError):
    """Base error for custom profile values and prompt journeys."""


class ConsentProfileDataConfigError(ConsentProfileDataError):
    """The exact profile-data gates are not enabled."""


class ConsentProfileDataValidationError(ConsentProfileDataError, ValueError):
    """Input is outside a closed, bounded schema."""


class ConsentProfileDataConflict(ConsentProfileDataError):
    """A state, idempotency, lease, or CAS precondition failed."""


class ConsentProfileDataNotFound(ConsentProfileDataError):
    """A tenant-scoped record is absent or deliberately undisclosed."""


class ConsentProfileDataPermissionDenied(ConsentProfileDataError):
    """Binding or authenticated authority is insufficient."""


class ConsentProfileDataIntegrityError(ConsentProfileDataError):
    """Persisted state or an integrity chain is invalid."""


def profile_data_enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return true only for exact parent and profile-data boolean gates."""

    if config is None:
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
    profile_data = consent.get("profile_data") if isinstance(consent, Mapping) else None
    return (
        isinstance(consent, Mapping)
        and consent.get("enable") is True
        and isinstance(profile_data, Mapping)
        and profile_data.get("enable") is True
    )


def require_profile_data_enabled(config: Mapping[str, Any] | None = None) -> None:
    if not profile_data_enabled(config):
        raise ConsentProfileDataConfigError(
            "consent profile data is disabled; explicitly enable "
            "consent_preferences and consent_preferences.profile_data"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentProfileDataValidationError(
            "profile data must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise ConsentProfileDataValidationError("profile data exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ConsentProfileDataValidationError("tenant_id is invalid") from exc


def _id(value: object, label: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ConsentProfileDataValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ConsentProfileDataValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConsentProfileDataValidationError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise ConsentProfileDataValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _sequence(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_DEFINITIONS,
) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ConsentProfileDataValidationError(f"{label} must be a list")
    if not minimum <= len(value) <= maximum:
        raise ConsentProfileDataValidationError(
            f"{label} must contain between {minimum} and {maximum} values"
        )
    return value


def _closed(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ConsentProfileDataValidationError(f"{label} schema is closed")
    return value


def _retention(value: object) -> int:
    return _integer(
        value,
        "retention_seconds",
        _MIN_RETENTION_SECONDS,
        _MAX_RETENTION_SECONDS,
    )


def _option(value: object) -> dict[str, str]:
    item = _closed(
        value,
        "preference option",
        frozenset({"value_id", "label_ref"}),
    )
    return {
        "value_id": _id(item["value_id"], "option value_id"),
        "label_ref": _id(item["label_ref"], "option label_ref"),
    }


def _definition(value: object) -> dict[str, object]:
    item = _closed(
        value,
        "preference definition",
        frozenset(
            {
                "preference_id",
                "definition_version",
                "label_ref",
                "value_type",
                "options",
                "required",
                "expires_after_seconds",
                "retention_seconds",
            }
        ),
    )
    value_type = item["value_type"]
    if value_type not in VALUE_TYPES:
        raise ConsentProfileDataValidationError("preference value_type is unsupported")
    if not isinstance(item["required"], bool):
        raise ConsentProfileDataValidationError("preference required must be boolean")
    options = tuple(_option(option) for option in _sequence(item["options"], "options"))
    option_ids = tuple(option["value_id"] for option in options)
    if len(set(option_ids)) != len(option_ids):
        raise ConsentProfileDataValidationError("preference option IDs must be unique")
    if value_type == "boolean" and options:
        raise ConsentProfileDataValidationError("boolean values cannot define options")
    if value_type != "boolean" and not options:
        raise ConsentProfileDataValidationError("select values require options")
    raw_expiry = item["expires_after_seconds"]
    expiry = None
    if raw_expiry is not None:
        expiry = _integer(raw_expiry, "expires_after_seconds", 60, _MAX_EXPIRY_SECONDS)
    return {
        "preference_id": _id(item["preference_id"], "preference_id"),
        "definition_version": _integer(
            item["definition_version"], "definition_version", 1, 1_000_000
        ),
        "label_ref": _id(item["label_ref"], "label_ref"),
        "value_type": value_type,
        "options": list(options),
        "required": item["required"],
        "expires_after_seconds": expiry,
        "retention_seconds": _retention(item["retention_seconds"]),
    }


def _definitions(value: object) -> tuple[dict[str, object], ...]:
    values = tuple(
        _definition(item)
        for item in _sequence(value, "definitions", minimum=1, maximum=_MAX_DEFINITIONS)
    )
    identifiers = tuple(str(item["preference_id"]) for item in values)
    if len(set(identifiers)) != len(identifiers):
        raise ConsentProfileDataValidationError("preference IDs must be unique")
    return values


def _normalize_value(definition: Mapping[str, object], value: object) -> object:
    value_type = definition["value_type"]
    if value_type == "boolean":
        if not isinstance(value, bool):
            raise ConsentProfileDataValidationError("boolean preference requires boolean")
        return value
    allowed = [str(option["value_id"]) for option in definition["options"]]  # type: ignore[index]
    if value_type == "single_select":
        selected = _id(value, "preference value")
        if selected not in allowed:
            raise ConsentProfileDataValidationError("preference value is not published")
        return selected
    selected_values = tuple(
        _id(item, "preference value")
        for item in _sequence(value, "preference values", minimum=1, maximum=64)
    )
    if len(set(selected_values)) != len(selected_values) or not set(selected_values).issubset(
        allowed
    ):
        raise ConsentProfileDataValidationError(
            "multi-select values must be unique published options"
        )
    return [item for item in allowed if item in selected_values]


@dataclass(frozen=True, slots=True)
class PublicProfileAuthority:
    """Immutable server-side result of public credential/profile verification."""

    tenant_id: str
    profile_id: str
    property_id: str
    catalog_id: str
    catalog_version: int
    publication_sha256: str
    bundle_sha256: str
    configuration_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    profile_capability_sha256: str


@dataclass(frozen=True, slots=True)
class PromptContext:
    """Trusted ephemeral purpose signals; never persisted with an assignment."""

    purpose_signals: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if type(self.purpose_signals) is not tuple:
            raise ConsentProfileDataValidationError("purpose_signals must be an immutable tuple")
        seen: set[str] = set()
        for pair in self.purpose_signals:
            if type(pair) is not tuple or len(pair) != 2:
                raise ConsentProfileDataValidationError("purpose signals must be immutable pairs")
            purpose_id, signal = pair
            purpose = _id(purpose_id, "purpose_id")
            if purpose in seen or signal not in PURPOSE_SIGNALS:
                raise ConsentProfileDataValidationError(
                    "purpose signals must be unique grant/deny pairs"
                )
            seen.add(purpose)


@dataclass(frozen=True)
class PreferenceCatalog:
    tenant_id: str
    catalog_id: str
    version: int
    property_id: str
    publication_sha256: str
    bundle_sha256: str
    configuration_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    definitions: tuple[Mapping[str, object], ...]
    state: str
    revision: int
    created_by: str
    approved_by: str | None
    retained_until: float
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class ProfileValue:
    tenant_id: str
    profile_id: str
    preference_id: str
    catalog_id: str
    catalog_version: int
    definition_version: int
    value_type: str
    value: object
    status: str
    revision: int
    expires_at: float | None
    retained_until: float
    receipt_id: str
    binding_sha256: str
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class ValueReceipt:
    tenant_id: str
    profile_id: str
    sequence: int
    receipt_id: str
    preference_id: str
    action: str
    catalog_id: str
    catalog_version: int
    value_type: str
    value: object
    status: str
    value_revision: int
    definition_version: int
    binding_sha256: str
    expires_at: float | None
    value_record_sha256: str
    previous_receipt_sha256: str
    retained_until: float
    occurred_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class ConsumerProfileView:
    tenant_id: str
    profile_id: str
    current_records: tuple[ProfileValue, ...]
    active_values: Mapping[str, object]
    history: tuple[ValueReceipt, ...]
    prompt_interactions: tuple[Mapping[str, object], ...]
    generated_at: float


@dataclass(frozen=True)
class ProfileExport:
    schema: str
    tenant_id: str
    profile_id: str
    body: Mapping[str, object]
    export_sha256: str


@dataclass(frozen=True)
class JourneyVersion:
    tenant_id: str
    journey_id: str
    version: int
    property_id: str
    catalog_id: str
    catalog_version: int
    publication_sha256: str
    bundle_sha256: str
    configuration_sha256: str
    policy_sha256: str
    stages: tuple[Mapping[str, object], ...]
    max_prompts: int
    cooldown_seconds: int
    frequency_cap: int
    frequency_window_seconds: int
    state: str
    revision: int
    created_by: str
    approved_by: str | None
    retained_until: float
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class PromptItem:
    stage_id: str
    preference_id: str
    definition_version: int
    label_ref: str
    value_type: str
    required: bool
    options: tuple[Mapping[str, str], ...]


@dataclass(frozen=True, slots=True)
class PromptAssignment:
    assignment_id: str
    binding_sha256: str
    profile_token: str
    journey_id: str
    journey_version: int
    journey_sha256: str
    stage_ids: tuple[str, ...]
    prompts: tuple[PromptItem, ...]
    eligible: bool
    reason: str
    assigned_at: float


@dataclass(frozen=True)
class IntegrityVerification:
    tenant_id: str
    verified_records: int
    receipts: int
    audit_events: int
    terminal_audit_sha256: str


def product_boundaries() -> Mapping[str, object]:
    """Return explicit local-code and external-validation boundaries."""

    return {
        "provider_neutral": True,
        "network_io": False,
        "live_traffic_operated": False,
        "accessibility_acceptance_verified": False,
        "customer_acceptance_verified": False,
        "protected_trait_inference": False,
        "raw_pii_persisted": False,
        "raw_profile_capability_persisted": False,
    }


class ConsentProfileDataStore:
    """Tenant-isolated SQLite authority for profile data and prompt journeys."""

    def __init__(
        self,
        path: str | Path,
        *,
        config_gate: Callable[[], None] = require_profile_data_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        self.path = Path(path)
        self._principal_resolver = principal_resolver
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise ConsentProfileDataPermissionDenied(
                "an authenticated administrative principal is required"
            )
        return _id(actor, "authenticated principal")

    def _connect(self) -> sqlite3.Connection:
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=30.0)
        else:
            connection = sqlite3.connect(
                self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS catalogs(
                    tenant_id TEXT NOT NULL,catalog_id TEXT NOT NULL,version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,catalog_id,version)
                );
                CREATE TABLE IF NOT EXISTS profile_values(
                    tenant_id TEXT NOT NULL,profile_id TEXT NOT NULL,preference_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,profile_id,preference_id)
                );
                CREATE TABLE IF NOT EXISTS value_receipts(
                    tenant_id TEXT NOT NULL,profile_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    receipt_id TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,profile_id,sequence),
                    UNIQUE(tenant_id,receipt_id)
                );
                CREATE TABLE IF NOT EXISTS receipt_checkpoints(
                    tenant_id TEXT NOT NULL,profile_id TEXT NOT NULL,
                    last_sequence INTEGER NOT NULL,last_sha256 TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,profile_id)
                );
                CREATE TABLE IF NOT EXISTS journeys(
                    tenant_id TEXT NOT NULL,journey_id TEXT NOT NULL,version INTEGER NOT NULL,
                    state TEXT NOT NULL,payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,journey_id,version)
                );
                CREATE TABLE IF NOT EXISTS prompt_events(
                    tenant_id TEXT NOT NULL,event_id TEXT NOT NULL,profile_token TEXT NOT NULL,
                    journey_id TEXT NOT NULL,occurred_at REAL NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,event_id)
                );
                CREATE INDEX IF NOT EXISTS prompt_event_lookup
                    ON prompt_events(tenant_id,profile_token,journey_id,occurred_at);
                CREATE TABLE IF NOT EXISTS prompt_aggregates(
                    tenant_id TEXT NOT NULL,journey_id TEXT NOT NULL,version INTEGER NOT NULL,
                    stage_id TEXT NOT NULL,preference_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,journey_id,version,stage_id,preference_id)
                );
                CREATE TABLE IF NOT EXISTS operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,result_id TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise ConsentProfileDataIntegrityError(
                    "consent profile-data database schema is unsupported"
                )
        if not consent_storage.shared():
            ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _payload(row: sqlite3.Row, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ConsentProfileDataIntegrityError(
                f"persisted {label} is not canonical JSON"
            ) from exc
        if not isinstance(payload, dict) or _sha256(payload) != row["integrity_sha256"]:
            raise ConsentProfileDataIntegrityError(
                f"persisted {label} failed integrity verification"
            )
        return payload

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha = hashlib.sha256(key.encode()).hexdigest()
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha),
        ).fetchone()
        if row is not None:
            binding = {
                "tenant_id": row["tenant_id"],
                "operation_sha256": row["operation_sha256"],
                "request_sha256": row["request_sha256"],
                "result_kind": row["result_kind"],
                "result_id": row["result_id"],
            }
            if _sha256(binding) != row["integrity_sha256"]:
                raise ConsentProfileDataIntegrityError(
                    "idempotency binding failed integrity verification"
                )
            if row["request_sha256"] != request_sha:
                raise ConsentProfileDataConflict(
                    "idempotency key is bound to different canonical content"
                )
        return request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        binding = {
            "tenant_id": tenant_id,
            "operation_sha256": hashlib.sha256(idempotency_key.encode()).hexdigest(),
            "request_sha256": request_sha,
            "result_kind": result_kind,
            "result_id": result_id,
        }
        connection.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?,?)",
            (
                tenant_id,
                binding["operation_sha256"],
                request_sha,
                result_kind,
                result_id,
                _sha256(binding),
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        subject: str,
        actor: str,
        details: Mapping[str, object],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM audit_events WHERE tenant_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else previous["integrity_sha256"]
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant_id,
            "sequence": sequence,
            "action": _id(action, "audit action"),
            "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
            "actor_ref": _id(actor, "audit actor"),
            "details": dict(details),
            "occurred_at": now,
            "previous_sha256": previous_sha,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO audit_events VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )

    @staticmethod
    def _catalog_from(payload: Mapping[str, Any], digest: str) -> PreferenceCatalog:
        values = dict(payload)
        values["definitions"] = tuple(dict(item) for item in values["definitions"])
        return PreferenceCatalog(**values, integrity_sha256=digest)

    @staticmethod
    def _value_from(payload: Mapping[str, Any], digest: str) -> ProfileValue:
        return ProfileValue(**dict(payload), integrity_sha256=digest)

    @staticmethod
    def _receipt_from(payload: Mapping[str, Any], digest: str) -> ValueReceipt:
        return ValueReceipt(**dict(payload), integrity_sha256=digest)

    @staticmethod
    def _journey_from(payload: Mapping[str, Any], digest: str) -> JourneyVersion:
        values = dict(payload)
        values["stages"] = tuple(dict(item) for item in values["stages"])
        return JourneyVersion(**values, integrity_sha256=digest)

    @staticmethod
    def _authority_body(authority: object) -> dict[str, object]:
        if type(authority) is not PublicProfileAuthority:
            raise ConsentProfileDataPermissionDenied(
                "a server-constructed PublicProfileAuthority is required"
            )
        assert isinstance(authority, PublicProfileAuthority)
        tenant = _tenant(authority.tenant_id)
        if tenant != authority.tenant_id:
            raise ConsentProfileDataPermissionDenied(
                "public profile authority tenant is not canonical"
            )
        return {
            "tenant_id": tenant,
            "profile_id": _id(authority.profile_id, "profile_id"),
            "property_id": _id(authority.property_id, "property_id"),
            "catalog_id": _id(authority.catalog_id, "catalog_id"),
            "catalog_version": _integer(authority.catalog_version, "catalog_version", 1, 1_000_000),
            "publication_sha256": _digest(authority.publication_sha256, "publication_sha256"),
            "bundle_sha256": _digest(authority.bundle_sha256, "bundle_sha256"),
            "configuration_sha256": _digest(authority.configuration_sha256, "configuration_sha256"),
            "policy_id": _id(authority.policy_id, "policy_id"),
            "policy_version": _integer(authority.policy_version, "policy_version", 1, 1_000_000),
            "policy_sha256": _digest(authority.policy_sha256, "policy_sha256"),
            "profile_capability_sha256": _digest(
                authority.profile_capability_sha256,
                "profile_capability_sha256",
            ),
        }

    @staticmethod
    def _get_catalog(
        connection: sqlite3.Connection,
        tenant_id: str,
        catalog_id: str,
        version: int,
    ) -> PreferenceCatalog:
        row = connection.execute(
            "SELECT * FROM catalogs WHERE tenant_id=? AND catalog_id=? AND version=?",
            (tenant_id, catalog_id, version),
        ).fetchone()
        if row is None:
            raise ConsentProfileDataNotFound("preference catalog was not found")
        return ConsentProfileDataStore._catalog_from(
            ConsentProfileDataStore._payload(row, "preference catalog"),
            row["integrity_sha256"],
        )

    @staticmethod
    def _catalog_binding(catalog: PreferenceCatalog) -> dict[str, object]:
        return {
            "tenant_id": catalog.tenant_id,
            "property_id": catalog.property_id,
            "catalog_id": catalog.catalog_id,
            "catalog_version": catalog.version,
            "publication_sha256": catalog.publication_sha256,
            "bundle_sha256": catalog.bundle_sha256,
            "configuration_sha256": catalog.configuration_sha256,
            "policy_id": catalog.policy_id,
            "policy_version": catalog.policy_version,
            "policy_sha256": catalog.policy_sha256,
        }

    def _bound_catalog(
        self,
        connection: sqlite3.Connection,
        authority_body: Mapping[str, object],
    ) -> PreferenceCatalog:
        catalog = self._get_catalog(
            connection,
            str(authority_body["tenant_id"]),
            str(authority_body["catalog_id"]),
            int(authority_body["catalog_version"]),
        )
        if catalog.state != "published":
            raise ConsentProfileDataPermissionDenied(
                "public profile authority references an unpublished catalog"
            )
        expected = self._catalog_binding(catalog)
        supplied = {key: authority_body[key] for key in expected}
        if supplied != expected:
            raise ConsentProfileDataPermissionDenied(
                "public profile authority does not match the published catalog"
            )
        return catalog

    @staticmethod
    def _require_profile_binding(
        connection: sqlite3.Connection,
        tenant_id: str,
        profile_id: str,
        binding_sha256: str,
    ) -> None:
        """Prevent a new capability/publication binding from inheriting a profile."""

        mismatch = connection.execute(
            "SELECT 1 FROM profile_values WHERE tenant_id=? AND profile_id=? "
            "AND json_extract(payload_json,'$.binding_sha256')<>? "
            "UNION ALL SELECT 1 FROM value_receipts WHERE tenant_id=? AND profile_id=? "
            "AND json_extract(payload_json,'$.binding_sha256')<>? LIMIT 1",
            (
                tenant_id,
                profile_id,
                binding_sha256,
                tenant_id,
                profile_id,
                binding_sha256,
            ),
        ).fetchone()
        if mismatch is not None:
            raise ConsentProfileDataPermissionDenied(
                "profile records belong to a different public authority binding"
            )

    def create_catalog_version(
        self,
        tenant_id: str,
        catalog_id: str,
        *,
        property_id: str,
        publication_sha256: str,
        bundle_sha256: str,
        configuration_sha256: str,
        policy_id: str,
        policy_version: int,
        policy_sha256: str,
        definitions: Sequence[Mapping[str, object]],
        retention_seconds: int,
        expected_latest_version: int,
        idempotency_key: str,
    ) -> PreferenceCatalog:
        """Create a pending immutable publication snapshot under version CAS."""

        tenant = _tenant(tenant_id)
        catalog_key = _id(catalog_id, "catalog_id")
        property_key = _id(property_id, "property_id")
        publication = _digest(publication_sha256, "publication_sha256")
        bundle = _digest(bundle_sha256, "bundle_sha256")
        configuration = _digest(configuration_sha256, "configuration_sha256")
        policy_key = _id(policy_id, "policy_id")
        policy_ver = _integer(policy_version, "policy_version", 1, 1_000_000)
        policy_digest = _digest(policy_sha256, "policy_sha256")
        validated = _definitions(definitions)
        retention = _retention(retention_seconds)
        expected = _integer(expected_latest_version, "expected_latest_version", 0, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "create_catalog_version",
            "catalog_id": catalog_key,
            "property_id": property_key,
            "publication_sha256": publication,
            "bundle_sha256": bundle,
            "configuration_sha256": configuration,
            "policy_id": policy_key,
            "policy_version": policy_ver,
            "policy_sha256": policy_digest,
            "definitions": list(validated),
            "retention_seconds": retention,
            "expected_latest_version": expected,
            "actor": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                return self._get_catalog(
                    connection, tenant, catalog_key, int(operation["result_id"])
                )
            row = connection.execute(
                "SELECT MAX(version) AS latest FROM catalogs WHERE tenant_id=? AND catalog_id=?",
                (tenant, catalog_key),
            ).fetchone()
            latest = 0 if row is None or row["latest"] is None else int(row["latest"])
            if latest != expected:
                raise ConsentProfileDataConflict(
                    f"catalog latest-version CAS failed: expected {expected}, found {latest}"
                )
            version = latest + 1
            payload = {
                "tenant_id": tenant,
                "catalog_id": catalog_key,
                "version": version,
                "property_id": property_key,
                "publication_sha256": publication,
                "bundle_sha256": bundle,
                "configuration_sha256": configuration,
                "policy_id": policy_key,
                "policy_version": policy_ver,
                "policy_sha256": policy_digest,
                "definitions": list(validated),
                "state": "pending_approval",
                "revision": 1,
                "created_by": actor,
                "approved_by": None,
                "retained_until": now + retention,
                "created_at": now,
                "updated_at": now,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO catalogs VALUES(?,?,?,?,?)",
                (
                    tenant,
                    catalog_key,
                    version,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "catalog",
                str(version),
            )
            self._audit(
                connection,
                tenant,
                "catalog_created",
                f"{catalog_key}:{version}",
                actor,
                {"definition_count": len(validated)},
                now,
            )
            return self._catalog_from(payload, digest)

    def get_catalog_version(
        self,
        tenant_id: str,
        catalog_id: str,
        version: int,
    ) -> PreferenceCatalog:
        tenant = _tenant(tenant_id)
        catalog = _id(catalog_id, "catalog_id")
        selected = _integer(version, "version", 1, 1_000_000)
        with self._connect() as connection:
            return self._get_catalog(connection, tenant, catalog, selected)

    def list_catalogs(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        """List one tenant's integrity-checked catalog versions, newest first."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 500)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT catalog_id,version FROM catalogs WHERE tenant_id=? "
                "ORDER BY catalog_id,version DESC LIMIT ?",
                (tenant, bounded + 1),
            ).fetchall()
            items = [
                self._get_catalog(connection, tenant, str(row[0]), int(row[1]))
                for row in rows[:bounded]
            ]
        return {"items": items, "truncated": len(rows) > bounded}

    def approve_catalog_version(
        self,
        tenant_id: str,
        catalog_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> PreferenceCatalog:
        tenant = _tenant(tenant_id)
        catalog_key = _id(catalog_id, "catalog_id")
        selected = _integer(version, "version", 1, 1_000_000)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "approve_catalog_version",
            "catalog_id": catalog_key,
            "version": selected,
            "expected_revision": expected,
            "actor": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            current = self._get_catalog(connection, tenant, catalog_key, selected)
            if operation is not None:
                return current
            if current.revision != expected:
                raise ConsentProfileDataConflict(
                    f"catalog revision CAS failed: expected {expected}, found {current.revision}"
                )
            if current.state != "pending_approval":
                raise ConsentProfileDataConflict("catalog is not pending approval")
            if current.created_by == actor:
                raise ConsentProfileDataPermissionDenied(
                    "catalog creators cannot approve their own publication"
                )
            payload = {
                key: value for key, value in current.__dict__.items() if key != "integrity_sha256"
            }
            payload.update(
                {
                    "definitions": [dict(item) for item in current.definitions],
                    "state": "published",
                    "revision": current.revision + 1,
                    "approved_by": actor,
                    "updated_at": now,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE catalogs SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND catalog_id=? AND version=?",
                (
                    _canonical(payload).decode("ascii"),
                    digest,
                    tenant,
                    catalog_key,
                    selected,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "catalog",
                str(selected),
            )
            self._audit(
                connection,
                tenant,
                "catalog_published",
                f"{catalog_key}:{selected}",
                actor,
                {},
                now,
            )
            return self._catalog_from(payload, digest)

    @staticmethod
    def _definition_for(
        catalog: PreferenceCatalog,
        preference_id: str,
    ) -> Mapping[str, object]:
        for definition in catalog.definitions:
            if definition["preference_id"] == preference_id:
                return definition
        raise ConsentProfileDataNotFound("published custom preference was not found")

    @staticmethod
    def _get_value_row(
        connection: sqlite3.Connection,
        tenant_id: str,
        profile_id: str,
        preference_id: str,
    ) -> tuple[ProfileValue, dict[str, Any]] | None:
        row = connection.execute(
            "SELECT * FROM profile_values WHERE tenant_id=? AND profile_id=? AND preference_id=?",
            (tenant_id, profile_id, preference_id),
        ).fetchone()
        if row is None:
            return None
        payload = ConsentProfileDataStore._payload(row, "profile value")
        return (
            ConsentProfileDataStore._value_from(payload, row["integrity_sha256"]),
            payload,
        )

    @staticmethod
    def _receipt_head(
        connection: sqlite3.Connection,
        tenant_id: str,
        profile_id: str,
    ) -> tuple[int, str]:
        row = connection.execute(
            "SELECT sequence,integrity_sha256 FROM value_receipts "
            "WHERE tenant_id=? AND profile_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id, profile_id),
        ).fetchone()
        if row is not None:
            return int(row["sequence"]), str(row["integrity_sha256"])
        checkpoint = connection.execute(
            "SELECT * FROM receipt_checkpoints WHERE tenant_id=? AND profile_id=?",
            (tenant_id, profile_id),
        ).fetchone()
        if checkpoint is None:
            return 0, "0" * 64
        checkpoint_body = {
            "tenant_id": checkpoint["tenant_id"],
            "profile_id": checkpoint["profile_id"],
            "last_sequence": checkpoint["last_sequence"],
            "last_sha256": checkpoint["last_sha256"],
        }
        if _sha256(checkpoint_body) != checkpoint["integrity_sha256"]:
            raise ConsentProfileDataIntegrityError(
                "receipt retention checkpoint failed integrity verification"
            )
        return int(checkpoint["last_sequence"]), str(checkpoint["last_sha256"])

    @staticmethod
    def _get_receipt_by_id(
        connection: sqlite3.Connection,
        tenant_id: str,
        receipt_id: str,
    ) -> ValueReceipt:
        row = connection.execute(
            "SELECT * FROM value_receipts WHERE tenant_id=? AND receipt_id=?",
            (tenant_id, receipt_id),
        ).fetchone()
        if row is None:
            raise ConsentProfileDataNotFound("value receipt was not found")
        return ConsentProfileDataStore._receipt_from(
            ConsentProfileDataStore._payload(row, "value receipt"),
            row["integrity_sha256"],
        )

    @staticmethod
    def _value_from_receipt(receipt: ValueReceipt) -> ProfileValue:
        return ProfileValue(
            tenant_id=receipt.tenant_id,
            profile_id=receipt.profile_id,
            preference_id=receipt.preference_id,
            catalog_id=receipt.catalog_id,
            catalog_version=receipt.catalog_version,
            definition_version=receipt.definition_version,
            value_type=receipt.value_type,
            value=receipt.value,
            status=receipt.status,
            revision=receipt.value_revision,
            expires_at=receipt.expires_at,
            retained_until=receipt.retained_until,
            receipt_id=receipt.receipt_id,
            binding_sha256=receipt.binding_sha256,
            updated_at=receipt.occurred_at,
            integrity_sha256=receipt.value_record_sha256,
        )

    def set_public_value(
        self,
        authority: PublicProfileAuthority,
        preference_id: str,
        value: object,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProfileValue:
        """Store one volunteered closed value using only server binding authority."""

        binding = self._authority_body(authority)
        tenant = str(binding["tenant_id"])
        profile = str(binding["profile_id"])
        preference = _id(preference_id, "preference_id")
        expected = _integer(expected_revision, "expected_revision", 0, 1_000_000)
        binding_sha = _sha256(binding)
        now = _timestamp(self._clock(), "current time")
        with self._connect() as connection:
            self._begin(connection)
            catalog = self._bound_catalog(connection, binding)
            self._require_profile_binding(connection, tenant, profile, binding_sha)
            definition = self._definition_for(catalog, preference)
            normalized = _normalize_value(definition, value)
            request = {
                "action": "set_public_value",
                "binding_sha256": binding_sha,
                "preference_id": preference,
                "value": normalized,
                "expected_revision": expected,
            }
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                receipt = self._get_receipt_by_id(connection, tenant, str(operation["result_id"]))
                return self._value_from_receipt(receipt)
            existing = self._get_value_row(connection, tenant, profile, preference)
            revision = 0 if existing is None else existing[0].revision
            if revision != expected:
                raise ConsentProfileDataConflict(
                    f"profile value revision CAS failed: expected {expected}, found {revision}"
                )
            next_revision = revision + 1
            retention = int(definition["retention_seconds"])
            expires_after = definition["expires_after_seconds"]
            expires_at = None if expires_after is None else now + int(expires_after)
            sequence, previous_sha = self._receipt_head(connection, tenant, profile)
            receipt_id = (
                "value-" + hashlib.sha256(f"{tenant}\0{idempotency_key}".encode()).hexdigest()[:40]
            )
            value_payload = {
                "tenant_id": tenant,
                "profile_id": profile,
                "preference_id": preference,
                "catalog_id": catalog.catalog_id,
                "catalog_version": catalog.version,
                "definition_version": definition["definition_version"],
                "value_type": definition["value_type"],
                "value": normalized,
                "status": "active",
                "revision": next_revision,
                "expires_at": expires_at,
                "retained_until": now + retention,
                "receipt_id": receipt_id,
                "binding_sha256": binding_sha,
                "updated_at": now,
            }
            value_digest = _sha256(value_payload)
            receipt_payload = {
                "tenant_id": tenant,
                "profile_id": profile,
                "sequence": sequence + 1,
                "receipt_id": receipt_id,
                "preference_id": preference,
                "action": "set",
                "catalog_id": catalog.catalog_id,
                "catalog_version": catalog.version,
                "value_type": definition["value_type"],
                "value": normalized,
                "status": "active",
                "value_revision": next_revision,
                "definition_version": definition["definition_version"],
                "binding_sha256": binding_sha,
                "expires_at": expires_at,
                "value_record_sha256": value_digest,
                "previous_receipt_sha256": previous_sha,
                "retained_until": now + retention,
                "occurred_at": now,
            }
            receipt_digest = _sha256(receipt_payload)
            connection.execute(
                "INSERT INTO profile_values VALUES(?,?,?,?,?) "
                "ON CONFLICT(tenant_id,profile_id,preference_id) DO UPDATE SET "
                "payload_json=excluded.payload_json,integrity_sha256=excluded.integrity_sha256",
                (
                    tenant,
                    profile,
                    preference,
                    _canonical(value_payload).decode("ascii"),
                    value_digest,
                ),
            )
            connection.execute(
                "INSERT INTO value_receipts VALUES(?,?,?,?,?,?,?)",
                (
                    tenant,
                    profile,
                    sequence + 1,
                    receipt_id,
                    now + retention,
                    _canonical(receipt_payload).decode("ascii"),
                    receipt_digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "value_receipt",
                receipt_id,
            )
            self._audit(
                connection,
                tenant,
                "public_value_set",
                receipt_id,
                "public-profile",
                {
                    "profile_sha256": hashlib.sha256(profile.encode()).hexdigest(),
                    "preference_id": preference,
                    "value_revision": next_revision,
                },
                now,
            )
            return self._value_from(value_payload, value_digest)

    def _remove_public_value(
        self,
        authority: PublicProfileAuthority,
        preference_id: str,
        *,
        action: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProfileValue:
        binding = self._authority_body(authority)
        tenant = str(binding["tenant_id"])
        profile = str(binding["profile_id"])
        preference = _id(preference_id, "preference_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        binding_sha = _sha256(binding)
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": action,
            "binding_sha256": binding_sha,
            "preference_id": preference,
            "expected_revision": expected,
        }
        with self._connect() as connection:
            self._begin(connection)
            catalog = self._bound_catalog(connection, binding)
            self._require_profile_binding(connection, tenant, profile, binding_sha)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                receipt = self._get_receipt_by_id(connection, tenant, str(operation["result_id"]))
                return self._value_from_receipt(receipt)
            existing = self._get_value_row(connection, tenant, profile, preference)
            if existing is None:
                raise ConsentProfileDataNotFound("profile value was not found")
            current, _ = existing
            if current.revision != expected:
                raise ConsentProfileDataConflict(
                    f"profile value revision CAS failed: expected {expected}, "
                    f"found {current.revision}"
                )
            if current.status != "active":
                raise ConsentProfileDataConflict("profile value is not active")
            definition = self._definition_for(catalog, preference)
            sequence, previous_sha = self._receipt_head(connection, tenant, profile)
            receipt_id = (
                "value-" + hashlib.sha256(f"{tenant}\0{idempotency_key}".encode()).hexdigest()[:40]
            )
            retention = int(definition["retention_seconds"])
            next_revision = current.revision + 1
            value_payload = {
                "tenant_id": tenant,
                "profile_id": profile,
                "preference_id": preference,
                "catalog_id": catalog.catalog_id,
                "catalog_version": catalog.version,
                "definition_version": definition["definition_version"],
                "value_type": definition["value_type"],
                "value": None,
                "status": action,
                "revision": next_revision,
                "expires_at": None,
                "retained_until": now + retention,
                "receipt_id": receipt_id,
                "binding_sha256": binding_sha,
                "updated_at": now,
            }
            value_digest = _sha256(value_payload)
            receipt_payload = {
                "tenant_id": tenant,
                "profile_id": profile,
                "sequence": sequence + 1,
                "receipt_id": receipt_id,
                "preference_id": preference,
                "action": action,
                "catalog_id": catalog.catalog_id,
                "catalog_version": catalog.version,
                "value_type": definition["value_type"],
                "value": None,
                "status": action,
                "value_revision": next_revision,
                "definition_version": definition["definition_version"],
                "binding_sha256": binding_sha,
                "expires_at": None,
                "value_record_sha256": value_digest,
                "previous_receipt_sha256": previous_sha,
                "retained_until": now + retention,
                "occurred_at": now,
            }
            receipt_digest = _sha256(receipt_payload)
            connection.execute(
                "UPDATE profile_values SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND profile_id=? AND preference_id=?",
                (
                    _canonical(value_payload).decode("ascii"),
                    value_digest,
                    tenant,
                    profile,
                    preference,
                ),
            )
            connection.execute(
                "INSERT INTO value_receipts VALUES(?,?,?,?,?,?,?)",
                (
                    tenant,
                    profile,
                    sequence + 1,
                    receipt_id,
                    now + retention,
                    _canonical(receipt_payload).decode("ascii"),
                    receipt_digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "value_receipt",
                receipt_id,
            )
            self._audit(
                connection,
                tenant,
                f"public_value_{action}",
                receipt_id,
                "public-profile",
                {
                    "profile_sha256": hashlib.sha256(profile.encode()).hexdigest(),
                    "preference_id": preference,
                    "value_revision": next_revision,
                },
                now,
            )
            return self._value_from(value_payload, value_digest)

    def unset_public_value(
        self,
        authority: PublicProfileAuthority,
        preference_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProfileValue:
        return self._remove_public_value(
            authority,
            preference_id,
            action="unset",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def revoke_public_value(
        self,
        authority: PublicProfileAuthority,
        preference_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProfileValue:
        return self._remove_public_value(
            authority,
            preference_id,
            action="revoked",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def get_current_value(
        self,
        authority: PublicProfileAuthority,
        preference_id: str,
    ) -> ProfileValue:
        binding = self._authority_body(authority)
        preference = _id(preference_id, "preference_id")
        binding_sha = _sha256(binding)
        with self._connect() as connection:
            self._bound_catalog(connection, binding)
            self._require_profile_binding(
                connection,
                str(binding["tenant_id"]),
                str(binding["profile_id"]),
                binding_sha,
            )
            current = self._get_value_row(
                connection,
                str(binding["tenant_id"]),
                str(binding["profile_id"]),
                preference,
            )
            if current is None:
                raise ConsentProfileDataNotFound("profile value was not found")
            return current[0]

    def value_history(
        self,
        authority: PublicProfileAuthority,
        preference_id: str | None = None,
    ) -> tuple[ValueReceipt, ...]:
        binding = self._authority_body(authority)
        binding_sha = _sha256(binding)
        preference = None if preference_id is None else _id(preference_id, "preference_id")
        with self._connect() as connection:
            self._bound_catalog(connection, binding)
            self._require_profile_binding(
                connection,
                str(binding["tenant_id"]),
                str(binding["profile_id"]),
                binding_sha,
            )
            query = (
                "SELECT * FROM value_receipts WHERE tenant_id=? AND profile_id=? "
                + (
                    ""
                    if preference is None
                    else "AND json_extract(payload_json,'$.preference_id')=? "
                )
                + "ORDER BY sequence"
            )
            parameters: tuple[object, ...] = (
                str(binding["tenant_id"]),
                str(binding["profile_id"]),
            )
            if preference is not None:
                parameters += (preference,)
            rows = connection.execute(query, parameters).fetchall()
            return tuple(
                self._receipt_from(self._payload(row, "value receipt"), row["integrity_sha256"])
                for row in rows
            )

    @staticmethod
    def _validate_condition(
        value: object,
        definitions: Mapping[str, Mapping[str, object]],
        prompted_preferences: frozenset[str],
    ) -> dict[str, object] | None:
        if value is None:
            return None
        item = _closed(
            value,
            "journey condition",
            frozenset({"source", "key", "operator", "value"}),
        )
        source = item["source"]
        operator = item["operator"]
        if source not in CONDITION_SOURCES or operator not in CONDITION_OPERATORS:
            raise ConsentProfileDataValidationError(
                "journey condition source or operator is unsupported"
            )
        key = _id(item["key"], "condition key")
        if source == "purpose":
            if operator != "equals" or item["value"] not in PURPOSE_SIGNALS:
                raise ConsentProfileDataValidationError(
                    "purpose conditions require exact grant or deny equality"
                )
            normalized: object = item["value"]
        else:
            definition = definitions.get(key)
            if definition is None or key in prompted_preferences:
                raise ConsentProfileDataValidationError(
                    "preference conditions require an already-collected published value"
                )
            if operator == "contains":
                if definition["value_type"] != "multi_select":
                    raise ConsentProfileDataValidationError(
                        "contains is allowed only for multi-select preferences"
                    )
                selected = _id(item["value"], "condition value")
                allowed = {
                    str(option["value_id"])
                    for option in definition["options"]  # type: ignore[index]
                }
                if selected not in allowed:
                    raise ConsentProfileDataValidationError(
                        "condition value is not a published option"
                    )
                normalized = selected
            else:
                normalized = _normalize_value(definition, item["value"])
        return {
            "source": source,
            "key": key,
            "operator": operator,
            "value": normalized,
        }

    @classmethod
    def _validate_stages(
        cls,
        value: object,
        catalog: PreferenceCatalog,
    ) -> tuple[dict[str, object], ...]:
        definitions = {str(item["preference_id"]): item for item in catalog.definitions}
        stages: list[dict[str, object]] = []
        seen_stages: set[str] = set()
        raw_stages = _sequence(
            value,
            "journey stages",
            minimum=1,
            maximum=_MAX_STAGES,
        )
        for raw in raw_stages:
            item = _closed(
                raw,
                "journey stage",
                frozenset(
                    {
                        "stage_id",
                        "priority",
                        "prompt_label_ref",
                        "preference_ids",
                        "condition",
                    }
                ),
            )
            stage_id = _id(item["stage_id"], "stage_id")
            if stage_id in seen_stages:
                raise ConsentProfileDataValidationError("journey stage IDs must be unique")
            seen_stages.add(stage_id)
            preference_ids = tuple(
                _id(candidate, "preference_id")
                for candidate in _sequence(
                    item["preference_ids"],
                    "stage preference_ids",
                    minimum=1,
                    maximum=64,
                )
            )
            if len(set(preference_ids)) != len(preference_ids) or not set(preference_ids).issubset(
                definitions
            ):
                raise ConsentProfileDataValidationError(
                    "stage preferences must be unique published definitions"
                )
            stages.append(
                {
                    "stage_id": stage_id,
                    "priority": _integer(item["priority"], "stage priority", 0, 10_000),
                    "prompt_label_ref": _id(item["prompt_label_ref"], "prompt_label_ref"),
                    "preference_ids": list(preference_ids),
                    "condition": cls._validate_condition(
                        item["condition"], definitions, frozenset(preference_ids)
                    ),
                }
            )
        return tuple(stages)

    @staticmethod
    def _get_journey(
        connection: sqlite3.Connection,
        tenant_id: str,
        journey_id: str,
        version: int,
    ) -> JourneyVersion:
        row = connection.execute(
            "SELECT * FROM journeys WHERE tenant_id=? AND journey_id=? AND version=?",
            (tenant_id, journey_id, version),
        ).fetchone()
        if row is None:
            raise ConsentProfileDataNotFound("progressive journey was not found")
        return ConsentProfileDataStore._journey_from(
            ConsentProfileDataStore._payload(row, "progressive journey"),
            row["integrity_sha256"],
        )

    def create_journey_version(
        self,
        tenant_id: str,
        journey_id: str,
        *,
        catalog_id: str,
        catalog_version: int,
        stages: Sequence[Mapping[str, object]],
        max_prompts: int,
        cooldown_seconds: int,
        frequency_cap: int,
        frequency_window_seconds: int,
        retention_seconds: int,
        expected_latest_version: int,
        idempotency_key: str,
    ) -> JourneyVersion:
        """Create an immutable draft tied to one exact published configuration."""

        tenant = _tenant(tenant_id)
        journey_key = _id(journey_id, "journey_id")
        catalog_key = _id(catalog_id, "catalog_id")
        catalog_ver = _integer(catalog_version, "catalog_version", 1, 1_000_000)
        prompts = _integer(max_prompts, "max_prompts", 1, 10)
        cooldown = _integer(cooldown_seconds, "cooldown_seconds", 60, 30 * 24 * 60 * 60)
        cap = _integer(frequency_cap, "frequency_cap", 1, 100)
        window = _integer(
            frequency_window_seconds,
            "frequency_window_seconds",
            cooldown,
            90 * 24 * 60 * 60,
        )
        retention = _retention(retention_seconds)
        expected = _integer(expected_latest_version, "expected_latest_version", 0, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        with self._connect() as connection:
            self._begin(connection)
            catalog = self._get_catalog(connection, tenant, catalog_key, catalog_ver)
            if catalog.state != "published":
                raise ConsentProfileDataPermissionDenied(
                    "journeys require an independently published catalog"
                )
            validated_stages = self._validate_stages(stages, catalog)
            request = {
                "action": "create_journey_version",
                "journey_id": journey_key,
                "catalog_id": catalog_key,
                "catalog_version": catalog_ver,
                "stages": list(validated_stages),
                "max_prompts": prompts,
                "cooldown_seconds": cooldown,
                "frequency_cap": cap,
                "frequency_window_seconds": window,
                "retention_seconds": retention,
                "expected_latest_version": expected,
                "actor": actor,
            }
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                return self._get_journey(
                    connection, tenant, journey_key, int(operation["result_id"])
                )
            row = connection.execute(
                "SELECT MAX(version) AS latest FROM journeys WHERE tenant_id=? AND journey_id=?",
                (tenant, journey_key),
            ).fetchone()
            latest = 0 if row is None or row["latest"] is None else int(row["latest"])
            if latest != expected:
                raise ConsentProfileDataConflict(
                    f"journey latest-version CAS failed: expected {expected}, found {latest}"
                )
            version = latest + 1
            payload = {
                "tenant_id": tenant,
                "journey_id": journey_key,
                "version": version,
                "property_id": catalog.property_id,
                "catalog_id": catalog.catalog_id,
                "catalog_version": catalog.version,
                "publication_sha256": catalog.publication_sha256,
                "bundle_sha256": catalog.bundle_sha256,
                "configuration_sha256": catalog.configuration_sha256,
                "policy_sha256": catalog.policy_sha256,
                "stages": list(validated_stages),
                "max_prompts": prompts,
                "cooldown_seconds": cooldown,
                "frequency_cap": cap,
                "frequency_window_seconds": window,
                "state": "draft",
                "revision": 1,
                "created_by": actor,
                "approved_by": None,
                "retained_until": now + retention,
                "created_at": now,
                "updated_at": now,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO journeys VALUES(?,?,?,?,?,?)",
                (
                    tenant,
                    journey_key,
                    version,
                    "draft",
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "journey",
                str(version),
            )
            self._audit(
                connection,
                tenant,
                "journey_created",
                f"{journey_key}:{version}",
                actor,
                {"stage_count": len(validated_stages)},
                now,
            )
            return self._journey_from(payload, digest)

    def get_journey_version(
        self,
        tenant_id: str,
        journey_id: str,
        version: int,
    ) -> JourneyVersion:
        tenant = _tenant(tenant_id)
        journey = _id(journey_id, "journey_id")
        selected = _integer(version, "version", 1, 1_000_000)
        with self._connect() as connection:
            return self._get_journey(connection, tenant, journey, selected)

    def list_journeys(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        """List one tenant's integrity-checked journey versions, newest first."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 500)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT journey_id,version FROM journeys WHERE tenant_id=? "
                "ORDER BY journey_id,version DESC LIMIT ?",
                (tenant, bounded + 1),
            ).fetchall()
            items = [
                self._get_journey(connection, tenant, str(row[0]), int(row[1]))
                for row in rows[:bounded]
            ]
        return {"items": items, "truncated": len(rows) > bounded}

    def approve_journey_version(
        self,
        tenant_id: str,
        journey_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> JourneyVersion:
        tenant = _tenant(tenant_id)
        journey = _id(journey_id, "journey_id")
        selected = _integer(version, "version", 1, 1_000_000)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "approve_journey_version",
            "journey_id": journey,
            "version": selected,
            "expected_revision": expected,
            "actor": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            current = self._get_journey(connection, tenant, journey, selected)
            if operation is not None:
                return current
            if current.revision != expected:
                raise ConsentProfileDataConflict(
                    f"journey revision CAS failed: expected {expected}, found {current.revision}"
                )
            if current.state != "draft":
                raise ConsentProfileDataConflict("journey is not a draft")
            if current.created_by == actor:
                raise ConsentProfileDataPermissionDenied(
                    "journey creators cannot approve their own version"
                )
            return self._update_journey(
                connection,
                current,
                state="approved",
                actor=actor,
                now=now,
                operation=(idempotency_key, request_sha),
                audit_action="journey_approved",
                approved_by=actor,
            )

    def _update_journey(
        self,
        connection: sqlite3.Connection,
        current: JourneyVersion,
        *,
        state: str,
        actor: str,
        now: float,
        operation: tuple[str, str],
        audit_action: str,
        approved_by: str | None = None,
    ) -> JourneyVersion:
        payload = {
            key: value for key, value in current.__dict__.items() if key != "integrity_sha256"
        }
        payload.update(
            {
                "stages": [dict(item) for item in current.stages],
                "state": state,
                "revision": current.revision + 1,
                "updated_at": now,
            }
        )
        if approved_by is not None:
            payload["approved_by"] = approved_by
        digest = _sha256(payload)
        connection.execute(
            "UPDATE journeys SET state=?,payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND journey_id=? AND version=?",
            (
                state,
                _canonical(payload).decode("ascii"),
                digest,
                current.tenant_id,
                current.journey_id,
                current.version,
            ),
        )
        idempotency_key, request_sha = operation
        self._record_operation(
            connection,
            current.tenant_id,
            idempotency_key,
            request_sha,
            "journey",
            str(current.version),
        )
        self._audit(
            connection,
            current.tenant_id,
            audit_action,
            f"{current.journey_id}:{current.version}",
            actor,
            {"state": state},
            now,
        )
        return self._journey_from(payload, digest)

    def _transition_journey(
        self,
        tenant_id: str,
        journey_id: str,
        version: int,
        *,
        target: str,
        allowed: frozenset[str],
        expected_revision: int,
        idempotency_key: str,
    ) -> JourneyVersion:
        tenant = _tenant(tenant_id)
        journey = _id(journey_id, "journey_id")
        selected = _integer(version, "version", 1, 1_000_000)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        action = f"journey_{target}"
        request = {
            "action": action,
            "journey_id": journey,
            "version": selected,
            "expected_revision": expected,
            "actor": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            current = self._get_journey(connection, tenant, journey, selected)
            if operation is not None:
                return current
            if current.revision != expected:
                raise ConsentProfileDataConflict(
                    f"journey revision CAS failed: expected {expected}, found {current.revision}"
                )
            if current.state not in allowed:
                raise ConsentProfileDataConflict(
                    f"journey cannot transition from {current.state} to {target}"
                )
            if target == "active":
                other = connection.execute(
                    "SELECT 1 FROM journeys WHERE tenant_id=? AND state='active' "
                    "AND json_extract(payload_json,'$.property_id')=? "
                    "AND json_extract(payload_json,'$.configuration_sha256')=? "
                    "AND NOT (journey_id=? AND version=?) LIMIT 1",
                    (
                        tenant,
                        current.property_id,
                        current.configuration_sha256,
                        journey,
                        selected,
                    ),
                ).fetchone()
                if other is not None:
                    raise ConsentProfileDataConflict(
                        "another journey is already active for this configuration"
                    )
            return self._update_journey(
                connection,
                current,
                state=target,
                actor=actor,
                now=now,
                operation=(idempotency_key, request_sha),
                audit_action=action,
            )

    def activate_journey(
        self,
        tenant_id: str,
        journey_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> JourneyVersion:
        return self._transition_journey(
            tenant_id,
            journey_id,
            version,
            target="active",
            allowed=frozenset({"approved", "paused"}),
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def pause_journey(
        self,
        tenant_id: str,
        journey_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> JourneyVersion:
        return self._transition_journey(
            tenant_id,
            journey_id,
            version,
            target="paused",
            allowed=frozenset({"active"}),
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def kill_journey(
        self,
        tenant_id: str,
        journey_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> JourneyVersion:
        return self._transition_journey(
            tenant_id,
            journey_id,
            version,
            target="killed",
            allowed=frozenset({"approved", "active", "paused"}),
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def rollback_journey(
        self,
        tenant_id: str,
        journey_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> JourneyVersion:
        return self._transition_journey(
            tenant_id,
            journey_id,
            version,
            target="rolled_back",
            allowed=frozenset({"active", "paused"}),
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def _profile_token(binding: Mapping[str, object]) -> str:
        return hashlib.sha256(
            (
                "consent-profile-prompt\0"
                + str(binding["tenant_id"])
                + "\0"
                + str(binding["profile_id"])
                + "\0"
                + str(binding["profile_capability_sha256"])
            ).encode()
        ).hexdigest()

    @staticmethod
    def _prompt_item(
        definition: Mapping[str, object],
        stage_id: str,
    ) -> PromptItem:
        return PromptItem(
            stage_id=stage_id,
            preference_id=str(definition["preference_id"]),
            definition_version=int(definition["definition_version"]),
            label_ref=str(definition["label_ref"]),
            value_type=str(definition["value_type"]),
            required=bool(definition["required"]),
            options=tuple(dict(option) for option in definition["options"]),  # type: ignore[arg-type]
        )

    @staticmethod
    def _prompt_json(item: PromptItem) -> dict[str, object]:
        return {
            "stage_id": item.stage_id,
            "preference_id": item.preference_id,
            "definition_version": item.definition_version,
            "label_ref": item.label_ref,
            "value_type": item.value_type,
            "required": item.required,
            "options": [dict(option) for option in item.options],
        }

    @staticmethod
    def _assignment_json(assignment: PromptAssignment) -> dict[str, object]:
        return {
            "assignment_id": assignment.assignment_id,
            "binding_sha256": assignment.binding_sha256,
            "profile_token": assignment.profile_token,
            "journey_id": assignment.journey_id,
            "journey_version": assignment.journey_version,
            "journey_sha256": assignment.journey_sha256,
            "stage_ids": list(assignment.stage_ids),
            "prompts": [ConsentProfileDataStore._prompt_json(item) for item in assignment.prompts],
            "eligible": assignment.eligible,
            "reason": assignment.reason,
            "assigned_at": assignment.assigned_at,
        }

    @staticmethod
    def _assignment_from_json(value: Mapping[str, Any]) -> PromptAssignment:
        return PromptAssignment(
            assignment_id=str(value["assignment_id"]),
            binding_sha256=str(value["binding_sha256"]),
            profile_token=str(value["profile_token"]),
            journey_id=str(value["journey_id"]),
            journey_version=int(value["journey_version"]),
            journey_sha256=str(value["journey_sha256"]),
            stage_ids=tuple(value["stage_ids"]),
            prompts=tuple(
                PromptItem(
                    stage_id=str(item["stage_id"]),
                    preference_id=str(item["preference_id"]),
                    definition_version=int(item["definition_version"]),
                    label_ref=str(item["label_ref"]),
                    value_type=str(item["value_type"]),
                    required=bool(item["required"]),
                    options=tuple(dict(option) for option in item["options"]),
                )
                for item in value["prompts"]
            ),
            eligible=bool(value["eligible"]),
            reason=str(value["reason"]),
            assigned_at=float(value["assigned_at"]),
        )

    @staticmethod
    def _condition_met(
        condition: object,
        current: Mapping[str, ProfileValue],
        purpose_signals: Mapping[str, str],
        now: float,
    ) -> bool:
        if condition is None:
            return True
        if not isinstance(condition, Mapping):
            raise ConsentProfileDataIntegrityError("journey condition is invalid")
        source = condition["source"]
        key = str(condition["key"])
        if source == "purpose":
            actual: object = purpose_signals.get(key)
        else:
            stored = current.get(key)
            if (
                stored is None
                or stored.status != "active"
                or (stored.expires_at is not None and stored.expires_at <= now)
            ):
                return False
            actual = stored.value
        if condition["operator"] == "equals":
            return actual == condition["value"]
        if condition["operator"] == "contains":
            return isinstance(actual, list) and condition["value"] in actual
        raise ConsentProfileDataIntegrityError("journey condition operator is invalid")

    @staticmethod
    def _increment_aggregate(
        connection: sqlite3.Connection,
        tenant_id: str,
        journey: JourneyVersion,
        stage_id: str,
        preference_id: str,
        outcome: str,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM prompt_aggregates WHERE tenant_id=? AND journey_id=? "
            "AND version=? AND stage_id=? AND preference_id=?",
            (tenant_id, journey.journey_id, journey.version, stage_id, preference_id),
        ).fetchone()
        if row is None:
            payload: dict[str, object] = {
                "tenant_id": tenant_id,
                "journey_id": journey.journey_id,
                "version": journey.version,
                "stage_id": stage_id,
                "preference_id": preference_id,
                "exposures": 0,
                "completions": 0,
                "dismissals": 0,
            }
        else:
            payload = ConsentProfileDataStore._payload(row, "prompt aggregate")
        field = {
            "exposure": "exposures",
            "completed": "completions",
            "dismissed": "dismissals",
        }[outcome]
        payload[field] = int(payload[field]) + 1
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO prompt_aggregates VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(tenant_id,journey_id,version,stage_id,preference_id) "
            "DO UPDATE SET payload_json=excluded.payload_json,"
            "integrity_sha256=excluded.integrity_sha256",
            (
                tenant_id,
                journey.journey_id,
                journey.version,
                stage_id,
                preference_id,
                _canonical(payload).decode("ascii"),
                digest,
            ),
        )

    def assign_prompt(
        self,
        authority: PublicProfileAuthority,
        context: PromptContext,
        journey_id: str,
        *,
        idempotency_key: str,
    ) -> PromptAssignment:
        """Choose and record a safe deterministic prompt or explicit no-prompt."""

        binding = self._authority_body(authority)
        if type(context) is not PromptContext:
            raise ConsentProfileDataPermissionDenied(
                "a server-constructed PromptContext is required"
            )
        journey_key = _id(journey_id, "journey_id")
        operation_key = _id(idempotency_key, "idempotency_key", _OP_RE)
        tenant = str(binding["tenant_id"])
        profile = str(binding["profile_id"])
        binding_sha = _sha256(binding)
        profile_token = self._profile_token(binding)
        purpose_signals = dict(context.purpose_signals)
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "assign_prompt",
            "binding_sha256": binding_sha,
            "journey_id": journey_key,
            "context_sha256": _sha256({"purpose_signals": list(context.purpose_signals)}),
        }
        with self._connect() as connection:
            self._begin(connection)
            catalog = self._bound_catalog(connection, binding)
            self._require_profile_binding(connection, tenant, profile, binding_sha)
            request_sha, operation = self._operation(connection, tenant, operation_key, request)
            if operation is not None:
                row = connection.execute(
                    "SELECT * FROM prompt_events WHERE tenant_id=? AND event_id=?",
                    (tenant, operation["result_id"]),
                ).fetchone()
                if row is None:
                    raise ConsentProfileDataIntegrityError("prompt idempotency result is missing")
                event = self._payload(row, "prompt event")
                return self._assignment_from_json(event["assignment"])
            row = connection.execute(
                "SELECT * FROM journeys WHERE tenant_id=? AND journey_id=? "
                "AND state='active' "
                "AND json_extract(payload_json,'$.retained_until')>? "
                "ORDER BY version DESC LIMIT 1",
                (tenant, journey_key, now),
            ).fetchone()
            assignment_id = (
                "prompt-" + hashlib.sha256(f"{tenant}\0{operation_key}".encode()).hexdigest()[:40]
            )
            if row is None:
                assignment = PromptAssignment(
                    assignment_id=assignment_id,
                    binding_sha256=binding_sha,
                    profile_token=profile_token,
                    journey_id=journey_key,
                    journey_version=0,
                    journey_sha256="0" * 64,
                    stage_ids=(),
                    prompts=(),
                    eligible=False,
                    reason="not_active",
                    assigned_at=now,
                )
                retained_until = now + _MIN_RETENTION_SECONDS
                journey = None
            else:
                journey = self._journey_from(
                    self._payload(row, "progressive journey"), row["integrity_sha256"]
                )
                expected_binding = {
                    "property_id": catalog.property_id,
                    "catalog_id": catalog.catalog_id,
                    "catalog_version": catalog.version,
                    "publication_sha256": catalog.publication_sha256,
                    "bundle_sha256": catalog.bundle_sha256,
                    "configuration_sha256": catalog.configuration_sha256,
                    "policy_sha256": catalog.policy_sha256,
                }
                actual_binding = {key: getattr(journey, key) for key in expected_binding}
                if actual_binding != expected_binding:
                    raise ConsentProfileDataIntegrityError(
                        "active journey publication binding is inconsistent"
                    )
                value_rows = connection.execute(
                    "SELECT * FROM profile_values WHERE tenant_id=? AND profile_id=?",
                    (tenant, profile),
                ).fetchall()
                current = {
                    str(payload["preference_id"]): self._value_from(
                        payload, value_row["integrity_sha256"]
                    )
                    for value_row in value_rows
                    for payload in [self._payload(value_row, "profile value")]
                }
                recent_rows = connection.execute(
                    "SELECT * FROM prompt_events WHERE tenant_id=? AND profile_token=? "
                    "AND journey_id=? AND occurred_at>=? ORDER BY occurred_at DESC",
                    (
                        tenant,
                        profile_token,
                        journey.journey_id,
                        now - journey.frequency_window_seconds,
                    ),
                ).fetchall()
                recent_events = [self._payload(item, "prompt event") for item in recent_rows]
                exposures = sum(item["event_type"] == "exposure" for item in recent_events)
                definitions = {str(item["preference_id"]): item for item in catalog.definitions}
                candidates: list[tuple[bool, int, int, int, str, str]] = []
                condition_matched = False
                missing_seen = False
                cooldown_seen = False
                for stage_index, stage in enumerate(journey.stages):
                    if not self._condition_met(stage["condition"], current, purpose_signals, now):
                        continue
                    condition_matched = True
                    for preference_index, preference in enumerate(
                        stage["preference_ids"]  # type: ignore[union-attr]
                    ):
                        definition = definitions[str(preference)]
                        existing = current.get(str(preference))
                        if (
                            existing is not None
                            and existing.status == "active"
                            and (existing.expires_at is None or existing.expires_at > now)
                        ):
                            continue
                        missing_seen = True
                        recently_prompted = any(
                            event["event_type"] == "exposure"
                            and event["occurred_at"] > now - journey.cooldown_seconds
                            and str(preference) in event["preference_ids"]
                            for event in recent_events
                        )
                        if recently_prompted:
                            cooldown_seen = True
                            continue
                        candidates.append(
                            (
                                not bool(definition["required"]),
                                int(stage["priority"]),
                                stage_index,
                                preference_index,
                                str(stage["stage_id"]),
                                str(preference),
                            )
                        )
                candidates.sort()
                if exposures >= journey.frequency_cap:
                    selected_candidates: list[tuple[bool, int, int, int, str, str]] = []
                    reason = "frequency_cap"
                else:
                    selected_candidates = candidates[: journey.max_prompts]
                    if selected_candidates:
                        reason = "assigned"
                    elif cooldown_seen:
                        reason = "cooldown"
                    elif condition_matched and not missing_seen:
                        reason = "complete"
                    else:
                        reason = "conditions_unmet"
                prompt_items = tuple(
                    self._prompt_item(definitions[item[5]], item[4]) for item in selected_candidates
                )
                stage_ids = tuple(dict.fromkeys(item[4] for item in selected_candidates))
                assignment = PromptAssignment(
                    assignment_id=assignment_id,
                    binding_sha256=binding_sha,
                    profile_token=profile_token,
                    journey_id=journey.journey_id,
                    journey_version=journey.version,
                    journey_sha256=journey.integrity_sha256,
                    stage_ids=stage_ids,
                    prompts=prompt_items,
                    eligible=bool(prompt_items),
                    reason=reason,
                    assigned_at=now,
                )
                retained_until = journey.retained_until
            event_payload = {
                "tenant_id": tenant,
                "event_id": assignment_id,
                "profile_token": profile_token,
                "journey_id": journey_key,
                "journey_version": assignment.journey_version,
                "event_type": "exposure" if assignment.eligible else "no_prompt",
                "assignment": self._assignment_json(assignment),
                "preference_ids": [item.preference_id for item in assignment.prompts],
                "stage_ids": list(assignment.stage_ids),
                "stage_by_preference": {
                    item.preference_id: item.stage_id for item in assignment.prompts
                },
                "parent_assignment_id": None,
                "occurred_at": now,
                "retained_until": retained_until,
            }
            event_digest = _sha256(event_payload)
            connection.execute(
                "INSERT INTO prompt_events VALUES(?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    assignment_id,
                    profile_token,
                    journey_key,
                    now,
                    retained_until,
                    _canonical(event_payload).decode("ascii"),
                    event_digest,
                ),
            )
            if journey is not None and assignment.eligible:
                stage_by_preference = {
                    candidate[5]: candidate[4] for candidate in selected_candidates
                }
                for item in assignment.prompts:
                    self._increment_aggregate(
                        connection,
                        tenant,
                        journey,
                        stage_by_preference[item.preference_id],
                        item.preference_id,
                        "exposure",
                    )
            self._record_operation(
                connection,
                tenant,
                operation_key,
                request_sha,
                "prompt_assignment",
                assignment_id,
            )
            self._audit(
                connection,
                tenant,
                "prompt_assigned",
                assignment_id,
                "public-profile",
                {
                    "eligible": assignment.eligible,
                    "reason": assignment.reason,
                    "prompt_count": len(assignment.prompts),
                },
                now,
            )
            return assignment

    def record_prompt_interaction(
        self,
        authority: PublicProfileAuthority,
        assignment: PromptAssignment,
        outcome: str,
        *,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        """Record one deduplicated completion/dismissal with aggregate-only detail."""

        binding = self._authority_body(authority)
        if type(assignment) is not PromptAssignment:
            raise ConsentProfileDataPermissionDenied("a server-issued PromptAssignment is required")
        if outcome not in PROMPT_OUTCOMES:
            raise ConsentProfileDataValidationError("prompt outcome is unsupported")
        tenant = str(binding["tenant_id"])
        profile = str(binding["profile_id"])
        binding_sha = _sha256(binding)
        profile_token = self._profile_token(binding)
        if (
            assignment.binding_sha256 != binding_sha
            or assignment.profile_token != profile_token
            or not assignment.eligible
        ):
            raise ConsentProfileDataPermissionDenied(
                "prompt assignment does not belong to this profile authority"
            )
        operation_key = _id(idempotency_key, "idempotency_key", _OP_RE)
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "record_prompt_interaction",
            "binding_sha256": binding_sha,
            "assignment_sha256": _sha256(self._assignment_json(assignment)),
            "outcome": outcome,
        }
        event_id = (
            "interaction-" + hashlib.sha256(f"{tenant}\0{operation_key}".encode()).hexdigest()[:40]
        )
        with self._connect() as connection:
            self._begin(connection)
            self._bound_catalog(connection, binding)
            self._require_profile_binding(connection, tenant, profile, binding_sha)
            request_sha, operation = self._operation(connection, tenant, operation_key, request)
            if operation is not None:
                row = connection.execute(
                    "SELECT * FROM prompt_events WHERE tenant_id=? AND event_id=?",
                    (tenant, operation["result_id"]),
                ).fetchone()
                if row is None:
                    raise ConsentProfileDataIntegrityError(
                        "prompt interaction idempotency result is missing"
                    )
                return self._payload(row, "prompt interaction")
            exposure_row = connection.execute(
                "SELECT * FROM prompt_events WHERE tenant_id=? AND event_id=?",
                (tenant, assignment.assignment_id),
            ).fetchone()
            if exposure_row is None:
                raise ConsentProfileDataPermissionDenied("prompt assignment is unknown")
            exposure = self._payload(exposure_row, "prompt exposure")
            if exposure["assignment"] != self._assignment_json(assignment):
                raise ConsentProfileDataIntegrityError(
                    "prompt assignment differs from its stored exposure"
                )
            duplicate = connection.execute(
                "SELECT 1 FROM prompt_events WHERE tenant_id=? AND profile_token=? "
                "AND json_extract(payload_json,'$.parent_assignment_id')=? "
                "AND json_extract(payload_json,'$.event_type') IN ('completed','dismissed')",
                (tenant, profile_token, assignment.assignment_id),
            ).fetchone()
            if duplicate is not None:
                raise ConsentProfileDataConflict(
                    "prompt assignment already has a terminal interaction"
                )
            journey = self._get_journey(
                connection, tenant, assignment.journey_id, assignment.journey_version
            )
            if journey.integrity_sha256 != assignment.journey_sha256:
                raise ConsentProfileDataIntegrityError(
                    "prompt assignment journey digest is stale or invalid"
                )
            if outcome == "completed":
                for prompt in assignment.prompts:
                    current = self._get_value_row(connection, tenant, profile, prompt.preference_id)
                    if (
                        current is None
                        or current[0].status != "active"
                        or (current[0].expires_at is not None and current[0].expires_at <= now)
                    ):
                        raise ConsentProfileDataConflict(
                            "prompt completion requires every prompted value"
                        )
            event_payload = {
                "tenant_id": tenant,
                "event_id": event_id,
                "profile_token": profile_token,
                "journey_id": assignment.journey_id,
                "journey_version": assignment.journey_version,
                "event_type": outcome,
                "assignment": None,
                "preference_ids": [item.preference_id for item in assignment.prompts],
                "stage_ids": list(assignment.stage_ids),
                "stage_by_preference": {
                    item.preference_id: item.stage_id for item in assignment.prompts
                },
                "parent_assignment_id": assignment.assignment_id,
                "occurred_at": now,
                "retained_until": journey.retained_until,
            }
            digest = _sha256(event_payload)
            connection.execute(
                "INSERT INTO prompt_events VALUES(?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    event_id,
                    profile_token,
                    assignment.journey_id,
                    now,
                    journey.retained_until,
                    _canonical(event_payload).decode("ascii"),
                    digest,
                ),
            )
            for prompt in assignment.prompts:
                self._increment_aggregate(
                    connection,
                    tenant,
                    journey,
                    prompt.stage_id,
                    prompt.preference_id,
                    outcome,
                )
            self._record_operation(
                connection,
                tenant,
                operation_key,
                request_sha,
                "prompt_interaction",
                event_id,
            )
            self._audit(
                connection,
                tenant,
                "prompt_interaction_recorded",
                event_id,
                "public-profile",
                {"outcome": outcome, "prompt_count": len(assignment.prompts)},
                now,
            )
            return event_payload

    def consumer_view(
        self,
        authority: PublicProfileAuthority,
    ) -> ConsumerProfileView:
        """Return every retained record associated with the verified profile."""

        binding = self._authority_body(authority)
        tenant = str(binding["tenant_id"])
        profile = str(binding["profile_id"])
        token = self._profile_token(binding)
        binding_sha = _sha256(binding)
        now = _timestamp(self._clock(), "current time")
        with self._connect() as connection:
            self._bound_catalog(connection, binding)
            self._require_profile_binding(connection, tenant, profile, binding_sha)
            value_rows = connection.execute(
                "SELECT * FROM profile_values WHERE tenant_id=? AND profile_id=? "
                "ORDER BY preference_id",
                (tenant, profile),
            ).fetchall()
            values = tuple(
                self._value_from(self._payload(row, "profile value"), row["integrity_sha256"])
                for row in value_rows
            )
            active = {
                item.preference_id: item.value
                for item in values
                if item.status == "active" and (item.expires_at is None or item.expires_at > now)
            }
            history = self.value_history(authority)
            event_rows = connection.execute(
                "SELECT * FROM prompt_events WHERE tenant_id=? AND profile_token=? "
                "ORDER BY occurred_at,event_id",
                (tenant, token),
            ).fetchall()
            interactions = tuple(self._payload(row, "prompt event") for row in event_rows)
            return ConsumerProfileView(
                tenant_id=tenant,
                profile_id=profile,
                current_records=values,
                active_values=active,
                history=history,
                prompt_interactions=interactions,
                generated_at=now,
            )

    def export_profile(
        self,
        authority: PublicProfileAuthority,
    ) -> ProfileExport:
        """Produce a canonical consumer-facing export without creating new state."""

        view = self.consumer_view(authority)
        body = {
            "schema": EXPORT_SCHEMA,
            "tenant_id": view.tenant_id,
            "profile_id": view.profile_id,
            "current_records": [dict(item.__dict__) for item in view.current_records],
            "active_values": dict(view.active_values),
            "history": [dict(item.__dict__) for item in view.history],
            "prompt_interactions": [dict(item) for item in view.prompt_interactions],
            "generated_at": view.generated_at,
            "product_boundaries": dict(product_boundaries()),
        }
        return ProfileExport(
            schema=EXPORT_SCHEMA,
            tenant_id=view.tenant_id,
            profile_id=view.profile_id,
            body=body,
            export_sha256=_sha256(body),
        )

    @staticmethod
    def _decrement_event_aggregate(
        connection: sqlite3.Connection,
        event: Mapping[str, object],
    ) -> None:
        event_type = event["event_type"]
        if event_type not in {"exposure", "completed", "dismissed"}:
            return
        field = {
            "exposure": "exposures",
            "completed": "completions",
            "dismissed": "dismissals",
        }[str(event_type)]
        for preference_id, stage_id in event["stage_by_preference"].items():  # type: ignore[union-attr]
            row = connection.execute(
                "SELECT * FROM prompt_aggregates WHERE tenant_id=? AND journey_id=? "
                "AND version=? AND stage_id=? AND preference_id=?",
                (
                    event["tenant_id"],
                    event["journey_id"],
                    event["journey_version"],
                    stage_id,
                    preference_id,
                ),
            ).fetchone()
            if row is None:
                raise ConsentProfileDataIntegrityError("prompt event aggregate is missing")
            payload = ConsentProfileDataStore._payload(row, "prompt aggregate")
            if int(payload[field]) <= 0:
                raise ConsentProfileDataIntegrityError("prompt aggregate cannot be decremented")
            payload[field] = int(payload[field]) - 1
            if all(
                int(payload[count_field]) == 0
                for count_field in ("exposures", "completions", "dismissals")
            ):
                connection.execute(
                    "DELETE FROM prompt_aggregates WHERE tenant_id=? "
                    "AND journey_id=? AND version=? AND stage_id=? "
                    "AND preference_id=?",
                    (
                        event["tenant_id"],
                        event["journey_id"],
                        event["journey_version"],
                        stage_id,
                        preference_id,
                    ),
                )
                continue
            digest = _sha256(payload)
            connection.execute(
                "UPDATE prompt_aggregates SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND journey_id=? AND version=? AND stage_id=? "
                "AND preference_id=?",
                (
                    _canonical(payload).decode("ascii"),
                    digest,
                    event["tenant_id"],
                    event["journey_id"],
                    event["journey_version"],
                    stage_id,
                    preference_id,
                ),
            )

    def purge_expired(
        self,
        tenant_id: str,
        *,
        before: float,
        idempotency_key: str,
    ) -> Mapping[str, int]:
        """Apply record retention and preserve receipt-chain checkpoints."""

        tenant = _tenant(tenant_id)
        cutoff = _timestamp(before, "before")
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {"action": "purge_expired", "before": cutoff, "actor": actor}
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                try:
                    result = json.loads(operation["result_id"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ConsentProfileDataIntegrityError(
                        "purge idempotency result is invalid"
                    ) from exc
                if not isinstance(result, dict):
                    raise ConsentProfileDataIntegrityError("purge idempotency result is invalid")
                return {str(key): int(value) for key, value in result.items()}
            values = connection.execute(
                "DELETE FROM profile_values WHERE tenant_id=? "
                "AND json_extract(payload_json,'$.retained_until')<=?",
                (tenant, cutoff),
            ).rowcount
            profile_rows = connection.execute(
                "SELECT DISTINCT profile_id FROM value_receipts WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            receipts = 0
            for profile_row in profile_rows:
                profile = str(profile_row["profile_id"])
                rows = connection.execute(
                    "SELECT * FROM value_receipts WHERE tenant_id=? AND profile_id=? "
                    "ORDER BY sequence",
                    (tenant, profile),
                ).fetchall()
                purge_rows: list[sqlite3.Row] = []
                for row in rows:
                    if float(row["retained_until"]) > cutoff:
                        break
                    purge_rows.append(row)
                if purge_rows:
                    last = purge_rows[-1]
                    checkpoint = {
                        "tenant_id": tenant,
                        "profile_id": profile,
                        "last_sequence": int(last["sequence"]),
                        "last_sha256": str(last["integrity_sha256"]),
                    }
                    connection.execute(
                        "INSERT INTO receipt_checkpoints VALUES(?,?,?,?,?) "
                        "ON CONFLICT(tenant_id,profile_id) DO UPDATE SET "
                        "last_sequence=excluded.last_sequence,last_sha256=excluded.last_sha256,"
                        "integrity_sha256=excluded.integrity_sha256",
                        (
                            tenant,
                            profile,
                            checkpoint["last_sequence"],
                            checkpoint["last_sha256"],
                            _sha256(checkpoint),
                        ),
                    )
                    receipts += connection.execute(
                        "DELETE FROM value_receipts WHERE tenant_id=? AND profile_id=? "
                        "AND sequence<=?",
                        (tenant, profile, checkpoint["last_sequence"]),
                    ).rowcount
            event_rows = connection.execute(
                "SELECT * FROM prompt_events WHERE tenant_id=? AND retained_until<=?",
                (tenant, cutoff),
            ).fetchall()
            for event_row in event_rows:
                self._decrement_event_aggregate(
                    connection, self._payload(event_row, "prompt event")
                )
            events = connection.execute(
                "DELETE FROM prompt_events WHERE tenant_id=? AND retained_until<=?",
                (tenant, cutoff),
            ).rowcount
            journey_rows = connection.execute(
                "SELECT journey_id,version FROM journeys WHERE tenant_id=? "
                "AND json_extract(payload_json,'$.retained_until')<=?",
                (tenant, cutoff),
            ).fetchall()
            aggregates = 0
            journeys = 0
            for journey_row in journey_rows:
                aggregates += connection.execute(
                    "DELETE FROM prompt_aggregates WHERE tenant_id=? AND journey_id=? "
                    "AND version=?",
                    (tenant, journey_row["journey_id"], journey_row["version"]),
                ).rowcount
                journeys += connection.execute(
                    "DELETE FROM journeys WHERE tenant_id=? AND journey_id=? AND version=?",
                    (tenant, journey_row["journey_id"], journey_row["version"]),
                ).rowcount
            catalog_rows = connection.execute(
                "SELECT catalog_id,version FROM catalogs WHERE tenant_id=? "
                "AND json_extract(payload_json,'$.retained_until')<=?",
                (tenant, cutoff),
            ).fetchall()
            catalogs = 0
            for catalog_row in catalog_rows:
                referenced = connection.execute(
                    "SELECT 1 FROM profile_values WHERE tenant_id=? "
                    "AND json_extract(payload_json,'$.catalog_id')=? "
                    "AND json_extract(payload_json,'$.catalog_version')=? "
                    "UNION ALL SELECT 1 FROM journeys WHERE tenant_id=? "
                    "AND json_extract(payload_json,'$.catalog_id')=? "
                    "AND json_extract(payload_json,'$.catalog_version')=? LIMIT 1",
                    (
                        tenant,
                        catalog_row["catalog_id"],
                        catalog_row["version"],
                        tenant,
                        catalog_row["catalog_id"],
                        catalog_row["version"],
                    ),
                ).fetchone()
                if referenced is None:
                    catalogs += connection.execute(
                        "DELETE FROM catalogs WHERE tenant_id=? AND catalog_id=? AND version=?",
                        (tenant, catalog_row["catalog_id"], catalog_row["version"]),
                    ).rowcount
            checkpoint_rows = connection.execute(
                "SELECT profile_id FROM receipt_checkpoints WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            checkpoints = 0
            for checkpoint_row in checkpoint_rows:
                profile = checkpoint_row["profile_id"]
                retained = connection.execute(
                    "SELECT 1 FROM value_receipts WHERE tenant_id=? AND profile_id=? "
                    "UNION ALL SELECT 1 FROM profile_values WHERE tenant_id=? AND profile_id=? "
                    "LIMIT 1",
                    (tenant, profile, tenant, profile),
                ).fetchone()
                if retained is None:
                    checkpoints += connection.execute(
                        "DELETE FROM receipt_checkpoints WHERE tenant_id=? AND profile_id=?",
                        (tenant, profile),
                    ).rowcount
            result = {
                "profile_values": values,
                "value_receipts": receipts,
                "prompt_events": events,
                "prompt_aggregates": aggregates,
                "journeys": journeys,
                "catalogs": catalogs,
                "receipt_checkpoints": checkpoints,
            }
            encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "purge",
                encoded,
            )
            self._audit(
                connection,
                tenant,
                "retention_purged",
                "profile-data-retention",
                actor,
                {"before": cutoff, "counts": result},
                now,
            )
            return result

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:  # noqa: C901
        """Verify row digests, receipt/audit chains, indexes, and aggregates."""

        tenant = _tenant(tenant_id)
        verified = 0
        receipt_count = 0
        with self._connect() as connection:
            table_rows: dict[str, list[sqlite3.Row]] = {}
            for table in (
                "catalogs",
                "profile_values",
                "journeys",
                "prompt_events",
                "prompt_aggregates",
            ):
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                table_rows[table] = rows
                for row in rows:
                    payload = self._payload(row, table)
                    if payload.get("tenant_id") != tenant:
                        raise ConsentProfileDataIntegrityError(
                            f"persisted {table} tenant binding is inconsistent"
                        )
                    if table == "journeys" and (
                        payload.get("journey_id") != row["journey_id"]
                        or payload.get("version") != row["version"]
                        or payload.get("state") != row["state"]
                        or payload.get("state") not in JOURNEY_STATES
                    ):
                        raise ConsentProfileDataIntegrityError("journey indexes are inconsistent")
                    if table == "catalogs" and (
                        payload.get("catalog_id") != row["catalog_id"]
                        or payload.get("version") != row["version"]
                        or payload.get("state") not in CATALOG_STATES
                    ):
                        raise ConsentProfileDataIntegrityError(
                            "catalog indexes or state are inconsistent"
                        )
                    if table == "profile_values" and (
                        payload.get("profile_id") != row["profile_id"]
                        or payload.get("preference_id") != row["preference_id"]
                    ):
                        raise ConsentProfileDataIntegrityError(
                            "profile value indexes are inconsistent"
                        )
                    if table == "prompt_events" and (
                        payload.get("event_id") != row["event_id"]
                        or payload.get("profile_token") != row["profile_token"]
                        or payload.get("occurred_at") != row["occurred_at"]
                        or payload.get("retained_until") != row["retained_until"]
                    ):
                        raise ConsentProfileDataIntegrityError("prompt event index is inconsistent")
                    if table == "prompt_aggregates" and (
                        payload.get("journey_id") != row["journey_id"]
                        or payload.get("version") != row["version"]
                        or payload.get("stage_id") != row["stage_id"]
                        or payload.get("preference_id") != row["preference_id"]
                    ):
                        raise ConsentProfileDataIntegrityError(
                            "prompt aggregate indexes are inconsistent"
                        )
                    verified += 1
            checkpoint_rows = connection.execute(
                "SELECT * FROM receipt_checkpoints WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            checkpoints: dict[str, tuple[int, str]] = {}
            for row in checkpoint_rows:
                body = {
                    "tenant_id": row["tenant_id"],
                    "profile_id": row["profile_id"],
                    "last_sequence": row["last_sequence"],
                    "last_sha256": row["last_sha256"],
                }
                if _sha256(body) != row["integrity_sha256"]:
                    raise ConsentProfileDataIntegrityError(
                        "receipt checkpoint failed integrity verification"
                    )
                checkpoints[str(row["profile_id"])] = (
                    int(row["last_sequence"]),
                    str(row["last_sha256"]),
                )
                verified += 1
            receipt_rows = connection.execute(
                "SELECT * FROM value_receipts WHERE tenant_id=? ORDER BY profile_id,sequence",
                (tenant,),
            ).fetchall()
            receipt_profiles = {str(row["profile_id"]) for row in receipt_rows} | set(checkpoints)
            for profile in receipt_profiles:
                expected_sequence, previous = checkpoints.get(profile, (0, "0" * 64))
                for row in (item for item in receipt_rows if item["profile_id"] == profile):
                    payload = self._payload(row, "value receipt")
                    expected_sequence += 1
                    if (
                        row["sequence"] != expected_sequence
                        or payload.get("sequence") != expected_sequence
                        or payload.get("tenant_id") != tenant
                        or payload.get("profile_id") != profile
                        or payload.get("previous_receipt_sha256") != previous
                        or payload.get("receipt_id") != row["receipt_id"]
                        or payload.get("retained_until") != row["retained_until"]
                    ):
                        raise ConsentProfileDataIntegrityError(
                            "profile value receipt chain is inconsistent"
                        )
                    previous = row["integrity_sha256"]
                    receipt_count += 1
                    verified += 1
            for row in table_rows["profile_values"]:
                payload = self._payload(row, "profile value")
                receipt = connection.execute(
                    "SELECT * FROM value_receipts WHERE tenant_id=? AND receipt_id=?",
                    (tenant, payload["receipt_id"]),
                ).fetchone()
                if receipt is None:
                    raise ConsentProfileDataIntegrityError(
                        "current profile value receipt is missing"
                    )
                receipt_payload = self._payload(receipt, "value receipt")
                if receipt_payload.get("value_record_sha256") != row["integrity_sha256"]:
                    raise ConsentProfileDataIntegrityError(
                        "current profile value and receipt digests disagree"
                    )
            computed: dict[tuple[str, int, str, str], dict[str, int]] = {}
            for row in table_rows["prompt_events"]:
                event = self._payload(row, "prompt event")
                event_type = event["event_type"]
                if event_type not in {"exposure", "completed", "dismissed"}:
                    continue
                field = {
                    "exposure": "exposures",
                    "completed": "completions",
                    "dismissed": "dismissals",
                }[str(event_type)]
                for preference, stage in event["stage_by_preference"].items():
                    key = (
                        str(event["journey_id"]),
                        int(event["journey_version"]),
                        str(stage),
                        str(preference),
                    )
                    counts = computed.setdefault(
                        key,
                        {"exposures": 0, "completions": 0, "dismissals": 0},
                    )
                    counts[field] += 1
            aggregate_keys: set[tuple[str, int, str, str]] = set()
            for row in table_rows["prompt_aggregates"]:
                payload = self._payload(row, "prompt aggregate")
                key = (
                    str(payload["journey_id"]),
                    int(payload["version"]),
                    str(payload["stage_id"]),
                    str(payload["preference_id"]),
                )
                aggregate_keys.add(key)
                actual = {
                    field: int(payload[field])
                    for field in ("exposures", "completions", "dismissals")
                }
                if actual != computed.get(key, {"exposures": 0, "completions": 0, "dismissals": 0}):
                    raise ConsentProfileDataIntegrityError(
                        "prompt aggregate does not match retained events"
                    )
            if set(computed) != aggregate_keys:
                raise ConsentProfileDataIntegrityError("retained prompt event aggregate is missing")
            operation_rows = connection.execute(
                "SELECT * FROM operations WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in operation_rows:
                binding = {
                    "tenant_id": row["tenant_id"],
                    "operation_sha256": row["operation_sha256"],
                    "request_sha256": row["request_sha256"],
                    "result_kind": row["result_kind"],
                    "result_id": row["result_id"],
                }
                if _sha256(binding) != row["integrity_sha256"]:
                    raise ConsentProfileDataIntegrityError(
                        "idempotency binding failed integrity verification"
                    )
                verified += 1
            audit_rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous = "0" * 64
            for expected_sequence, row in enumerate(audit_rows, 1):
                payload = self._payload(row, "audit event")
                if (
                    row["sequence"] != expected_sequence
                    or payload.get("sequence") != expected_sequence
                    or payload.get("tenant_id") != tenant
                    or payload.get("previous_sha256") != previous
                    or payload.get("schema") != AUDIT_SCHEMA
                ):
                    raise ConsentProfileDataIntegrityError(
                        "tenant audit hash chain is inconsistent"
                    )
                previous = row["integrity_sha256"]
                verified += 1
            return IntegrityVerification(
                tenant_id=tenant,
                verified_records=verified,
                receipts=receipt_count,
                audit_events=len(audit_rows),
                terminal_audit_sha256=previous,
            )


__all__ = [
    "ConsumerProfileView",
    "ConsentProfileDataConfigError",
    "ConsentProfileDataConflict",
    "ConsentProfileDataError",
    "ConsentProfileDataIntegrityError",
    "ConsentProfileDataNotFound",
    "ConsentProfileDataPermissionDenied",
    "ConsentProfileDataStore",
    "ConsentProfileDataValidationError",
    "IntegrityVerification",
    "JourneyVersion",
    "PreferenceCatalog",
    "ProfileExport",
    "ProfileValue",
    "PromptAssignment",
    "PromptContext",
    "PromptItem",
    "PublicProfileAuthority",
    "ValueReceipt",
    "product_boundaries",
    "profile_data_enabled",
    "require_profile_data_enabled",
]
