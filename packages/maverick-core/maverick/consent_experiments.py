"""Governed consent-surface experimentation with privacy-bounded analytics.

This authority deliberately supports a narrow kind of experiment: an approved
choice of pre-certified presentation bundles.  It cannot change consent
semantics, legal-signal handling, required purposes, accessibility behaviour,
or reject/accept parity.  Assignment is sticky and keyed, while the durable
store retains only keyed subject tokens needed for bounded deduplication and
aggregate counters -- never raw user identities, profiles, contexts, or event
payloads.

The capability is fail-closed unless both ``[consent_preferences]`` and
``[consent_preferences.experiments]`` contain the exact boolean ``enable =
true``.  A caller must also supply a tenant-aware key authority; this module
never persists assignment or integrity keys beside the experiment database.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import NormalDist
from typing import Any, Protocol

from . import consent_storage
from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

EXPERIMENT_SCHEMA = "lightwork.consent-experiment.v1"
ANALYSIS_SCHEMA = "lightwork.consent-experiment-analysis.v1"
EXPORT_SCHEMA = "lightwork.consent-experiment-export.v1"

_DATABASE_SCHEMA_VERSION = "1"
_OBJECT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COUNTRY_RE = re.compile(r"[A-Z]{2}\Z")
_LOCALE_RE = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_MAX_JSON_BYTES = 1_048_576
_MAX_VARIANTS = 10
_MAX_AUDIENCE_VALUES = 100
_MAX_AUDIT_EVENTS = 10_000
_MAX_ANALYSIS_LOOKS = 20
_MAX_EXPOSURES = 100_000_000
_MAX_EXPERIMENT_SECONDS = 366 * 24 * 60 * 60
_MAX_DEDUPE_RETENTION_DAYS = 90
_ALLOWED_AUDIENCE_KEYS = frozenset(
    {"country_codes", "region_codes", "channels", "locales"}
)
_PRIVACY_SIGNALS = frozenset(
    {"gpc", "dnt", "opt_out", "do_not_sell", "withdrawn", "revoked"}
)
_STATES = frozenset(
    {"draft", "approved", "active", "paused", "killed", "rolled_back"}
)


class ConsentExperimentError(RuntimeError):
    """Base error for the consent experimentation authority."""


class ConsentExperimentConfigError(ConsentExperimentError):
    """The independently gated experiment capability is not enabled."""


class ConsentExperimentValidationError(ConsentExperimentError, ValueError):
    """A request is outside the closed experiment contract."""


class ConsentExperimentConflict(ConsentExperimentError):
    """A CAS, uniqueness, or idempotency precondition failed."""


class ConsentExperimentNotFound(ConsentExperimentError):
    """The requested tenant-scoped experiment does not exist."""


class ConsentExperimentStateError(ConsentExperimentError):
    """The requested operation is unsafe in the experiment's current state."""


class ConsentExperimentPermissionDenied(ConsentExperimentError):
    """A caller violates a human separation-of-duties boundary."""


class ConsentExperimentIntegrityError(ConsentExperimentError):
    """Durable experiment state failed an integrity or schema check."""


class ExperimentKeyAuthority(Protocol):
    """Tenant-aware capability key source.

    Implementations should obtain the capability key from a deployment secret
    manager or HSM-backed lease.  Returned key bytes must be at least 256 bits.
    """

    def key_for(self, tenant_id: str, _capability: str) -> bytes:
        """Return key material for one tenant and named capability."""


def _canonical(value: object) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentExperimentValidationError("experiment data must be finite JSON") from exc
    if len(payload) > _MAX_JSON_BYTES:
        raise ConsentExperimentValidationError("experiment data exceeds 1 MiB")
    return payload


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mac(key: bytes, value: object) -> str:
    return hmac.new(key, _canonical(value), hashlib.sha256).hexdigest()


def _loads(value: object, field: str) -> Any:
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ConsentExperimentIntegrityError(f"stored {field} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ConsentExperimentIntegrityError(f"stored {field} is invalid") from exc


def _object_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _OBJECT_ID_RE.fullmatch(value) is None:
        raise ConsentExperimentValidationError(
            f"{field} must be a strict 1-128 character opaque identifier"
        )
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise ConsentExperimentValidationError("tenant_id is invalid") from exc


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ConsentExperimentValidationError(f"{field} must be a SHA-256 digest")
    return value.lower().removeprefix("sha256:")


def _integer(value: object, field: str, lower: int, upper: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not lower <= value <= upper
    ):
        raise ConsentExperimentValidationError(
            f"{field} must be an integer between {lower} and {upper}"
        )
    return value


def _number(value: object, field: str, lower: float, upper: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConsentExperimentValidationError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or not lower <= result <= upper:
        raise ConsentExperimentValidationError(
            f"{field} must be between {lower} and {upper}"
        )
    return result


def _timestamp(value: object, field: str) -> float:
    return _number(value, field, 0.000001, 32_503_680_000.0)


def _principal(value: object, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 512:
        raise ConsentExperimentValidationError(f"{field} is invalid")
    if any(ord(character) < 32 for character in value):
        raise ConsentExperimentValidationError(f"{field} contains control characters")
    return value


def _idempotency_key(value: object) -> str:
    if not isinstance(value, str) or not 8 <= len(value.encode("utf-8")) <= 256:
        raise ConsentExperimentValidationError(
            "idempotency_key must contain between 8 and 256 UTF-8 bytes"
        )
    if any(ord(character) < 32 for character in value):
        raise ConsentExperimentValidationError("idempotency_key contains control characters")
    return value


def _config_enabled(config: object) -> bool:
    if not isinstance(config, Mapping):
        return False
    consent = config.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    experiments = consent.get("experiments")
    return isinstance(experiments, Mapping) and experiments.get("enable") is True


def experiments_enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return true only for the two exact, independently nested boolean gates."""

    if config is not None:
        return _config_enabled(config)
    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        return _config_enabled(load_config())
    except Exception:
        return False


def require_experiments_enabled(config: Mapping[str, Any] | None = None) -> None:
    if not experiments_enabled(config):
        raise ConsentExperimentConfigError(
            "consent experiments are disabled; explicitly enable both "
            "[consent_preferences] and [consent_preferences.experiments]"
        )


@dataclass(frozen=True)
class ExperimentVariant:
    """A pre-certified presentation bundle; it contains no mutable legal semantics."""

    variant_id: str
    allocation_bps: int
    content_ref: str
    content_sha256: str
    accessibility_evidence_sha256: str
    equal_choice_evidence_sha256: str
    is_control: bool = False
    is_holdout: bool = False

    def normalized(self) -> dict[str, Any]:
        variant = _object_id(self.variant_id, "variant_id")
        allocation = _integer(self.allocation_bps, "allocation_bps", 1, 10_000)
        if not isinstance(self.is_control, bool) or not isinstance(self.is_holdout, bool):
            raise ConsentExperimentValidationError("variant flags must be booleans")
        if self.is_control and self.is_holdout:
            raise ConsentExperimentValidationError("a variant cannot be control and holdout")
        return {
            "variant_id": variant,
            "allocation_bps": allocation,
            "content_ref": _object_id(self.content_ref, "content_ref"),
            "content_sha256": _digest(self.content_sha256, "content_sha256"),
            "accessibility_evidence_sha256": _digest(
                self.accessibility_evidence_sha256,
                "accessibility_evidence_sha256",
            ),
            "equal_choice_evidence_sha256": _digest(
                self.equal_choice_evidence_sha256,
                "equal_choice_evidence_sha256",
            ),
            "is_control": self.is_control,
            "is_holdout": self.is_holdout,
        }


def _audience_values(key: str, raw: object) -> list[str]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise ConsentExperimentValidationError(f"audience {key} must be a sequence")
    if not 1 <= len(raw) <= _MAX_AUDIENCE_VALUES:
        raise ConsentExperimentValidationError(f"audience {key} has invalid size")
    values: set[str] = set()
    for value in raw:
        if not isinstance(value, str):
            raise ConsentExperimentValidationError(f"audience {key} values must be strings")
        if key == "country_codes":
            if _COUNTRY_RE.fullmatch(value) is None:
                raise ConsentExperimentValidationError("country codes must be two uppercase letters")
        elif key == "locales":
            if _LOCALE_RE.fullmatch(value) is None:
                raise ConsentExperimentValidationError("audience locale is invalid")
        else:
            _object_id(value, f"audience {key} value")
        values.add(value)
    if len(values) != len(raw):
        raise ConsentExperimentValidationError(f"audience {key} values must be unique")
    return sorted(values)


def _normalize_audience(value: Mapping[str, Sequence[str]] | None) -> dict[str, list[str]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or set(value) - _ALLOWED_AUDIENCE_KEYS:
        raise ConsentExperimentValidationError("audience contains unsupported conditions")
    return {key: _audience_values(key, raw) for key, raw in sorted(value.items())}


@dataclass(frozen=True)
class ExperimentSpec:
    """Immutable, bounded definition approved as one exact digest."""

    experiment_id: str
    metric_id: str
    variants: Sequence[ExperimentVariant]
    starts_at: float
    ends_at: float
    traffic_bps: int = 10_000
    max_exposures: int = 1_000_000
    min_sample_per_variant: int = 100
    alpha: float = 0.05
    max_analysis_looks: int = 5
    minimum_effect: float = 0.0
    dedupe_retention_days: int = 30
    audience: Mapping[str, Sequence[str]] | None = None

    def normalized(self) -> dict[str, Any]:
        experiment = _object_id(self.experiment_id, "experiment_id")
        metric = _object_id(self.metric_id, "metric_id")
        if (
            isinstance(self.variants, (str, bytes))
            or not isinstance(self.variants, Sequence)
            or not 2 <= len(self.variants) <= _MAX_VARIANTS
        ):
            raise ConsentExperimentValidationError("variants must contain 2-10 entries")
        if any(not isinstance(variant, ExperimentVariant) for variant in self.variants):
            raise ConsentExperimentValidationError(
                "every variant must be an ExperimentVariant"
            )
        variants = [variant.normalized() for variant in self.variants]
        identities = [str(variant["variant_id"]) for variant in variants]
        if len(set(identities)) != len(identities):
            raise ConsentExperimentValidationError("variant identifiers must be unique")
        if sum(int(variant["allocation_bps"]) for variant in variants) != 10_000:
            raise ConsentExperimentValidationError("variant allocations must total 10000 bps")
        controls = [variant for variant in variants if variant["is_control"]]
        holdouts = [variant for variant in variants if variant["is_holdout"]]
        if len(controls) != 1:
            raise ConsentExperimentValidationError("exactly one control variant is required")
        if len(holdouts) > 1:
            raise ConsentExperimentValidationError("at most one holdout variant is allowed")
        starts = _timestamp(self.starts_at, "starts_at")
        ends = _timestamp(self.ends_at, "ends_at")
        if ends <= starts or ends - starts > _MAX_EXPERIMENT_SECONDS:
            raise ConsentExperimentValidationError(
                "experiment window must be positive and no longer than 366 days"
            )
        variants.sort(key=lambda item: str(item["variant_id"]))
        return {
            "schema": EXPERIMENT_SCHEMA,
            "experiment_id": experiment,
            "metric_id": metric,
            "variants": variants,
            "control_variant_id": str(controls[0]["variant_id"]),
            "holdout_variant_id": (
                str(holdouts[0]["variant_id"]) if holdouts else None
            ),
            "starts_at": starts,
            "ends_at": ends,
            "traffic_bps": _integer(self.traffic_bps, "traffic_bps", 1, 10_000),
            "max_exposures": _integer(
                self.max_exposures,
                "max_exposures",
                1,
                _MAX_EXPOSURES,
            ),
            "min_sample_per_variant": _integer(
                self.min_sample_per_variant,
                "min_sample_per_variant",
                20,
                10_000_000,
            ),
            "alpha": _number(self.alpha, "alpha", 0.001, 0.1),
            "max_analysis_looks": _integer(
                self.max_analysis_looks,
                "max_analysis_looks",
                1,
                _MAX_ANALYSIS_LOOKS,
            ),
            "minimum_effect": _number(
                self.minimum_effect,
                "minimum_effect",
                0.0,
                0.5,
            ),
            "dedupe_retention_days": _integer(
                self.dedupe_retention_days,
                "dedupe_retention_days",
                1,
                _MAX_DEDUPE_RETENTION_DAYS,
            ),
            "audience": _normalize_audience(self.audience),
            "safety_contract": {
                "legal_signals": "always_precede_experiment",
                "required_purposes": "never_experiment",
                "accessibility": "certified_evidence_required",
                "choice_parity": "equal_accept_reject_evidence_required",
                "mutable_surface": "certified_content_reference_only",
            },
        }


@dataclass(frozen=True)
class AssignmentContext:
    """Ephemeral audience and safety context; it is validated but never persisted."""

    country_code: str | None = None
    region_code: str | None = None
    channel: str | None = None
    locale: str | None = None
    privacy_signals: Sequence[str] = ()
    required_purpose: bool = False
    accessibility_supported: bool = True
    equal_choice_prominence: bool = True

    def normalized(self) -> dict[str, Any]:
        country = self.country_code
        if country is not None and (
            not isinstance(country, str) or _COUNTRY_RE.fullmatch(country) is None
        ):
            raise ConsentExperimentValidationError("country_code is invalid")
        region = self.region_code
        if region is not None:
            region = _object_id(region, "region_code")
        channel = self.channel
        if channel is not None:
            channel = _object_id(channel, "channel")
        locale = self.locale
        if locale is not None and (
            not isinstance(locale, str) or _LOCALE_RE.fullmatch(locale) is None
        ):
            raise ConsentExperimentValidationError("locale is invalid")
        if isinstance(self.privacy_signals, (str, bytes)):
            raise ConsentExperimentValidationError("privacy_signals must be a sequence")
        raw_signals = list(self.privacy_signals)
        if any(not isinstance(signal, str) for signal in raw_signals):
            raise ConsentExperimentValidationError("privacy signals must be strings")
        if len(set(raw_signals)) != len(raw_signals):
            raise ConsentExperimentValidationError("privacy signals must be unique")
        signals = sorted(raw_signals)
        if any(signal not in _PRIVACY_SIGNALS for signal in signals):
            raise ConsentExperimentValidationError("privacy_signals contains an unknown signal")
        for field, value in (
            ("required_purpose", self.required_purpose),
            ("accessibility_supported", self.accessibility_supported),
            ("equal_choice_prominence", self.equal_choice_prominence),
        ):
            if not isinstance(value, bool):
                raise ConsentExperimentValidationError(f"{field} must be a boolean")
        return {
            "country_code": country,
            "region_code": region,
            "channel": channel,
            "locale": locale,
            "privacy_signals": signals,
            "required_purpose": self.required_purpose,
            "accessibility_supported": self.accessibility_supported,
            "equal_choice_prominence": self.equal_choice_prominence,
        }


@dataclass(frozen=True)
class ExperimentAssignment:
    experiment_id: str
    variant_id: str
    eligible: bool
    is_control: bool
    is_holdout: bool
    reason: str
    assignment_receipt_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ConsentExperimentAuthority:
    """Private SQLite/CAS authority for one deployment's tenant experiments."""

    _MUTABLE_STATE_COLUMNS = (
        "state",
        "revision",
        "approved_definition_sha256",
        "approved_by_token",
        "approved_at",
        "activated_at",
        "paused_at",
        "killed_at",
        "rolled_back_at",
        "rollback_variant_id",
        "updated_at",
        "state_mac",
    )

    def __init__(
        self,
        path: str | Path,
        *,
        key_authority: ExperimentKeyAuthority,
        config_loader: Callable[[], Mapping[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if key_authority is None or not callable(getattr(key_authority, "key_for", None)):
            raise ConsentExperimentValidationError("a capability key authority is required")
        self.path = Path(path).expanduser()
        self._key_authority = key_authority
        self._config_loader = config_loader
        self._clock = clock
        self._initialize()

    def _require_enabled(self) -> None:
        if self._config_loader is None:
            require_experiments_enabled()
            return
        try:
            config = self._config_loader()
        except Exception as exc:
            raise ConsentExperimentConfigError(
                "consent experiment configuration is unavailable"
            ) from exc
        if not _config_enabled(config):
            raise ConsentExperimentConfigError(
                "consent experiments require exact nested enable booleans"
            )

    def _key(self, tenant: str, purpose: str) -> bytes:
        try:
            root = self._key_authority.key_for(
                tenant,
                "lightwork.consent-experiments.v1",
            )
        except Exception as exc:
            raise ConsentExperimentIntegrityError(
                "experiment capability key is unavailable"
            ) from exc
        if not isinstance(root, bytes) or len(root) < 32:
            raise ConsentExperimentIntegrityError(
                "experiment capability key must contain at least 32 bytes"
            )
        return hmac.new(root, purpose.encode("ascii"), hashlib.sha256).digest()

    @contextlib.contextmanager
    def _connect(self):
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=10.0)
        else:
            ensure_private_directory(self.path.parent)
            if not self.path.exists():
                try:
                    descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            ensure_private_file(self.path, 0o600)
            connection = sqlite3.connect(
                str(self.path),
                timeout=10.0,
                isolation_level=None,
            )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if journal is None or str(journal[0]).lower() != "wal":
                raise ConsentExperimentIntegrityError("experiment database requires WAL mode")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA temp_store=MEMORY")
            yield connection
        finally:
            connection.close()
            for suffix in ("", "-wal", "-shm"):
                candidate = Path(f"{self.path}{suffix}")
                if candidate.exists():
                    with contextlib.suppress(OSError):
                        ensure_private_file(candidate, 0o600)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS consent_experiment_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consent_experiments (
                    tenant TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    definition_json TEXT NOT NULL,
                    definition_sha256 TEXT NOT NULL,
                    definition_mac TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('draft','approved','active','paused','killed','rolled_back')
                    ),
                    revision INTEGER NOT NULL,
                    approved_definition_sha256 TEXT,
                    approved_by_token TEXT,
                    approved_at REAL,
                    activated_at REAL,
                    paused_at REAL,
                    killed_at REAL,
                    rolled_back_at REAL,
                    rollback_variant_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    state_mac TEXT NOT NULL,
                    PRIMARY KEY (tenant, experiment_id)
                );
                CREATE TABLE IF NOT EXISTS consent_experiment_aggregates (
                    tenant TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    variant_id TEXT NOT NULL,
                    exposures INTEGER NOT NULL,
                    outcomes INTEGER NOT NULL,
                    successes INTEGER NOT NULL,
                    failures INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    record_mac TEXT NOT NULL,
                    PRIMARY KEY (tenant, experiment_id, variant_id),
                    FOREIGN KEY (tenant, experiment_id)
                        REFERENCES consent_experiments(tenant, experiment_id)
                );
                CREATE TABLE IF NOT EXISTS consent_experiment_dedupe (
                    tenant TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    subject_token TEXT NOT NULL,
                    variant_id TEXT NOT NULL,
                    outcome_success INTEGER CHECK (outcome_success IN (0,1)),
                    expires_at REAL NOT NULL,
                    revision INTEGER NOT NULL,
                    record_mac TEXT NOT NULL,
                    PRIMARY KEY (tenant, experiment_id, subject_token),
                    FOREIGN KEY (tenant, experiment_id)
                        REFERENCES consent_experiments(tenant, experiment_id)
                );
                CREATE INDEX IF NOT EXISTS consent_experiment_dedupe_expiry
                    ON consent_experiment_dedupe(tenant, expires_at);
                CREATE TABLE IF NOT EXISTS consent_experiment_idempotency (
                    tenant TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_token TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    result_mac TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, namespace, key_token)
                );
                CREATE TABLE IF NOT EXISTS consent_experiment_analyses (
                    tenant TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    look_number INTEGER NOT NULL,
                    aggregate_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    result_mac TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, experiment_id, look_number),
                    UNIQUE (tenant, experiment_id, aggregate_sha256)
                );
                CREATE TABLE IF NOT EXISTS consent_experiment_audit (
                    tenant TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    event_index INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor_token TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_mac TEXT,
                    event_mac TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, experiment_id, event_index)
                );

                CREATE TRIGGER IF NOT EXISTS consent_experiment_definition_immutable
                    BEFORE UPDATE OF definition_json, definition_sha256, definition_mac
                    ON consent_experiments
                    BEGIN SELECT RAISE(ABORT, 'experiment definitions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_no_delete
                    BEFORE DELETE ON consent_experiments
                    BEGIN SELECT RAISE(ABORT, 'experiments are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_identity_immutable
                    BEFORE UPDATE OF tenant, experiment_id ON consent_experiments
                    BEGIN SELECT RAISE(ABORT, 'experiment identity is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_aggregate_no_delete
                    BEFORE DELETE ON consent_experiment_aggregates
                    BEGIN SELECT RAISE(ABORT, 'experiment aggregates are durable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_aggregate_identity_immutable
                    BEFORE UPDATE OF tenant, experiment_id, variant_id
                    ON consent_experiment_aggregates
                    BEGIN SELECT RAISE(ABORT, 'aggregate identity is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_dedupe_identity_immutable
                    BEFORE UPDATE OF tenant, experiment_id, subject_token, variant_id, expires_at
                    ON consent_experiment_dedupe
                    BEGIN SELECT RAISE(ABORT, 'dedupe identity is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_audit_no_update
                    BEFORE UPDATE ON consent_experiment_audit
                    BEGIN SELECT RAISE(ABORT, 'experiment audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_audit_no_delete
                    BEFORE DELETE ON consent_experiment_audit
                    BEGIN SELECT RAISE(ABORT, 'experiment audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_analysis_no_update
                    BEFORE UPDATE ON consent_experiment_analyses
                    BEGIN SELECT RAISE(ABORT, 'experiment analysis is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_analysis_no_delete
                    BEFORE DELETE ON consent_experiment_analyses
                    BEGIN SELECT RAISE(ABORT, 'experiment analysis is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_idempotency_no_update
                    BEFORE UPDATE ON consent_experiment_idempotency
                    BEGIN SELECT RAISE(ABORT, 'experiment idempotency is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_experiment_idempotency_no_delete
                    BEFORE DELETE ON consent_experiment_idempotency
                    BEGIN SELECT RAISE(ABORT, 'experiment idempotency is immutable'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO consent_experiment_meta(key, value) VALUES (?, ?)",
                ("schema_version", _DATABASE_SCHEMA_VERSION),
            )
            rows = connection.execute(
                "SELECT key, value FROM consent_experiment_meta"
            ).fetchall()
            if [(str(row["key"]), str(row["value"])) for row in rows] != [
                ("schema_version", _DATABASE_SCHEMA_VERSION)
            ]:
                raise ConsentExperimentIntegrityError("experiment database schema is untrusted")

    @staticmethod
    def _state_body(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "tenant_sha256": hashlib.sha256(str(row["tenant"]).encode("utf-8")).hexdigest(),
            "experiment_id": row["experiment_id"],
            "state": row["state"],
            "revision": row["revision"],
            "approved_definition_sha256": row["approved_definition_sha256"],
            "approved_by_token": row["approved_by_token"],
            "approved_at": row["approved_at"],
            "activated_at": row["activated_at"],
            "paused_at": row["paused_at"],
            "killed_at": row["killed_at"],
            "rolled_back_at": row["rolled_back_at"],
            "rollback_variant_id": row["rollback_variant_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _aggregate_body(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "tenant_sha256": hashlib.sha256(str(row["tenant"]).encode("utf-8")).hexdigest(),
            "experiment_id": row["experiment_id"],
            "variant_id": row["variant_id"],
            "exposures": row["exposures"],
            "outcomes": row["outcomes"],
            "successes": row["successes"],
            "failures": row["failures"],
            "revision": row["revision"],
        }

    @staticmethod
    def _dedupe_body(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "tenant_sha256": hashlib.sha256(str(row["tenant"]).encode("utf-8")).hexdigest(),
            "experiment_id": row["experiment_id"],
            "subject_token": row["subject_token"],
            "variant_id": row["variant_id"],
            "outcome_success": row["outcome_success"],
            "expires_at": row["expires_at"],
            "revision": row["revision"],
        }

    def _load_experiment(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        experiment: str,
        key: bytes,
    ) -> tuple[sqlite3.Row, dict[str, Any]]:
        row = connection.execute(
            "SELECT * FROM consent_experiments WHERE tenant = ? AND experiment_id = ?",
            (tenant, experiment),
        ).fetchone()
        if row is None:
            raise ConsentExperimentNotFound("experiment does not exist in this tenant")
        definition = _loads(row["definition_json"], "experiment definition")
        if not isinstance(definition, dict):
            raise ConsentExperimentIntegrityError("stored experiment definition is invalid")
        canonical = _canonical(definition).decode("ascii")
        definition_sha = _sha256(definition)
        expected_mac = _mac(
            key,
            {
                "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                "experiment_id": experiment,
                "definition_sha256": definition_sha,
            },
        )
        if (
            canonical != row["definition_json"]
            or definition_sha != row["definition_sha256"]
            or not text_equals(expected_mac, str(row["definition_mac"]))
            or definition.get("experiment_id") != experiment
            or definition.get("schema") != EXPERIMENT_SCHEMA
            or row["state"] not in _STATES
        ):
            raise ConsentExperimentIntegrityError("stored experiment definition failed integrity")
        expected_state_mac = _mac(key, self._state_body(row))
        if not text_equals(expected_state_mac, str(row["state_mac"])):
            raise ConsentExperimentIntegrityError("stored experiment state failed integrity")
        return row, definition

    def _verify_aggregate(self, row: sqlite3.Row, key: bytes) -> None:
        body = self._aggregate_body(row)
        if (
            int(row["exposures"]) < 0
            or int(row["outcomes"]) < 0
            or int(row["successes"]) < 0
            or int(row["failures"]) < 0
            or int(row["outcomes"]) > int(row["exposures"])
            or int(row["successes"]) + int(row["failures"]) != int(row["outcomes"])
            or not text_equals(_mac(key, body), str(row["record_mac"]))
        ):
            raise ConsentExperimentIntegrityError("stored aggregate failed integrity")

    def _verify_dedupe(self, row: sqlite3.Row, key: bytes) -> None:
        if not text_equals(_mac(key, self._dedupe_body(row)), str(row["record_mac"])):
            raise ConsentExperimentIntegrityError("stored dedupe record failed integrity")

    @staticmethod
    def _project(row: Mapping[str, Any], definition: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": EXPERIMENT_SCHEMA,
            "definition": definition,
            "definition_sha256": row["definition_sha256"],
            "state": row["state"],
            "revision": int(row["revision"]),
            "approved_definition_sha256": row["approved_definition_sha256"],
            "approved_by_token": row["approved_by_token"],
            "approved_at": row["approved_at"],
            "activated_at": row["activated_at"],
            "paused_at": row["paused_at"],
            "killed_at": row["killed_at"],
            "rolled_back_at": row["rolled_back_at"],
            "rollback_variant_id": row["rollback_variant_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _actor_token(self, key: bytes, actor: str) -> str:
        return hmac.new(key, f"actor\0{actor}".encode(), hashlib.sha256).hexdigest()

    def _subject_token(self, key: bytes, experiment: str, subject: str) -> str:
        return hmac.new(
            key,
            f"subject\0{experiment}\0{subject}".encode(),
            hashlib.sha256,
        ).hexdigest()

    def _idempotency_token(self, key: bytes, value: str) -> str:
        return hmac.new(key, f"idempotency\0{value}".encode(), hashlib.sha256).hexdigest()

    def _idempotent_result(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_token: str,
        request_sha256: str,
        integrity_key: bytes,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256, result_json, result_mac FROM "
            "consent_experiment_idempotency WHERE tenant = ? AND namespace = ? "
            "AND key_token = ?",
            (tenant, namespace, key_token),
        ).fetchone()
        if row is None:
            return None
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise ConsentExperimentIntegrityError("stored idempotency result is invalid")
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "namespace": namespace,
            "key_token": key_token,
            "request_sha256": row["request_sha256"],
            "result": result,
        }
        if not text_equals(_mac(integrity_key, body), str(row["result_mac"])):
            raise ConsentExperimentIntegrityError("stored idempotency result failed integrity")
        if not hmac.compare_digest(str(row["request_sha256"]), request_sha256):
            raise ConsentExperimentConflict(
                "idempotency key is already bound to different experiment content"
            )
        return result

    def _save_idempotency(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_token: str,
        request_sha256: str,
        result: dict[str, Any],
        now: float,
        integrity_key: bytes,
    ) -> None:
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "namespace": namespace,
            "key_token": key_token,
            "request_sha256": request_sha256,
            "result": result,
        }
        connection.execute(
            "INSERT INTO consent_experiment_idempotency(tenant, namespace, key_token, "
            "request_sha256, result_json, result_mac, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                namespace,
                key_token,
                request_sha256,
                _canonical(result).decode("ascii"),
                _mac(integrity_key, body),
                now,
            ),
        )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        experiment: str,
        action: str,
        actor_token: str,
        details: dict[str, Any],
        now: float,
        integrity_key: bytes,
    ) -> None:
        previous = connection.execute(
            "SELECT event_index, event_mac FROM consent_experiment_audit "
            "WHERE tenant = ? AND experiment_id = ? ORDER BY event_index DESC LIMIT 1",
            (tenant, experiment),
        ).fetchone()
        event_index = int(previous["event_index"]) + 1 if previous is not None else 1
        previous_mac = str(previous["event_mac"]) if previous is not None else None
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "experiment_id": experiment,
            "event_index": event_index,
            "action": _object_id(action, "audit action"),
            "actor_token": actor_token,
            "details": details,
            "previous_mac": previous_mac,
            "created_at": now,
        }
        connection.execute(
            "INSERT INTO consent_experiment_audit(tenant, experiment_id, event_index, "
            "action, actor_token, details_json, previous_mac, event_mac, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                experiment,
                event_index,
                action,
                actor_token,
                _canonical(details).decode("ascii"),
                previous_mac,
                _mac(integrity_key, body),
                now,
            ),
        )

    def _verified_creator_token(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        experiment: str,
        integrity_key: bytes,
    ) -> str:
        event = connection.execute(
            "SELECT event_index, action, actor_token, details_json, previous_mac, "
            "event_mac, created_at FROM consent_experiment_audit WHERE tenant = ? "
            "AND experiment_id = ? AND event_index = 1",
            (tenant, experiment),
        ).fetchone()
        if event is None or event["action"] != "experiment.created":
            raise ConsentExperimentIntegrityError(
                "experiment creation authority is unavailable"
            )
        details = _loads(event["details_json"], "creation audit details")
        if not isinstance(details, dict):
            raise ConsentExperimentIntegrityError(
                "experiment creation audit details are invalid"
            )
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "experiment_id": experiment,
            "event_index": int(event["event_index"]),
            "action": str(event["action"]),
            "actor_token": str(event["actor_token"]),
            "details": details,
            "previous_mac": event["previous_mac"],
            "created_at": float(event["created_at"]),
        }
        if event["previous_mac"] is not None or not text_equals(
            _mac(integrity_key, body),
            str(event["event_mac"]),
        ):
            raise ConsentExperimentIntegrityError(
                "experiment creation audit integrity verification failed"
            )
        return str(event["actor_token"])

    def _cas_state(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        expected_revision: int,
        changes: Mapping[str, Any],
        integrity_key: bytes,
    ) -> sqlite3.Row:
        expected = _integer(expected_revision, "expected_revision", 0, 2_147_483_647)
        if int(row["revision"]) != expected:
            raise ConsentExperimentConflict(
                f"experiment revision is {int(row['revision'])}, expected {expected}"
            )
        values = dict(row)
        if set(changes) - set(self._MUTABLE_STATE_COLUMNS):
            raise ConsentExperimentIntegrityError("internal state update is outside schema")
        values.update(changes)
        values["revision"] = expected + 1
        values["state_mac"] = _mac(integrity_key, self._state_body(values))
        assignments = ", ".join(f"{column} = ?" for column in self._MUTABLE_STATE_COLUMNS)
        parameters = [values[column] for column in self._MUTABLE_STATE_COLUMNS]
        parameters.extend((row["tenant"], row["experiment_id"], expected))
        updated = connection.execute(
            f"UPDATE consent_experiments SET {assignments} "
            "WHERE tenant = ? AND experiment_id = ? AND revision = ?",
            parameters,
        )
        if updated.rowcount != 1:
            raise ConsentExperimentConflict("experiment changed concurrently")
        current = connection.execute(
            "SELECT * FROM consent_experiments WHERE tenant = ? AND experiment_id = ?",
            (row["tenant"], row["experiment_id"]),
        ).fetchone()
        if current is None:
            raise ConsentExperimentIntegrityError("experiment disappeared during CAS")
        return current

    def create_experiment(
        self,
        tenant_id: str,
        spec: ExperimentSpec,
        *,
        created_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create one immutable draft definition; exact retries are idempotent."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        if not isinstance(spec, ExperimentSpec):
            raise ConsentExperimentValidationError("spec must be an ExperimentSpec")
        definition = spec.normalized()
        experiment = str(definition["experiment_id"])
        actor = _principal(created_by, "created_by")
        idem = _idempotency_key(idempotency_key)
        now = _timestamp(self._clock(), "clock")
        integrity_key = self._key(tenant, "integrity")
        actor_token = self._actor_token(integrity_key, actor)
        key_token = self._idempotency_token(integrity_key, idem)
        request_sha = _sha256(
            {"definition": definition, "created_by_token": actor_token}
        )
        definition_sha = _sha256(definition)
        definition_mac = _mac(
            integrity_key,
            {
                "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                "experiment_id": experiment,
                "definition_sha256": definition_sha,
            },
        )
        namespace = f"experiment.create:{experiment}"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    integrity_key=integrity_key,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                if connection.execute(
                    "SELECT 1 FROM consent_experiments WHERE tenant = ? AND experiment_id = ?",
                    (tenant, experiment),
                ).fetchone() is not None:
                    raise ConsentExperimentConflict(
                        "experiment_id is already bound in this tenant"
                    )
                values: dict[str, Any] = {
                    "tenant": tenant,
                    "experiment_id": experiment,
                    "state": "draft",
                    "revision": 0,
                    "approved_definition_sha256": None,
                    "approved_by_token": None,
                    "approved_at": None,
                    "activated_at": None,
                    "paused_at": None,
                    "killed_at": None,
                    "rolled_back_at": None,
                    "rollback_variant_id": None,
                    "created_at": now,
                    "updated_at": now,
                }
                values["state_mac"] = _mac(integrity_key, self._state_body(values))
                connection.execute(
                    "INSERT INTO consent_experiments(tenant, experiment_id, definition_json, "
                    "definition_sha256, definition_mac, state, revision, "
                    "approved_definition_sha256, approved_by_token, approved_at, "
                    "activated_at, paused_at, killed_at, rolled_back_at, "
                    "rollback_variant_id, created_at, updated_at, state_mac) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        experiment,
                        _canonical(definition).decode("ascii"),
                        definition_sha,
                        definition_mac,
                        values["state"],
                        values["revision"],
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        now,
                        now,
                        values["state_mac"],
                    ),
                )
                for variant in definition["variants"]:
                    aggregate = {
                        "tenant": tenant,
                        "experiment_id": experiment,
                        "variant_id": variant["variant_id"],
                        "exposures": 0,
                        "outcomes": 0,
                        "successes": 0,
                        "failures": 0,
                        "revision": 0,
                    }
                    connection.execute(
                        "INSERT INTO consent_experiment_aggregates(tenant, experiment_id, "
                        "variant_id, exposures, outcomes, successes, failures, revision, "
                        "record_mac) VALUES (?, ?, ?, 0, 0, 0, 0, 0, ?)",
                        (
                            tenant,
                            experiment,
                            variant["variant_id"],
                            _mac(integrity_key, self._aggregate_body(aggregate)),
                        ),
                    )
                self._append_audit(
                    connection,
                    tenant=tenant,
                    experiment=experiment,
                    action="experiment.created",
                    actor_token=actor_token,
                    details={"definition_sha256": definition_sha, "revision": 0},
                    now=now,
                    integrity_key=integrity_key,
                )
                stored = connection.execute(
                    "SELECT * FROM consent_experiments WHERE tenant = ? AND experiment_id = ?",
                    (tenant, experiment),
                ).fetchone()
                if stored is None:
                    raise ConsentExperimentIntegrityError("created experiment is unavailable")
                result = self._project(stored, definition)
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                    integrity_key=integrity_key,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def get_experiment(self, tenant_id: str, experiment_id: str) -> dict[str, Any]:
        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        key = self._key(tenant, "integrity")
        with self._connect() as connection:
            row, definition = self._load_experiment(connection, tenant, experiment, key)
            return self._project(row, definition)

    def list_experiments(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        """List one tenant's integrity-checked experiments, newest first."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        bounded = _integer(limit, "limit", 1, 500)
        key = self._key(tenant, "integrity")
        with self._connect() as connection:
            ids = [
                str(row["experiment_id"])
                for row in connection.execute(
                    "SELECT experiment_id FROM consent_experiments WHERE tenant = ? "
                    "ORDER BY created_at DESC, experiment_id LIMIT ?",
                    (tenant, bounded + 1),
                ).fetchall()
            ]
            items = []
            for experiment in ids[:bounded]:
                row, definition = self._load_experiment(connection, tenant, experiment, key)
                items.append(self._project(row, definition))
        return {"items": items, "truncated": len(ids) > bounded}

    def _transition(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
        operation: str,
        allowed_states: frozenset[str],
        target_state: str,
        extra_changes: Mapping[str, Any] | None = None,
        require_exact_approval: bool = False,
        require_distinct_creator: bool = False,
    ) -> dict[str, Any]:
        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        revision = _integer(expected_revision, "expected_revision", 0, 2_147_483_647)
        principal = _principal(actor, "actor")
        idem = _idempotency_key(idempotency_key)
        now = _timestamp(self._clock(), "clock")
        integrity_key = self._key(tenant, "integrity")
        actor_token = self._actor_token(integrity_key, principal)
        key_token = self._idempotency_token(integrity_key, idem)
        request = {
            "experiment_id": experiment,
            "expected_revision": revision,
            "actor_token": actor_token,
            "operation": operation,
            "target_state": target_state,
            # Generated lifecycle timestamps are result metadata, not caller
            # request identity.  Excluding them lets an exact retry recover the
            # first committed result even when the wall clock has advanced.
            "extra_changes": {
                key: value
                for key, value in dict(extra_changes or {}).items()
                if not key.endswith("_at")
            },
        }
        request_sha = _sha256(request)
        namespace = f"experiment.{operation}:{experiment}"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    integrity_key=integrity_key,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                row, definition = self._load_experiment(
                    connection, tenant, experiment, integrity_key
                )
                if require_distinct_creator and hmac.compare_digest(
                    actor_token,
                    self._verified_creator_token(
                        connection,
                        tenant=tenant,
                        experiment=experiment,
                        integrity_key=integrity_key,
                    ),
                ):
                    raise ConsentExperimentPermissionDenied(
                        "experiment creator cannot approve their own definition"
                    )
                if int(row["revision"]) != revision:
                    raise ConsentExperimentConflict(
                        f"experiment revision is {int(row['revision'])}, expected {revision}"
                    )
                if row["state"] not in allowed_states:
                    raise ConsentExperimentStateError(
                        f"cannot {operation} an experiment in state {row['state']}"
                    )
                if require_exact_approval and (
                    row["approved_by_token"] is None
                    or row["approved_definition_sha256"] != row["definition_sha256"]
                ):
                    raise ConsentExperimentStateError(
                        "activation requires human approval of the exact definition"
                    )
                changes = {
                    "state": target_state,
                    "updated_at": now,
                    **dict(extra_changes or {}),
                }
                current = self._cas_state(
                    connection,
                    row,
                    expected_revision=revision,
                    changes=changes,
                    integrity_key=integrity_key,
                )
                self._append_audit(
                    connection,
                    tenant=tenant,
                    experiment=experiment,
                    action=f"experiment.{operation}",
                    actor_token=actor_token,
                    details={
                        "from_state": row["state"],
                        "to_state": target_state,
                        "revision": int(current["revision"]),
                    },
                    now=now,
                    integrity_key=integrity_key,
                )
                result = self._project(current, definition)
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                    integrity_key=integrity_key,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def approve(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        expected_revision: int,
        approved_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Human-approve the exact immutable definition digest under CAS."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        principal = _principal(approved_by, "approved_by")
        integrity_key = self._key(tenant, "integrity")
        actor_token = self._actor_token(integrity_key, principal)
        with self._connect() as connection:
            row, _definition = self._load_experiment(
                connection, tenant, experiment, integrity_key
            )
            definition_sha = str(row["definition_sha256"])
        now = _timestamp(self._clock(), "clock")
        return self._transition(
            tenant,
            experiment,
            expected_revision=expected_revision,
            actor=principal,
            idempotency_key=idempotency_key,
            operation="approved",
            allowed_states=frozenset({"draft"}),
            target_state="approved",
            extra_changes={
                "approved_definition_sha256": definition_sha,
                "approved_by_token": actor_token,
                "approved_at": now,
            },
            require_distinct_creator=True,
        )

    def activate(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        expected_revision: int,
        activated_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Activate only an independently approved, byte-identical definition."""

        return self._transition(
            tenant_id,
            experiment_id,
            expected_revision=expected_revision,
            actor=activated_by,
            idempotency_key=idempotency_key,
            operation="activated",
            allowed_states=frozenset({"draft", "approved"}),
            target_state="active",
            extra_changes={"activated_at": _timestamp(self._clock(), "clock")},
            require_exact_approval=True,
        )

    def pause(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        expected_revision: int,
        paused_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._transition(
            tenant_id,
            experiment_id,
            expected_revision=expected_revision,
            actor=paused_by,
            idempotency_key=idempotency_key,
            operation="paused",
            allowed_states=frozenset({"active"}),
            target_state="paused",
            extra_changes={"paused_at": _timestamp(self._clock(), "clock")},
        )

    def resume(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        expected_revision: int,
        resumed_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._transition(
            tenant_id,
            experiment_id,
            expected_revision=expected_revision,
            actor=resumed_by,
            idempotency_key=idempotency_key,
            operation="resumed",
            allowed_states=frozenset({"paused"}),
            target_state="active",
        )

    def kill(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        expected_revision: int,
        killed_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._transition(
            tenant_id,
            experiment_id,
            expected_revision=expected_revision,
            actor=killed_by,
            idempotency_key=idempotency_key,
            operation="killed",
            allowed_states=frozenset({"draft", "approved", "active", "paused"}),
            target_state="killed",
            extra_changes={"killed_at": _timestamp(self._clock(), "clock")},
        )

    def rollback(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        expected_revision: int,
        rolled_back_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        key = self._key(tenant, "integrity")
        with self._connect() as connection:
            _row, definition = self._load_experiment(connection, tenant, experiment, key)
        return self._transition(
            tenant,
            experiment,
            expected_revision=expected_revision,
            actor=rolled_back_by,
            idempotency_key=idempotency_key,
            operation="rolled_back",
            allowed_states=frozenset({"approved", "active", "paused", "killed"}),
            target_state="rolled_back",
            extra_changes={
                "rolled_back_at": _timestamp(self._clock(), "clock"),
                "rollback_variant_id": definition["control_variant_id"],
            },
        )

    @staticmethod
    def _audience_matches(definition: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
        audience = definition["audience"]
        mapping = {
            "country_codes": "country_code",
            "region_codes": "region_code",
            "channels": "channel",
            "locales": "locale",
        }
        return all(context[mapping[key]] in allowed for key, allowed in audience.items())

    @staticmethod
    def _variant_for_bucket(definition: Mapping[str, Any], bucket: int) -> dict[str, Any]:
        cumulative = 0
        for variant in definition["variants"]:
            cumulative += int(variant["allocation_bps"])
            if bucket < cumulative:
                return variant
        raise ConsentExperimentIntegrityError("variant allocations do not cover assignment")

    def _compute_assignment(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        experiment: str,
        subject: str,
        context: dict[str, Any],
        now: float,
        integrity_key: bytes,
    ) -> tuple[ExperimentAssignment, str, dict[str, Any]]:
        row, definition = self._load_experiment(
            connection, tenant, experiment, integrity_key
        )
        assignment_key = self._key(tenant, "assignment")
        subject_token = self._subject_token(assignment_key, experiment, subject)

        def fallback(reason: str) -> tuple[ExperimentAssignment, str, dict[str, Any]]:
            return (
                self._forced_control_assignment(
                    tenant=tenant,
                    experiment=experiment,
                    subject_token=subject_token,
                    definition=definition,
                    reason=reason,
                ),
                subject_token,
                definition,
            )

        if row["state"] == "paused":
            return fallback("paused")
        if row["state"] == "killed":
            return fallback("killed")
        if row["state"] == "rolled_back":
            return fallback("rolled_back")
        if row["state"] != "active":
            return fallback("not_active")
        if now < float(definition["starts_at"]):
            return fallback("not_started")
        if now >= float(definition["ends_at"]):
            return fallback("ended")
        if context["privacy_signals"]:
            return fallback("legal_signal_precedence")
        if context["required_purpose"]:
            return fallback("required_purpose_precedence")
        if not context["accessibility_supported"]:
            return fallback("accessibility_guardrail")
        if not context["equal_choice_prominence"]:
            return fallback("choice_parity_guardrail")
        if not self._audience_matches(definition, context):
            return fallback("outside_audience")
        traffic_digest = hmac.new(
            assignment_key,
            f"traffic\0{experiment}\0{subject}".encode(),
            hashlib.sha256,
        ).digest()
        if int.from_bytes(traffic_digest[:8], "big") % 10_000 >= int(
            definition["traffic_bps"]
        ):
            return fallback("outside_traffic")
        variant_digest = hmac.new(
            assignment_key,
            f"variant\0{experiment}\0{subject}".encode(),
            hashlib.sha256,
        ).digest()
        variant = self._variant_for_bucket(
            definition,
            int.from_bytes(variant_digest[:8], "big") % 10_000,
        )
        reason = "holdout" if variant["is_holdout"] else "assigned"
        receipt = _mac(
            assignment_key,
            {
                "experiment_id": experiment,
                "subject_token": subject_token,
                "variant_id": variant["variant_id"],
                "eligible": True,
                "reason": reason,
            },
        )
        return (
            ExperimentAssignment(
                experiment,
                str(variant["variant_id"]),
                True,
                bool(variant["is_control"]),
                bool(variant["is_holdout"]),
                reason,
                receipt,
            ),
            subject_token,
            definition,
        )

    def _forced_control_assignment(
        self,
        *,
        tenant: str,
        experiment: str,
        subject_token: str,
        definition: Mapping[str, Any],
        reason: str,
    ) -> ExperimentAssignment:
        control_id = str(definition["control_variant_id"])
        assignment_key = self._key(tenant, "assignment")
        receipt = _mac(
            assignment_key,
            {
                "experiment_id": experiment,
                "subject_token": subject_token,
                "variant_id": control_id,
                "eligible": False,
                "reason": reason,
            },
        )
        return ExperimentAssignment(
            experiment,
            control_id,
            False,
            True,
            False,
            reason,
            receipt,
        )

    def assign(
        self,
        tenant_id: str,
        experiment_id: str,
        subject_identity: str,
        context: AssignmentContext,
        *,
        at: float | None = None,
    ) -> ExperimentAssignment:
        """Return a deterministic assignment without persisting identity or context."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        subject = _principal(subject_identity, "subject_identity")
        if not isinstance(context, AssignmentContext):
            raise ConsentExperimentValidationError("context must be an AssignmentContext")
        normalized_context = context.normalized()
        now = _timestamp(self._clock() if at is None else at, "at")
        key = self._key(tenant, "integrity")
        with self._connect() as connection:
            assignment, subject_token, definition = self._compute_assignment(
                connection,
                tenant=tenant,
                experiment=experiment,
                subject=subject,
                context=normalized_context,
                now=now,
                integrity_key=key,
            )
            aggregates = connection.execute(
                "SELECT * FROM consent_experiment_aggregates WHERE tenant = ? "
                "AND experiment_id = ?",
                (tenant, experiment),
            ).fetchall()
            for row in aggregates:
                self._verify_aggregate(row, key)
            if sum(int(row["exposures"]) for row in aggregates) >= int(
                definition["max_exposures"]
            ):
                return self._forced_control_assignment(
                    tenant=tenant,
                    experiment=experiment,
                    subject_token=subject_token,
                    definition=definition,
                    reason="max_exposures",
                )
            return assignment

    def _update_aggregate(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        experiment: str,
        variant: str,
        exposure_delta: int,
        outcome_success: bool | None,
        integrity_key: bytes,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM consent_experiment_aggregates WHERE tenant = ? "
            "AND experiment_id = ? AND variant_id = ?",
            (tenant, experiment, variant),
        ).fetchone()
        if row is None:
            raise ConsentExperimentIntegrityError("assigned variant aggregate is missing")
        self._verify_aggregate(row, integrity_key)
        values = dict(row)
        values["exposures"] = int(row["exposures"]) + exposure_delta
        if outcome_success is not None:
            values["outcomes"] = int(row["outcomes"]) + 1
            if outcome_success:
                values["successes"] = int(row["successes"]) + 1
            else:
                values["failures"] = int(row["failures"]) + 1
        values["revision"] = int(row["revision"]) + 1
        values["record_mac"] = _mac(integrity_key, self._aggregate_body(values))
        updated = connection.execute(
            "UPDATE consent_experiment_aggregates SET exposures = ?, outcomes = ?, "
            "successes = ?, failures = ?, revision = ?, record_mac = ? "
            "WHERE tenant = ? AND experiment_id = ? AND variant_id = ? AND revision = ?",
            (
                values["exposures"],
                values["outcomes"],
                values["successes"],
                values["failures"],
                values["revision"],
                values["record_mac"],
                tenant,
                experiment,
                variant,
                row["revision"],
            ),
        )
        if updated.rowcount != 1:
            raise ConsentExperimentConflict("aggregate changed concurrently")
        current = connection.execute(
            "SELECT * FROM consent_experiment_aggregates WHERE tenant = ? "
            "AND experiment_id = ? AND variant_id = ?",
            (tenant, experiment, variant),
        ).fetchone()
        if current is None:
            raise ConsentExperimentIntegrityError("aggregate disappeared during CAS")
        return current

    def record_exposure(
        self,
        tenant_id: str,
        experiment_id: str,
        subject_identity: str,
        context: AssignmentContext,
        *,
        idempotency_key: str,
        occurred_at: float | None = None,
    ) -> dict[str, Any]:
        """Deduplicate one exposure and update only bounded aggregate counters."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        subject = _principal(subject_identity, "subject_identity")
        if not isinstance(context, AssignmentContext):
            raise ConsentExperimentValidationError("context must be an AssignmentContext")
        normalized_context = context.normalized()
        idem = _idempotency_key(idempotency_key)
        now = _timestamp(self._clock() if occurred_at is None else occurred_at, "occurred_at")
        integrity_key = self._key(tenant, "integrity")
        assignment_key = self._key(tenant, "assignment")
        subject_token = self._subject_token(assignment_key, experiment, subject)
        key_token = self._idempotency_token(integrity_key, idem)
        namespace = f"exposure.record:{experiment}"
        request_sha = _sha256(
            {
                "experiment_id": experiment,
                "subject_token": subject_token,
                "context": normalized_context,
                "occurred_at": occurred_at,
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    integrity_key=integrity_key,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                assignment, subject_token, definition = self._compute_assignment(
                    connection,
                    tenant=tenant,
                    experiment=experiment,
                    subject=subject,
                    context=normalized_context,
                    now=now,
                    integrity_key=integrity_key,
                )
                if not assignment.eligible:
                    result = {"assignment": assignment.as_dict(), "recorded": False}
                    self._save_idempotency(
                        connection,
                        tenant=tenant,
                        namespace=namespace,
                        key_token=key_token,
                        request_sha256=request_sha,
                        result=result,
                        now=now,
                        integrity_key=integrity_key,
                    )
                    connection.execute("COMMIT")
                    return result
                aggregate_rows = connection.execute(
                    "SELECT * FROM consent_experiment_aggregates WHERE tenant = ? "
                    "AND experiment_id = ?",
                    (tenant, experiment),
                ).fetchall()
                for aggregate in aggregate_rows:
                    self._verify_aggregate(aggregate, integrity_key)
                if sum(int(row["exposures"]) for row in aggregate_rows) >= int(
                    definition["max_exposures"]
                ):
                    forced = self._forced_control_assignment(
                        tenant=tenant,
                        experiment=experiment,
                        subject_token=subject_token,
                        definition=definition,
                        reason="max_exposures",
                    )
                    result = {
                        "assignment": forced.as_dict(),
                        "recorded": False,
                    }
                    self._save_idempotency(
                        connection,
                        tenant=tenant,
                        namespace=namespace,
                        key_token=key_token,
                        request_sha256=request_sha,
                        result=result,
                        now=now,
                        integrity_key=integrity_key,
                    )
                    connection.execute("COMMIT")
                    return result
                existing = connection.execute(
                    "SELECT * FROM consent_experiment_dedupe WHERE tenant = ? "
                    "AND experiment_id = ? AND subject_token = ?",
                    (tenant, experiment, subject_token),
                ).fetchone()
                if existing is not None:
                    self._verify_dedupe(existing, integrity_key)
                    if existing["variant_id"] != assignment.variant_id:
                        raise ConsentExperimentIntegrityError(
                            "sticky assignment disagrees with durable dedupe state"
                        )
                    result = {
                        "assignment": assignment.as_dict(),
                        "recorded": True,
                        "deduplicated": True,
                    }
                else:
                    retention_seconds = int(definition["dedupe_retention_days"]) * 86_400
                    expires_at = min(
                        now + retention_seconds,
                        float(definition["ends_at"]) + retention_seconds,
                    )
                    dedupe = {
                        "tenant": tenant,
                        "experiment_id": experiment,
                        "subject_token": subject_token,
                        "variant_id": assignment.variant_id,
                        "outcome_success": None,
                        "expires_at": expires_at,
                        "revision": 0,
                    }
                    connection.execute(
                        "INSERT INTO consent_experiment_dedupe(tenant, experiment_id, "
                        "subject_token, variant_id, outcome_success, expires_at, revision, "
                        "record_mac) VALUES (?, ?, ?, ?, NULL, ?, 0, ?)",
                        (
                            tenant,
                            experiment,
                            subject_token,
                            assignment.variant_id,
                            expires_at,
                            _mac(integrity_key, self._dedupe_body(dedupe)),
                        ),
                    )
                    self._update_aggregate(
                        connection,
                        tenant=tenant,
                        experiment=experiment,
                        variant=assignment.variant_id,
                        exposure_delta=1,
                        outcome_success=None,
                        integrity_key=integrity_key,
                    )
                    result = {
                        "assignment": assignment.as_dict(),
                        "recorded": True,
                        "deduplicated": False,
                    }
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                    integrity_key=integrity_key,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def record_outcome(
        self,
        tenant_id: str,
        experiment_id: str,
        subject_identity: str,
        *,
        success: bool,
        idempotency_key: str,
        occurred_at: float | None = None,
    ) -> dict[str, Any]:
        """Record one binary outcome only after a retained deduplicated exposure."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        subject = _principal(subject_identity, "subject_identity")
        if not isinstance(success, bool):
            raise ConsentExperimentValidationError("success must be a boolean")
        idem = _idempotency_key(idempotency_key)
        now = _timestamp(self._clock() if occurred_at is None else occurred_at, "occurred_at")
        integrity_key = self._key(tenant, "integrity")
        assignment_key = self._key(tenant, "assignment")
        subject_token = self._subject_token(assignment_key, experiment, subject)
        key_token = self._idempotency_token(integrity_key, idem)
        namespace = f"outcome.record:{experiment}"
        request_sha = _sha256(
            {
                "experiment_id": experiment,
                "subject_token": subject_token,
                "success": success,
                "occurred_at": occurred_at,
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    integrity_key=integrity_key,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                self._load_experiment(connection, tenant, experiment, integrity_key)
                row = connection.execute(
                    "SELECT * FROM consent_experiment_dedupe WHERE tenant = ? "
                    "AND experiment_id = ? AND subject_token = ?",
                    (tenant, experiment, subject_token),
                ).fetchone()
                if row is None:
                    raise ConsentExperimentStateError(
                        "an unexpired recorded exposure is required before an outcome"
                    )
                self._verify_dedupe(row, integrity_key)
                if float(row["expires_at"]) <= now:
                    raise ConsentExperimentStateError(
                        "the privacy-bounded exposure dedupe window has expired"
                    )
                existing = row["outcome_success"]
                if existing is not None:
                    if bool(existing) != success:
                        raise ConsentExperimentConflict(
                            "subject outcome is already bound to a different value"
                        )
                    result = {
                        "experiment_id": experiment,
                        "variant_id": row["variant_id"],
                        "recorded": True,
                        "deduplicated": True,
                    }
                else:
                    values = dict(row)
                    values["outcome_success"] = int(success)
                    values["revision"] = int(row["revision"]) + 1
                    values["record_mac"] = _mac(
                        integrity_key, self._dedupe_body(values)
                    )
                    updated = connection.execute(
                        "UPDATE consent_experiment_dedupe SET outcome_success = ?, "
                        "revision = ?, record_mac = ? WHERE tenant = ? AND "
                        "experiment_id = ? AND subject_token = ? AND revision = ?",
                        (
                            int(success),
                            values["revision"],
                            values["record_mac"],
                            tenant,
                            experiment,
                            subject_token,
                            row["revision"],
                        ),
                    )
                    if updated.rowcount != 1:
                        raise ConsentExperimentConflict("outcome changed concurrently")
                    self._update_aggregate(
                        connection,
                        tenant=tenant,
                        experiment=experiment,
                        variant=str(row["variant_id"]),
                        exposure_delta=0,
                        outcome_success=success,
                        integrity_key=integrity_key,
                    )
                    result = {
                        "experiment_id": experiment,
                        "variant_id": row["variant_id"],
                        "recorded": True,
                        "deduplicated": False,
                    }
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                    integrity_key=integrity_key,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def purge_expired_dedupe(
        self,
        tenant_id: str,
        *,
        purged_by: str,
        idempotency_key: str,
        before: float | None = None,
    ) -> dict[str, Any]:
        """Delete expired pseudonymous dedupe tokens without changing aggregates."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        principal = _principal(purged_by, "purged_by")
        idem = _idempotency_key(idempotency_key)
        now = _timestamp(self._clock(), "clock")
        cutoff = _timestamp(now if before is None else before, "before")
        if cutoff > now:
            raise ConsentExperimentValidationError("before cannot be in the future")
        integrity_key = self._key(tenant, "integrity")
        actor_token = self._actor_token(integrity_key, principal)
        key_token = self._idempotency_token(integrity_key, idem)
        namespace = "dedupe.purge"
        request_sha = _sha256(
            {"before": before, "actor_token": actor_token}
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    integrity_key=integrity_key,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                rows = connection.execute(
                    "SELECT * FROM consent_experiment_dedupe WHERE tenant = ? "
                    "AND expires_at <= ?",
                    (tenant, cutoff),
                ).fetchall()
                for row in rows:
                    self._verify_dedupe(row, integrity_key)
                counts: dict[str, int] = {}
                for row in rows:
                    experiment = str(row["experiment_id"])
                    counts[experiment] = counts.get(experiment, 0) + 1
                connection.execute(
                    "DELETE FROM consent_experiment_dedupe WHERE tenant = ? "
                    "AND expires_at <= ?",
                    (tenant, cutoff),
                )
                for experiment, count in sorted(counts.items()):
                    self._append_audit(
                        connection,
                        tenant=tenant,
                        experiment=experiment,
                        action="dedupe.purged",
                        actor_token=actor_token,
                        details={"records_purged": count, "before": cutoff},
                        now=now,
                        integrity_key=integrity_key,
                    )
                result = {"records_purged": len(rows), "before": cutoff}
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                    integrity_key=integrity_key,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _wilson(successes: int, outcomes: int, alpha: float) -> tuple[float, float]:
        if outcomes == 0:
            return 0.0, 1.0
        z = NormalDist().inv_cdf(1.0 - alpha / 2.0)
        proportion = successes / outcomes
        denominator = 1.0 + z * z / outcomes
        center = (proportion + z * z / (2.0 * outcomes)) / denominator
        margin = (
            z
            * math.sqrt(
                proportion * (1.0 - proportion) / outcomes
                + z * z / (4.0 * outcomes * outcomes)
            )
            / denominator
        )
        return max(0.0, center - margin), min(1.0, center + margin)

    @staticmethod
    def _two_proportion_p_value(
        successes_a: int,
        outcomes_a: int,
        successes_b: int,
        outcomes_b: int,
    ) -> float:
        if outcomes_a == 0 or outcomes_b == 0:
            return 1.0
        pooled = (successes_a + successes_b) / (outcomes_a + outcomes_b)
        standard_error = math.sqrt(
            pooled * (1.0 - pooled) * (1.0 / outcomes_a + 1.0 / outcomes_b)
        )
        if standard_error == 0.0:
            return 1.0
        difference = successes_a / outcomes_a - successes_b / outcomes_b
        return math.erfc(abs(difference / standard_error) / math.sqrt(2.0))

    def _analysis_result(
        self,
        *,
        definition: dict[str, Any],
        aggregates: Sequence[sqlite3.Row],
        look_number: int,
        aggregate_sha256: str,
        state: str,
        created_at: float,
    ) -> dict[str, Any]:
        comparison_count = max(
            1,
            sum(
                1
                for variant in definition["variants"]
                if not variant["is_control"] and not variant["is_holdout"]
            ),
        )
        alpha_per_look = float(definition["alpha"]) / (
            int(definition["max_analysis_looks"]) * comparison_count
        )
        min_sample = int(definition["min_sample_per_variant"])
        cells: list[dict[str, Any]] = []
        indexed: dict[str, dict[str, Any]] = {}
        for row in sorted(aggregates, key=lambda item: str(item["variant_id"])):
            outcomes = int(row["outcomes"])
            successes = int(row["successes"])
            interval = self._wilson(successes, outcomes, alpha_per_look)
            cell = {
                "variant_id": str(row["variant_id"]),
                "exposures": int(row["exposures"]),
                "outcomes": outcomes,
                "successes": successes,
                "failures": int(row["failures"]),
                "conversion_rate": successes / outcomes if outcomes else None,
                "confidence_interval": [interval[0], interval[1]],
                "minimum_sample_met": outcomes >= min_sample,
            }
            cells.append(cell)
            indexed[cell["variant_id"]] = cell
        control_id = str(definition["control_variant_id"])
        control = indexed[control_id]
        comparisons: list[dict[str, Any]] = []
        eligible_winners: list[tuple[float, str]] = []
        for variant in definition["variants"]:
            variant_id = str(variant["variant_id"])
            if variant_id == control_id or variant["is_holdout"]:
                continue
            cell = indexed[variant_id]
            effect = (
                float(cell["conversion_rate"]) - float(control["conversion_rate"])
                if cell["conversion_rate"] is not None
                and control["conversion_rate"] is not None
                else None
            )
            p_value = self._two_proportion_p_value(
                int(cell["successes"]),
                int(cell["outcomes"]),
                int(control["successes"]),
                int(control["outcomes"]),
            )
            difference_interval = [
                float(cell["confidence_interval"][0])
                - float(control["confidence_interval"][1]),
                float(cell["confidence_interval"][1])
                - float(control["confidence_interval"][0]),
            ]
            thresholds_met = bool(
                cell["minimum_sample_met"]
                and control["minimum_sample_met"]
                and effect is not None
                and p_value <= alpha_per_look
                and difference_interval[0] >= float(definition["minimum_effect"])
                and state not in {"killed", "rolled_back"}
            )
            if thresholds_met:
                eligible_winners.append((difference_interval[0], variant_id))
            comparisons.append(
                {
                    "variant_id": variant_id,
                    "control_variant_id": control_id,
                    "absolute_effect": effect,
                    "effect_confidence_interval": difference_interval,
                    "two_sided_p_value": p_value,
                    "alpha_boundary": alpha_per_look,
                    "minimum_effect": definition["minimum_effect"],
                    "thresholds_met": thresholds_met,
                }
            )
        winner = max(eligible_winners)[1] if eligible_winners else None
        return {
            "schema": ANALYSIS_SCHEMA,
            "experiment_id": definition["experiment_id"],
            "metric_id": definition["metric_id"],
            "look_number": look_number,
            "max_analysis_looks": definition["max_analysis_looks"],
            "aggregate_sha256": aggregate_sha256,
            "alpha_familywise": definition["alpha"],
            "alpha_boundary": alpha_per_look,
            "comparison_count": comparison_count,
            "minimum_sample_per_variant": min_sample,
            "cells": cells,
            "comparisons": comparisons,
            "winner_variant_id": winner,
            "causal_claim_authorized": winner is not None,
            "decision": "bounded_winner" if winner is not None else "no_winner",
            "created_at": created_at,
            "limitations": [
                "Bonferroni alpha spending bounds repeated configured looks.",
                "Wilson intervals and a two-proportion z test assume binary independent outcomes.",
                "No winner is declared before both compared arms meet the minimum sample.",
                "Operational noncompliance, attrition, and external validity require separate review.",
            ],
        }

    def analyze(
        self,
        tenant_id: str,
        experiment_id: str,
        *,
        analyzed_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Persist one bounded sequential look and never infer an early winner."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        principal = _principal(analyzed_by, "analyzed_by")
        idem = _idempotency_key(idempotency_key)
        now = _timestamp(self._clock(), "clock")
        integrity_key = self._key(tenant, "integrity")
        actor_token = self._actor_token(integrity_key, principal)
        key_token = self._idempotency_token(integrity_key, idem)
        namespace = f"analysis.run:{experiment}"
        request_sha = _sha256(
            {"experiment_id": experiment, "actor_token": actor_token}
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    integrity_key=integrity_key,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                row, definition = self._load_experiment(
                    connection, tenant, experiment, integrity_key
                )
                aggregates = connection.execute(
                    "SELECT * FROM consent_experiment_aggregates WHERE tenant = ? "
                    "AND experiment_id = ? ORDER BY variant_id",
                    (tenant, experiment),
                ).fetchall()
                for aggregate in aggregates:
                    self._verify_aggregate(aggregate, integrity_key)
                snapshot = [self._aggregate_body(aggregate) for aggregate in aggregates]
                aggregate_sha = _sha256(snapshot)
                existing = connection.execute(
                    "SELECT result_json, result_mac FROM consent_experiment_analyses "
                    "WHERE tenant = ? AND experiment_id = ? AND aggregate_sha256 = ?",
                    (tenant, experiment, aggregate_sha),
                ).fetchone()
                if existing is not None:
                    result = _loads(existing["result_json"], "analysis result")
                    if not isinstance(result, dict) or not text_equals(
                        _mac(integrity_key, result), str(existing["result_mac"])
                    ):
                        raise ConsentExperimentIntegrityError(
                            "stored analysis result failed integrity"
                        )
                    result = {**result, "reused_snapshot": True}
                else:
                    prior = connection.execute(
                        "SELECT COALESCE(MAX(look_number), 0) FROM "
                        "consent_experiment_analyses WHERE tenant = ? AND experiment_id = ?",
                        (tenant, experiment),
                    ).fetchone()
                    look_number = int(prior[0]) + 1
                    if look_number > int(definition["max_analysis_looks"]):
                        raise ConsentExperimentStateError(
                            "configured sequential analysis look budget is exhausted"
                        )
                    result = self._analysis_result(
                        definition=definition,
                        aggregates=aggregates,
                        look_number=look_number,
                        aggregate_sha256=aggregate_sha,
                        state=str(row["state"]),
                        created_at=now,
                    )
                    connection.execute(
                        "INSERT INTO consent_experiment_analyses(tenant, experiment_id, "
                        "look_number, aggregate_sha256, result_json, result_mac, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            experiment,
                            look_number,
                            aggregate_sha,
                            _canonical(result).decode("ascii"),
                            _mac(integrity_key, result),
                            now,
                        ),
                    )
                    self._append_audit(
                        connection,
                        tenant=tenant,
                        experiment=experiment,
                        action="analysis.completed",
                        actor_token=actor_token,
                        details={
                            "look_number": look_number,
                            "aggregate_sha256": aggregate_sha,
                            "winner_variant_id": result["winner_variant_id"],
                            "causal_claim_authorized": result["causal_claim_authorized"],
                        },
                        now=now,
                        integrity_key=integrity_key,
                    )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace=namespace,
                    key_token=key_token,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                    integrity_key=integrity_key,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def audit_export(self, tenant_id: str, experiment_id: str) -> dict[str, Any]:
        """Return a verified aggregate-only export with no subject or event records."""

        self._require_enabled()
        tenant = _tenant_id(tenant_id)
        experiment = _object_id(experiment_id, "experiment_id")
        integrity_key = self._key(tenant, "integrity")
        with self._connect() as connection:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if quick_check is None or quick_check[0] != "ok":
                raise ConsentExperimentIntegrityError("experiment database integrity failed")
            required_triggers = {
                "consent_experiment_definition_immutable",
                "consent_experiment_no_delete",
                "consent_experiment_identity_immutable",
                "consent_experiment_aggregate_no_delete",
                "consent_experiment_aggregate_identity_immutable",
                "consent_experiment_dedupe_identity_immutable",
                "consent_experiment_audit_no_update",
                "consent_experiment_audit_no_delete",
                "consent_experiment_analysis_no_update",
                "consent_experiment_analysis_no_delete",
                "consent_experiment_idempotency_no_update",
                "consent_experiment_idempotency_no_delete",
            }
            triggers = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                ).fetchall()
            }
            if not required_triggers.issubset(triggers):
                raise ConsentExperimentIntegrityError("experiment immutability controls are missing")
            meta = connection.execute(
                "SELECT key, value FROM consent_experiment_meta ORDER BY key"
            ).fetchall()
            if [(str(item["key"]), str(item["value"])) for item in meta] != [
                ("schema_version", _DATABASE_SCHEMA_VERSION)
            ]:
                raise ConsentExperimentIntegrityError(
                    "experiment database schema metadata is untrusted"
                )
            row, definition = self._load_experiment(
                connection, tenant, experiment, integrity_key
            )
            aggregates = connection.execute(
                "SELECT * FROM consent_experiment_aggregates WHERE tenant = ? "
                "AND experiment_id = ? ORDER BY variant_id",
                (tenant, experiment),
            ).fetchall()
            aggregate_export: list[dict[str, Any]] = []
            for aggregate in aggregates:
                self._verify_aggregate(aggregate, integrity_key)
                aggregate_export.append(
                    {
                        "variant_id": aggregate["variant_id"],
                        "exposures": int(aggregate["exposures"]),
                        "outcomes": int(aggregate["outcomes"]),
                        "successes": int(aggregate["successes"]),
                        "failures": int(aggregate["failures"]),
                        "revision": int(aggregate["revision"]),
                    }
                )
            if {str(item["variant_id"]) for item in aggregates} != {
                str(item["variant_id"]) for item in definition["variants"]
            }:
                raise ConsentExperimentIntegrityError(
                    "experiment aggregate set does not match the definition"
                )
            audits = connection.execute(
                "SELECT * FROM consent_experiment_audit WHERE tenant = ? "
                "AND experiment_id = ? ORDER BY event_index",
                (tenant, experiment),
            ).fetchall()
            if len(audits) > _MAX_AUDIT_EVENTS:
                raise ConsentExperimentIntegrityError("audit export exceeds bounded limit")
            audit_export: list[dict[str, Any]] = []
            previous_mac: str | None = None
            for expected_index, audit in enumerate(audits, start=1):
                details = _loads(audit["details_json"], "audit details")
                body = {
                    "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                    "experiment_id": experiment,
                    "event_index": int(audit["event_index"]),
                    "action": audit["action"],
                    "actor_token": audit["actor_token"],
                    "details": details,
                    "previous_mac": audit["previous_mac"],
                    "created_at": audit["created_at"],
                }
                if (
                    int(audit["event_index"]) != expected_index
                    or audit["previous_mac"] != previous_mac
                    or not text_equals(
                        _mac(integrity_key, body), str(audit["event_mac"])
                    )
                ):
                    raise ConsentExperimentIntegrityError("experiment audit chain failed")
                previous_mac = str(audit["event_mac"])
                audit_export.append(
                    {
                        "event_index": expected_index,
                        "action": audit["action"],
                        "actor_token": audit["actor_token"],
                        "details": details,
                        "created_at": audit["created_at"],
                        "event_mac": audit["event_mac"],
                    }
                )
            analyses = connection.execute(
                "SELECT * FROM consent_experiment_analyses WHERE tenant = ? "
                "AND experiment_id = ? ORDER BY look_number",
                (tenant, experiment),
            ).fetchall()
            analysis_export: list[dict[str, Any]] = []
            for analysis in analyses:
                result = _loads(analysis["result_json"], "analysis result")
                if not isinstance(result, dict) or not text_equals(
                    _mac(integrity_key, result), str(analysis["result_mac"])
                ):
                    raise ConsentExperimentIntegrityError("analysis export failed integrity")
                analysis_export.append(result)
            dedupe_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM consent_experiment_dedupe WHERE tenant = ? "
                    "AND experiment_id = ?",
                    (tenant, experiment),
                ).fetchone()[0]
            )
            export = {
                "schema": EXPORT_SCHEMA,
                "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                "experiment": self._project(row, definition),
                "aggregates": aggregate_export,
                "analyses": analysis_export,
                "audit": audit_export,
                "pseudonymous_dedupe_record_count": dedupe_count,
                "raw_identity_retained": False,
                "raw_profile_retained": False,
                "raw_event_payload_retained": False,
                "integrity_verified": True,
            }
            return {**export, "export_sha256": _sha256(export)}


__all__ = [
    "ANALYSIS_SCHEMA",
    "EXPERIMENT_SCHEMA",
    "EXPORT_SCHEMA",
    "AssignmentContext",
    "ConsentExperimentAuthority",
    "ConsentExperimentConfigError",
    "ConsentExperimentConflict",
    "ConsentExperimentError",
    "ConsentExperimentIntegrityError",
    "ConsentExperimentNotFound",
    "ConsentExperimentStateError",
    "ConsentExperimentValidationError",
    "ExperimentAssignment",
    "ExperimentKeyAuthority",
    "ExperimentSpec",
    "ExperimentVariant",
    "experiments_enabled",
    "require_experiments_enabled",
]
