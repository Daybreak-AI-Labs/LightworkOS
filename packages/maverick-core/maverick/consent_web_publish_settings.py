"""Governed website SDK publish-settings authority.

This module stores immutable, tenant-bound website settings versions.  Every
create, activate, rollback, withdrawal, and read re-resolves the existing
consent-publishing property/publication authority supplied by the server.  The
browser cannot select tenant, actor, property or publication revisions, or
their digests.

The public projection is intentionally small and executable-content free.  It
contains a CSP *nonce requirement* flag, never a nonce value.  Local SQLite
integrity and recovery readiness do not establish browser, website, CDN, SDK,
or customer-property acceptance.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from . import consent_storage
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
PUBLIC_PROJECTION_SCHEMA = "lightwork.consent-web-publish-settings.public.v1"
SETTINGS_SCHEMA = "lightwork.consent-web-publish-settings.version.v1"
HEAD_SCHEMA = "lightwork.consent-web-publish-settings.head.v1"
OPERATION_SCHEMA = "lightwork.consent-web-publish-settings.operation.v1"
AUDIT_SCHEMA = "lightwork.consent-web-publish-settings.audit.v1"
TOMBSTONE_SCHEMA = "lightwork.consent-web-publish-settings.tombstone.v1"
META_SCHEMA = "lightwork.consent-web-publish-settings.store.v1"
RECOVERY_SCHEMA = "lightwork.consent-web-publish-settings.recovery.v1"

BROWSER_PROPERTY_ACCEPTANCE_VERIFIED = False
LIVE_BROWSER_ACCEPTANCE_VERIFIED = False
GENESIS_SHA256 = "0" * 64

ANALYTICS_CATEGORIES = frozenset(
    {"advertising", "analytics", "essential", "functional"}
)
COMMON_TRACKERS = frozenset(
    {
        "google_analytics",
        "google_tag_manager",
        "linkedin_insight",
        "meta_pixel",
        "microsoft_clarity",
        "tiktok_pixel",
    }
)
COOKIE_SAME_SITE_VALUES = frozenset({"lax", "none", "strict"})
COOKIE_DOMAIN_SEPARATION_VALUES = frozenset({"host_only", "property_domain"})

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SEMVER_RE = re.compile(
    r"(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\."
    r"(?:0|[1-9][0-9]{0,5})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_GEO_RE = re.compile(r"[A-Z]{2}(?:-[A-Z0-9]{1,16})?\Z")
_MAX_JSON_BYTES = 128 * 1024
_MAX_HISTORY = 1_000
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60


class WebPublishSettingsError(RuntimeError):
    """Base error with a closed, non-sensitive code."""

    def __init__(self, error_code: str) -> None:
        if not isinstance(error_code, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]{0,95}", error_code
        ):
            raise ValueError("web publish-settings error code is invalid")
        self.error_code = error_code
        super().__init__(error_code)


class WebPublishSettingsConfigError(WebPublishSettingsError):
    """The exact feature gate or a server-owned dependency is unavailable."""


class WebPublishSettingsValidationError(WebPublishSettingsError, ValueError):
    """A value is outside the closed, bounded contract."""


class WebPublishSettingsConflict(WebPublishSettingsError):
    """A CAS, idempotency, state, or authority precondition changed."""


class WebPublishSettingsNotFound(WebPublishSettingsError):
    """A tenant-scoped property settings record is absent."""


class WebPublishSettingsPermissionDenied(WebPublishSettingsError):
    """Authenticated administrative authority is unavailable."""


class WebPublishSettingsIntegrityError(WebPublishSettingsError):
    """Persisted state or local hash linkage cannot be trusted."""


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        result = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise WebPublishSettingsValidationError(
            "web_publish_settings_material_invalid"
        ) from exc
    if not 1 <= len(result) <= maximum:
        raise WebPublishSettingsValidationError(
            "web_publish_settings_material_oversized"
        )
    return result


def canonical_sha256(value: object) -> str:
    """Return the deterministic SHA-256 used by this authority."""

    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _tenant(value: object) -> str:
    if not isinstance(value, str):
        raise WebPublishSettingsValidationError("web_publish_settings_tenant_invalid")
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise WebPublishSettingsValidationError(
            "web_publish_settings_tenant_invalid"
        ) from exc


def _opaque(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise WebPublishSettingsValidationError(
            f"web_publish_settings_{label}_invalid"
        )
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise WebPublishSettingsValidationError(
            f"web_publish_settings_{label}_invalid"
        )
    return value


def _integer(value: object, *, minimum: int, maximum: int, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise WebPublishSettingsValidationError(
            f"web_publish_settings_{label}_invalid"
        )
    return value


def _timestamp(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WebPublishSettingsValidationError(
            f"web_publish_settings_{label}_invalid"
        )
    selected = float(value)
    if not math.isfinite(selected) or not 0 < selected < 100_000_000_000.0:
        raise WebPublishSettingsValidationError(
            f"web_publish_settings_{label}_invalid"
        )
    return selected


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), label="clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except WebPublishSettingsError:
        raise
    except Exception as exc:
        raise WebPublishSettingsConfigError(
            "web_publish_settings_clock_unavailable"
        ) from exc


def _idempotency_digest(value: object) -> str:
    if not isinstance(value, str) or _OP_RE.fullmatch(value) is None:
        raise WebPublishSettingsValidationError(
            "web_publish_settings_idempotency_key_invalid"
        )
    return _text_sha256("lightwork.web-publish-settings.idempotency.v1:" + value)


def _limit(value: object) -> int:
    return _integer(value, minimum=1, maximum=_MAX_HISTORY, label="limit")


@dataclass(frozen=True, slots=True)
class WebPublishSettingsConfig:
    """Exact default-off nested policy."""

    enable: bool = False
    retention_seconds: int = 365 * 24 * 60 * 60
    max_history: int = 250

    def __post_init__(self) -> None:
        if type(self.enable) is not bool:
            raise WebPublishSettingsConfigError(
                "web_publish_settings_enable_invalid"
            )
        try:
            _integer(
                self.retention_seconds,
                minimum=_MIN_RETENTION_SECONDS,
                maximum=_MAX_RETENTION_SECONDS,
                label="retention_seconds",
            )
            _integer(self.max_history, minimum=1, maximum=_MAX_HISTORY, label="max_history")
        except WebPublishSettingsValidationError as exc:
            raise WebPublishSettingsConfigError(exc.error_code) from exc

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> WebPublishSettingsConfig:
        if not isinstance(config, Mapping):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_configuration_unavailable"
            )
        consent = config.get("consent_preferences")
        if consent is None:
            return cls()
        if not isinstance(consent, Mapping):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_configuration_invalid"
            )
        publishing = consent.get("publishing")
        if publishing is None:
            return cls()
        if not isinstance(publishing, Mapping):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_configuration_invalid"
            )
        section = publishing.get("web_settings")
        if section is None:
            return cls()
        if not isinstance(section, Mapping):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_configuration_invalid"
            )
        allowed = frozenset({"enable", "retention_seconds", "max_history"})
        if any(key not in allowed for key in section):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_configuration_unknown_key"
            )
        values = {key: section[key] for key in allowed if key in section}
        try:
            selected = cls(**values)
        except TypeError as exc:
            raise WebPublishSettingsConfigError(
                "web_publish_settings_configuration_invalid"
            ) from exc
        if selected.enable and (
            consent.get("enable") is not True or publishing.get("enable") is not True
        ):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_parent_gate_disabled"
            )
        return selected


@dataclass(frozen=True, slots=True)
class GeolocationReconsent:
    jurisdiction: str
    reconsent_after_days: int

    def __post_init__(self) -> None:
        if not isinstance(self.jurisdiction, str) or _GEO_RE.fullmatch(
            self.jurisdiction
        ) is None:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_jurisdiction_invalid"
            )
        _integer(
            self.reconsent_after_days,
            minimum=1,
            maximum=3_650,
            label="reconsent_after_days",
        )


@dataclass(frozen=True, slots=True)
class AnalyticsCategoryAssignment:
    tracker: str
    category: str

    def __post_init__(self) -> None:
        if self.tracker not in COMMON_TRACKERS:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_tracker_invalid"
            )
        if self.category not in ANALYTICS_CATEGORIES:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_analytics_category_invalid"
            )


@dataclass(frozen=True, slots=True)
class WebsitePublishSettings:
    """Closed SDK settings.  There is deliberately no nonce-value field."""

    sdk_version: str
    geolocation_reconsent: tuple[GeolocationReconsent, ...]
    analytics_tracking_enabled: bool
    analytics_category_assignments: tuple[AnalyticsCategoryAssignment, ...]
    common_trackers: tuple[str, ...]
    cookie_same_site: str
    cookie_domain_separation: str
    spa_reload_on_route_change: bool
    csp_nonce_required: bool
    automatic_refresh_seconds: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.sdk_version, str) or _SEMVER_RE.fullmatch(
            self.sdk_version
        ) is None:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_sdk_version_invalid"
            )
        if type(self.analytics_tracking_enabled) is not bool:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_analytics_tracking_invalid"
            )
        if type(self.spa_reload_on_route_change) is not bool:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_spa_reload_invalid"
            )
        if type(self.csp_nonce_required) is not bool:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_csp_nonce_requirement_invalid"
            )
        if self.cookie_same_site not in COOKIE_SAME_SITE_VALUES:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_same_site_invalid"
            )
        if self.cookie_domain_separation not in COOKIE_DOMAIN_SEPARATION_VALUES:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_domain_separation_invalid"
            )
        if self.automatic_refresh_seconds is not None:
            _integer(
                self.automatic_refresh_seconds,
                minimum=30,
                maximum=86_400,
                label="automatic_refresh_seconds",
            )
        if not isinstance(self.geolocation_reconsent, tuple) or len(
            self.geolocation_reconsent
        ) > 64:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_geolocation_reconsent_invalid"
            )
        jurisdictions: list[str] = []
        for rule in self.geolocation_reconsent:
            if not isinstance(rule, GeolocationReconsent):
                raise WebPublishSettingsValidationError(
                    "web_publish_settings_geolocation_reconsent_invalid"
                )
            jurisdictions.append(rule.jurisdiction)
        if jurisdictions != sorted(jurisdictions) or len(jurisdictions) != len(
            set(jurisdictions)
        ):
            raise WebPublishSettingsValidationError(
                "web_publish_settings_geolocation_reconsent_invalid"
            )
        if (
            not isinstance(self.common_trackers, tuple)
            or len(self.common_trackers) > len(COMMON_TRACKERS)
            or any(not isinstance(tracker, str) for tracker in self.common_trackers)
            or tuple(sorted(self.common_trackers)) != self.common_trackers
            or len(set(self.common_trackers)) != len(self.common_trackers)
            or any(tracker not in COMMON_TRACKERS for tracker in self.common_trackers)
        ):
            raise WebPublishSettingsValidationError(
                "web_publish_settings_common_trackers_invalid"
            )
        if not isinstance(self.analytics_category_assignments, tuple) or len(
            self.analytics_category_assignments
        ) > len(COMMON_TRACKERS):
            raise WebPublishSettingsValidationError(
                "web_publish_settings_analytics_assignments_invalid"
            )
        assignment_trackers: list[str] = []
        for assignment in self.analytics_category_assignments:
            if not isinstance(assignment, AnalyticsCategoryAssignment):
                raise WebPublishSettingsValidationError(
                    "web_publish_settings_analytics_assignments_invalid"
                )
            assignment_trackers.append(assignment.tracker)
            if assignment.tracker not in self.common_trackers:
                raise WebPublishSettingsValidationError(
                    "web_publish_settings_assignment_tracker_not_enabled"
                )
        if assignment_trackers != sorted(assignment_trackers) or len(
            assignment_trackers
        ) != len(set(assignment_trackers)):
            raise WebPublishSettingsValidationError(
                "web_publish_settings_analytics_assignments_invalid"
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> WebsitePublishSettings:
        if not isinstance(value, Mapping):
            raise WebPublishSettingsValidationError(
                "web_publish_settings_settings_invalid"
            )
        allowed = {
            "sdk_version",
            "geolocation_reconsent",
            "analytics_tracking_enabled",
            "analytics_category_assignments",
            "common_trackers",
            "cookie_same_site",
            "cookie_domain_separation",
            "spa_reload_on_route_change",
            "csp_nonce_required",
            "automatic_refresh_seconds",
        }
        if set(value) != allowed:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_settings_fields_invalid"
            )
        geolocation = value["geolocation_reconsent"]
        assignments = value["analytics_category_assignments"]
        trackers = value["common_trackers"]
        if (
            not isinstance(geolocation, Sequence)
            or isinstance(geolocation, (str, bytes))
            or not isinstance(assignments, Sequence)
            or isinstance(assignments, (str, bytes))
            or not isinstance(trackers, Sequence)
            or isinstance(trackers, (str, bytes))
        ):
            raise WebPublishSettingsValidationError(
                "web_publish_settings_settings_invalid"
            )
        try:
            return cls(
                sdk_version=value["sdk_version"],
                geolocation_reconsent=tuple(
                    GeolocationReconsent(**dict(item))
                    if isinstance(item, Mapping)
                    else GeolocationReconsent("", 0)
                    for item in geolocation
                ),
                analytics_tracking_enabled=value["analytics_tracking_enabled"],
                analytics_category_assignments=tuple(
                    AnalyticsCategoryAssignment(**dict(item))
                    if isinstance(item, Mapping)
                    else AnalyticsCategoryAssignment("", "")
                    for item in assignments
                ),
                common_trackers=tuple(trackers),
                cookie_same_site=value["cookie_same_site"],
                cookie_domain_separation=value["cookie_domain_separation"],
                spa_reload_on_route_change=value["spa_reload_on_route_change"],
                csp_nonce_required=value["csp_nonce_required"],
                automatic_refresh_seconds=value["automatic_refresh_seconds"],
            )
        except TypeError as exc:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_settings_invalid"
            ) from exc

    def as_mapping(self) -> dict[str, object]:
        return {
            "sdk_version": self.sdk_version,
            "geolocation_reconsent": [asdict(item) for item in self.geolocation_reconsent],
            "analytics_tracking_enabled": self.analytics_tracking_enabled,
            "analytics_category_assignments": [
                asdict(item) for item in self.analytics_category_assignments
            ],
            "common_trackers": list(self.common_trackers),
            "cookie_same_site": self.cookie_same_site,
            "cookie_domain_separation": self.cookie_domain_separation,
            "spa_reload_on_route_change": self.spa_reload_on_route_change,
            "csp_nonce_required": self.csp_nonce_required,
            "automatic_refresh_seconds": self.automatic_refresh_seconds,
        }


@dataclass(frozen=True, slots=True)
class WebsitePublishingAuthority:
    """Exact server-resolved pin to the existing publishing authority."""

    tenant_id: str
    property_id: str
    property_kind: str
    property_revision: int
    property_sha256: str
    publication_id: str
    publication_revision: int
    publication_sha256: str
    publication_bundle_sha256: str
    publication_action: str
    publication_property_revision: int

    def __post_init__(self) -> None:
        _tenant(self.tenant_id)
        _opaque(self.property_id, label="property_id")
        if self.property_kind != "web":
            raise WebPublishSettingsConflict("web_publish_settings_property_not_web")
        _integer(
            self.property_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="property_revision",
        )
        _digest(self.property_sha256, label="property_sha256")
        _opaque(self.publication_id, label="publication_id")
        _integer(
            self.publication_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="publication_revision",
        )
        _digest(self.publication_sha256, label="publication_sha256")
        _digest(self.publication_bundle_sha256, label="publication_bundle_sha256")
        if self.publication_action not in {"publish", "rollback", "withdraw"}:
            raise WebPublishSettingsValidationError(
                "web_publish_settings_publication_action_invalid"
            )
        _integer(
            self.publication_property_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="publication_property_revision",
        )

    @property
    def usable(self) -> bool:
        return (
            self.publication_action in {"publish", "rollback"}
            and self.publication_property_revision == self.property_revision
        )

    def pin_mapping(self) -> dict[str, object]:
        return {
            "property_revision": self.property_revision,
            "property_sha256": self.property_sha256,
            "publication_id": self.publication_id,
            "publication_revision": self.publication_revision,
            "publication_sha256": self.publication_sha256,
            "publication_bundle_sha256": self.publication_bundle_sha256,
            "publication_action": self.publication_action,
            "publication_property_revision": self.publication_property_revision,
        }


@runtime_checkable
class PublishingAuthorityResolver(Protocol):
    def __call__(
        self, tenant_id: str, property_id: str
    ) -> WebsitePublishingAuthority: ...


PrincipalResolver = Callable[[], str]


@dataclass(frozen=True, slots=True)
class SettingsVersion:
    property_id: str
    version_id: str
    version_number: int
    settings: WebsitePublishSettings
    settings_sha256: str
    property_revision: int
    property_sha256: str
    publication_id: str
    publication_revision: int
    publication_sha256: str
    publication_bundle_sha256: str
    publication_property_revision: int
    created_by_sha256: str
    created_at: float
    retained_until: float
    record_sha256: str
    authority_current: bool = False


@dataclass(frozen=True, slots=True)
class SettingsHead:
    property_id: str
    revision: int
    state: str
    latest_version_id: str
    active_version_id: str | None
    property_revision: int
    property_sha256: str
    publication_id: str
    publication_revision: int
    publication_sha256: str
    publication_bundle_sha256: str
    publication_property_revision: int
    updated_at: float
    head_sha256: str
    authority_current: bool = False


def _authority_matches(
    authority: WebsitePublishingAuthority, pinned: SettingsVersion | SettingsHead
) -> bool:
    return (
        authority.usable
        and authority.property_id == pinned.property_id
        and authority.property_revision == pinned.property_revision
        and hmac.compare_digest(authority.property_sha256, pinned.property_sha256)
        and authority.publication_id == pinned.publication_id
        and authority.publication_revision == pinned.publication_revision
        and hmac.compare_digest(
            authority.publication_sha256, pinned.publication_sha256
        )
        and hmac.compare_digest(
            authority.publication_bundle_sha256,
            pinned.publication_bundle_sha256,
        )
        and authority.publication_property_revision
        == pinned.publication_property_revision
    )


def _version_material(version: SettingsVersion) -> dict[str, object]:
    result = asdict(version)
    result.pop("record_sha256", None)
    result.pop("authority_current", None)
    result["settings"] = version.settings.as_mapping()
    return {"schema": SETTINGS_SCHEMA, **result}


def _head_material(head: SettingsHead) -> dict[str, object]:
    result = asdict(head)
    result.pop("head_sha256", None)
    result.pop("authority_current", None)
    return {"schema": HEAD_SCHEMA, **result}


@contextmanager
def _closing_sqlite(connection: Any):
    """Close a per-call sqlite3 connection on exit; a shared (Postgres) session is left as before."""
    try:
        yield connection
    finally:
        if isinstance(connection, sqlite3.Connection):
            connection.close()


class WebPublishSettingsStore:
    """Tenant-bound immutable-version authority with CAS heads."""

    _schema_lock = threading.RLock()

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        publishing_authority_resolver: PublishingAuthorityResolver,
        principal_resolver: PrincipalResolver,
        retention_seconds: int = 365 * 24 * 60 * 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.tenant_id = _tenant(tenant_id)
        self.tenant_sha256 = _text_sha256(
            "lightwork.web-publish-settings.tenant.v1:" + self.tenant_id
        )
        if not callable(publishing_authority_resolver):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_publishing_authority_unavailable"
            )
        if not callable(principal_resolver):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_principal_authority_unavailable"
            )
        if not callable(clock):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_clock_unavailable"
            )
        self._publishing_authority_resolver = publishing_authority_resolver
        self._principal_resolver = principal_resolver
        self._retention_seconds = _integer(
            retention_seconds,
            minimum=_MIN_RETENTION_SECONDS,
            maximum=_MAX_RETENTION_SECONDS,
            label="retention_seconds",
        )
        self._clock = clock
        try:
            ensure_private_directory(self.path.parent)
            with self._schema_lock:
                with _closing_sqlite(self._connect(initializing=True)) as connection, connection:
                    self._create_schema(connection)
            if not consent_storage.shared():
                ensure_private_file(self.path)
        except WebPublishSettingsError:
            raise
        except (OSError, PermissionError, sqlite3.DatabaseError) as exc:
            raise WebPublishSettingsConfigError(
                "web_publish_settings_store_unavailable"
            ) from exc

    def _connect(self, *, initializing: bool = False) -> sqlite3.Connection:
        try:
            if consent_storage.shared():
                connection = consent_storage.connect(self.path, timeout=30)
            else:
                connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=30000")
                if initializing:
                    connection.execute("PRAGMA journal_mode=WAL")
                    connection.execute("PRAGMA synchronous=FULL")
            except BaseException:
                if isinstance(connection, sqlite3.Connection):
                    connection.close()
                raise
            return connection
        except sqlite3.DatabaseError as exc:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_store_invalid"
            ) from exc

    @contextmanager
    def _transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_meta_on(connection)
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS web_publish_settings_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL,
                tenant_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                integrity_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS web_publish_settings_versions (
                version_id TEXT PRIMARY KEY,
                property_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                settings_json TEXT NOT NULL,
                settings_sha256 TEXT NOT NULL,
                property_revision INTEGER NOT NULL,
                property_sha256 TEXT NOT NULL,
                publication_id TEXT NOT NULL,
                publication_revision INTEGER NOT NULL,
                publication_sha256 TEXT NOT NULL,
                publication_bundle_sha256 TEXT NOT NULL,
                publication_property_revision INTEGER NOT NULL,
                created_by_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                retained_until REAL NOT NULL,
                record_sha256 TEXT NOT NULL,
                UNIQUE(property_id, version_number)
            );
            CREATE TABLE IF NOT EXISTS web_publish_settings_heads (
                property_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                state TEXT NOT NULL,
                latest_version_id TEXT NOT NULL,
                active_version_id TEXT,
                property_revision INTEGER NOT NULL,
                property_sha256 TEXT NOT NULL,
                publication_id TEXT NOT NULL,
                publication_revision INTEGER NOT NULL,
                publication_sha256 TEXT NOT NULL,
                publication_bundle_sha256 TEXT NOT NULL,
                publication_property_revision INTEGER NOT NULL,
                updated_at REAL NOT NULL,
                head_sha256 TEXT NOT NULL,
                FOREIGN KEY(latest_version_id) REFERENCES web_publish_settings_versions(version_id),
                FOREIGN KEY(active_version_id) REFERENCES web_publish_settings_versions(version_id)
            );
            CREATE TABLE IF NOT EXISTS web_publish_settings_operations (
                idempotency_sha256 TEXT PRIMARY KEY,
                operation_type TEXT NOT NULL,
                property_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                result_json TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                integrity_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS web_publish_settings_audit (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                property_id TEXT NOT NULL,
                actor_sha256 TEXT NOT NULL,
                detail_sha256 TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                previous_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS web_publish_settings_tombstones (
                version_id TEXT PRIMARY KEY,
                property_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                settings_sha256 TEXT NOT NULL,
                final_record_sha256 TEXT NOT NULL,
                retained_until REAL NOT NULL,
                purged_at REAL NOT NULL,
                tombstone_sha256 TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS web_publish_settings_versions_immutable
            BEFORE UPDATE ON web_publish_settings_versions
            BEGIN SELECT RAISE(ABORT, 'immutable web publish-settings version'); END;
            CREATE TRIGGER IF NOT EXISTS web_publish_settings_audit_immutable_update
            BEFORE UPDATE ON web_publish_settings_audit
            BEGIN SELECT RAISE(ABORT, 'immutable web publish-settings audit'); END;
            CREATE TRIGGER IF NOT EXISTS web_publish_settings_audit_immutable_delete
            BEFORE DELETE ON web_publish_settings_audit
            BEGIN SELECT RAISE(ABORT, 'immutable web publish-settings audit'); END;
            CREATE TRIGGER IF NOT EXISTS web_publish_settings_operations_immutable_update
            BEFORE UPDATE ON web_publish_settings_operations
            BEGIN SELECT RAISE(ABORT, 'immutable web publish-settings operation'); END;
            """
        )
        row = connection.execute(
            "SELECT 1 FROM web_publish_settings_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            now = _clock_value(self._clock)
            material = {
                "schema": META_SCHEMA,
                "schema_version": SCHEMA_VERSION,
                "tenant_sha256": self.tenant_sha256,
                "created_at": now,
            }
            connection.execute(
                "INSERT INTO web_publish_settings_meta VALUES (1,?,?,?,?)",
                (
                    SCHEMA_VERSION,
                    self.tenant_sha256,
                    now,
                    canonical_sha256(material),
                ),
            )
        self._verify_meta_on(connection)

    def _verify_meta_on(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT schema_version,tenant_sha256,created_at,integrity_sha256 "
            "FROM web_publish_settings_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_metadata_missing"
            )
        material = {
            "schema": META_SCHEMA,
            "schema_version": int(row["schema_version"]),
            "tenant_sha256": str(row["tenant_sha256"]),
            "created_at": float(row["created_at"]),
        }
        if (
            material["schema_version"] != SCHEMA_VERSION
            or not hmac.compare_digest(
                str(material["tenant_sha256"]), self.tenant_sha256
            )
            or not hmac.compare_digest(
                canonical_sha256(material), str(row["integrity_sha256"])
            )
        ):
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_metadata_invalid"
            )

    def _resolve_authority(
        self, property_id: object, *, require_usable: bool
    ) -> WebsitePublishingAuthority:
        selected = _opaque(property_id, label="property_id")
        try:
            authority = self._publishing_authority_resolver(self.tenant_id, selected)
        except (KeyboardInterrupt, SystemExit):
            raise
        except WebPublishSettingsError:
            raise
        except Exception as exc:
            raise WebPublishSettingsConfigError(
                "web_publish_settings_publishing_authority_unavailable"
            ) from exc
        if not isinstance(authority, WebsitePublishingAuthority):
            raise WebPublishSettingsConfigError(
                "web_publish_settings_publishing_authority_invalid"
            )
        if authority.tenant_id != self.tenant_id or authority.property_id != selected:
            raise WebPublishSettingsConflict(
                "web_publish_settings_publishing_authority_mismatch"
            )
        if require_usable and not authority.usable:
            raise WebPublishSettingsConflict(
                "web_publish_settings_publication_not_usable"
            )
        return authority

    def _actor_sha256(self) -> str:
        try:
            principal = self._principal_resolver()
        except (KeyboardInterrupt, SystemExit):
            raise
        except WebPublishSettingsError:
            raise
        except Exception as exc:
            raise WebPublishSettingsPermissionDenied(
                "web_publish_settings_principal_unavailable"
            ) from exc
        if (
            not isinstance(principal, str)
            or not principal.strip()
            or len(principal) > 512
        ):
            raise WebPublishSettingsPermissionDenied(
                "web_publish_settings_principal_unavailable"
            )
        return _text_sha256(
            "lightwork.web-publish-settings.actor.v1:"
            f"{self.tenant_sha256}:{principal.strip()}"
        )

    @staticmethod
    def _version_from_row(
        row: sqlite3.Row, authority: WebsitePublishingAuthority | None = None
    ) -> SettingsVersion:
        try:
            raw_settings = json.loads(str(row["settings_json"]))
        except (TypeError, ValueError) as exc:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_version_invalid"
            ) from exc
        settings = WebsitePublishSettings.from_mapping(raw_settings)
        version = SettingsVersion(
            property_id=str(row["property_id"]),
            version_id=str(row["version_id"]),
            version_number=int(row["version_number"]),
            settings=settings,
            settings_sha256=str(row["settings_sha256"]),
            property_revision=int(row["property_revision"]),
            property_sha256=str(row["property_sha256"]),
            publication_id=str(row["publication_id"]),
            publication_revision=int(row["publication_revision"]),
            publication_sha256=str(row["publication_sha256"]),
            publication_bundle_sha256=str(row["publication_bundle_sha256"]),
            publication_property_revision=int(row["publication_property_revision"]),
            created_by_sha256=str(row["created_by_sha256"]),
            created_at=float(row["created_at"]),
            retained_until=float(row["retained_until"]),
            record_sha256=str(row["record_sha256"]),
            authority_current=False,
        )
        _opaque(version.property_id, label="property_id")
        _opaque(version.version_id, label="version_id")
        _integer(
            version.version_number,
            minimum=1,
            maximum=2**31 - 1,
            label="version_number",
        )
        for label in (
            "settings_sha256",
            "property_sha256",
            "publication_sha256",
            "publication_bundle_sha256",
            "created_by_sha256",
            "record_sha256",
        ):
            _digest(getattr(version, label), label=label)
        if not hmac.compare_digest(
            version.settings_sha256, canonical_sha256(settings.as_mapping())
        ) or not hmac.compare_digest(
            version.record_sha256, canonical_sha256(_version_material(version))
        ):
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_version_integrity_invalid"
            )
        return replace(
            version,
            authority_current=(
                authority is not None and _authority_matches(authority, version)
            ),
        )

    @staticmethod
    def _head_from_row(
        row: sqlite3.Row, authority: WebsitePublishingAuthority | None = None
    ) -> SettingsHead:
        head = SettingsHead(
            property_id=str(row["property_id"]),
            revision=int(row["revision"]),
            state=str(row["state"]),
            latest_version_id=str(row["latest_version_id"]),
            active_version_id=(
                None
                if row["active_version_id"] is None
                else str(row["active_version_id"])
            ),
            property_revision=int(row["property_revision"]),
            property_sha256=str(row["property_sha256"]),
            publication_id=str(row["publication_id"]),
            publication_revision=int(row["publication_revision"]),
            publication_sha256=str(row["publication_sha256"]),
            publication_bundle_sha256=str(row["publication_bundle_sha256"]),
            publication_property_revision=int(row["publication_property_revision"]),
            updated_at=float(row["updated_at"]),
            head_sha256=str(row["head_sha256"]),
            authority_current=False,
        )
        if head.state not in {"active", "draft", "withdrawn"}:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_head_state_invalid"
            )
        if (head.state == "active") != (head.active_version_id is not None):
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_head_state_invalid"
            )
        if not hmac.compare_digest(
            head.head_sha256, canonical_sha256(_head_material(head))
        ):
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_head_integrity_invalid"
            )
        return replace(
            head,
            authority_current=(
                authority is not None and _authority_matches(authority, head)
            ),
        )

    @staticmethod
    def _append_audit_on(
        connection: sqlite3.Connection,
        *,
        event_type: str,
        property_id: str,
        actor_sha256: str,
        detail: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        if event_type not in {
            "created",
            "activated",
            "rolled_back",
            "withdrawn",
            "retention_purged",
        }:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_event_type_invalid"
            )
        previous_row = connection.execute(
            "SELECT sequence,event_sha256 FROM web_publish_settings_audit "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous_row is None else int(previous_row["sequence"]) + 1
        previous = (
            GENESIS_SHA256
            if previous_row is None
            else str(previous_row["event_sha256"])
        )
        detail_sha256 = canonical_sha256(dict(detail))
        material = {
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "event_type": event_type,
            "property_id": property_id,
            "actor_sha256": actor_sha256,
            "detail_sha256": detail_sha256,
            "occurred_at": occurred_at,
            "previous_sha256": previous,
        }
        connection.execute(
            "INSERT INTO web_publish_settings_audit VALUES (?,?,?,?,?,?,?,?)",
            (
                sequence,
                event_type,
                property_id,
                actor_sha256,
                detail_sha256,
                occurred_at,
                previous,
                canonical_sha256(material),
            ),
        )

    @staticmethod
    def _operation_integrity(
        *,
        idempotency_sha256: str,
        operation_type: str,
        property_id: str,
        request_sha256: str,
        result_json: str,
        occurred_at: float,
    ) -> str:
        return canonical_sha256(
            {
                "schema": OPERATION_SCHEMA,
                "idempotency_sha256": idempotency_sha256,
                "operation_type": operation_type,
                "property_id": property_id,
                "request_sha256": request_sha256,
                "result_json": result_json,
                "occurred_at": occurred_at,
            }
        )

    @classmethod
    def _operation_replay(
        cls,
        connection: sqlite3.Connection,
        *,
        idempotency_sha256: str,
        operation_type: str,
        property_id: str,
        request_sha256: str,
    ) -> dict[str, object] | None:
        row = connection.execute(
            "SELECT * FROM web_publish_settings_operations WHERE idempotency_sha256=?",
            (idempotency_sha256,),
        ).fetchone()
        if row is None:
            return None
        values = {
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "operation_type": str(row["operation_type"]),
            "property_id": str(row["property_id"]),
            "request_sha256": str(row["request_sha256"]),
            "result_json": str(row["result_json"]),
            "occurred_at": float(row["occurred_at"]),
        }
        if not hmac.compare_digest(
            cls._operation_integrity(**values), str(row["integrity_sha256"])
        ):
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_operation_integrity_invalid"
            )
        if (
            values["operation_type"] != operation_type
            or values["property_id"] != property_id
            or not hmac.compare_digest(values["request_sha256"], request_sha256)
        ):
            raise WebPublishSettingsConflict(
                "web_publish_settings_idempotency_conflict"
            )
        try:
            result = json.loads(values["result_json"])
        except (TypeError, ValueError) as exc:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_operation_integrity_invalid"
            ) from exc
        if not isinstance(result, dict):
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_operation_integrity_invalid"
            )
        return result

    @classmethod
    def _record_operation_on(
        cls,
        connection: sqlite3.Connection,
        *,
        idempotency_sha256: str,
        operation_type: str,
        property_id: str,
        request_sha256: str,
        result: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        result_json = _canonical(dict(result)).decode("ascii")
        integrity = cls._operation_integrity(
            idempotency_sha256=idempotency_sha256,
            operation_type=operation_type,
            property_id=property_id,
            request_sha256=request_sha256,
            result_json=result_json,
            occurred_at=occurred_at,
        )
        connection.execute(
            "INSERT INTO web_publish_settings_operations VALUES (?,?,?,?,?,?,?)",
            (
                idempotency_sha256,
                operation_type,
                property_id,
                request_sha256,
                result_json,
                occurred_at,
                integrity,
            ),
        )

    @staticmethod
    def _result_reference(
        *, head: SettingsHead, version_id: str | None, idempotent_replay: bool
    ) -> dict[str, object]:
        return {
            "property_id": head.property_id,
            "head_revision": head.revision,
            "state": head.state,
            "latest_version_id": head.latest_version_id,
            "active_version_id": head.active_version_id,
            "version_id": version_id,
            "authority_current": head.authority_current,
            "idempotent_replay": idempotent_replay,
        }

    def create_version(
        self,
        *,
        property_id: str,
        settings: WebsitePublishSettings | Mapping[str, Any],
        expected_head_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        authority = self._resolve_authority(property_id, require_usable=True)
        actor = self._actor_sha256()
        selected = (
            settings
            if isinstance(settings, WebsitePublishSettings)
            else WebsitePublishSettings.from_mapping(settings)
        )
        expected = _integer(
            expected_head_revision,
            minimum=0,
            maximum=2**31 - 1,
            label="expected_head_revision",
        )
        idem = _idempotency_digest(idempotency_key)
        request_sha256 = canonical_sha256(
            {
                "operation": "create",
                "property_id": property_id,
                "expected_head_revision": expected,
                "settings": selected.as_mapping(),
                "authority": authority.pin_mapping(),
            }
        )
        now = _clock_value(self._clock)
        with self._transaction() as connection:
            replay = self._operation_replay(
                connection,
                idempotency_sha256=idem,
                operation_type="create",
                property_id=property_id,
                request_sha256=request_sha256,
            )
            if replay is not None:
                replay["idempotent_replay"] = True
                return replay
            row = connection.execute(
                "SELECT * FROM web_publish_settings_heads WHERE property_id=?",
                (property_id,),
            ).fetchone()
            current = 0 if row is None else int(row["revision"])
            if current != expected:
                raise WebPublishSettingsConflict(
                    "web_publish_settings_head_revision_conflict"
                )
            number_row = connection.execute(
                "SELECT COALESCE(MAX(version_number),0) AS maximum "
                "FROM web_publish_settings_versions WHERE property_id=?",
                (property_id,),
            ).fetchone()
            version_number = int(number_row["maximum"]) + 1
            version_id = "wps-" + secrets.token_hex(16)
            settings_sha256 = canonical_sha256(selected.as_mapping())
            version = SettingsVersion(
                property_id=property_id,
                version_id=version_id,
                version_number=version_number,
                settings=selected,
                settings_sha256=settings_sha256,
                property_revision=authority.property_revision,
                property_sha256=authority.property_sha256,
                publication_id=authority.publication_id,
                publication_revision=authority.publication_revision,
                publication_sha256=authority.publication_sha256,
                publication_bundle_sha256=authority.publication_bundle_sha256,
                publication_property_revision=authority.publication_property_revision,
                created_by_sha256=actor,
                created_at=now,
                retained_until=now + self._retention_seconds,
                record_sha256=GENESIS_SHA256,
                authority_current=True,
            )
            version = replace(
                version, record_sha256=canonical_sha256(_version_material(version))
            )
            connection.execute(
                """
                INSERT INTO web_publish_settings_versions VALUES (
                    ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
                )
                """,
                (
                    version.version_id,
                    version.property_id,
                    version.version_number,
                    _canonical(version.settings.as_mapping()).decode("ascii"),
                    version.settings_sha256,
                    version.property_revision,
                    version.property_sha256,
                    version.publication_id,
                    version.publication_revision,
                    version.publication_sha256,
                    version.publication_bundle_sha256,
                    version.publication_property_revision,
                    version.created_by_sha256,
                    version.created_at,
                    version.retained_until,
                    version.record_sha256,
                ),
            )
            active_version_id: str | None = None
            state = "draft"
            if row is not None:
                old_head = self._head_from_row(row, authority)
                if old_head.authority_current:
                    active_version_id = old_head.active_version_id
                    state = old_head.state if old_head.state == "active" else "draft"
            head = SettingsHead(
                property_id=property_id,
                revision=current + 1,
                state=state,
                latest_version_id=version_id,
                active_version_id=active_version_id,
                property_revision=authority.property_revision,
                property_sha256=authority.property_sha256,
                publication_id=authority.publication_id,
                publication_revision=authority.publication_revision,
                publication_sha256=authority.publication_sha256,
                publication_bundle_sha256=authority.publication_bundle_sha256,
                publication_property_revision=authority.publication_property_revision,
                updated_at=now,
                head_sha256=GENESIS_SHA256,
                authority_current=True,
            )
            head = replace(head, head_sha256=canonical_sha256(_head_material(head)))
            values = (
                head.revision,
                head.state,
                head.latest_version_id,
                head.active_version_id,
                head.property_revision,
                head.property_sha256,
                head.publication_id,
                head.publication_revision,
                head.publication_sha256,
                head.publication_bundle_sha256,
                head.publication_property_revision,
                head.updated_at,
                head.head_sha256,
            )
            if row is None:
                connection.execute(
                    "INSERT INTO web_publish_settings_heads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (property_id, *values),
                )
            else:
                result = connection.execute(
                    """
                    UPDATE web_publish_settings_heads SET
                        revision=?,state=?,latest_version_id=?,active_version_id=?,
                        property_revision=?,property_sha256=?,publication_id=?,
                        publication_revision=?,publication_sha256=?,
                        publication_bundle_sha256=?,publication_property_revision=?,
                        updated_at=?,head_sha256=?
                    WHERE property_id=? AND revision=?
                    """,
                    (*values, property_id, expected),
                )
                if result.rowcount != 1:
                    raise WebPublishSettingsConflict(
                        "web_publish_settings_head_revision_conflict"
                    )
            operation_result = self._result_reference(
                head=head, version_id=version_id, idempotent_replay=False
            )
            self._record_operation_on(
                connection,
                idempotency_sha256=idem,
                operation_type="create",
                property_id=property_id,
                request_sha256=request_sha256,
                result=operation_result,
                occurred_at=now,
            )
            self._append_audit_on(
                connection,
                event_type="created",
                property_id=property_id,
                actor_sha256=actor,
                detail={
                    "version_id": version_id,
                    "version_number": version_number,
                    "settings_sha256": settings_sha256,
                    "head_revision": head.revision,
                    "authority": authority.pin_mapping(),
                },
                occurred_at=now,
            )
            return operation_result

    def _select_version_on(
        self,
        connection: sqlite3.Connection,
        *,
        property_id: str,
        version_id: str,
        authority: WebsitePublishingAuthority,
    ) -> SettingsVersion:
        row = connection.execute(
            "SELECT * FROM web_publish_settings_versions "
            "WHERE property_id=? AND version_id=?",
            (property_id, version_id),
        ).fetchone()
        if row is None:
            raise WebPublishSettingsNotFound(
                "web_publish_settings_version_not_found"
            )
        return self._version_from_row(row, authority)

    def _head_mutation(
        self,
        *,
        property_id: str,
        version_id: str | None,
        expected_head_revision: int,
        idempotency_key: str,
        operation_type: str,
    ) -> dict[str, object]:
        authority = self._resolve_authority(property_id, require_usable=True)
        actor = self._actor_sha256()
        expected = _integer(
            expected_head_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="expected_head_revision",
        )
        if operation_type not in {"activate", "rollback", "withdraw"}:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_operation_invalid"
            )
        selected_version = (
            None if version_id is None else _opaque(version_id, label="version_id")
        )
        if (operation_type == "withdraw") != (selected_version is None):
            raise WebPublishSettingsValidationError(
                "web_publish_settings_operation_invalid"
            )
        idem = _idempotency_digest(idempotency_key)
        request_sha256 = canonical_sha256(
            {
                "operation": operation_type,
                "property_id": property_id,
                "version_id": selected_version,
                "expected_head_revision": expected,
                "authority": authority.pin_mapping(),
            }
        )
        now = _clock_value(self._clock)
        with self._transaction() as connection:
            replay = self._operation_replay(
                connection,
                idempotency_sha256=idem,
                operation_type=operation_type,
                property_id=property_id,
                request_sha256=request_sha256,
            )
            if replay is not None:
                replay["idempotent_replay"] = True
                return replay
            row = connection.execute(
                "SELECT * FROM web_publish_settings_heads WHERE property_id=?",
                (property_id,),
            ).fetchone()
            if row is None:
                raise WebPublishSettingsNotFound(
                    "web_publish_settings_head_not_found"
                )
            old = self._head_from_row(row, authority)
            if old.revision != expected:
                raise WebPublishSettingsConflict(
                    "web_publish_settings_head_revision_conflict"
                )
            target: SettingsVersion | None = None
            if selected_version is not None:
                target = self._select_version_on(
                    connection,
                    property_id=property_id,
                    version_id=selected_version,
                    authority=authority,
                )
                if not target.authority_current:
                    raise WebPublishSettingsConflict(
                        "web_publish_settings_version_authority_stale"
                    )
            head = SettingsHead(
                property_id=property_id,
                revision=old.revision + 1,
                state="withdrawn" if target is None else "active",
                latest_version_id=old.latest_version_id,
                active_version_id=None if target is None else target.version_id,
                property_revision=authority.property_revision,
                property_sha256=authority.property_sha256,
                publication_id=authority.publication_id,
                publication_revision=authority.publication_revision,
                publication_sha256=authority.publication_sha256,
                publication_bundle_sha256=authority.publication_bundle_sha256,
                publication_property_revision=authority.publication_property_revision,
                updated_at=now,
                head_sha256=GENESIS_SHA256,
                authority_current=True,
            )
            head = replace(head, head_sha256=canonical_sha256(_head_material(head)))
            result = connection.execute(
                """
                UPDATE web_publish_settings_heads SET
                    revision=?,state=?,latest_version_id=?,active_version_id=?,
                    property_revision=?,property_sha256=?,publication_id=?,
                    publication_revision=?,publication_sha256=?,
                    publication_bundle_sha256=?,publication_property_revision=?,
                    updated_at=?,head_sha256=?
                WHERE property_id=? AND revision=?
                """,
                (
                    head.revision,
                    head.state,
                    head.latest_version_id,
                    head.active_version_id,
                    head.property_revision,
                    head.property_sha256,
                    head.publication_id,
                    head.publication_revision,
                    head.publication_sha256,
                    head.publication_bundle_sha256,
                    head.publication_property_revision,
                    head.updated_at,
                    head.head_sha256,
                    property_id,
                    expected,
                ),
            )
            if result.rowcount != 1:
                raise WebPublishSettingsConflict(
                    "web_publish_settings_head_revision_conflict"
                )
            operation_result = self._result_reference(
                head=head,
                version_id=selected_version,
                idempotent_replay=False,
            )
            self._record_operation_on(
                connection,
                idempotency_sha256=idem,
                operation_type=operation_type,
                property_id=property_id,
                request_sha256=request_sha256,
                result=operation_result,
                occurred_at=now,
            )
            event_type = {
                "activate": "activated",
                "rollback": "rolled_back",
                "withdraw": "withdrawn",
            }[operation_type]
            self._append_audit_on(
                connection,
                event_type=event_type,
                property_id=property_id,
                actor_sha256=actor,
                detail={
                    "version_id": selected_version,
                    "head_revision": head.revision,
                    "authority": authority.pin_mapping(),
                },
                occurred_at=now,
            )
            return operation_result

    def activate_version(
        self,
        *,
        property_id: str,
        version_id: str,
        expected_head_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        return self._head_mutation(
            property_id=property_id,
            version_id=version_id,
            expected_head_revision=expected_head_revision,
            idempotency_key=idempotency_key,
            operation_type="activate",
        )

    def rollback(
        self,
        *,
        property_id: str,
        target_version_id: str,
        expected_head_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        return self._head_mutation(
            property_id=property_id,
            version_id=target_version_id,
            expected_head_revision=expected_head_revision,
            idempotency_key=idempotency_key,
            operation_type="rollback",
        )

    def withdraw(
        self,
        *,
        property_id: str,
        expected_head_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        return self._head_mutation(
            property_id=property_id,
            version_id=None,
            expected_head_revision=expected_head_revision,
            idempotency_key=idempotency_key,
            operation_type="withdraw",
        )

    def get_head(self, *, property_id: str) -> SettingsHead:
        authority = self._resolve_authority(property_id, require_usable=False)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            row = connection.execute(
                "SELECT * FROM web_publish_settings_heads WHERE property_id=?",
                (property_id,),
            ).fetchone()
            if row is None:
                raise WebPublishSettingsNotFound(
                    "web_publish_settings_head_not_found"
                )
            return self._head_from_row(row, authority)

    def get_version(self, *, property_id: str, version_id: str) -> SettingsVersion:
        authority = self._resolve_authority(property_id, require_usable=False)
        selected = _opaque(version_id, label="version_id")
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            return self._select_version_on(
                connection,
                property_id=property_id,
                version_id=selected,
                authority=authority,
            )

    def list_versions(
        self, *, property_id: str, limit: int = 100
    ) -> list[SettingsVersion]:
        authority = self._resolve_authority(property_id, require_usable=False)
        selected_limit = _limit(limit)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            rows = connection.execute(
                "SELECT * FROM web_publish_settings_versions WHERE property_id=? "
                "ORDER BY version_number DESC LIMIT ?",
                (property_id, selected_limit),
            ).fetchall()
            return [self._version_from_row(row, authority) for row in rows]

    def public_projection(self, *, property_id: str) -> dict[str, object]:
        """Return SDK-safe JSON or an explicit enabled-but-not-ready state."""

        authority = self._resolve_authority(property_id, require_usable=False)
        base: dict[str, object] = {
            "schema": PUBLIC_PROJECTION_SCHEMA,
            "enabled": True,
            "ready": False,
            "reason": "settings_not_ready",
            "property_id": property_id,
            "browser_property_acceptance_verified": False,
        }
        if not authority.usable:
            base["reason"] = "publication_withdrawn_or_stale"
            return base
        try:
            with _closing_sqlite(self._connect()) as connection, connection:
                self._verify_meta_on(connection)
                row = connection.execute(
                    "SELECT * FROM web_publish_settings_heads WHERE property_id=?",
                    (property_id,),
                ).fetchone()
                if row is None:
                    return base
                head = self._head_from_row(row, authority)
                if (
                    head.state != "active"
                    or not head.authority_current
                    or head.active_version_id is None
                ):
                    base["reason"] = (
                        "settings_withdrawn"
                        if head.state == "withdrawn"
                        else "settings_authority_stale_or_inactive"
                    )
                    return base
                version = self._select_version_on(
                    connection,
                    property_id=property_id,
                    version_id=head.active_version_id,
                    authority=authority,
                )
                if not version.authority_current:
                    base["reason"] = "settings_authority_stale_or_inactive"
                    return base
        except WebPublishSettingsNotFound:
            return base
        settings = version.settings
        base.update(
            {
                "ready": True,
                "reason": "ready",
                "head_revision": head.revision,
                "settings_version_id": version.version_id,
                "settings_sha256": version.settings_sha256,
                "property": {
                    "revision": authority.property_revision,
                    "sha256": authority.property_sha256,
                },
                "publication": {
                    "id": authority.publication_id,
                    "revision": authority.publication_revision,
                    "sha256": authority.publication_sha256,
                    "bundle_sha256": authority.publication_bundle_sha256,
                },
                "settings": {
                    "sdk_version": settings.sdk_version,
                    "geolocation_reconsent": [
                        asdict(item) for item in settings.geolocation_reconsent
                    ],
                    "analytics": {
                        "tracking_enabled": settings.analytics_tracking_enabled,
                        "category_assignments": [
                            asdict(item)
                            for item in settings.analytics_category_assignments
                        ],
                    },
                    "common_trackers": list(settings.common_trackers),
                    "cookies": {
                        "same_site": settings.cookie_same_site,
                        "domain_separation": settings.cookie_domain_separation,
                        "secure_required": True,
                    },
                    "spa": {
                        "reload_on_route_change": settings.spa_reload_on_route_change
                    },
                    "csp": {"nonce_required": settings.csp_nonce_required},
                    "automatic_refresh_seconds": settings.automatic_refresh_seconds,
                },
            }
        )
        return base

    def audit_history(
        self, *, property_id: str | None = None, limit: int = 100
    ) -> list[dict[str, object]]:
        if property_id is not None:
            self._resolve_authority(property_id, require_usable=False)
        selected_limit = _limit(limit)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            if property_id is None:
                rows = connection.execute(
                    "SELECT * FROM web_publish_settings_audit "
                    "ORDER BY sequence DESC LIMIT ?",
                    (selected_limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM web_publish_settings_audit WHERE property_id=? "
                    "ORDER BY sequence DESC LIMIT ?",
                    (property_id, selected_limit),
                ).fetchall()
            return [
                {
                    "sequence": int(row["sequence"]),
                    "event_type": str(row["event_type"]),
                    "property_id": str(row["property_id"]),
                    "actor_sha256": str(row["actor_sha256"]),
                    "detail_sha256": str(row["detail_sha256"]),
                    "occurred_at": float(row["occurred_at"]),
                    "previous_sha256": str(row["previous_sha256"]),
                    "event_sha256": str(row["event_sha256"]),
                }
                for row in rows
            ]

    def purge_version(
        self,
        *,
        property_id: str,
        version_id: str,
        expected_head_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        authority = self._resolve_authority(property_id, require_usable=False)
        actor = self._actor_sha256()
        selected_version = _opaque(version_id, label="version_id")
        expected = _integer(
            expected_head_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="expected_head_revision",
        )
        idem = _idempotency_digest(idempotency_key)
        request_sha256 = canonical_sha256(
            {
                "operation": "retention_purge",
                "property_id": property_id,
                "version_id": selected_version,
                "expected_head_revision": expected,
                "authority": authority.pin_mapping(),
            }
        )
        now = _clock_value(self._clock)
        with self._transaction() as connection:
            replay = self._operation_replay(
                connection,
                idempotency_sha256=idem,
                operation_type="retention_purge",
                property_id=property_id,
                request_sha256=request_sha256,
            )
            if replay is not None:
                replay["idempotent_replay"] = True
                return replay
            head_row = connection.execute(
                "SELECT * FROM web_publish_settings_heads WHERE property_id=?",
                (property_id,),
            ).fetchone()
            if head_row is None:
                raise WebPublishSettingsNotFound(
                    "web_publish_settings_head_not_found"
                )
            old = self._head_from_row(head_row, authority)
            if old.revision != expected:
                raise WebPublishSettingsConflict(
                    "web_publish_settings_head_revision_conflict"
                )
            if selected_version in {old.latest_version_id, old.active_version_id}:
                raise WebPublishSettingsConflict(
                    "web_publish_settings_retention_target_in_use"
                )
            version = self._select_version_on(
                connection,
                property_id=property_id,
                version_id=selected_version,
                authority=authority,
            )
            if now < version.retained_until:
                raise WebPublishSettingsConflict(
                    "web_publish_settings_retention_not_elapsed"
                )
            tombstone_material = {
                "schema": TOMBSTONE_SCHEMA,
                "version_id": version.version_id,
                "property_id": property_id,
                "version_number": version.version_number,
                "settings_sha256": version.settings_sha256,
                "final_record_sha256": version.record_sha256,
                "retained_until": version.retained_until,
                "purged_at": now,
            }
            tombstone_sha256 = canonical_sha256(tombstone_material)
            connection.execute(
                "INSERT INTO web_publish_settings_tombstones VALUES (?,?,?,?,?,?,?,?)",
                (
                    version.version_id,
                    property_id,
                    version.version_number,
                    version.settings_sha256,
                    version.record_sha256,
                    version.retained_until,
                    now,
                    tombstone_sha256,
                ),
            )
            connection.execute(
                "DELETE FROM web_publish_settings_versions WHERE version_id=?",
                (version.version_id,),
            )
            head = replace(
                old,
                revision=old.revision + 1,
                updated_at=now,
                head_sha256=GENESIS_SHA256,
                authority_current=old.authority_current,
            )
            head = replace(head, head_sha256=canonical_sha256(_head_material(head)))
            result = connection.execute(
                "UPDATE web_publish_settings_heads SET revision=?,updated_at=?,head_sha256=? "
                "WHERE property_id=? AND revision=?",
                (head.revision, now, head.head_sha256, property_id, expected),
            )
            if result.rowcount != 1:
                raise WebPublishSettingsConflict(
                    "web_publish_settings_head_revision_conflict"
                )
            operation_result = self._result_reference(
                head=head,
                version_id=version.version_id,
                idempotent_replay=False,
            )
            operation_result["purged"] = True
            operation_result["tombstone_sha256"] = tombstone_sha256
            self._record_operation_on(
                connection,
                idempotency_sha256=idem,
                operation_type="retention_purge",
                property_id=property_id,
                request_sha256=request_sha256,
                result=operation_result,
                occurred_at=now,
            )
            self._append_audit_on(
                connection,
                event_type="retention_purged",
                property_id=property_id,
                actor_sha256=actor,
                detail={
                    "version_id": version.version_id,
                    "tombstone_sha256": tombstone_sha256,
                    "head_revision": head.revision,
                },
                occurred_at=now,
            )
            return operation_result

    def verify_integrity(self) -> dict[str, object]:
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            version_rows = connection.execute(
                "SELECT * FROM web_publish_settings_versions ORDER BY property_id,version_number"
            ).fetchall()
            for row in version_rows:
                self._version_from_row(row)
            head_rows = connection.execute(
                "SELECT * FROM web_publish_settings_heads ORDER BY property_id"
            ).fetchall()
            for row in head_rows:
                head = self._head_from_row(row)
                for selected in (head.latest_version_id, head.active_version_id):
                    if selected is not None and connection.execute(
                        "SELECT 1 FROM web_publish_settings_versions WHERE version_id=?",
                        (selected,),
                    ).fetchone() is None:
                        raise WebPublishSettingsIntegrityError(
                            "web_publish_settings_head_target_missing"
                        )
            operation_rows = connection.execute(
                "SELECT * FROM web_publish_settings_operations"
            ).fetchall()
            for row in operation_rows:
                values = {
                    "idempotency_sha256": str(row["idempotency_sha256"]),
                    "operation_type": str(row["operation_type"]),
                    "property_id": str(row["property_id"]),
                    "request_sha256": str(row["request_sha256"]),
                    "result_json": str(row["result_json"]),
                    "occurred_at": float(row["occurred_at"]),
                }
                if not hmac.compare_digest(
                    self._operation_integrity(**values),
                    str(row["integrity_sha256"]),
                ):
                    raise WebPublishSettingsIntegrityError(
                        "web_publish_settings_operation_integrity_invalid"
                    )
            previous = GENESIS_SHA256
            audit_rows = connection.execute(
                "SELECT * FROM web_publish_settings_audit ORDER BY sequence"
            ).fetchall()
            for expected_sequence, row in enumerate(audit_rows, start=1):
                material = {
                    "schema": AUDIT_SCHEMA,
                    "sequence": int(row["sequence"]),
                    "event_type": str(row["event_type"]),
                    "property_id": str(row["property_id"]),
                    "actor_sha256": str(row["actor_sha256"]),
                    "detail_sha256": str(row["detail_sha256"]),
                    "occurred_at": float(row["occurred_at"]),
                    "previous_sha256": str(row["previous_sha256"]),
                }
                if (
                    material["sequence"] != expected_sequence
                    or not hmac.compare_digest(
                        str(material["previous_sha256"]), previous
                    )
                    or not hmac.compare_digest(
                        canonical_sha256(material), str(row["event_sha256"])
                    )
                ):
                    raise WebPublishSettingsIntegrityError(
                        "web_publish_settings_audit_integrity_invalid"
                    )
                previous = str(row["event_sha256"])
            tombstone_rows = connection.execute(
                "SELECT * FROM web_publish_settings_tombstones"
            ).fetchall()
            for row in tombstone_rows:
                material = {
                    "schema": TOMBSTONE_SCHEMA,
                    "version_id": str(row["version_id"]),
                    "property_id": str(row["property_id"]),
                    "version_number": int(row["version_number"]),
                    "settings_sha256": str(row["settings_sha256"]),
                    "final_record_sha256": str(row["final_record_sha256"]),
                    "retained_until": float(row["retained_until"]),
                    "purged_at": float(row["purged_at"]),
                }
                if not hmac.compare_digest(
                    canonical_sha256(material), str(row["tombstone_sha256"])
                ):
                    raise WebPublishSettingsIntegrityError(
                        "web_publish_settings_tombstone_integrity_invalid"
                    )
            return {
                "schema": "lightwork.consent-web-publish-settings.integrity.v1",
                "valid": True,
                "schema_version": SCHEMA_VERSION,
                "version_count": len(version_rows),
                "head_count": len(head_rows),
                "operation_count": len(operation_rows),
                "audit_event_count": len(audit_rows),
                "tombstone_count": len(tombstone_rows),
                "audit_tail_sha256": previous,
                "external_worm_anchor_verified": False,
                "browser_property_acceptance_verified": False,
            }

    def recovery_status(self) -> dict[str, object]:
        """Verify durable local state and report the bounded recovery contract."""

        integrity = self.verify_integrity()
        try:
            with _closing_sqlite(self._connect()) as connection, connection:
                quick_check = connection.execute("PRAGMA quick_check").fetchone()
                wal = connection.execute("PRAGMA journal_mode").fetchone()
        except sqlite3.DatabaseError as exc:
            raise WebPublishSettingsIntegrityError(
                "web_publish_settings_recovery_check_failed"
            ) from exc
        database_valid = (
            quick_check is not None and str(quick_check[0]).lower() == "ok"
        )
        return {
            "schema": RECOVERY_SCHEMA,
            "ready": bool(integrity["valid"] and database_valid),
            "database_quick_check_valid": database_valid,
            "journal_mode": None if wal is None else str(wal[0]).lower(),
            "atomic_transactions": True,
            "immutable_versions": True,
            "cas_heads": True,
            "external_backup_restore_verified": False,
            "browser_property_acceptance_verified": False,
        }


__all__ = [
    "ANALYTICS_CATEGORIES",
    "BROWSER_PROPERTY_ACCEPTANCE_VERIFIED",
    "COMMON_TRACKERS",
    "COOKIE_DOMAIN_SEPARATION_VALUES",
    "COOKIE_SAME_SITE_VALUES",
    "LIVE_BROWSER_ACCEPTANCE_VERIFIED",
    "PUBLIC_PROJECTION_SCHEMA",
    "AnalyticsCategoryAssignment",
    "GeolocationReconsent",
    "PublishingAuthorityResolver",
    "SettingsHead",
    "SettingsVersion",
    "WebPublishSettingsConfig",
    "WebPublishSettingsConfigError",
    "WebPublishSettingsConflict",
    "WebPublishSettingsError",
    "WebPublishSettingsIntegrityError",
    "WebPublishSettingsNotFound",
    "WebPublishSettingsPermissionDenied",
    "WebPublishSettingsStore",
    "WebPublishSettingsValidationError",
    "WebsitePublishSettings",
    "WebsitePublishingAuthority",
    "canonical_sha256",
]
