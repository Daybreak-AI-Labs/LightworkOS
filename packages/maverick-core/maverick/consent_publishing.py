"""Tenant-scoped authority for publishing consumer consent experiences.

This module is the durable publishing boundary behind, but deliberately not
itself, a banner, preference centre, scanner, or mobile SDK.  It stores only
operator-authored configuration and opaque identifiers.  Consumer identity,
credentials, cookies, request headers, and device identifiers are outside its
contract.

The authority has four important properties:

* every method requires an explicit tenant identifier;
* versioned content and publication records are immutable;
* mutable property and publication heads use optimistic concurrency;
* withdrawal advances the head to a content-free immutable tombstone; and
* public resolution starts from a server-resolved property and fails closed.

Translations are plain text.  Templates are closed structured records rather
than HTML, JavaScript, or CSS.  That keeps executable content outside the
publishing database and makes every publication digest deterministic.

When ``require_signed_publications`` is on, each publish, restore and
withdrawal is also signed inside its own transaction with the workspace's
Ed25519 key (:mod:`maverick.consent_publication_signing`); a publish or
restore without a usable key is refused, and nothing is signed when it is off.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import consent_publication_signing as publication_signing
from . import consent_storage
from .constant_time import text_equals
from .file_lock import (
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import canonical_tenant_id

SCHEMA_VERSION = 2
PREVIEW_SCHEMA = "lightwork.consent-publication-preview.v1"
PUBLICATION_SCHEMA = "lightwork.consent-publication.v1"
PUBLIC_CONFIGURATION_SCHEMA = "lightwork.public-consent-configuration.v1"
WITHDRAWAL_TOMBSTONE_SCHEMA = "lightwork.consent-publication-withdrawal.v1"

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_BUNDLE_RE = re.compile(
    r"(?=.{3,255}\Z)[A-Za-z][A-Za-z0-9_-]*"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+\Z"
)
_LOCALE_RE = re.compile(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}\Z")
_JURISDICTION_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_COUNTRY_RE = re.compile(r"[A-Z]{2}\Z")
_REGION_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{0,31}\Z")
_FORBIDDEN_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_UNSAFE_TEXT_RE = re.compile(
    r"(?:javascript|vbscript)\s*:|data\s*:\s*text/html",
    re.IGNORECASE,
)
_THEME_COLOR_RE = re.compile(r"[0-9a-fA-F]{6}\Z")

_MAX_JSON_BYTES = 512 * 1024
_MAX_BUNDLE_BYTES = 512 * 1024
_MAX_PUBLIC_BYTES = 256 * 1024
_MAX_TRANSLATION_BYTES = 64 * 1024
_MAX_TEXT_BYTES = 4096
_MAX_BRANDING_TEXT_BYTES = 512
_MAX_MESSAGES = 256
_MAX_PROPERTIES_VALUES = 64
_MAX_RULES = 128
_MAX_SELECTORS = 64
_MAX_REFS = 128
_MAX_READ_LIMIT = 500

_PROPERTY_KINDS = frozenset({"web", "mobile"})
_MOBILE_PLATFORMS = frozenset({"android", "fireos", "ios", "roku", "tizen", "tvos", "webos"})
_RESOURCE_KINDS = frozenset(
    {
        "purpose",
        "topic",
        "custom_preference",
        "notice",
        "translation",
        "template",
        "theme",
        "rule_group",
    }
)
_LAWFUL_BASES = frozenset(
    {
        "consent",
        "contract",
        "legal_obligation",
        "legitimate_interests",
        "public_task",
        "vital_interests",
    }
)
_PREFERENCE_DEFAULTS = frozenset({"denied", "granted", "unset"})
_CUSTOM_VALUE_TYPES = frozenset({"boolean", "multi_select", "single_select"})
_TEMPLATE_SURFACES = frozenset({"banner", "mobile_sheet", "modal", "preferences_center"})
_TEMPLATE_ACTIONS = frozenset(
    {
        "accept_all",
        "close",
        "manage_preferences",
        "reject_all",
        "save_preferences",
    }
)
_CONSENT_MODES = frozenset({"notice_only", "opt_in", "opt_out"})
_IDEMPOTENCY_NAMESPACE = "consent-publishing-mutation"


class ConsentPublishingError(RuntimeError):
    """Base error for the consent publishing authority."""


class PublishingValidationError(ConsentPublishingError, ValueError):
    """An input cannot be represented by the closed publishing contract."""


class PublishingConflict(ConsentPublishingError):
    """An optimistic-concurrency precondition did not hold."""


class PublishingIdempotencyConflict(ConsentPublishingError):
    """An idempotency key was rebound to different request content."""


class PublishingNotFound(ConsentPublishingError):
    """A tenant-scoped publishing resource does not exist."""


class PublishingSigningUnavailable(PublishingConflict):
    """Signed publishing is required but no signing key is in custody."""


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise PublishingValidationError("publishing data must be finite JSON") from exc
    if not 1 <= len(payload) <= maximum:
        raise PublishingValidationError("publishing data exceeds its byte bound")
    return payload


def _sha256(value: object, *, maximum: int = _MAX_JSON_BYTES) -> str:
    return hashlib.sha256(_canonical(value, maximum=maximum)).hexdigest()


def _text(value: object, label: str, pattern: re.Pattern[str] = _REF_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PublishingValidationError(f"{label} is not a bounded opaque identifier")
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise PublishingValidationError("tenant_id is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PublishingValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1:
        raise PublishingValidationError(f"{label} must be a positive integer")
    return value


def _revision(value: object, label: str = "expected_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise PublishingValidationError(f"{label} must be a non-negative integer")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise PublishingValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_READ_LIMIT:
        raise PublishingValidationError(f"limit must be between 1 and {_MAX_READ_LIMIT}")
    return value


def _loads(value: object, label: str, *, maximum: int = _MAX_JSON_BYTES) -> Any:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise ConsentPublishingError(f"stored {label} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ConsentPublishingError(f"stored {label} is invalid") from exc


def _plain_text(value: object, label: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise PublishingValidationError(f"{label} must be non-empty bounded plain text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise PublishingValidationError(f"{label} must be valid UTF-8 text") from exc
    if size > _MAX_TEXT_BYTES:
        raise PublishingValidationError(f"{label} exceeds its byte bound")
    if "<" in value or ">" in value or _FORBIDDEN_CONTROL_RE.search(value):
        raise PublishingValidationError(f"{label} cannot contain markup or control data")
    if _UNSAFE_TEXT_RE.search(value):
        raise PublishingValidationError(f"{label} cannot contain an executable URI")
    return value


def _branding_text(value: object, label: str) -> str:
    """Validate public brand copy without tightening legacy unbranded text."""

    if not isinstance(value, str) or value != value.strip() or not value:
        raise PublishingValidationError(f"{label} must be bounded plain text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise PublishingValidationError(f"{label} must be valid UTF-8 text") from exc
    if size > _MAX_BRANDING_TEXT_BYTES or "<" in value or ">" in value:
        raise PublishingValidationError(f"{label} must be bounded plain text")
    if any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise PublishingValidationError(f"{label} contains control data")
    if _UNSAFE_TEXT_RE.search(value):
        raise PublishingValidationError(f"{label} cannot contain an executable URI")
    return value


def _theme_color(value: object, label: str) -> str:
    if not isinstance(value, str) or not _THEME_COLOR_RE.fullmatch(value):
        raise PublishingValidationError(f"{label} must be one six-digit hexadecimal color")
    return value.lower()


def _relative_luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255.0 for index in (0, 2, 4)]
    linear = [
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(foreground: str, background: str) -> float:
    left = _relative_luminance(foreground)
    right = _relative_luminance(background)
    lighter, darker = max(left, right), min(left, right)
    return (lighter + 0.05) / (darker + 0.05)


def _locale(value: object, label: str = "locale") -> str:
    if not isinstance(value, str) or not _LOCALE_RE.fullmatch(value):
        raise PublishingValidationError(f"{label} must be a bounded BCP-47-style locale")
    parts = value.split("-")
    normalized = [parts[0].lower()]
    for part in parts[1:]:
        if len(part) == 4 and part.isalpha():
            normalized.append(part.title())
        elif len(part) == 2 and part.isalpha():
            normalized.append(part.upper())
        else:
            normalized.append(part.lower())
    return "-".join(normalized)


def _jurisdiction(value: object) -> str:
    if not isinstance(value, str):
        raise PublishingValidationError("jurisdiction must be a bounded identifier")
    normalized = value.lower()
    if not _JURISDICTION_RE.fullmatch(normalized):
        raise PublishingValidationError("jurisdiction must be a bounded identifier")
    return normalized


def _country(value: object, *, allow_empty: bool = False) -> str:
    if value == "" and allow_empty:
        return ""
    if not isinstance(value, str):
        raise PublishingValidationError("country_code must be an alpha-2 code")
    normalized = value.upper()
    if not _COUNTRY_RE.fullmatch(normalized):
        raise PublishingValidationError("country_code must be an alpha-2 code")
    return normalized


def _region(value: object, *, allow_empty: bool = False) -> str:
    if value == "" and allow_empty:
        return ""
    if not isinstance(value, str):
        raise PublishingValidationError("region_code must be a bounded code")
    normalized = value.upper()
    if not _REGION_RE.fullmatch(normalized):
        raise PublishingValidationError("region_code must be a bounded code")
    return normalized


def _domain(value: object) -> str:
    if not isinstance(value, str):
        raise PublishingValidationError("web domain is invalid")
    normalized = value.lower()
    if "*" in normalized or not _DOMAIN_RE.fullmatch(normalized):
        raise PublishingValidationError("web domain must be an exact DNS name")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return normalized
    raise PublishingValidationError("web domains cannot be IP addresses")


def _origin(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or "*" in value:
        raise PublishingValidationError("origin must be one exact HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PublishingValidationError("origin must be one exact HTTPS origin") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise PublishingValidationError("origin must be one exact HTTPS origin")
    host = _domain(parsed.hostname)
    if port is not None and not 1 <= port <= 65535:
        raise PublishingValidationError("origin port is invalid")
    return f"https://{host}" + (f":{port}" if port is not None else "")


def _bundle_id(value: object) -> str:
    if not isinstance(value, str) or "*" in value or not _BUNDLE_RE.fullmatch(value):
        raise PublishingValidationError("bundle_id must be one exact application id")
    return value


def _bounded_values(
    values: object,
    label: str,
    normalizer: Callable[[object], str],
    *,
    maximum: int = _MAX_PROPERTIES_VALUES,
    allow_empty: bool = False,
) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise PublishingValidationError(f"{label} must be a bounded sequence")
    if (not allow_empty and not values) or len(values) > maximum:
        raise PublishingValidationError(f"{label} must be a bounded sequence")
    normalized = [normalizer(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise PublishingValidationError(f"{label} cannot contain duplicates")
    return sorted(normalized)


def _version_ref(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"id", "version"}:
        raise PublishingValidationError(f"{label} must contain only id and version")
    return {
        "id": _text(value["id"], f"{label}.id"),
        "version": _positive_integer(value["version"], f"{label}.version"),
    }


def _version_refs(value: object, label: str) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise PublishingValidationError(f"{label} must be a bounded sequence")
    if len(value) > _MAX_REFS:
        raise PublishingValidationError(f"{label} exceeds its item bound")
    normalized = [_version_ref(item, label) for item in value]
    keys = {(item["id"], item["version"]) for item in normalized}
    if len(keys) != len(normalized):
        raise PublishingValidationError(f"{label} cannot contain duplicates")
    return sorted(normalized, key=lambda item: (item["id"], item["version"]))


def _normalize_rule(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PublishingValidationError("each rule must be a closed mapping")
    allowed = {
        "consent_mode",
        "country_codes",
        "custom_preferences",
        "default_locale",
        "jurisdictions",
        "locales",
        "notice",
        "priority",
        "purposes",
        "region_codes",
        "rule_id",
        "template",
        "topics",
        "translation_catalog_id",
        "translation_versions",
    }
    unknown = set(value) - allowed
    if unknown:
        raise PublishingValidationError("rule contains unsupported fields")
    required = {
        "default_locale",
        "locales",
        "notice",
        "priority",
        "rule_id",
        "template",
        "translation_catalog_id",
        "translation_versions",
    }
    if not required.issubset(value):
        raise PublishingValidationError("rule is missing required fields")
    priority = value["priority"]
    if (
        isinstance(priority, bool)
        or not isinstance(priority, int)
        or not 0 <= priority <= 1_000_000
    ):
        raise PublishingValidationError("rule priority must be between 0 and 1000000")
    locales = _bounded_values(
        value["locales"],
        "rule.locales",
        _locale,
        maximum=32,
    )
    default_locale = _locale(value["default_locale"], "default_locale")
    if default_locale not in locales:
        raise PublishingValidationError("default_locale must be one of rule.locales")
    raw_versions = value["translation_versions"]
    if not isinstance(raw_versions, Mapping) or not raw_versions:
        raise PublishingValidationError("translation_versions must be a mapping")
    translation_versions: dict[str, int] = {}
    for raw_locale, raw_version in raw_versions.items():
        normalized_locale = _locale(raw_locale, "translation locale")
        if normalized_locale in translation_versions:
            raise PublishingValidationError("translation locale is duplicated")
        translation_versions[normalized_locale] = _positive_integer(
            raw_version,
            "translation version",
        )
    if set(translation_versions) != set(locales):
        raise PublishingValidationError("translation_versions must exactly cover rule.locales")
    mode = value.get("consent_mode", "opt_in")
    if mode not in _CONSENT_MODES:
        raise PublishingValidationError("consent_mode is invalid")
    purposes = _version_refs(value.get("purposes", ()), "rule.purposes")
    topics = _version_refs(value.get("topics", ()), "rule.topics")
    custom = _version_refs(
        value.get("custom_preferences", ()),
        "rule.custom_preferences",
    )
    if not purposes and not topics and not custom:
        raise PublishingValidationError("rule must expose at least one preference")
    rule = {
        "rule_id": _text(value["rule_id"], "rule_id"),
        "priority": priority,
        "jurisdictions": _bounded_values(
            value.get("jurisdictions", ()),
            "rule.jurisdictions",
            _jurisdiction,
            maximum=_MAX_SELECTORS,
            allow_empty=True,
        ),
        "country_codes": _bounded_values(
            value.get("country_codes", ()),
            "rule.country_codes",
            _country,
            maximum=_MAX_SELECTORS,
            allow_empty=True,
        ),
        "region_codes": _bounded_values(
            value.get("region_codes", ()),
            "rule.region_codes",
            _region,
            maximum=_MAX_SELECTORS,
            allow_empty=True,
        ),
        "locales": locales,
        "default_locale": default_locale,
        "consent_mode": mode,
        "purposes": purposes,
        "topics": topics,
        "custom_preferences": custom,
        "notice": _version_ref(value["notice"], "rule.notice"),
        "template": _version_ref(value["template"], "rule.template"),
        "translation_catalog_id": _text(
            value["translation_catalog_id"],
            "translation_catalog_id",
        ),
        "translation_versions": dict(sorted(translation_versions.items())),
    }
    rule["rule_sha256"] = _sha256(rule)
    return rule


class ConsentPublishingStore:
    """Private SQLite authority for tenant-scoped consent publications."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        signing: Callable[[], publication_signing.SigningPolicy] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{secrets.token_urlsafe(18)}")
        # ``[consent_preferences.publishing] require_signed_publications`` and
        # the signing key custody, read on every publish (unset: unsigned).
        self._signing = signing or publication_signing.configured_policy
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    @staticmethod
    def _tenant(value: object) -> str:
        return _tenant_id(value)

    def _new_id(self, prefix: str) -> str:
        return _text(self._id_factory(prefix), f"{prefix}_id")

    @staticmethod
    def _idempotency_key(value: object) -> str:
        raw = _text(value, "idempotency_key", _IDEMPOTENCY_RE)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @contextlib.contextmanager
    def _connect(self):
        with consent_storage.authority_connection(
            self.path, ensure_directory=ensure_private_directory,
            ensure_file=ensure_private_file,
        ) as connection:
            yield connection

    @contextlib.contextmanager
    def _snapshot(self):
        """Hold one consistent read snapshot across a multi-query decision."""

        with self._connect() as connection:
            connection.execute("BEGIN")
            try:
                yield connection
            finally:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")

    def catalog(self, tenant_id: str, *, kind: str, query: str = "", resource_id: str = "",
                offset: int = 0, limit: int = 25) -> dict[str, Any]:
        """Bounded, tenant-scoped record selection from one consistent snapshot."""
        tenant = self._tenant(tenant_id)
        if kind not in _RESOURCE_KINDS | {"property"} or len(query) > 200 or not 0 <= offset <= 1_000_000 or not 1 <= limit <= 50:
            raise PublishingValidationError("invalid catalog search or page size")
        if resource_id:
            resource_id = _text(resource_id, "resource_id")
        with self._snapshot() as connection:
            if kind == "property":
                where = "p.tenant = ? AND instr(lower(p.property_id), lower(?)) > 0"
                args = [tenant, query]
                if resource_id:
                    where += " AND p.property_id = ?"
                    args.append(resource_id)
                total = connection.execute("SELECT count(*) FROM publishing_properties p WHERE " + where, args).fetchone()[0]
                rows = connection.execute(
                    "SELECT p.*, coalesce(h.current_revision, 0) AS publication_revision, a.action AS publication_action FROM publishing_properties p "
                    "LEFT JOIN consent_publication_heads h ON h.tenant = p.tenant AND h.property_id = p.property_id "
                    "LEFT JOIN consent_publications a ON a.tenant=h.tenant AND a.property_id=h.property_id AND a.publication_id=h.current_publication_id AND a.publication_revision=h.current_revision WHERE "
                    + where + " ORDER BY p.property_id LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
                items = [{**self._property_result(row, tenant), "publication_revision": int(row["publication_revision"]), "publication_action": row["publication_action"]} for row in rows]
            else:
                where = "v.tenant = ? AND v.resource_kind = ? AND instr(lower(v.resource_id || ' ' || v.locale), lower(?)) > 0"
                args = [tenant, kind, query]
                if resource_id:
                    where += " AND v.resource_id = ?"
                    args.append(resource_id)
                else:
                    where += " AND v.version = h.current_version"
                joined = " FROM publishing_versions v JOIN publishing_version_heads h ON h.tenant = v.tenant AND h.resource_kind = v.resource_kind AND h.resource_id = v.resource_id AND h.locale = v.locale WHERE "
                total = connection.execute("SELECT count(*)" + joined + where, args).fetchone()[0]
                rows = connection.execute("SELECT v.*, h.current_version" + joined + where + " ORDER BY v.resource_id, v.locale, v.version DESC LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
                items = []
                for row in rows:
                    item = self._resource_result(row, tenant)
                    item.pop("payload")
                    item["current_version"] = int(row["current_version"])
                    items.append(item)
            return {"items": items, "total": total, "offset": offset, "limit": limit,
                    "next_offset": offset + limit if offset + limit < total else None}

    def resource_version(self, tenant_id: str, kind: str, resource_id: str, version: int, *, locale: str = "") -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        if kind not in _RESOURCE_KINDS:
            raise PublishingValidationError("unknown resource kind")
        resource_id = _text(resource_id, "resource_id")
        version = _positive_integer(version, "version")
        locale = _locale(locale) if kind == "translation" else ""
        with self._snapshot() as connection:
            return self._resource_result(self._resource_row(connection, tenant, kind, resource_id, version, locale=locale), tenant)

    def _initialize(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS publishing_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS publishing_properties (
                tenant TEXT NOT NULL,
                property_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('web', 'mobile')),
                consent_group_id TEXT NOT NULL,
                web_domains_json TEXT NOT NULL,
                origins_json TEXT NOT NULL,
                bundle_ids_json TEXT NOT NULL,
                platform TEXT,
                revision INTEGER NOT NULL,
                record_sha256 TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (tenant, property_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS publishing_versions (
                tenant TEXT NOT NULL,
                resource_kind TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                locale TEXT NOT NULL,
                version INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                resource_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (
                    tenant, resource_kind, resource_id, locale, version
                )
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS publishing_version_heads (
                tenant TEXT NOT NULL,
                resource_kind TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                locale TEXT NOT NULL,
                current_version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                PRIMARY KEY (tenant, resource_kind, resource_id, locale)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_publications (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                publication_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                publication_revision INTEGER NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('publish', 'rollback', 'withdraw')),
                source_publication_id TEXT,
                property_revision INTEGER NOT NULL,
                bundle_json TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                publication_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE (tenant, publication_id),
                UNIQUE (tenant, property_id, publication_revision),
                FOREIGN KEY (tenant, property_id)
                    REFERENCES publishing_properties(tenant, property_id)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS consent_publications_property
            ON consent_publications(tenant, property_id, publication_revision DESC)
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_publication_heads (
                tenant TEXT NOT NULL,
                property_id TEXT NOT NULL,
                current_publication_id TEXT NOT NULL,
                current_revision INTEGER NOT NULL,
                PRIMARY KEY (tenant, property_id),
                FOREIGN KEY (tenant, property_id)
                    REFERENCES publishing_properties(tenant, property_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_publication_signatures (
                tenant TEXT NOT NULL,
                publication_id TEXT NOT NULL,
                publication_sha256 TEXT NOT NULL,
                key_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                signature TEXT NOT NULL,
                signed_at REAL NOT NULL,
                PRIMARY KEY (tenant, publication_id),
                FOREIGN KEY (tenant, publication_id)
                    REFERENCES consent_publications(tenant, publication_id)
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_publication_signatures_no_update
            BEFORE UPDATE ON consent_publication_signatures
            BEGIN SELECT RAISE(ABORT, 'publication signatures are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_publication_signatures_no_delete
            BEFORE DELETE ON consent_publication_signatures
            BEGIN SELECT RAISE(ABORT, 'publication signatures are immutable'); END
            """,
            """
            CREATE TABLE IF NOT EXISTS publishing_idempotency (
                tenant TEXT NOT NULL,
                namespace TEXT NOT NULL,
                key_sha256 TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (tenant, namespace, key_sha256)
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS publishing_versions_no_update
            BEFORE UPDATE ON publishing_versions
            BEGIN SELECT RAISE(ABORT, 'publishing versions are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS publishing_versions_no_delete
            BEFORE DELETE ON publishing_versions
            BEGIN SELECT RAISE(ABORT, 'publishing versions are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_publications_no_update
            BEFORE UPDATE ON consent_publications
            BEGIN SELECT RAISE(ABORT, 'consent publications are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_publications_no_delete
            BEFORE DELETE ON consent_publications
            BEGIN SELECT RAISE(ABORT, 'consent publications are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS publishing_idempotency_no_update
            BEFORE UPDATE ON publishing_idempotency
            BEGIN SELECT RAISE(ABORT, 'idempotency claims are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS publishing_idempotency_no_delete
            BEFORE DELETE ON publishing_idempotency
            BEGIN SELECT RAISE(ABORT, 'idempotency claims are immutable'); END
            """,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in statements:
                    connection.execute(statement)
                connection.execute(
                    "INSERT OR IGNORE INTO publishing_meta(key, value) "
                    "VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
                row = connection.execute(
                    "SELECT value FROM publishing_meta WHERE key = 'schema_version'"
                ).fetchone()
                if row is not None and row["value"] == "1":
                    self._migrate_v1_to_v2(connection)
                    connection.execute(
                        "UPDATE publishing_meta SET value=? WHERE key='schema_version'",
                        (str(SCHEMA_VERSION),),
                    )
                    row = connection.execute(
                        "SELECT value FROM publishing_meta WHERE key = 'schema_version'"
                    ).fetchone()
                if row is None or row["value"] != str(SCHEMA_VERSION):
                    raise ConsentPublishingError("unsupported consent publishing store schema")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
        """Atomically widen immutable publication history for withdrawals."""

        connection.execute("DROP TRIGGER IF EXISTS consent_publications_no_update")
        connection.execute("DROP TRIGGER IF EXISTS consent_publications_no_delete")
        connection.execute("DROP INDEX IF EXISTS consent_publications_property")
        connection.execute("ALTER TABLE consent_publications RENAME TO consent_publications_v1")
        connection.execute(
            """
            CREATE TABLE consent_publications (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                publication_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                publication_revision INTEGER NOT NULL,
                action TEXT NOT NULL CHECK (
                    action IN ('publish', 'rollback', 'withdraw')
                ),
                source_publication_id TEXT,
                property_revision INTEGER NOT NULL,
                bundle_json TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                publication_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE (tenant, publication_id),
                UNIQUE (tenant, property_id, publication_revision),
                FOREIGN KEY (tenant, property_id)
                    REFERENCES publishing_properties(tenant, property_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO consent_publications(
                sequence,tenant,publication_id,property_id,publication_revision,
                action,source_publication_id,property_revision,bundle_json,
                bundle_sha256,publication_sha256,created_at
            )
            SELECT sequence,tenant,publication_id,property_id,publication_revision,
                action,source_publication_id,property_revision,bundle_json,
                bundle_sha256,publication_sha256,created_at
            FROM consent_publications_v1
            """
        )
        connection.execute("DROP TABLE consent_publications_v1")
        connection.execute(
            "CREATE INDEX consent_publications_property ON consent_publications("
            "tenant,property_id,publication_revision DESC)"
        )
        connection.execute(
            "CREATE TRIGGER consent_publications_no_update "
            "BEFORE UPDATE ON consent_publications "
            "BEGIN SELECT RAISE(ABORT, 'consent publications are immutable'); END"
        )
        connection.execute(
            "CREATE TRIGGER consent_publications_no_delete "
            "BEFORE DELETE ON consent_publications "
            "BEGIN SELECT RAISE(ABORT, 'consent publications are immutable'); END"
        )

    @staticmethod
    def _replay(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256, result_json FROM publishing_idempotency "
            "WHERE tenant = ? AND namespace = ? AND key_sha256 = ?",
            (tenant, _IDEMPOTENCY_NAMESPACE, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not text_equals(str(row["request_sha256"]), request_sha256):
            raise PublishingIdempotencyConflict(
                "idempotency key was already used for different content"
            )
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise ConsentPublishingError("stored idempotency result is invalid")
        return result

    @staticmethod
    def _save_replay(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        key_sha256: str,
        request_sha256: str,
        result: Mapping[str, Any],
        created_at: float,
    ) -> None:
        connection.execute(
            "INSERT INTO publishing_idempotency(tenant, namespace, key_sha256, "
            "request_sha256, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                tenant,
                _IDEMPOTENCY_NAMESPACE,
                key_sha256,
                request_sha256,
                _canonical(result).decode("ascii"),
                created_at,
            ),
        )

    @staticmethod
    def _property_result(row: sqlite3.Row, tenant: str) -> dict[str, Any]:
        domains = _loads(row["web_domains_json"], "property domains")
        origins = _loads(row["origins_json"], "property origins")
        bundles = _loads(row["bundle_ids_json"], "property bundle ids")
        if not all(isinstance(value, list) for value in (domains, origins, bundles)):
            raise ConsentPublishingError("stored property is invalid")
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "property_id": str(row["property_id"]),
            "kind": str(row["kind"]),
            "consent_group_id": str(row["consent_group_id"]),
            "web_domains": domains,
            "origin_allowlist": origins,
            "mobile_bundle_ids": bundles,
            "platform": row["platform"],
            "revision": int(row["revision"]),
        }
        expected = _sha256(body)
        if not text_equals(expected, str(row["record_sha256"])):
            raise ConsentPublishingError("stored property digest is invalid")
        return {
            **body,
            "record_sha256": expected,
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _property_row(
        connection: sqlite3.Connection,
        tenant: str,
        property_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM publishing_properties WHERE tenant = ? AND property_id = ?",
            (tenant, property_id),
        ).fetchone()
        if row is None:
            raise PublishingNotFound("property does not exist in this tenant")
        return row

    def upsert_property(
        self,
        tenant_id: str,
        property_id: str,
        *,
        kind: str,
        consent_group_id: str,
        expected_revision: int,
        idempotency_key: str,
        web_domains: Sequence[str] = (),
        origin_allowlist: Sequence[str] = (),
        mobile_bundle_ids: Sequence[str] = (),
        platform: str | None = None,
    ) -> dict[str, Any]:
        """Create or CAS-revise a web or mobile property authorization."""

        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        group = _text(consent_group_id, "consent_group_id")
        expected = _revision(expected_revision)
        if kind not in _PROPERTY_KINDS:
            raise PublishingValidationError("property kind must be web or mobile")
        if kind == "web":
            domains = _bounded_values(web_domains, "web_domains", _domain)
            origins = _bounded_values(origin_allowlist, "origin_allowlist", _origin)
            bundles: list[str] = []
            normalized_platform = None
            if mobile_bundle_ids or platform is not None:
                raise PublishingValidationError("web properties cannot have mobile ids")
            for origin in origins:
                host = urlsplit(origin).hostname
                assert host is not None
                if not any(host == domain or host.endswith(f".{domain}") for domain in domains):
                    raise PublishingValidationError(
                        "each origin must belong to an exact property domain"
                    )
        else:
            if web_domains or origin_allowlist:
                raise PublishingValidationError("mobile properties cannot have web origins")
            domains = []
            origins = []
            bundles = _bounded_values(
                mobile_bundle_ids,
                "mobile_bundle_ids",
                _bundle_id,
            )
            if platform not in _MOBILE_PLATFORMS:
                raise PublishingValidationError("mobile platform is invalid")
            normalized_platform = platform
        key_sha = self._idempotency_key(idempotency_key)
        request = {
            "operation": "upsert_property",
            "property_id": property_ref,
            "kind": kind,
            "consent_group_id": group,
            "expected_revision": expected,
            "web_domains": domains,
            "origin_allowlist": origins,
            "mobile_bundle_ids": bundles,
            "platform": normalized_platform,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                row = connection.execute(
                    "SELECT revision FROM publishing_properties "
                    "WHERE tenant = ? AND property_id = ?",
                    (tenant, property_ref),
                ).fetchone()
                current = int(row["revision"]) if row is not None else 0
                if current != expected:
                    raise PublishingConflict(f"property revision is {current}, expected {expected}")
                new_revision = current + 1
                body = {
                    "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                    "property_id": property_ref,
                    "kind": kind,
                    "consent_group_id": group,
                    "web_domains": domains,
                    "origin_allowlist": origins,
                    "mobile_bundle_ids": bundles,
                    "platform": normalized_platform,
                    "revision": new_revision,
                }
                record_sha = _sha256(body)
                if row is None:
                    connection.execute(
                        "INSERT INTO publishing_properties(tenant, property_id, "
                        "kind, consent_group_id, web_domains_json, origins_json, "
                        "bundle_ids_json, platform, revision, record_sha256, "
                        "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            property_ref,
                            kind,
                            group,
                            _canonical(domains).decode("ascii"),
                            _canonical(origins).decode("ascii"),
                            _canonical(bundles).decode("ascii"),
                            normalized_platform,
                            new_revision,
                            record_sha,
                            now,
                        ),
                    )
                else:
                    updated = connection.execute(
                        "UPDATE publishing_properties SET kind = ?, "
                        "consent_group_id = ?, web_domains_json = ?, "
                        "origins_json = ?, bundle_ids_json = ?, platform = ?, "
                        "revision = ?, record_sha256 = ?, updated_at = ? "
                        "WHERE tenant = ? AND property_id = ? AND revision = ?",
                        (
                            kind,
                            group,
                            _canonical(domains).decode("ascii"),
                            _canonical(origins).decode("ascii"),
                            _canonical(bundles).decode("ascii"),
                            normalized_platform,
                            new_revision,
                            record_sha,
                            now,
                            tenant,
                            property_ref,
                            current,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise PublishingConflict("property changed concurrently")
                result = {**body, "record_sha256": record_sha, "updated_at": now}
                self._save_replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    created_at=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _resource_result(row: sqlite3.Row, tenant: str) -> dict[str, Any]:
        payload = _loads(row["payload_json"], "publishing resource")
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "resource_kind": str(row["resource_kind"]),
            "resource_id": str(row["resource_id"]),
            "locale": str(row["locale"]),
            "version": int(row["version"]),
            "payload": payload,
        }
        expected = _sha256(body)
        if not text_equals(expected, str(row["resource_sha256"])):
            raise ConsentPublishingError("stored publishing resource digest is invalid")
        return {
            **body,
            "resource_sha256": expected,
            "created_at": float(row["created_at"]),
        }

    @staticmethod
    def _resource_row(
        connection: sqlite3.Connection,
        tenant: str,
        kind: str,
        resource_id: str,
        version: int,
        *,
        locale: str = "",
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM publishing_versions WHERE tenant = ? "
            "AND resource_kind = ? AND resource_id = ? AND locale = ? "
            "AND version = ?",
            (tenant, kind, resource_id, locale, version),
        ).fetchone()
        if row is None:
            raise PublishingNotFound(f"{kind} version does not exist in this tenant")
        return row

    def _append_resource(
        self,
        tenant_id: str,
        *,
        kind: str,
        resource_id: str,
        version: int,
        payload: Mapping[str, Any],
        expected_current_version: int,
        idempotency_key: str,
        locale: str = "",
        required_resources: Sequence[tuple[str, str, int, str]] = (),
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        if kind not in _RESOURCE_KINDS:
            raise PublishingValidationError("resource kind is invalid")
        resource_ref = _text(resource_id, "resource_id")
        resource_version = _positive_integer(version, "version")
        expected = _revision(expected_current_version, "expected_current_version")
        normalized_locale = _locale(locale) if locale else ""
        key_sha = self._idempotency_key(idempotency_key)
        request = {
            "operation": f"put_{kind}_version",
            "resource_id": resource_ref,
            "locale": normalized_locale,
            "version": resource_version,
            "payload": payload,
            "expected_current_version": expected,
        }
        request_sha = _sha256(request)
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "resource_kind": kind,
            "resource_id": resource_ref,
            "locale": normalized_locale,
            "version": resource_version,
            "payload": payload,
        }
        resource_sha = _sha256(body)
        payload_json = _canonical(payload).decode("ascii")
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                for ref_kind, ref_id, ref_version, ref_locale in required_resources:
                    self._resource_row(
                        connection,
                        tenant,
                        ref_kind,
                        ref_id,
                        ref_version,
                        locale=ref_locale,
                    )
                head = connection.execute(
                    "SELECT current_version FROM publishing_version_heads "
                    "WHERE tenant = ? AND resource_kind = ? AND resource_id = ? "
                    "AND locale = ?",
                    (tenant, kind, resource_ref, normalized_locale),
                ).fetchone()
                current = int(head["current_version"]) if head is not None else 0
                if current != expected:
                    raise PublishingConflict(
                        f"{kind} current version is {current}, expected {expected}"
                    )
                if resource_version != current + 1:
                    raise PublishingConflict(f"{kind} versions must advance by exactly one")
                connection.execute(
                    "INSERT INTO publishing_versions(tenant, resource_kind, "
                    "resource_id, locale, version, payload_json, resource_sha256, "
                    "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        kind,
                        resource_ref,
                        normalized_locale,
                        resource_version,
                        payload_json,
                        resource_sha,
                        now,
                    ),
                )
                if head is None:
                    connection.execute(
                        "INSERT INTO publishing_version_heads(tenant, "
                        "resource_kind, resource_id, locale, current_version, "
                        "revision) VALUES (?, ?, ?, ?, ?, 1)",
                        (
                            tenant,
                            kind,
                            resource_ref,
                            normalized_locale,
                            resource_version,
                        ),
                    )
                else:
                    updated = connection.execute(
                        "UPDATE publishing_version_heads SET current_version = ?, "
                        "revision = revision + 1 WHERE tenant = ? AND "
                        "resource_kind = ? AND resource_id = ? AND locale = ? "
                        "AND current_version = ?",
                        (
                            resource_version,
                            tenant,
                            kind,
                            resource_ref,
                            normalized_locale,
                            current,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise PublishingConflict(f"{kind} changed concurrently")
                result = {
                    **body,
                    "resource_sha256": resource_sha,
                    "created_at": now,
                }
                self._save_replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    created_at=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def put_purpose_version(
        self,
        tenant_id: str,
        purpose_id: str,
        version: int,
        *,
        title_key: str,
        description_key: str,
        lawful_basis: str,
        required: bool,
        default_choice: str,
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        if lawful_basis not in _LAWFUL_BASES:
            raise PublishingValidationError("lawful_basis is invalid")
        if not isinstance(required, bool):
            raise PublishingValidationError("required must be boolean")
        if default_choice not in _PREFERENCE_DEFAULTS:
            raise PublishingValidationError("default_choice is invalid")
        if required and default_choice == "unset":
            raise PublishingValidationError("a required purpose needs an explicit default")
        payload = {
            "title_key": _text(title_key, "title_key"),
            "description_key": _text(description_key, "description_key"),
            "lawful_basis": lawful_basis,
            "required": required,
            "default_choice": default_choice,
        }
        return self._append_resource(
            tenant,
            kind="purpose",
            resource_id=_text(purpose_id, "purpose_id"),
            version=version,
            payload=payload,
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
        )

    def put_topic_version(
        self,
        tenant_id: str,
        topic_id: str,
        version: int,
        *,
        purpose_id: str,
        purpose_version: int,
        title_key: str,
        description_key: str,
        default_choice: str,
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        purpose_ref = _text(purpose_id, "purpose_id")
        purpose_ver = _positive_integer(purpose_version, "purpose_version")
        if default_choice not in _PREFERENCE_DEFAULTS:
            raise PublishingValidationError("default_choice is invalid")
        payload = {
            "purpose": {"id": purpose_ref, "version": purpose_ver},
            "title_key": _text(title_key, "title_key"),
            "description_key": _text(description_key, "description_key"),
            "default_choice": default_choice,
        }
        return self._append_resource(
            tenant,
            kind="topic",
            resource_id=_text(topic_id, "topic_id"),
            version=version,
            payload=payload,
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
            required_resources=(("purpose", purpose_ref, purpose_ver, ""),),
        )

    def put_custom_preference_version(
        self,
        tenant_id: str,
        preference_id: str,
        version: int,
        *,
        title_key: str,
        description_key: str,
        value_type: str,
        option_ids: Sequence[str],
        required: bool,
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        if value_type not in _CUSTOM_VALUE_TYPES:
            raise PublishingValidationError("custom preference value_type is invalid")
        if not isinstance(required, bool):
            raise PublishingValidationError("required must be boolean")
        options = _bounded_values(
            option_ids,
            "option_ids",
            lambda value: _text(value, "option_id"),
            maximum=64,
            allow_empty=value_type == "boolean",
        )
        if value_type == "boolean" and options:
            raise PublishingValidationError("boolean preferences cannot have options")
        if value_type != "boolean" and not options:
            raise PublishingValidationError("select preferences require options")
        payload = {
            "title_key": _text(title_key, "title_key"),
            "description_key": _text(description_key, "description_key"),
            "value_type": value_type,
            "option_ids": options,
            "required": required,
        }
        return self._append_resource(
            tenant,
            kind="custom_preference",
            resource_id=_text(preference_id, "preference_id"),
            version=version,
            payload=payload,
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
        )

    def put_notice_version(
        self,
        tenant_id: str,
        notice_id: str,
        version: int,
        *,
        title_key: str,
        body_key: str,
        document_sha256: str,
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        payload = {
            "title_key": _text(title_key, "title_key"),
            "body_key": _text(body_key, "body_key"),
            "document_sha256": _digest(document_sha256, "document_sha256"),
        }
        return self._append_resource(
            tenant,
            kind="notice",
            resource_id=_text(notice_id, "notice_id"),
            version=version,
            payload=payload,
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
        )

    def put_translation_version(
        self,
        tenant_id: str,
        catalog_id: str,
        locale: str,
        version: int,
        *,
        messages: Mapping[str, str],
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        if not isinstance(messages, Mapping) or not 1 <= len(messages) <= _MAX_MESSAGES:
            raise PublishingValidationError("messages must be a bounded mapping")
        normalized: dict[str, str] = {}
        for raw_key, raw_value in messages.items():
            key = _text(raw_key, "message key")
            if key in normalized:
                raise PublishingValidationError("message key is duplicated")
            normalized[key] = _plain_text(raw_value, f"message {key}")
        normalized = dict(sorted(normalized.items()))
        _canonical(normalized, maximum=_MAX_TRANSLATION_BYTES)
        return self._append_resource(
            tenant,
            kind="translation",
            resource_id=_text(catalog_id, "catalog_id"),
            locale=_locale(locale),
            version=version,
            payload={"messages": normalized},
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
        )

    def put_template_version(
        self,
        tenant_id: str,
        template_id: str,
        version: int,
        *,
        surface: str,
        title_key: str,
        body_key: str,
        actions: Mapping[str, str],
        theme_token_id: str,
        theme_token_version: int | None = None,
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        if surface not in _TEMPLATE_SURFACES:
            raise PublishingValidationError("template surface is invalid")
        if not isinstance(actions, Mapping) or not 1 <= len(actions) <= len(_TEMPLATE_ACTIONS):
            raise PublishingValidationError("template actions must be a bounded mapping")
        normalized_actions: dict[str, str] = {}
        for raw_action, raw_key in actions.items():
            if raw_action not in _TEMPLATE_ACTIONS:
                raise PublishingValidationError("template action is invalid")
            normalized_actions[raw_action] = _text(raw_key, "action label key")
        theme_id = _text(theme_token_id, "theme_token_id")
        normalized_theme_version = (
            _positive_integer(theme_token_version, "theme_token_version")
            if theme_token_version is not None
            else None
        )
        payload = {
            "surface": surface,
            "title_key": _text(title_key, "title_key"),
            "body_key": _text(body_key, "body_key"),
            "actions": dict(sorted(normalized_actions.items())),
            "theme_token_id": theme_id,
        }
        if normalized_theme_version is not None:
            payload["theme_token_version"] = normalized_theme_version
        return self._append_resource(
            tenant,
            kind="template",
            resource_id=_text(template_id, "template_id"),
            version=version,
            payload=payload,
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
            required_resources=(
                (("theme", theme_id, normalized_theme_version, ""),)
                if normalized_theme_version is not None
                else ()
            ),
        )

    def put_theme_token_version(
        self,
        tenant_id: str,
        theme_token_id: str,
        version: int,
        *,
        display_name_key: str,
        heading_key: str,
        description_key: str,
        primary_color: str,
        primary_text_color: str,
        surface_color: str,
        text_color: str,
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Append one closed, accessible visual-brand token version.

        Colors are stored without a leading ``#`` and are the only style
        primitives accepted.  HTML, CSS, URLs, fonts, executable assets, and
        arbitrary style properties remain outside this authority.
        """

        tenant = self._tenant(tenant_id)
        primary = _theme_color(primary_color, "primary_color")
        primary_text = _theme_color(primary_text_color, "primary_text_color")
        surface = _theme_color(surface_color, "surface_color")
        text = _theme_color(text_color, "text_color")
        if _contrast_ratio(primary_text, primary) < 4.5:
            raise PublishingValidationError(
                "primary_text_color must have at least 4.5:1 contrast against primary_color"
            )
        if _contrast_ratio(text, surface) < 4.5:
            raise PublishingValidationError(
                "text_color must have at least 4.5:1 contrast against surface_color"
            )
        payload = {
            "display_name_key": _text(display_name_key, "display_name_key"),
            "heading_key": _text(heading_key, "heading_key"),
            "description_key": _text(description_key, "description_key"),
            "primary_color": primary,
            "primary_text_color": primary_text,
            "surface_color": surface,
            "text_color": text,
        }
        return self._append_resource(
            tenant,
            kind="theme",
            resource_id=_text(theme_token_id, "theme_token_id"),
            version=version,
            payload=payload,
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
        )

    def put_rule_group_version(
        self,
        tenant_id: str,
        rule_group_id: str,
        version: int,
        *,
        rules: Sequence[Mapping[str, Any]],
        expected_current_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        if isinstance(rules, (str, bytes)) or not isinstance(rules, Sequence):
            raise PublishingValidationError("rules must be a bounded sequence")
        if not 1 <= len(rules) <= _MAX_RULES:
            raise PublishingValidationError("rules must be a non-empty bounded sequence")
        normalized = [_normalize_rule(rule) for rule in rules]
        ids = [rule["rule_id"] for rule in normalized]
        if len(set(ids)) != len(ids):
            raise PublishingValidationError("rule ids must be unique")
        normalized.sort(key=lambda rule: (-int(rule["priority"]), str(rule["rule_id"])))
        return self._append_resource(
            tenant,
            kind="rule_group",
            resource_id=_text(rule_group_id, "rule_group_id"),
            version=version,
            payload={"rules": normalized},
            expected_current_version=expected_current_version,
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def _resource_snapshot(result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "resource_kind": result["resource_kind"],
            "resource_id": result["resource_id"],
            "locale": result["locale"],
            "version": result["version"],
            "payload": result["payload"],
            "resource_sha256": result["resource_sha256"],
        }

    def _build_preview(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        property_id: str,
        rule_group_id: str,
        rule_group_version: int,
    ) -> dict[str, Any]:
        property_result = self._property_result(
            self._property_row(connection, tenant, property_id),
            tenant,
        )
        rule_group = self._resource_result(
            self._resource_row(
                connection,
                tenant,
                "rule_group",
                rule_group_id,
                rule_group_version,
            ),
            tenant,
        )
        payload = rule_group["payload"]
        if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list):
            raise ConsentPublishingError("stored rule group is invalid")
        resources: dict[tuple[str, str, str, int], dict[str, Any]] = {}

        def add(kind: str, ref: Mapping[str, Any], locale: str = "") -> dict[str, Any]:
            key = (kind, str(ref["id"]), locale, int(ref["version"]))
            existing = resources.get(key)
            if existing is not None:
                return existing
            result = self._resource_result(
                self._resource_row(
                    connection,
                    tenant,
                    kind,
                    key[1],
                    key[3],
                    locale=locale,
                ),
                tenant,
            )
            snapshot = self._resource_snapshot(result)
            resources[key] = snapshot
            return snapshot

        for rule in payload["rules"]:
            if not isinstance(rule, dict):
                raise ConsentPublishingError("stored publishing rule is invalid")
            purpose_keys = {(str(ref["id"]), int(ref["version"])) for ref in rule["purposes"]}
            referenced: list[dict[str, Any]] = []
            for kind, field in (
                ("purpose", "purposes"),
                ("topic", "topics"),
                ("custom_preference", "custom_preferences"),
            ):
                for ref in rule[field]:
                    resource = add(kind, ref)
                    referenced.append(resource)
                    if kind == "topic":
                        topic_purpose = resource["payload"].get("purpose")
                        if (
                            not isinstance(topic_purpose, dict)
                            or (
                                str(topic_purpose.get("id")),
                                int(topic_purpose.get("version", 0)),
                            )
                            not in purpose_keys
                        ):
                            raise PublishingValidationError(
                                "each topic's pinned purpose must be in the rule"
                            )
            notice = add("notice", rule["notice"])
            template = add("template", rule["template"])
            theme_version = template["payload"].get("theme_token_version")
            theme = None
            if theme_version is not None:
                theme = add(
                    "theme",
                    {
                        "id": template["payload"].get("theme_token_id"),
                        "version": theme_version,
                    },
                )
            required_keys: set[str] = set()
            for resource in referenced:
                required_keys.add(str(resource["payload"]["title_key"]))
                required_keys.add(str(resource["payload"]["description_key"]))
            required_keys.update(
                {
                    str(notice["payload"]["title_key"]),
                    str(notice["payload"]["body_key"]),
                    str(template["payload"]["title_key"]),
                    str(template["payload"]["body_key"]),
                }
            )
            required_keys.update(str(key) for key in template["payload"]["actions"].values())
            if theme is not None:
                required_keys.update(
                    str(theme["payload"][key])
                    for key in ("display_name_key", "heading_key", "description_key")
                )
            catalog_id = str(rule["translation_catalog_id"])
            for locale, version in rule["translation_versions"].items():
                translation = add(
                    "translation",
                    {"id": catalog_id, "version": int(version)},
                    str(locale),
                )
                messages = translation["payload"].get("messages")
                if not isinstance(messages, dict) or not required_keys.issubset(messages):
                    raise PublishingValidationError(
                        "translation catalog is missing a referenced message key"
                    )
                if theme is not None:
                    for field, key_field in (
                        ("display_name", "display_name_key"),
                        ("heading", "heading_key"),
                        ("description", "description_key"),
                    ):
                        message_key = str(theme["payload"][key_field])
                        _branding_text(messages[message_key], f"branding {field}")
        property_snapshot = {
            "property_id": property_result["property_id"],
            "kind": property_result["kind"],
            "consent_group_id": property_result["consent_group_id"],
            "revision": property_result["revision"],
            "record_sha256": property_result["record_sha256"],
        }
        bundle = {
            "schema": PREVIEW_SCHEMA,
            "property": property_snapshot,
            "rule_group": self._resource_snapshot(rule_group),
            "resources": sorted(
                resources.values(),
                key=lambda item: (
                    str(item["resource_kind"]),
                    str(item["resource_id"]),
                    str(item["locale"]),
                    int(item["version"]),
                ),
            ),
        }
        encoded = _canonical(bundle, maximum=_MAX_BUNDLE_BYTES)
        return {
            "schema": PREVIEW_SCHEMA,
            "bundle": bundle,
            "bundle_sha256": hashlib.sha256(encoded).hexdigest(),
        }

    def preview(
        self,
        tenant_id: str,
        property_id: str,
        rule_group_id: str,
        rule_group_version: int,
    ) -> dict[str, Any]:
        """Resolve and validate an exact unpublished configuration bundle."""

        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        group_ref = _text(rule_group_id, "rule_group_id")
        group_version = _positive_integer(rule_group_version, "rule_group_version")
        with self._snapshot() as connection:
            return self._build_preview(
                connection,
                tenant,
                property_ref,
                group_ref,
                group_version,
            )

    @staticmethod
    def _withdrawal_tombstone(
        property_id: str,
        property_revision: int,
        source_publication_id: str,
    ) -> dict[str, Any]:
        return {
            "schema": WITHDRAWAL_TOMBSTONE_SCHEMA,
            "property_id": property_id,
            "property_revision": property_revision,
            "withdrawn_publication_id": source_publication_id,
        }

    @classmethod
    def _publication_bundle(cls, row: sqlite3.Row) -> dict[str, Any]:
        bundle = _loads(
            row["bundle_json"],
            "publication bundle",
            maximum=_MAX_BUNDLE_BYTES,
        )
        if not isinstance(bundle, dict):
            raise ConsentPublishingError("stored publication bundle is invalid")
        actual_bundle_sha = _sha256(bundle, maximum=_MAX_BUNDLE_BYTES)
        if not text_equals(actual_bundle_sha, str(row["bundle_sha256"])):
            raise ConsentPublishingError("stored publication bundle is invalid")
        action = str(row["action"])
        if action == "withdraw":
            source = row["source_publication_id"]
            if not isinstance(source, str) or bundle != cls._withdrawal_tombstone(
                str(row["property_id"]),
                int(row["property_revision"]),
                source,
            ):
                raise ConsentPublishingError("stored withdrawal tombstone is invalid")
        elif bundle.get("schema") != PREVIEW_SCHEMA:
            raise ConsentPublishingError("stored publication bundle schema is invalid")
        return bundle

    @classmethod
    def _publication_result(
        cls,
        row: sqlite3.Row,
        tenant: str,
    ) -> dict[str, Any]:
        cls._publication_bundle(row)
        body = {
            "schema": PUBLICATION_SCHEMA,
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "publication_id": str(row["publication_id"]),
            "property_id": str(row["property_id"]),
            "publication_revision": int(row["publication_revision"]),
            "action": str(row["action"]),
            "source_publication_id": row["source_publication_id"],
            "property_revision": int(row["property_revision"]),
            "bundle_sha256": str(row["bundle_sha256"]),
            "created_at": float(row["created_at"]),
        }
        expected = _sha256(body)
        if not text_equals(expected, str(row["publication_sha256"])):
            raise ConsentPublishingError("stored publication digest is invalid")
        return {**body, "publication_sha256": expected}

    def _insert_publication(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        property_id: str,
        expected_publication_revision: int,
        action: str,
        source_publication_id: str | None,
        property_revision: int,
        bundle_json: str,
        bundle_sha256: str,
        created_at: float,
    ) -> dict[str, Any]:
        head = connection.execute(
            "SELECT current_revision FROM consent_publication_heads "
            "WHERE tenant = ? AND property_id = ?",
            (tenant, property_id),
        ).fetchone()
        current = int(head["current_revision"]) if head is not None else 0
        if current != expected_publication_revision:
            raise PublishingConflict(
                f"publication revision is {current}, expected {expected_publication_revision}"
            )
        revision = current + 1
        publication_id = self._new_id("publication")
        body = {
            "schema": PUBLICATION_SCHEMA,
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "publication_id": publication_id,
            "property_id": property_id,
            "publication_revision": revision,
            "action": action,
            "source_publication_id": source_publication_id,
            "property_revision": property_revision,
            "bundle_sha256": bundle_sha256,
            "created_at": created_at,
        }
        publication_sha = _sha256(body)
        connection.execute(
            "INSERT INTO consent_publications(tenant, publication_id, "
            "property_id, publication_revision, action, source_publication_id, "
            "property_revision, bundle_json, bundle_sha256, publication_sha256, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                publication_id,
                property_id,
                revision,
                action,
                source_publication_id,
                property_revision,
                bundle_json,
                bundle_sha256,
                publication_sha,
                created_at,
            ),
        )
        if head is None:
            connection.execute(
                "INSERT INTO consent_publication_heads(tenant, property_id, "
                "current_publication_id, current_revision) VALUES (?, ?, ?, ?)",
                (tenant, property_id, publication_id, revision),
            )
        else:
            updated = connection.execute(
                "UPDATE consent_publication_heads SET current_publication_id = ?, "
                "current_revision = ? WHERE tenant = ? AND property_id = ? "
                "AND current_revision = ?",
                (publication_id, revision, tenant, property_id, current),
            )
            if updated.rowcount != 1:
                raise PublishingConflict("publication head changed concurrently")
        return {**body, "publication_sha256": publication_sha}

    def _signing_policy(self) -> publication_signing.SigningPolicy:
        try:
            policy = self._signing()
        except Exception as exc:  # noqa: BLE001 -- never publish around an unreadable policy
            raise ConsentPublishingError("publication signing policy is unavailable") from exc
        if not isinstance(policy, publication_signing.SigningPolicy):
            raise ConsentPublishingError("publication signing policy is unavailable")
        return policy

    @staticmethod
    def _signer(
        policy: publication_signing.SigningPolicy,
        tenant: str,
        *,
        optional: bool = False,
    ) -> publication_signing.PublicationSigner | None:
        """The workspace signer when signing is required; ``optional`` never refuses."""
        if not policy.required:
            return None
        try:
            return policy.custody.signer_for(tenant)
        except (publication_signing.PublicationSigningUnavailable, ImportError) as exc:
            if optional:
                return None
            raise PublishingSigningUnavailable(
                str(exc) if isinstance(exc, publication_signing.PublicationSigningUnavailable)
                else "publication signing is not available on this installation"
            ) from exc

    @staticmethod
    def _sign_publication(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        result: dict[str, Any],
        signer: publication_signing.PublicationSigner | None,
        signed_at: float,
    ) -> dict[str, Any]:
        """Sign one new publication inside its own transaction (or leave it unsigned)."""
        if signer is None:
            return result
        statement = publication_signing.publication_statement(signer.key_id, result)
        signature = signer.sign(publication_signing.canonical(statement))
        connection.execute(
            "INSERT INTO consent_publication_signatures(tenant, publication_id, "
            "publication_sha256, key_id, public_key, signature, signed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                result["publication_id"],
                result["publication_sha256"],
                signer.key_id,
                signer.public_key_hex,
                signature,
                signed_at,
            ),
        )
        return {
            **result,
            "signature": {
                "algorithm": publication_signing.ALGORITHM,
                "key_id": signer.key_id,
                "signature": signature,
            },
        }

    @staticmethod
    def _with_stored_signature(
        connection: sqlite3.Connection,
        tenant: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """A stored publication as it was returned when made (signature included)."""
        row = connection.execute(
            "SELECT key_id, signature FROM consent_publication_signatures "
            "WHERE tenant = ? AND publication_id = ?",
            (tenant, result["publication_id"]),
        ).fetchone()
        if row is None:
            return result
        return {
            **result,
            "signature": {
                "algorithm": publication_signing.ALGORITHM,
                "key_id": str(row["key_id"]),
                "signature": str(row["signature"]),
            },
        }

    def publication_signature(
        self,
        tenant_id: str,
        publication_id: str,
        *,
        trusted_public_keys: frozenset[str],
    ) -> dict[str, Any] | None:
        """The publish-time signature of one publication, or None.

        None when the publication was not signed, its record or signature does
        not verify, or it was signed by a key this installation no longer
        trusts. Nothing here signs or reveals a private key.
        """

        tenant = self._tenant(tenant_id)
        publication_ref = _text(publication_id, "publication_id")
        with self._snapshot() as connection:
            publication_row = connection.execute(
                "SELECT * FROM consent_publications WHERE tenant = ? AND publication_id = ?",
                (tenant, publication_ref),
            ).fetchone()
            signature_row = connection.execute(
                "SELECT * FROM consent_publication_signatures "
                "WHERE tenant = ? AND publication_id = ?",
                (tenant, publication_ref),
            ).fetchone()
        if publication_row is None or signature_row is None:
            return None
        try:
            publication = self._publication_result(publication_row, tenant)
        except ConsentPublishingError:
            return None
        public_key = str(signature_row["public_key"])
        key_id = str(signature_row["key_id"])
        if (
            public_key not in trusted_public_keys
            or key_id != publication_signing.key_id_for(public_key)
            or not text_equals(
                str(signature_row["publication_sha256"]),
                publication["publication_sha256"],
            )
        ):
            return None
        statement = publication_signing.publication_statement(key_id, publication)
        if not publication_signing.verify(
            public_key,
            str(signature_row["signature"]),
            publication_signing.canonical(statement),
        ):
            return None
        return {
            "algorithm": publication_signing.ALGORITHM,
            "key_id": key_id,
            "public_key": public_key,
            "signature": str(signature_row["signature"]),
            "signed_at": float(signature_row["signed_at"]),
        }

    def publish(
        self,
        tenant_id: str,
        property_id: str,
        rule_group_id: str,
        rule_group_version: int,
        *,
        expected_property_revision: int,
        expected_publication_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Atomically publish a fully pinned immutable configuration bundle."""

        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        group_ref = _text(rule_group_id, "rule_group_id")
        group_version = _positive_integer(rule_group_version, "rule_group_version")
        expected_property = _revision(
            expected_property_revision,
            "expected_property_revision",
        )
        expected_publication = _revision(
            expected_publication_revision,
            "expected_publication_revision",
        )
        key_sha = self._idempotency_key(idempotency_key)
        request = {
            "operation": "publish",
            "property_id": property_ref,
            "rule_group_id": group_ref,
            "rule_group_version": group_version,
            "expected_property_revision": expected_property,
            "expected_publication_revision": expected_publication,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        policy = self._signing_policy()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                signer = self._signer(policy, tenant)
                property_result = self._property_result(
                    self._property_row(connection, tenant, property_ref),
                    tenant,
                )
                if property_result["revision"] != expected_property:
                    raise PublishingConflict(
                        f"property revision is {property_result['revision']}, "
                        f"expected {expected_property}"
                    )
                preview = self._build_preview(
                    connection,
                    tenant,
                    property_ref,
                    group_ref,
                    group_version,
                )
                bundle_json = _canonical(
                    preview["bundle"],
                    maximum=_MAX_BUNDLE_BYTES,
                ).decode("ascii")
                result = self._insert_publication(
                    connection,
                    tenant=tenant,
                    property_id=property_ref,
                    expected_publication_revision=expected_publication,
                    action="publish",
                    source_publication_id=None,
                    property_revision=expected_property,
                    bundle_json=bundle_json,
                    bundle_sha256=str(preview["bundle_sha256"]),
                    created_at=now,
                )
                result = self._sign_publication(
                    connection,
                    tenant=tenant,
                    result=result,
                    signer=signer,
                    signed_at=now,
                )
                self._save_replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    created_at=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def rollback(
        self,
        tenant_id: str,
        property_id: str,
        target_publication_id: str,
        *,
        expected_property_revision: int,
        expected_publication_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """CAS-publish a prior immutable bundle as a new rollback record."""

        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        target_ref = _text(target_publication_id, "target_publication_id")
        expected_property = _revision(
            expected_property_revision,
            "expected_property_revision",
        )
        expected_publication = _revision(
            expected_publication_revision,
            "expected_publication_revision",
        )
        key_sha = self._idempotency_key(idempotency_key)
        request = {
            "operation": "rollback",
            "property_id": property_ref,
            "target_publication_id": target_ref,
            "expected_property_revision": expected_property,
            "expected_publication_revision": expected_publication,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        policy = self._signing_policy()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                signer = self._signer(policy, tenant)
                property_result = self._property_result(
                    self._property_row(connection, tenant, property_ref),
                    tenant,
                )
                if property_result["revision"] != expected_property:
                    raise PublishingConflict(
                        f"property revision is {property_result['revision']}, "
                        f"expected {expected_property}"
                    )
                target = connection.execute(
                    "SELECT * FROM consent_publications WHERE tenant = ? "
                    "AND property_id = ? AND publication_id = ?",
                    (tenant, property_ref, target_ref),
                ).fetchone()
                if target is None:
                    raise PublishingNotFound("target publication does not exist in this tenant")
                self._publication_result(target, tenant)
                if str(target["action"]) == "withdraw":
                    raise PublishingValidationError(
                        "a withdrawal tombstone cannot be a rollback target"
                    )
                if int(target["property_revision"]) != expected_property:
                    raise PublishingConflict(
                        "target publication belongs to a different property revision"
                    )
                bundle = _loads(
                    target["bundle_json"],
                    "publication bundle",
                    maximum=_MAX_BUNDLE_BYTES,
                )
                actual_bundle_sha = _sha256(bundle, maximum=_MAX_BUNDLE_BYTES)
                if not text_equals(
                    actual_bundle_sha,
                    str(target["bundle_sha256"]),
                ):
                    raise ConsentPublishingError("stored publication bundle is invalid")
                result = self._insert_publication(
                    connection,
                    tenant=tenant,
                    property_id=property_ref,
                    expected_publication_revision=expected_publication,
                    action="rollback",
                    source_publication_id=target_ref,
                    property_revision=expected_property,
                    bundle_json=_canonical(
                        bundle,
                        maximum=_MAX_BUNDLE_BYTES,
                    ).decode("ascii"),
                    bundle_sha256=actual_bundle_sha,
                    created_at=now,
                )
                result = self._sign_publication(
                    connection,
                    tenant=tenant,
                    result=result,
                    signer=signer,
                    signed_at=now,
                )
                self._save_replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    created_at=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def withdraw(
        self,
        tenant_id: str,
        property_id: str,
        *,
        expected_property_revision: int,
        expected_publication_revision: int,
        idempotency_key: str,
        before_write: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
        receipt_owner: str | None = None,
    ) -> dict[str, Any]:
        """CAS-replace the active publication head with an immutable tombstone.

        The caller supplies no publication id, bundle, content, credential, or
        target.  The active publication is resolved under the same immediate
        transaction as the head CAS.  Repeating a withdrawal against the exact
        current tombstone is a no-change operation and returns that certified
        history record without appending another tombstone.
        """

        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        expected_property = _revision(
            expected_property_revision,
            "expected_property_revision",
        )
        expected_publication = _revision(
            expected_publication_revision,
            "expected_publication_revision",
        )
        key_sha = self._idempotency_key(idempotency_key)
        request = {
            "operation": "withdraw",
            "property_id": property_ref,
            "expected_property_revision": expected_property,
            "expected_publication_revision": expected_publication,
        }
        if receipt_owner is not None:
            request["receipt_owner"] = _text(receipt_owner, "receipt_owner", _DIGEST_RE)
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        policy = self._signing_policy()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                # A withdrawal is signed when it can be, never refused for want of a key.
                signer = self._signer(policy, tenant, optional=True)
                property_result = self._property_result(
                    self._property_row(connection, tenant, property_ref),
                    tenant,
                )
                if property_result["revision"] != expected_property:
                    raise PublishingConflict(
                        f"property revision is {property_result['revision']}, "
                        f"expected {expected_property}"
                    )
                head = connection.execute(
                    "SELECT current_publication_id,current_revision "
                    "FROM consent_publication_heads WHERE tenant=? AND property_id=?",
                    (tenant, property_ref),
                ).fetchone()
                if head is None:
                    raise PublishingConflict("property has no publication head to withdraw")
                current_revision = int(head["current_revision"])
                if current_revision != expected_publication:
                    raise PublishingConflict(
                        f"publication revision is {current_revision}, "
                        f"expected {expected_publication}"
                    )
                current = connection.execute(
                    "SELECT * FROM consent_publications WHERE tenant=? "
                    "AND property_id=? AND publication_id=?",
                    (tenant, property_ref, head["current_publication_id"]),
                ).fetchone()
                if current is None:
                    raise ConsentPublishingError("publication head is invalid")
                current_result = self._publication_result(current, tenant)
                if int(current["publication_revision"]) != current_revision:
                    raise ConsentPublishingError("publication head revision is invalid")
                if current_result["action"] == "withdraw":
                    current_result = self._with_stored_signature(
                        connection, tenant, current_result
                    )
                    if before_write is not None:
                        before_write(property_result, current_result)
                    if receipt_owner is not None:
                        current_result["withdrawal_receipt"] = {"owner": receipt_owner, "changed": False, "recorded_at": _timestamp(self._clock(), "clock")}
                    self._save_replay(
                        connection,
                        tenant=tenant,
                        key_sha256=key_sha,
                        request_sha256=request_sha,
                        result=current_result,
                        created_at=now,
                    )
                    connection.execute("COMMIT")
                    return current_result
                source_publication_id = str(current_result["publication_id"])
                tombstone = self._withdrawal_tombstone(
                    property_ref,
                    expected_property,
                    source_publication_id,
                )
                tombstone_json = _canonical(
                    tombstone,
                    maximum=_MAX_BUNDLE_BYTES,
                ).decode("ascii")
                if before_write is not None:
                    before_write(property_result, current_result)
                now = _timestamp(self._clock(), "clock")
                result = self._insert_publication(
                    connection,
                    tenant=tenant,
                    property_id=property_ref,
                    expected_publication_revision=expected_publication,
                    action="withdraw",
                    source_publication_id=source_publication_id,
                    property_revision=expected_property,
                    bundle_json=tombstone_json,
                    bundle_sha256=_sha256(tombstone, maximum=_MAX_BUNDLE_BYTES),
                    created_at=now,
                )
                result = self._sign_publication(
                    connection,
                    tenant=tenant,
                    result=result,
                    signer=signer,
                    signed_at=now,
                )
                if receipt_owner is not None:
                    result["withdrawal_receipt"] = {"owner": receipt_owner, "changed": True, "recorded_at": now}
                self._save_replay(
                    connection,
                    tenant=tenant,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    created_at=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def withdrawal_preview(self, tenant_id: str, property_id: str) -> dict[str, Any]:
        """Read the current property and exact head from one native snapshot."""
        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        with self._snapshot() as connection:
            property_result = self._property_result(self._property_row(connection, tenant, property_ref), tenant)
            row = connection.execute(
                "SELECT p.* FROM consent_publications p JOIN consent_publication_heads h "
                "ON h.tenant=p.tenant AND h.property_id=p.property_id AND h.current_publication_id=p.publication_id "
                "AND h.current_revision=p.publication_revision WHERE p.tenant=? AND p.property_id=?",
                (tenant, property_ref),
            ).fetchone()
            if row is None:
                raise PublishingConflict("property has no valid publication head to withdraw")
            return {"property": property_result, "head": self._publication_result(row, tenant)}

    def withdrawal_original(
        self, tenant_id: str, property_id: str, *, expected_property_revision: int,
        expected_publication_revision: int, idempotency_key: str, receipt_owner: str,
    ) -> dict[str, Any] | None:
        """Read only the atomically accepted exact owner-bound withdrawal request."""
        tenant = self._tenant(tenant_id)
        request = {"operation": "withdraw", "property_id": _text(property_id, "property_id"),
                   "expected_property_revision": _revision(expected_property_revision, "expected_property_revision"),
                   "expected_publication_revision": _revision(expected_publication_revision, "expected_publication_revision"),
                   "receipt_owner": _text(receipt_owner, "receipt_owner", _DIGEST_RE)}
        with self._snapshot() as connection:
            result = self._replay(connection, tenant=tenant, key_sha256=self._idempotency_key(idempotency_key), request_sha256=_sha256(request))
            if result is not None:
                row = connection.execute(
                    "SELECT * FROM consent_publications WHERE tenant=? AND property_id=? AND publication_id=?",
                    (tenant, request["property_id"], result.get("publication_id")),
                ).fetchone()
                if row is None:
                    raise ConsentPublishingError("the original withdrawal publication is unavailable")
                actual = self._publication_result(row, tenant)
                if actual["action"] != "withdraw" or any(result.get(key) != value for key, value in actual.items()):
                    raise ConsentPublishingError("the original withdrawal publication could not be verified")
        if result is not None and result.get("withdrawal_receipt", {}).get("owner") != receipt_owner:
            raise ConsentPublishingError("the accepted withdrawal owner could not be verified")
        return result

    @staticmethod
    def _denied(property_id: str, evaluated_at: float, reason: str) -> dict[str, Any]:
        return {
            "schema": PUBLIC_CONFIGURATION_SCHEMA,
            "allowed": False,
            "reason": reason,
            "property_id": property_id,
            "evaluated_at": evaluated_at,
        }

    @staticmethod
    def _jurisdiction_chain(value: str) -> list[str]:
        parts = value.split("-")
        return ["-".join(parts[:index]) for index in range(len(parts), 0, -1)]

    @classmethod
    def _rule_matches(
        cls,
        rule: Mapping[str, Any],
        jurisdiction: str,
        country_code: str,
        region_code: str,
    ) -> bool:
        jurisdictions = rule["jurisdictions"]
        if jurisdictions and not set(jurisdictions).intersection(
            cls._jurisdiction_chain(jurisdiction) if jurisdiction else ()
        ):
            return False
        countries = rule["country_codes"]
        if countries and country_code not in countries:
            return False
        regions = rule["region_codes"]
        return not regions or region_code in regions

    @staticmethod
    def _select_locale(rule: Mapping[str, Any], requested: str) -> str:
        locales = list(rule["locales"])
        if requested in locales:
            return requested
        language = requested.split("-", 1)[0]
        if language in locales:
            return language
        return str(rule["default_locale"])

    @staticmethod
    def _resource_index(
        bundle: Mapping[str, Any],
    ) -> dict[tuple[str, str, str, int], dict[str, Any]]:
        values = bundle.get("resources")
        if not isinstance(values, list) or len(values) > _MAX_REFS * 8:
            raise ConsentPublishingError("stored publication resources are invalid")
        index: dict[tuple[str, str, str, int], dict[str, Any]] = {}
        for value in values:
            if not isinstance(value, dict):
                raise ConsentPublishingError("stored publication resource is invalid")
            key = (
                str(value.get("resource_kind")),
                str(value.get("resource_id")),
                str(value.get("locale")),
                int(value.get("version", 0)),
            )
            if key in index:
                raise ConsentPublishingError("stored publication has duplicate resources")
            index[key] = value
        return index

    @staticmethod
    def _localized_preference(
        resource: Mapping[str, Any],
        messages: Mapping[str, str],
    ) -> dict[str, Any]:
        payload = resource["payload"]
        result = {
            "id": resource["resource_id"],
            "version": resource["version"],
            "resource_sha256": resource["resource_sha256"],
            "title": messages[payload["title_key"]],
            "description": messages[payload["description_key"]],
        }
        for field in (
            "default_choice",
            "lawful_basis",
            "option_ids",
            "purpose",
            "required",
            "value_type",
        ):
            if field in payload:
                result[field] = payload[field]
        return result

    def resolve_public_configuration(
        self,
        tenant_id: str,
        property_id: str,
        *,
        server_origin: str | None = None,
        server_bundle_id: str | None = None,
        server_platform: str | None = None,
        jurisdiction: str = "",
        country_code: str = "",
        region_code: str = "",
        requested_locale: str,
        evaluated_at: float | None = None,
    ) -> dict[str, Any]:
        """Resolve one bounded public configuration from trusted server facts.

        The ``server_*`` values must come from the authenticated request host or
        application integration, never from a client-selected property id.
        Missing properties, mismatches, stale publications, and unmatched
        rules return a deny result rather than a permissive fallback.
        """

        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        locale = _locale(requested_locale, "requested_locale")
        normalized_jurisdiction = _jurisdiction(jurisdiction) if jurisdiction else ""
        normalized_country = _country(country_code, allow_empty=True)
        normalized_region = _region(region_code, allow_empty=True)
        now = _timestamp(
            self._clock() if evaluated_at is None else evaluated_at,
            "evaluated_at",
        )
        normalized_origin = _origin(server_origin) if server_origin is not None else None
        normalized_bundle = _bundle_id(server_bundle_id) if server_bundle_id is not None else None
        if server_platform is not None and server_platform not in _MOBILE_PLATFORMS:
            raise PublishingValidationError("server_platform is invalid")
        with self._snapshot() as connection:
            property_row = connection.execute(
                "SELECT * FROM publishing_properties WHERE tenant = ? AND property_id = ?",
                (tenant, property_ref),
            ).fetchone()
            if property_row is None:
                return self._denied(property_ref, now, "unavailable")
            try:
                property_result = self._property_result(property_row, tenant)
            except ConsentPublishingError:
                return self._denied(property_ref, now, "authority_integrity_failure")
            if property_result["kind"] == "web":
                authorized = (
                    normalized_origin is not None
                    and normalized_origin in property_result["origin_allowlist"]
                    and normalized_bundle is None
                    and server_platform is None
                )
            else:
                authorized = (
                    normalized_origin is None
                    and normalized_bundle in property_result["mobile_bundle_ids"]
                    and server_platform == property_result["platform"]
                )
            if not authorized:
                return self._denied(property_ref, now, "property_authorization_failed")
            head = connection.execute(
                "SELECT current_publication_id, current_revision "
                "FROM consent_publication_heads WHERE tenant = ? AND property_id = ?",
                (tenant, property_ref),
            ).fetchone()
            if head is None:
                return self._denied(property_ref, now, "unavailable")
            publication = connection.execute(
                "SELECT * FROM consent_publications WHERE tenant = ? "
                "AND property_id = ? AND publication_id = ?",
                (tenant, property_ref, head["current_publication_id"]),
            ).fetchone()
            if publication is None:
                return self._denied(property_ref, now, "authority_integrity_failure")
            try:
                publication_result = self._publication_result(publication, tenant)
                bundle = self._publication_bundle(publication)
            except ConsentPublishingError:
                return self._denied(property_ref, now, "authority_integrity_failure")
            if publication_result["action"] == "withdraw":
                return self._denied(property_ref, now, "withdrawn")
            snapshot = bundle.get("property")
            if (
                not isinstance(snapshot, dict)
                or snapshot.get("revision") != property_result["revision"]
                or snapshot.get("record_sha256") != property_result["record_sha256"]
                or publication_result["property_revision"] != property_result["revision"]
            ):
                return self._denied(property_ref, now, "stale_publication")
            group = bundle.get("rule_group")
            if not isinstance(group, dict) or not isinstance(group.get("payload"), dict):
                return self._denied(property_ref, now, "authority_integrity_failure")
            rules = group["payload"].get("rules")
            if not isinstance(rules, list) or len(rules) > _MAX_RULES:
                return self._denied(property_ref, now, "authority_integrity_failure")
            selected = next(
                (
                    rule
                    for rule in rules
                    if isinstance(rule, dict)
                    and self._rule_matches(
                        rule,
                        normalized_jurisdiction,
                        normalized_country,
                        normalized_region,
                    )
                ),
                None,
            )
            if selected is None:
                return self._denied(
                    property_ref,
                    now,
                    "no_published_rule_match",
                )
            selected_locale = self._select_locale(selected, locale)
            try:
                index = self._resource_index(bundle)

                def resource(kind: str, ref: Mapping[str, Any], loc: str = ""):
                    return index[(kind, str(ref["id"]), loc, int(ref["version"]))]

                translation = resource(
                    "translation",
                    {
                        "id": selected["translation_catalog_id"],
                        "version": selected["translation_versions"][selected_locale],
                    },
                    selected_locale,
                )
                messages = translation["payload"]["messages"]
                purposes = [
                    self._localized_preference(resource("purpose", ref), messages)
                    for ref in selected["purposes"]
                ]
                topics = [
                    self._localized_preference(resource("topic", ref), messages)
                    for ref in selected["topics"]
                ]
                custom = [
                    self._localized_preference(
                        resource("custom_preference", ref),
                        messages,
                    )
                    for ref in selected["custom_preferences"]
                ]
                notice_resource = resource("notice", selected["notice"])
                notice_payload = notice_resource["payload"]
                notice = {
                    "id": notice_resource["resource_id"],
                    "version": notice_resource["version"],
                    "resource_sha256": notice_resource["resource_sha256"],
                    "document_sha256": notice_payload["document_sha256"],
                    "title": messages[notice_payload["title_key"]],
                    "body": messages[notice_payload["body_key"]],
                }
                template_resource = resource("template", selected["template"])
                template_payload = template_resource["payload"]
                template = {
                    "id": template_resource["resource_id"],
                    "version": template_resource["version"],
                    "resource_sha256": template_resource["resource_sha256"],
                    "surface": template_payload["surface"],
                    "theme_token_id": template_payload["theme_token_id"],
                    "title": messages[template_payload["title_key"]],
                    "body": messages[template_payload["body_key"]],
                    "actions": {
                        action: messages[key] for action, key in template_payload["actions"].items()
                    },
                }
                branding = None
                theme_version = template_payload.get("theme_token_version")
                if theme_version is not None:
                    theme_resource = resource(
                        "theme",
                        {
                            "id": template_payload["theme_token_id"],
                            "version": theme_version,
                        },
                    )
                    theme_payload = theme_resource["payload"]
                    branding_body = {
                        "theme_token_id": theme_resource["resource_id"],
                        "version": theme_resource["version"],
                        "resource_sha256": theme_resource["resource_sha256"],
                        "display_name": _branding_text(
                            messages[theme_payload["display_name_key"]],
                            "branding display_name",
                        ),
                        "heading": _branding_text(
                            messages[theme_payload["heading_key"]],
                            "branding heading",
                        ),
                        "description": _branding_text(
                            messages[theme_payload["description_key"]],
                            "branding description",
                        ),
                        "primary_color": theme_payload["primary_color"],
                        "primary_text_color": theme_payload["primary_text_color"],
                        "surface_color": theme_payload["surface_color"],
                        "text_color": theme_payload["text_color"],
                    }
                    branding = {
                        **branding_body,
                        "branding_sha256": _sha256(branding_body),
                    }
            except (ConsentPublishingError, KeyError, TypeError, ValueError):
                return self._denied(property_ref, now, "authority_integrity_failure")
            configuration = {
                "consent_mode": selected["consent_mode"],
                "purposes": purposes,
                "topics": topics,
                "custom_preferences": custom,
                "notice": notice,
                "template": template,
            }
            if branding is not None:
                configuration["branding"] = branding
            digest_body = {
                "publication_sha256": publication_result["publication_sha256"],
                "property_id": property_ref,
                "property_revision": property_result["revision"],
                "consent_group_id": property_result["consent_group_id"],
                "rule_id": selected["rule_id"],
                "rule_sha256": selected["rule_sha256"],
                "locale": selected_locale,
                "configuration": configuration,
            }
            try:
                configuration_sha = _sha256(
                    digest_body,
                    maximum=_MAX_PUBLIC_BYTES,
                )
            except PublishingValidationError:
                return self._denied(
                    property_ref,
                    now,
                    "public_configuration_too_large",
                )
            result = {
                "schema": PUBLIC_CONFIGURATION_SCHEMA,
                "allowed": True,
                "reason": "published_rule_match",
                "property": {
                    "property_id": property_ref,
                    "kind": property_result["kind"],
                    "consent_group_id": property_result["consent_group_id"],
                    "revision": property_result["revision"],
                },
                "publication": publication_result,
                "rule": {
                    "rule_id": selected["rule_id"],
                    "rule_sha256": selected["rule_sha256"],
                    "locale": selected_locale,
                },
                "configuration": configuration,
                "configuration_sha256": configuration_sha,
                "evaluated_at": now,
            }
            try:
                _canonical(result, maximum=_MAX_PUBLIC_BYTES)
            except PublishingValidationError:
                return self._denied(
                    property_ref,
                    now,
                    "public_configuration_too_large",
                )
            return result

    def publication_history(
        self,
        tenant_id: str,
        property_id: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Return a bounded newest-first immutable publication history."""

        tenant = self._tenant(tenant_id)
        property_ref = _text(property_id, "property_id")
        page_size = _limit(limit)
        with self._connect() as connection:
            self._property_row(connection, tenant, property_ref)
            rows = connection.execute(
                "SELECT * FROM consent_publications WHERE tenant = ? "
                "AND property_id = ? ORDER BY publication_revision DESC LIMIT ?",
                (tenant, property_ref, page_size + 1),
            ).fetchall()
        return {
            "items": [self._publication_result(row, tenant) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }
