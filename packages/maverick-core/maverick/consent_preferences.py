"""Tenant-safe consent and preference authority.

This module is deliberately narrower than a CMP user interface.  It provides
the durable authority that collection surfaces, scanners, and enforcement
points can share:

* immutable, policy-version-bound preference receipts;
* pseudonymous known/anonymous profile linkage;
* explicit GPC and DNT observations (never inferred from transport);
* a tracker/SDK registry and closed-world scan admission;
* fail-closed enforcement and a replayable synchronization outbox.

The store accepts opaque identifiers and SHA-256 digests only.  It has no
credential, cookie, IP-address, email-address, free-text, or secret field.
Callers keep the corresponding identity and evidence material in their own
approved systems of record.

Restoration floors are integrity-checked local authority records, not an
independent proof against a privileged database writer who can remove rows and
triggers. Keep the database and deletion outbox under protected custody.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import consent_storage
from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
RECEIPT_SCHEMA = "lightwork.consent-preference-receipt.v1"
OUTBOX_SCHEMA = "lightwork.consent-preference-outbox.v1"
EXPORT_SCHEMA = "lightwork.consent-preference-export.v1"
LINK_AUTHORITY_SCHEMA = "lightwork.consent-profile-link-authority.v1"
LINK_EVENT_SCHEMA = "lightwork.consent-profile-link-event.v1"

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_COUNTRY_RE = re.compile(r"[A-Z]{2}\Z")
_REGION_RE = re.compile(r"(?:[A-Z0-9]{1,8}(?:-[A-Z0-9]{1,8}){0,2})?\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_MAX_JSON_BYTES = 256 * 1024
_MAX_CHOICES = 128
_MAX_PURPOSES = 128
_MAX_OBSERVATIONS = 512
_MAX_LINKED_PROFILES = 128
_MAX_DECISION_RECEIPTS = 4096
_MAX_READ_LIMIT = 500
_MAX_LINK_EVENTS = 10_000
_LAWFUL_BASES = frozenset(
    {
        "consent",
        "contract",
        "legal_obligation",
        "vital_interests",
        "public_task",
        "legitimate_interests",
    }
)
_ACTIONS = frozenset({"grant", "deny", "revoke", "withdraw"})
_IDENTITY_KINDS = frozenset({"known", "anonymous"})
_TRACKER_KINDS = frozenset({"web_tracker", "mobile_sdk"})
_TRACKER_STATUSES = frozenset({"approved", "blocked", "retired"})
_ASSERTION_SOURCES = frozenset({"client", "edge", "operator", "sdk", "header"})
_PRIVACY_SIGNALS = frozenset({"gpc", "dnt"})
_LINK_STATUSES = frozenset({"linked", "unlinked"})
_LINK_ACTIONS = frozenset({"linked", "unlinked", "relinked", "account_transition"})


class ConsentPreferencesError(RuntimeError):
    """Base error for the consent and preferences authority."""


class ConsentPreferencesConfigError(ConsentPreferencesError):
    """The capability is not explicitly enabled."""


class ConsentValidationError(ConsentPreferencesError, ValueError):
    """An input cannot be represented by the closed consent contract."""


class ConsentConflict(ConsentPreferencesError):
    """An optimistic-concurrency precondition did not hold."""


class ConsentIdempotencyConflict(ConsentPreferencesError):
    """An idempotency key was rebound to different content."""


class ConsentStalePolicy(ConsentPreferencesError):
    """Collection referenced a policy that is not currently authoritative."""


class ConsentNotFound(ConsentPreferencesError):
    """A tenant-scoped resource does not exist."""


class ScanAdmissionError(ConsentPreferencesError):
    """A scan contains an unknown, blocked, or inconsistent observation."""


def enabled() -> bool:
    """Return true only for explicit ``[consent_preferences] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("consent_preferences")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    """Reject use unless the capability was explicitly enabled."""

    if not enabled():
        raise ConsentPreferencesConfigError(
            "consent and preferences are disabled; set "
            "[consent_preferences] enable = true"
        )


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentValidationError("consent data must be finite JSON") from exc
    if not 1 <= len(payload) <= maximum:
        raise ConsentValidationError("consent data exceeds its byte bound")
    return payload


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, label: str, pattern: re.Pattern[str] = _REF_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ConsentValidationError(f"{label} is not a bounded opaque identifier")
    if _CONTROL_RE.search(value):
        raise ConsentValidationError(f"{label} contains control characters")
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise ConsentValidationError("tenant_id is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ConsentValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(
    value: object,
    label: str,
    *,
    allow_none: bool = False,
) -> float | None:
    if value is None and allow_none:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
        or float(value) > 100_000_000_000.0
    ):
        raise ConsentValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _positive_version(value: object, label: str = "version") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1:
        raise ConsentValidationError(f"{label} must be a positive integer")
    return value


def _expected_revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise ConsentValidationError("expected_revision must be a non-negative integer")
    return value


def _limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_READ_LIMIT:
        raise ConsentValidationError(f"limit must be between 1 and {_MAX_READ_LIMIT}")
    return value


def _loads(raw: object, label: str) -> Any:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ConsentPreferencesError(f"stored {label} is invalid")
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ConsentPreferencesError(f"stored {label} is invalid") from exc


@dataclass(frozen=True)
class ConsentContext:
    """Closed collection context; geography is a caller assertion, not proof."""

    jurisdiction: str
    country_code: str
    region_code: str = ""
    collection_point: str = "web"
    asserted_source: str = "client"

    def normalized(self) -> dict[str, Any]:
        jurisdiction = _text(self.jurisdiction, "jurisdiction")
        if not isinstance(self.country_code, str) or not _COUNTRY_RE.fullmatch(
            self.country_code
        ):
            raise ConsentValidationError("country_code must be an ISO-style alpha-2 code")
        if not isinstance(self.region_code, str) or not _REGION_RE.fullmatch(
            self.region_code
        ):
            raise ConsentValidationError("region_code is invalid")
        collection = _text(self.collection_point, "collection_point")
        if self.asserted_source not in _ASSERTION_SOURCES:
            raise ConsentValidationError("asserted_source is invalid")
        return {
            "jurisdiction": jurisdiction,
            "geolocation": {
                "country_code": self.country_code,
                "region_code": self.region_code,
                "asserted": True,
                "asserted_source": self.asserted_source,
                "verified": False,
            },
            "collection_point": collection,
        }


@dataclass(frozen=True)
class PreferenceChoice:
    """One purpose/channel/vendor decision captured in a receipt."""

    purpose_id: str
    action: str
    channel: str = "all"
    vendor_id: str = "all"
    expires_at: float | None = None

    def normalized(self, *, now: float) -> dict[str, Any]:
        purpose = _text(self.purpose_id, "purpose_id")
        channel = _text(self.channel, "channel")
        vendor = _text(self.vendor_id, "vendor_id")
        if self.action not in _ACTIONS:
            raise ConsentValidationError("action must be grant, deny, revoke, or withdraw")
        expiry = _timestamp(self.expires_at, "expires_at", allow_none=True)
        if expiry is not None and expiry <= now:
            raise ConsentValidationError("expires_at must be later than collection time")
        if expiry is not None and self.action in {"revoke", "withdraw"}:
            raise ConsentValidationError("revocation and withdrawal cannot expire")
        return {
            "purpose_id": purpose,
            "action": self.action,
            "channel": channel,
            "vendor_id": vendor,
            "expires_at": expiry,
        }


@dataclass(frozen=True)
class TrackerObservation:
    """Privacy-safe observation from an external web or SDK scanner."""

    asset_ref: str
    tracker_id: str
    location_ref: str
    evidence_sha256: str

    def normalized(self) -> dict[str, str]:
        return {
            "asset_ref": _text(self.asset_ref, "asset_ref"),
            "tracker_id": _text(self.tracker_id, "tracker_id"),
            "location_ref": _text(self.location_ref, "location_ref"),
            "evidence_sha256": _digest(self.evidence_sha256, "evidence_sha256"),
        }


@dataclass(frozen=True)
class EnforcementDecision:
    """Fail-closed consent enforcement result."""

    allowed: bool
    reason: str
    policy_id: str | None = None
    policy_version: int | None = None
    receipt_id: str | None = None
    receipt_sha256: str | None = None
    action: str | None = None
    profile_revision: int | None = None
    evaluated_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_choices(
    choices: Sequence[PreferenceChoice],
    *,
    now: float,
    signal: str | None,
    retention_until: float | None,
) -> list[dict[str, Any]]:
    if (
        isinstance(choices, (str, bytes))
        or not isinstance(choices, Sequence)
        or not 1 <= len(choices) <= _MAX_CHOICES
    ):
        raise ConsentValidationError("choices must be a non-empty bounded sequence")
    normalized: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for raw_choice in choices:
        if not isinstance(raw_choice, PreferenceChoice):
            raise ConsentValidationError("every choice must be a PreferenceChoice")
        choice = raw_choice.normalized(now=now)
        identity = (
            str(choice["purpose_id"]),
            str(choice["channel"]),
            str(choice["vendor_id"]),
        )
        if identity in identities:
            raise ConsentValidationError("a receipt cannot repeat a preference scope")
        identities.add(identity)
        normalized.append(choice)
    normalized.sort(
        key=lambda row: (row["purpose_id"], row["channel"], row["vendor_id"])
    )
    if signal is not None and any(
        item["action"] not in {"deny", "revoke", "withdraw"} for item in normalized
    ):
        raise ConsentValidationError("an asserted privacy signal cannot grant consent")
    for item in normalized:
        expiry = item["expires_at"]
        if retention_until is not None and expiry is not None and retention_until < expiry:
            raise ConsentValidationError("retention cannot end before a choice expiry")
    return normalized


def _decision_from_receipts(
    rows: Sequence[sqlite3.Row],
    *,
    purpose: str,
    channel: str,
    vendor: str,
    policy: str,
    version: int,
    profile_revision: int,
    evaluated: float,
    lifecycle_overrides: Mapping[str, Mapping[str, Any]] | None = None,
) -> EnforcementDecision | None:
    for row in rows:
        override = (lifecycle_overrides or {}).get(str(row["receipt_id"]), {})
        clear_expiration = override.get("clear_expiration") is True
        reactivation_at = override.get("reactivation_at")
        reactivated = (
            isinstance(reactivation_at, (int, float))
            and not isinstance(reactivation_at, bool)
            and math.isfinite(float(reactivation_at))
            and float(reactivation_at) <= evaluated
        )
        choices = _loads(row["choices_json"], "receipt choices")
        if not isinstance(choices, list):
            return EnforcementDecision(False, "untrusted_receipt")
        matches: list[tuple[int, dict[str, Any], bool]] = []
        for item in choices:
            if not isinstance(item, dict):
                return EnforcementDecision(False, "untrusted_receipt")
            if (
                item.get("purpose_id") == purpose
                and item.get("channel") in {channel, "all"}
                and item.get("vendor_id") in {vendor, "all"}
            ):
                expiry = None if clear_expiration or reactivated else item.get("expires_at")
                current = expiry is None or (
                    isinstance(expiry, (int, float))
                    and not isinstance(expiry, bool)
                    and math.isfinite(float(expiry))
                    and float(expiry) > evaluated
                )
                specificity = int(item.get("channel") == channel) + int(
                    item.get("vendor_id") == vendor
                )
                matches.append((specificity, item, current))
        if not matches:
            continue
        current_matches = [(score, item) for score, item, current in matches if current]
        # A receipt's still-current choices retain their usual specificity and
        # negative-action priority. Only when the newer receipt has no current
        # match may expiry block fallthrough to an older permanent grant.
        if not current_matches:
            return EnforcementDecision(
                False,
                "no_current_explicit_grant",
                policy_id=policy,
                policy_version=version,
                receipt_id=str(row["receipt_id"]),
                receipt_sha256=str(row["receipt_sha256"]),
                profile_revision=profile_revision,
                evaluated_at=evaluated,
            )
        most_specific = max(score for score, _item in current_matches)
        actions = {
            str(item.get("action"))
            for score, item in current_matches
            if score == most_specific
        }
        if not actions.issubset(_ACTIONS):
            return EnforcementDecision(False, "untrusted_receipt")
        # At equal specificity, negative choices always win.  Normally there
        # is one candidate because duplicate exact scopes are rejected at
        # collection; this also makes a partially corrupt row fail private.
        action = next(
            (
                candidate
                for candidate in ("withdraw", "revoke", "deny", "grant")
                if candidate in actions
            ),
            "deny",
        )
        allowed = action == "grant"
        return EnforcementDecision(
            allowed,
            "explicit_grant" if allowed else f"explicit_{action}",
            policy_id=policy,
            policy_version=version,
            receipt_id=str(row["receipt_id"]),
            receipt_sha256=str(row["receipt_sha256"]),
            action=action,
            profile_revision=profile_revision,
            evaluated_at=evaluated,
        )
    return None


class ConsentPreferenceStore:
    """SQLite-backed, tenant-scoped consent and preference authority."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self._id_factory = id_factory or (
            lambda prefix: f"{prefix}-{secrets.token_urlsafe(18)}"
        )
        self._initialize()

    def _new_id(self, prefix: str) -> str:
        candidate = self._id_factory(prefix)
        return _text(candidate, f"{prefix} identifier")

    @contextlib.contextmanager
    def _connect(self):
        with consent_storage.authority_connection(
            self.path, ensure_directory=ensure_private_directory,
            ensure_file=ensure_private_file,
        ) as connection:
            yield connection

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS consent_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consent_policies (
                    tenant TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    purposes_json TEXT NOT NULL,
                    notice_sha256 TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    effective_at REAL NOT NULL,
                    expires_at REAL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, policy_id, version)
                );
                CREATE TABLE IF NOT EXISTS consent_policy_heads (
                    tenant TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    current_version INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    PRIMARY KEY (tenant, policy_id)
                );
                CREATE TABLE IF NOT EXISTS consent_profiles (
                    tenant TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    identity_kind TEXT NOT NULL CHECK (
                        identity_kind IN ('known', 'anonymous')
                    ),
                    subject_sha256 TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, profile_id),
                    UNIQUE (tenant, identity_kind, subject_sha256)
                );
                CREATE TABLE IF NOT EXISTS consent_profile_links (
                    tenant TEXT NOT NULL,
                    link_id TEXT NOT NULL,
                    known_profile_id TEXT NOT NULL,
                    anonymous_profile_id TEXT NOT NULL,
                    link_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, link_id),
                    UNIQUE (tenant, anonymous_profile_id)
                );
                CREATE TABLE IF NOT EXISTS consent_profile_link_current (
                    tenant TEXT NOT NULL,
                    anonymous_profile_id TEXT NOT NULL,
                    known_profile_id TEXT NOT NULL,
                    link_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('linked', 'unlinked')),
                    revision INTEGER NOT NULL,
                    link_sha256 TEXT NOT NULL,
                    authority_sha256 TEXT NOT NULL,
                    audit_evidence_sha256 TEXT NOT NULL,
                    operation_key_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    retention_until REAL,
                    PRIMARY KEY (tenant, anonymous_profile_id)
                );
                CREATE INDEX IF NOT EXISTS consent_profile_link_current_known
                    ON consent_profile_link_current(tenant, known_profile_id, status);
                CREATE TABLE IF NOT EXISTS consent_profile_link_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    anonymous_profile_id TEXT NOT NULL,
                    known_profile_id TEXT NOT NULL,
                    link_id TEXT NOT NULL,
                    action TEXT NOT NULL CHECK (
                        action IN ('linked', 'unlinked', 'relinked', 'account_transition')
                    ),
                    link_revision INTEGER NOT NULL,
                    link_sha256 TEXT NOT NULL,
                    authority_sha256 TEXT NOT NULL,
                    audit_evidence_sha256 TEXT NOT NULL,
                    actor_sha256 TEXT NOT NULL,
                    reason_sha256 TEXT,
                    previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL,
                    retention_until REAL,
                    UNIQUE (tenant, anonymous_profile_id, link_revision)
                );
                CREATE INDEX IF NOT EXISTS consent_profile_link_event_history
                    ON consent_profile_link_events(
                        tenant, anonymous_profile_id, link_revision DESC
                    );
                CREATE TABLE IF NOT EXISTS consent_profile_lifecycle (
                    tenant TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
                    reason_code TEXT,
                    actor_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant, profile_id)
                );
                CREATE TABLE IF NOT EXISTS consent_receipts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    profile_revision INTEGER NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    context_sha256 TEXT NOT NULL,
                    choices_json TEXT NOT NULL,
                    actor_sha256 TEXT NOT NULL,
                    previous_receipt_sha256 TEXT,
                    receipt_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    retention_until REAL,
                    UNIQUE (tenant, receipt_id),
                    UNIQUE (tenant, receipt_sha256)
                );
                CREATE INDEX IF NOT EXISTS consent_receipts_profile
                    ON consent_receipts(tenant, profile_id, sequence DESC);
                CREATE TABLE IF NOT EXISTS consent_receipt_lifecycle (
                    tenant TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    reactivation_at REAL,
                    clear_expiration INTEGER NOT NULL CHECK (clear_expiration IN (0, 1)),
                    revision INTEGER NOT NULL,
                    actor_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant, receipt_id)
                );
                CREATE TABLE IF NOT EXISTS consent_idempotency (
                    tenant TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, namespace, key_sha256)
                );
                CREATE TABLE IF NOT EXISTS consent_trackers (
                    tenant TEXT NOT NULL,
                    tracker_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('web_tracker', 'mobile_sdk')),
                    vendor_id TEXT NOT NULL,
                    purpose_ids_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('approved', 'blocked', 'retired')),
                    revision INTEGER NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant, tracker_id)
                );
                CREATE TABLE IF NOT EXISTS consent_scan_observations (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    asset_ref TEXT NOT NULL,
                    tracker_id TEXT NOT NULL,
                    location_ref TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    admitted_at REAL NOT NULL,
                    observation_sha256 TEXT NOT NULL,
                    UNIQUE (tenant, scan_id, observation_sha256)
                );
                CREATE INDEX IF NOT EXISTS consent_scan_lookup
                    ON consent_scan_observations(tenant, scan_id, sequence);
                CREATE TABLE IF NOT EXISTS consent_outbox (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE (tenant, event_id)
                );
                CREATE INDEX IF NOT EXISTS consent_outbox_tenant
                    ON consent_outbox(tenant, sequence);
                CREATE TABLE IF NOT EXISTS consent_outbox_acks (
                    tenant TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    acknowledged_at REAL NOT NULL,
                    ack_sha256 TEXT NOT NULL,
                    PRIMARY KEY (tenant, destination_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS consent_access_log (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    actor_sha256 TEXT NOT NULL,
                    access_purpose TEXT NOT NULL,
                    export_sha256 TEXT NOT NULL,
                    accessed_at REAL NOT NULL,
                    access_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS consent_access_profile
                    ON consent_access_log(tenant, profile_id, sequence DESC);

                CREATE TRIGGER IF NOT EXISTS consent_receipts_no_update
                    BEFORE UPDATE ON consent_receipts
                    BEGIN SELECT RAISE(ABORT, 'consent receipts are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_receipts_no_delete
                    BEFORE DELETE ON consent_receipts
                    BEGIN SELECT RAISE(ABORT, 'consent receipts are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_links_no_update
                    BEFORE UPDATE ON consent_profile_links
                    BEGIN SELECT RAISE(ABORT, 'identity links are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_links_no_delete
                    BEFORE DELETE ON consent_profile_links
                    BEGIN SELECT RAISE(ABORT, 'identity links are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_link_events_no_update
                    BEFORE UPDATE ON consent_profile_link_events
                    BEGIN SELECT RAISE(ABORT, 'identity link history is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_link_events_no_delete
                    BEFORE DELETE ON consent_profile_link_events
                    BEGIN SELECT RAISE(ABORT, 'identity link history is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_policies_no_update
                    BEFORE UPDATE ON consent_policies
                    BEGIN SELECT RAISE(ABORT, 'consent policies are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_policies_no_delete
                    BEFORE DELETE ON consent_policies
                    BEGIN SELECT RAISE(ABORT, 'consent policies are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_idempotency_no_update
                    BEFORE UPDATE ON consent_idempotency
                    BEGIN SELECT RAISE(ABORT, 'idempotency claims are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_idempotency_no_delete
                    BEFORE DELETE ON consent_idempotency
                    BEGIN SELECT RAISE(ABORT, 'idempotency claims are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_outbox_no_update
                    BEFORE UPDATE ON consent_outbox
                    BEGIN SELECT RAISE(ABORT, 'consent outbox is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_outbox_no_delete
                    BEFORE DELETE ON consent_outbox
                    BEGIN SELECT RAISE(ABORT, 'consent outbox is immutable'); END;
                """
            )
            self._ensure_restoration_floor_schema(conn)
            conn.execute(
                "INSERT OR IGNORE INTO consent_meta(key, value) "
                "VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            existing = conn.execute(
                "SELECT value FROM consent_meta WHERE key = 'schema_version'"
            ).fetchone()
            if existing is None or existing["value"] != str(SCHEMA_VERSION):
                raise ConsentPreferencesError("unsupported consent store schema")
            self._backfill_profile_link_authority(conn)
            self._backfill_restoration_floors(conn, clock=self._clock)

    @staticmethod
    def _ensure_restoration_floor_schema(conn: sqlite3.Connection) -> None:
        # executescript commits a caller's active transaction in both SQLite
        # and the shared-store adapter. A store move must keep these DDL writes
        # in the same transaction as its copied rows and authority backfill.
        for statement in (
            """CREATE TABLE IF NOT EXISTS consent_profile_restoration_floors (
                marker_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                profile_revision INTEGER NOT NULL,
                receipt_sequence INTEGER NOT NULL CHECK (receipt_sequence >= 0),
                source TEXT NOT NULL CHECK (source IN (
                    'restoration', 'link_propagation', 'legacy_backfill'
                )),
                created_at REAL NOT NULL,
                record_sha256 TEXT NOT NULL
            )""",
            """CREATE INDEX IF NOT EXISTS consent_restoration_floor_profile
                ON consent_profile_restoration_floors(tenant, profile_id, marker_sequence DESC)""",
            """CREATE TRIGGER IF NOT EXISTS consent_restoration_floors_no_update
                BEFORE UPDATE ON consent_profile_restoration_floors
                BEGIN SELECT RAISE(ABORT, 'consent restoration floors are immutable'); END""",
            """CREATE TRIGGER IF NOT EXISTS consent_restoration_floors_no_delete
                BEFORE DELETE ON consent_profile_restoration_floors
                BEGIN SELECT RAISE(ABORT, 'consent restoration floors are immutable'); END""",
        ):
            conn.execute(statement)

    @staticmethod
    def _link_current_body(
        *,
        tenant: str,
        anonymous_profile_id: str,
        known_profile_id: str,
        link_id: str,
        status: str,
        revision: int,
        link_sha256: str,
        authority_sha256: str,
        audit_evidence_sha256: str,
        operation_key_sha256: str,
        updated_at: float,
        retention_until: float | None,
    ) -> dict[str, Any]:
        return {
            "schema": LINK_AUTHORITY_SCHEMA,
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "anonymous_profile_id": anonymous_profile_id,
            "known_profile_id": known_profile_id,
            "link_id": link_id,
            "status": status,
            "revision": revision,
            "link_sha256": link_sha256,
            "authority_sha256": authority_sha256,
            "audit_evidence_sha256": audit_evidence_sha256,
            "operation_key_sha256": operation_key_sha256,
            "updated_at": updated_at,
            "retention_until": retention_until,
        }

    @classmethod
    def _link_current(cls, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        body = cls._link_current_body(
            tenant=str(row["tenant"]),
            anonymous_profile_id=str(row["anonymous_profile_id"]),
            known_profile_id=str(row["known_profile_id"]),
            link_id=str(row["link_id"]),
            status=str(row["status"]),
            revision=int(row["revision"]),
            link_sha256=str(row["link_sha256"]),
            authority_sha256=str(row["authority_sha256"]),
            audit_evidence_sha256=str(row["audit_evidence_sha256"]),
            operation_key_sha256=str(row["operation_key_sha256"]),
            updated_at=float(row["updated_at"]),
            retention_until=(
                float(row["retention_until"])
                if row["retention_until"] is not None
                else None
            ),
        )
        if (
            body["status"] not in _LINK_STATUSES
            or body["revision"] < 1
            or not all(
                _DIGEST_RE.fullmatch(str(body[name]))
                for name in (
                    "link_sha256",
                    "authority_sha256",
                    "audit_evidence_sha256",
                    "operation_key_sha256",
                )
            )
            or not text_equals(_sha256(body), str(row["record_sha256"]))
        ):
            raise ConsentPreferencesError("stored profile link authority integrity failed")
        return {**body, "record_sha256": str(row["record_sha256"])}

    @staticmethod
    def _link_event_body(
        *,
        tenant: str,
        anonymous_profile_id: str,
        known_profile_id: str,
        link_id: str,
        action: str,
        link_revision: int,
        link_sha256: str,
        authority_sha256: str,
        audit_evidence_sha256: str,
        actor_sha256: str,
        reason_sha256: str | None,
        previous_event_sha256: str | None,
        created_at: float,
        retention_until: float | None,
    ) -> dict[str, Any]:
        return {
            "schema": LINK_EVENT_SCHEMA,
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "anonymous_profile_id": anonymous_profile_id,
            "known_profile_id": known_profile_id,
            "link_id": link_id,
            "action": action,
            "link_revision": link_revision,
            "link_sha256": link_sha256,
            "authority_sha256": authority_sha256,
            "audit_evidence_sha256": audit_evidence_sha256,
            "actor_sha256": actor_sha256,
            "reason_sha256": reason_sha256,
            "previous_event_sha256": previous_event_sha256,
            "created_at": created_at,
            "retention_until": retention_until,
        }

    @classmethod
    def _verified_link_events(
        cls,
        conn: sqlite3.Connection,
        tenant: str,
        anonymous_profile_id: str,
    ) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT * FROM consent_profile_link_events WHERE tenant = ? AND "
            "anonymous_profile_id = ? ORDER BY link_revision LIMIT ?",
            (tenant, anonymous_profile_id, _MAX_LINK_EVENTS + 1),
        ).fetchall()
        if len(rows) > _MAX_LINK_EVENTS:
            raise ConsentPreferencesError("profile link history bound exceeded")
        previous: str | None = None
        verified: list[dict[str, Any]] = []
        expected_revision = 1
        for row in rows:
            body = cls._link_event_body(
                tenant=str(row["tenant"]),
                anonymous_profile_id=str(row["anonymous_profile_id"]),
                known_profile_id=str(row["known_profile_id"]),
                link_id=str(row["link_id"]),
                action=str(row["action"]),
                link_revision=int(row["link_revision"]),
                link_sha256=str(row["link_sha256"]),
                authority_sha256=str(row["authority_sha256"]),
                audit_evidence_sha256=str(row["audit_evidence_sha256"]),
                actor_sha256=str(row["actor_sha256"]),
                reason_sha256=(
                    str(row["reason_sha256"])
                    if row["reason_sha256"] is not None
                    else None
                ),
                previous_event_sha256=(
                    str(row["previous_event_sha256"])
                    if row["previous_event_sha256"] is not None
                    else None
                ),
                created_at=float(row["created_at"]),
                retention_until=(
                    float(row["retention_until"])
                    if row["retention_until"] is not None
                    else None
                ),
            )
            event_sha = _sha256(body)
            if (
                body["action"] not in _LINK_ACTIONS
                or body["link_revision"] != expected_revision
                or body["previous_event_sha256"] != previous
                or not text_equals(event_sha, str(row["event_sha256"]))
            ):
                raise ConsentPreferencesError("stored profile link history integrity failed")
            for name in (
                "link_sha256",
                "authority_sha256",
                "audit_evidence_sha256",
                "actor_sha256",
            ):
                if not _DIGEST_RE.fullmatch(str(body[name])):
                    raise ConsentPreferencesError(
                        "stored profile link history integrity failed"
                    )
            if body["reason_sha256"] is not None and not _DIGEST_RE.fullmatch(
                str(body["reason_sha256"])
            ):
                raise ConsentPreferencesError("stored profile link history integrity failed")
            previous = event_sha
            expected_revision += 1
            verified.append({**body, "event_sha256": event_sha})
        return verified

    @classmethod
    def _insert_link_event(
        cls,
        conn: sqlite3.Connection,
        *,
        tenant: str,
        anonymous_profile_id: str,
        known_profile_id: str,
        link_id: str,
        action: str,
        link_revision: int,
        link_sha256: str,
        authority_sha256: str,
        audit_evidence_sha256: str,
        actor_sha256: str,
        reason_sha256: str | None,
        created_at: float,
        retention_until: float | None,
    ) -> str:
        events = cls._verified_link_events(conn, tenant, anonymous_profile_id)
        previous = events[-1]["event_sha256"] if events else None
        if link_revision != len(events) + 1:
            raise ConsentConflict("profile link revision changed")
        body = cls._link_event_body(
            tenant=tenant,
            anonymous_profile_id=anonymous_profile_id,
            known_profile_id=known_profile_id,
            link_id=link_id,
            action=action,
            link_revision=link_revision,
            link_sha256=link_sha256,
            authority_sha256=authority_sha256,
            audit_evidence_sha256=audit_evidence_sha256,
            actor_sha256=actor_sha256,
            reason_sha256=reason_sha256,
            previous_event_sha256=previous,
            created_at=created_at,
            retention_until=retention_until,
        )
        event_sha = _sha256(body)
        conn.execute(
            "INSERT INTO consent_profile_link_events(tenant,anonymous_profile_id,"
            "known_profile_id,link_id,action,link_revision,link_sha256,"
            "authority_sha256,audit_evidence_sha256,actor_sha256,reason_sha256,"
            "previous_event_sha256,event_sha256,created_at,retention_until) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                anonymous_profile_id,
                known_profile_id,
                link_id,
                action,
                link_revision,
                link_sha256,
                authority_sha256,
                audit_evidence_sha256,
                actor_sha256,
                reason_sha256,
                previous,
                event_sha,
                created_at,
                retention_until,
            ),
        )
        return event_sha

    @staticmethod
    def _assert_current_link_history(
        current: Mapping[str, Any],
        events: Sequence[Mapping[str, Any]],
    ) -> None:
        if len(events) != int(current["revision"]):
            raise ConsentPreferencesError("profile link authority history is incomplete")
        tail = events[-1] if events else None
        expected_actions = (
            {"linked", "relinked", "account_transition"}
            if current["status"] == "linked"
            else {"unlinked"}
        )
        if (
            tail is None
            or tail.get("action") not in expected_actions
            or tail.get("known_profile_id") != current["known_profile_id"]
            or tail.get("link_id") != current["link_id"]
            or not hmac.compare_digest(
                str(tail.get("link_sha256", "")),
                str(current["link_sha256"]),
            )
            or not hmac.compare_digest(
                str(tail.get("authority_sha256", "")),
                str(current["authority_sha256"]),
            )
            or not hmac.compare_digest(
                str(tail.get("audit_evidence_sha256", "")),
                str(current["audit_evidence_sha256"]),
            )
        ):
            raise ConsentPreferencesError("profile link authority history changed")

    @classmethod
    def _insert_link_current(
        cls,
        conn: sqlite3.Connection,
        *,
        tenant: str,
        anonymous_profile_id: str,
        known_profile_id: str,
        link_id: str,
        status: str,
        revision: int,
        link_sha256: str,
        authority_sha256: str,
        audit_evidence_sha256: str,
        operation_key_sha256: str,
        updated_at: float,
        retention_until: float | None,
    ) -> str:
        body = cls._link_current_body(
            tenant=tenant,
            anonymous_profile_id=anonymous_profile_id,
            known_profile_id=known_profile_id,
            link_id=link_id,
            status=status,
            revision=revision,
            link_sha256=link_sha256,
            authority_sha256=authority_sha256,
            audit_evidence_sha256=audit_evidence_sha256,
            operation_key_sha256=operation_key_sha256,
            updated_at=updated_at,
            retention_until=retention_until,
        )
        record_sha = _sha256(body)
        conn.execute(
            "INSERT INTO consent_profile_link_current(tenant,anonymous_profile_id,"
            "known_profile_id,link_id,status,revision,link_sha256,authority_sha256,"
            "audit_evidence_sha256,operation_key_sha256,record_sha256,updated_at,"
            "retention_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                anonymous_profile_id,
                known_profile_id,
                link_id,
                status,
                revision,
                link_sha256,
                authority_sha256,
                audit_evidence_sha256,
                operation_key_sha256,
                record_sha,
                updated_at,
                retention_until,
            ),
        )
        return record_sha

    def _backfill_profile_link_authority(self, conn: sqlite3.Connection) -> None:
        legacy_authority = hashlib.sha256(b"consent-link-legacy-authority-v1").hexdigest()
        legacy_audit = hashlib.sha256(b"consent-link-legacy-audit-v1").hexdigest()
        legacy_actor = hashlib.sha256(b"consent-link-legacy-migration-v1").hexdigest()
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT links.* FROM consent_profile_links AS links LEFT JOIN "
                "consent_profile_link_current AS current ON current.tenant = links.tenant "
                "AND current.anonymous_profile_id = links.anonymous_profile_id "
                "WHERE current.anonymous_profile_id IS NULL ORDER BY links.tenant, "
                "links.anonymous_profile_id"
            ).fetchall()
            for row in rows:
                tenant = str(row["tenant"])
                anonymous = str(row["anonymous_profile_id"])
                known = str(row["known_profile_id"])
                link_id = str(row["link_id"])
                link_sha = str(row["link_sha256"])
                created_at = float(row["created_at"])
                operation = hashlib.sha256(
                    f"legacy-link\0{tenant}\0{link_id}".encode()
                ).hexdigest()
                self._insert_link_event(
                    conn,
                    tenant=tenant,
                    anonymous_profile_id=anonymous,
                    known_profile_id=known,
                    link_id=link_id,
                    action="linked",
                    link_revision=1,
                    link_sha256=link_sha,
                    authority_sha256=legacy_authority,
                    audit_evidence_sha256=legacy_audit,
                    actor_sha256=legacy_actor,
                    reason_sha256=None,
                    created_at=created_at,
                    retention_until=None,
                )
                self._insert_link_current(
                    conn,
                    tenant=tenant,
                    anonymous_profile_id=anonymous,
                    known_profile_id=known,
                    link_id=link_id,
                    status="linked",
                    revision=1,
                    link_sha256=link_sha,
                    authority_sha256=legacy_authority,
                    audit_evidence_sha256=legacy_audit,
                    operation_key_sha256=operation,
                    updated_at=created_at,
                    retention_until=None,
                )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _insert_restoration_floor(
        conn: sqlite3.Connection,
        *,
        tenant: str,
        profile_id: str,
        profile_revision: int,
        receipt_sequence: int,
        source: str,
        created_at: float,
    ) -> None:
        body = {
            "tenant": tenant,
            "profile_id": profile_id,
            "profile_revision": profile_revision,
            "receipt_sequence": receipt_sequence,
            "source": source,
            "created_at": created_at,
        }
        conn.execute(
            "INSERT INTO consent_profile_restoration_floors(tenant, profile_id, "
            "profile_revision, receipt_sequence, source, created_at, record_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tenant, profile_id, profile_revision, receipt_sequence, source,
             created_at, _sha256(body)),
        )

    def _propagate_restoration_floor(
        self,
        conn: sqlite3.Connection,
        *,
        tenant: str,
        group: Sequence[str],
        now: float,
    ) -> None:
        """Keep the strongest erasure boundary after a later unlink."""
        floor = self._restoration_receipt_floor(conn, tenant, group)
        if floor == 0:
            return
        for profile_id in group:
            if self._restoration_receipt_floor(conn, tenant, [profile_id]) >= floor:
                continue
            profile = self._profile_row(conn, tenant, profile_id)
            self._insert_restoration_floor(
                conn, tenant=tenant, profile_id=profile_id,
                profile_revision=int(profile["revision"]),
                receipt_sequence=floor, source="link_propagation", created_at=now,
            )

    @classmethod
    def _backfill_restoration_floors(  # noqa: C901 - one atomic migration
        cls, conn: sqlite3.Connection, *, clock: Callable[[], float]
    ) -> None:
        """Conservatively revoke legacy restored grants using durable erasure events.

        Pre-upgrade stores did not record the receipt boundary when restoring a
        subject. The exact restore-time boundary cannot be reconstructed, so
        every receipt present at migration is excluded for that subject and
        every historically linked identity, including later valid grants.
        """
        owns_transaction = not conn.in_transaction
        if owns_transaction:
            conn.execute("BEGIN IMMEDIATE")
        try:
            completed = conn.execute(
                "SELECT value FROM consent_meta WHERE key = 'restoration_floor_backfill_v1'"
            ).fetchone()
            if completed is not None:
                if completed["value"] != "1":
                    raise ConsentPreferencesError("invalid consent restoration migration state")
                if owns_transaction:
                    conn.execute("COMMIT")
                return
            events = conn.execute(
                "SELECT tenant, event_id, event_type, payload_json, payload_sha256, "
                "created_at FROM consent_outbox WHERE event_type = 'profile.subject_deleted' "
                "ORDER BY sequence"
            )
            deleted_revisions: dict[tuple[str, str], int] = {}
            saw_event = False
            for event in events:
                saw_event = True
                body = _loads(event["payload_json"], "subject deletion event")
                if (
                    not isinstance(body, dict)
                    or body.get("schema") != OUTBOX_SCHEMA
                    or body.get("event_id") != event["event_id"]
                    or body.get("event_type") != event["event_type"]
                    or body.get("created_at") != event["created_at"]
                    or _canonical(body).decode("ascii") != event["payload_json"]
                    or not text_equals(_sha256(body), str(event["payload_sha256"]))
                ):
                    raise ConsentPreferencesError("stored subject deletion event integrity failed")
                payload = body.get("payload")
                if not isinstance(payload, dict):
                    raise ConsentPreferencesError("stored subject deletion event is invalid")
                profile_id = _text(payload.get("profile_id"), "profile_id")
                revision = _positive_version(payload.get("revision"), "revision")
                _digest(payload.get("tombstone_sha256"), "tombstone_sha256")
                tenant = str(event["tenant"])
                key = (tenant, profile_id)
                deleted_revisions[key] = max(deleted_revisions.get(key, 0), revision)
            if not saw_event:
                # An empty shared target may receive a pre-upgrade local store
                # after startup. Do not plant a target-only migration marker.
                if owns_transaction:
                    conn.execute("COMMIT")
                return
            if deleted_revisions:
                last_receipt = conn.execute(
                    "SELECT COALESCE(MAX(sequence), 0) AS value FROM consent_receipts"
                ).fetchone()
                receipt_sequence = int(last_receipt["value"])
                now = _timestamp(clock(), "clock")
                assert now is not None
                associations: dict[tuple[str, str], set[str]] = {}
                for link in conn.execute(
                    "SELECT tenant, known_profile_id, anonymous_profile_id "
                    "FROM consent_profile_links"
                ):
                    tenant = str(link["tenant"])
                    known = str(link["known_profile_id"])
                    anonymous = str(link["anonymous_profile_id"])
                    associations.setdefault((tenant, known), set()).add(anonymous)
                    associations.setdefault((tenant, anonymous), set()).add(known)
                for (tenant, profile_id), deleted_revision in deleted_revisions.items():
                    profile = conn.execute(
                        "SELECT revision FROM consent_profiles WHERE tenant = ? "
                        "AND profile_id = ?", (tenant, profile_id),
                    ).fetchone()
                    if profile is None:
                        raise ConsentPreferencesError("subject deletion profile is missing")
                    lifecycle = cls._profile_lifecycle(conn, tenant, profile_id)
                    if lifecycle["status"] != "active":
                        continue
                    profile_revision = int(profile["revision"])
                    if profile_revision <= deleted_revision:
                        raise ConsentPreferencesError("restored profile revision is invalid")
                    # Historical links may already be severed; every identity
                    # ever associated with this erased subject gets the safe
                    # migration boundary, including account transitions.
                    component = {profile_id}
                    pending = [profile_id]
                    while pending:
                        for linked in associations.get((tenant, pending.pop()), ()):
                            if linked not in component:
                                component.add(linked)
                                pending.append(linked)
                    for affected in component:
                        affected_profile = cls._profile_row(conn, tenant, affected)
                        existing_floor = conn.execute(
                            "SELECT 1 FROM consent_profile_restoration_floors WHERE "
                            "tenant = ? AND profile_id = ? LIMIT 1", (tenant, affected),
                        ).fetchone()
                        current_floor = cls._restoration_receipt_floor(
                            conn, tenant, [affected]
                        )
                        if existing_floor is None or current_floor < receipt_sequence:
                            cls._insert_restoration_floor(
                                conn, tenant=tenant, profile_id=affected,
                                profile_revision=int(affected_profile["revision"]),
                                receipt_sequence=receipt_sequence,
                                source="legacy_backfill", created_at=now,
                            )
            conn.execute(
                "INSERT INTO consent_meta(key, value) VALUES "
                "('restoration_floor_backfill_v1', '1')"
            )
            if owns_transaction:
                conn.execute("COMMIT")
        except BaseException:
            if owns_transaction and conn.in_transaction:
                conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _tenant(value: object) -> str:
        return _tenant_id(value)

    @staticmethod
    def _idem_key(value: object) -> tuple[str, str]:
        raw = _text(value, "idempotency_key", _IDEMPOTENCY_RE)
        return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _idempotent_result(
        conn: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = conn.execute(
            "SELECT request_sha256, result_json FROM consent_idempotency "
            "WHERE tenant = ? AND namespace = ? AND key_sha256 = ?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not text_equals(str(row["request_sha256"]), request_sha256):
            raise ConsentIdempotencyConflict(
                "idempotency key was already used for different content"
            )
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise ConsentPreferencesError("stored idempotency result is invalid")
        return result

    @staticmethod
    def _save_idempotency(
        conn: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
        result: Mapping[str, Any],
        now: float,
    ) -> None:
        encoded = _canonical(dict(result)).decode("ascii")
        conn.execute(
            "INSERT INTO consent_idempotency(tenant, namespace, key_sha256, "
            "request_sha256, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (tenant, namespace, key_sha256, request_sha256, encoded, now),
        )

    def _outbox(
        self,
        conn: sqlite3.Connection,
        *,
        tenant: str,
        event_type: str,
        payload: Mapping[str, Any],
        now: float,
    ) -> dict[str, Any]:
        event_id = self._new_id("CP-EVT")
        body = {
            "schema": OUTBOX_SCHEMA,
            "event_id": event_id,
            "event_type": _text(event_type, "event_type"),
            "payload": dict(payload),
            "created_at": now,
        }
        digest = _sha256(body)
        conn.execute(
            "INSERT INTO consent_outbox(tenant, event_id, event_type, payload_json, "
            "payload_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                tenant,
                event_id,
                event_type,
                _canonical(body).decode("ascii"),
                digest,
                now,
            ),
        )
        row = conn.execute("SELECT last_insert_rowid() AS value").fetchone()
        return {**body, "sequence": int(row["value"]), "payload_sha256": digest}

    def _active_policy(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        policy_id: str,
        at: float,
    ) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM consent_policies WHERE tenant = ? AND policy_id = ? "
            "AND effective_at <= ? AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY version DESC LIMIT 1",
            (tenant, policy_id, at, at),
        ).fetchone()

    def publish_policy(
        self,
        tenant_id: str,
        policy_id: str,
        version: int,
        purposes: Mapping[str, str],
        notice_sha256: str,
        effective_at: float,
        *,
        expires_at: float | None = None,
        expected_current_version: int | None = None,
    ) -> dict[str, Any]:
        """Append an immutable policy version using optimistic concurrency."""

        tenant = self._tenant(tenant_id)
        policy = _text(policy_id, "policy_id")
        version = _positive_version(version)
        notice = _digest(notice_sha256, "notice_sha256")
        effective = _timestamp(effective_at, "effective_at")
        expiry = _timestamp(expires_at, "expires_at", allow_none=True)
        assert effective is not None
        if expiry is not None and expiry <= effective:
            raise ConsentValidationError("policy expiry must follow its effective time")
        if not isinstance(purposes, Mapping) or not 1 <= len(purposes) <= _MAX_PURPOSES:
            raise ConsentValidationError("purposes must be a non-empty bounded mapping")
        normalized_purposes: dict[str, str] = {}
        for raw_purpose, raw_basis in purposes.items():
            purpose = _text(raw_purpose, "purpose_id")
            if raw_basis not in _LAWFUL_BASES:
                raise ConsentValidationError("lawful basis is invalid")
            normalized_purposes[purpose] = raw_basis
        normalized_purposes = dict(sorted(normalized_purposes.items()))
        body = {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "policy_id": policy,
            "version": version,
            "purposes": normalized_purposes,
            "notice_sha256": notice,
            "effective_at": effective,
            "expires_at": expiry,
        }
        digest = _sha256(body)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                head = conn.execute(
                    "SELECT current_version, revision FROM consent_policy_heads "
                    "WHERE tenant = ? AND policy_id = ?",
                    (tenant, policy),
                ).fetchone()
                current = int(head["current_version"]) if head is not None else 0
                expected = 0 if expected_current_version is None else _expected_revision(
                    expected_current_version
                )
                if current != expected:
                    raise ConsentConflict(
                        f"policy current version is {current}, expected {expected}"
                    )
                if version != current + 1:
                    raise ConsentConflict("policy versions must advance by exactly one")
                conn.execute(
                    "INSERT INTO consent_policies(tenant, policy_id, version, "
                    "purposes_json, notice_sha256, policy_sha256, effective_at, "
                    "expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        policy,
                        version,
                        _canonical(normalized_purposes).decode("ascii"),
                        notice,
                        digest,
                        effective,
                        expiry,
                        now,
                    ),
                )
                if head is None:
                    conn.execute(
                        "INSERT INTO consent_policy_heads(tenant, policy_id, "
                        "current_version, revision) VALUES (?, ?, ?, 1)",
                        (tenant, policy, version),
                    )
                else:
                    updated = conn.execute(
                        "UPDATE consent_policy_heads SET current_version = ?, "
                        "revision = revision + 1 WHERE tenant = ? AND policy_id = ? "
                        "AND current_version = ?",
                        (version, tenant, policy, current),
                    )
                    if updated.rowcount != 1:
                        raise ConsentConflict("policy changed concurrently")
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return {**body, "policy_sha256": digest}

    def unlink_profile(  # noqa: PLR0913 - explicit independent authorities
        self,
        tenant_id: str,
        anonymous_profile_id: str,
        *,
        expected_anonymous_revision: int,
        expected_known_revision: int,
        expected_link_revision: int,
        idempotency_key: str,
        identity_evidence_sha256: str,
        audit_evidence_sha256: str,
        actor_sha256: str,
        reason_sha256: str,
        retention_until: float,
    ) -> dict[str, Any]:
        """Unlink one anonymous profile under exact, independently evidenced CAS."""

        tenant = self._tenant(tenant_id)
        anonymous = _text(anonymous_profile_id, "anonymous_profile_id")
        anonymous_revision = _expected_revision(expected_anonymous_revision)
        known_revision = _expected_revision(expected_known_revision)
        link_revision = _expected_revision(expected_link_revision)
        identity_evidence = _digest(
            identity_evidence_sha256,
            "identity_evidence_sha256",
        )
        audit_evidence = _digest(audit_evidence_sha256, "audit_evidence_sha256")
        actor = _digest(actor_sha256, "actor_sha256")
        reason = _digest(reason_sha256, "reason_sha256")
        if hmac.compare_digest(identity_evidence, audit_evidence):
            raise ConsentValidationError(
                "identity and independent audit evidence must differ"
            )
        retained_until = _timestamp(retention_until, "retention_until")
        assert retained_until is not None
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "anonymous_profile_id": anonymous,
            "expected_anonymous_revision": anonymous_revision,
            "expected_known_revision": known_revision,
            "expected_link_revision": link_revision,
            "identity_evidence_sha256": identity_evidence,
            "audit_evidence_sha256": audit_evidence,
            "actor_sha256": actor,
            "reason_sha256": reason,
            "retention_until": retained_until,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        if retained_until <= now:
            raise ConsentValidationError("profile link retention must be in the future")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="profile.unlink",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                anonymous_row = self._profile_row(conn, tenant, anonymous)
                if (
                    anonymous_row["identity_kind"] != "anonymous"
                    or self._profile_lifecycle(conn, tenant, anonymous)["status"]
                    != "active"
                ):
                    raise ConsentConflict("anonymous profile is not active")
                if int(anonymous_row["revision"]) != anonymous_revision:
                    raise ConsentConflict("anonymous profile revision changed")
                current_row = conn.execute(
                    "SELECT * FROM consent_profile_link_current WHERE tenant = ? "
                    "AND anonymous_profile_id = ?",
                    (tenant, anonymous),
                ).fetchone()
                current = self._link_current(current_row)
                if current is None or current["status"] != "linked":
                    raise ConsentConflict("anonymous profile is not currently linked")
                if int(current["revision"]) != link_revision:
                    raise ConsentConflict("profile link revision changed")
                events = self._verified_link_events(conn, tenant, anonymous)
                self._assert_current_link_history(current, events)
                known = str(current["known_profile_id"])
                known_row = self._profile_row(conn, tenant, known)
                if (
                    known_row["identity_kind"] != "known"
                    or self._profile_lifecycle(conn, tenant, known)["status"] != "active"
                ):
                    raise ConsentConflict("known profile is not active")
                if int(known_row["revision"]) != known_revision:
                    raise ConsentConflict("known profile revision changed")
                first = conn.execute(
                    "UPDATE consent_profiles SET revision = revision + 1 "
                    "WHERE tenant = ? AND profile_id = ? AND revision = ?",
                    (tenant, known, known_revision),
                )
                second = conn.execute(
                    "UPDATE consent_profiles SET revision = revision + 1 "
                    "WHERE tenant = ? AND profile_id = ? AND revision = ?",
                    (tenant, anonymous, anonymous_revision),
                )
                if first.rowcount != 1 or second.rowcount != 1:
                    raise ConsentConflict("profile unlink changed concurrently")
                next_link_revision = link_revision + 1
                current_body = self._link_current_body(
                    tenant=tenant,
                    anonymous_profile_id=anonymous,
                    known_profile_id=known,
                    link_id=str(current["link_id"]),
                    status="unlinked",
                    revision=next_link_revision,
                    link_sha256=str(current["link_sha256"]),
                    authority_sha256=identity_evidence,
                    audit_evidence_sha256=audit_evidence,
                    operation_key_sha256=key_sha,
                    updated_at=now,
                    retention_until=retained_until,
                )
                current_sha = _sha256(current_body)
                changed = conn.execute(
                    "UPDATE consent_profile_link_current SET status = 'unlinked', "
                    "revision = ?, authority_sha256 = ?, audit_evidence_sha256 = ?, "
                    "operation_key_sha256 = ?, record_sha256 = ?, updated_at = ?, "
                    "retention_until = ? WHERE tenant = ? AND anonymous_profile_id = ? "
                    "AND status = 'linked' AND revision = ? AND record_sha256 = ?",
                    (
                        next_link_revision,
                        identity_evidence,
                        audit_evidence,
                        key_sha,
                        current_sha,
                        now,
                        retained_until,
                        tenant,
                        anonymous,
                        link_revision,
                        current["record_sha256"],
                    ),
                )
                if changed.rowcount != 1:
                    raise ConsentConflict("profile link changed concurrently")
                event_sha = self._insert_link_event(
                    conn,
                    tenant=tenant,
                    anonymous_profile_id=anonymous,
                    known_profile_id=known,
                    link_id=str(current["link_id"]),
                    action="unlinked",
                    link_revision=next_link_revision,
                    link_sha256=str(current["link_sha256"]),
                    authority_sha256=identity_evidence,
                    audit_evidence_sha256=audit_evidence,
                    actor_sha256=actor,
                    reason_sha256=reason,
                    created_at=now,
                    retention_until=retained_until,
                )
                result = {
                    "anonymous_profile_id": anonymous,
                    "previous_known_profile_id": known,
                    "link_id": str(current["link_id"]),
                    "link_sha256": str(current["link_sha256"]),
                    "link_status": "unlinked",
                    "link_revision": next_link_revision,
                    "anonymous_revision": anonymous_revision + 1,
                    "known_revision": known_revision + 1,
                    "transition_type": "unlinked",
                    "link_event_sha256": event_sha,
                    "receipt_histories_merged": False,
                    "retention_until": retained_until,
                    "updated_at": now,
                }
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="profile.unlinked",
                    payload={
                        "anonymous_profile_id": anonymous,
                        "known_profile_id": known,
                        "link_id": current["link_id"],
                        "link_sha256": current["link_sha256"],
                        "link_revision": next_link_revision,
                        "anonymous_revision": anonymous_revision + 1,
                        "known_revision": known_revision + 1,
                        "reason_sha256": reason,
                        "link_event_sha256": event_sha,
                        "receipt_histories_merged": False,
                    },
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="profile.unlink",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
    def create_profile(
        self,
        tenant_id: str,
        profile_id: str,
        identity_kind: str,
        subject_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create a tenant-scoped profile without retaining raw identity data."""

        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        if identity_kind not in _IDENTITY_KINDS:
            raise ConsentValidationError("identity_kind must be known or anonymous")
        subject = _digest(subject_sha256, "subject_sha256")
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "profile_id": profile,
            "identity_kind": identity_kind,
            "subject_sha256": subject,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="profile.create",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                try:
                    conn.execute(
                        "INSERT INTO consent_profiles(tenant, profile_id, "
                        "identity_kind, subject_sha256, revision, created_at) "
                        "VALUES (?, ?, ?, ?, 0, ?)",
                        (tenant, profile, identity_kind, subject, now),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConsentConflict(
                        "profile identity or profile_id already exists in this tenant"
                    ) from exc
                result = {**request, "revision": 0, "created_at": now}
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="profile.created",
                    payload={
                        "profile_id": profile,
                        "identity_kind": identity_kind,
                        "revision": 0,
                    },
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="profile.create",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def link_profiles(  # noqa: C901 - one atomic link/relink CAS transition
        self,
        tenant_id: str,
        known_profile_id: str,
        anonymous_profile_id: str,
        *,
        expected_known_revision: int,
        expected_anonymous_revision: int,
        idempotency_key: str,
        expected_link_revision: int | None = None,
        identity_evidence_sha256: str | None = None,
        audit_evidence_sha256: str | None = None,
        actor_sha256: str | None = None,
        retention_until: float | None = None,
    ) -> dict[str, Any]:
        """Link profiles, or relink an explicitly unlinked anonymous profile.

        The first link remains backwards compatible.  Every later link requires
        an exact current-link revision plus distinct identity and audit evidence.
        The legacy link row and all lifecycle events remain immutable; only the
        integrity-bound current authority is advanced under compare-and-swap.
        """

        tenant = self._tenant(tenant_id)
        known = _text(known_profile_id, "known_profile_id")
        anonymous = _text(anonymous_profile_id, "anonymous_profile_id")
        if known == anonymous:
            raise ConsentValidationError("known and anonymous profiles must differ")
        known_revision = _expected_revision(expected_known_revision)
        anonymous_revision = _expected_revision(expected_anonymous_revision)
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        lifecycle_values = (
            expected_link_revision,
            identity_evidence_sha256,
            audit_evidence_sha256,
            actor_sha256,
            retention_until,
        )
        lifecycle_supplied = any(value is not None for value in lifecycle_values)
        if lifecycle_supplied and any(value is None for value in lifecycle_values):
            raise ConsentValidationError(
                "relink authority requires revision, identity evidence, audit evidence, "
                "actor evidence, and retention"
            )
        if lifecycle_supplied:
            link_revision_expected = _expected_revision(expected_link_revision)
            authority_sha = _digest(
                identity_evidence_sha256,
                "identity_evidence_sha256",
            )
            audit_sha = _digest(audit_evidence_sha256, "audit_evidence_sha256")
            actor_sha = _digest(actor_sha256, "actor_sha256")
            retained_until = _timestamp(retention_until, "retention_until")
            assert retained_until is not None
            if hmac.compare_digest(authority_sha, audit_sha):
                raise ConsentValidationError(
                    "identity and independent audit evidence must differ"
                )
        else:
            link_revision_expected = None
            authority_sha = hashlib.sha256(b"consent-link-initial-authority-v1").hexdigest()
            audit_sha = hashlib.sha256(b"consent-link-initial-audit-v1").hexdigest()
            actor_sha = hashlib.sha256(b"consent-link-initial-actor-v1").hexdigest()
            retained_until = None
        request = {
            "known_profile_id": known,
            "anonymous_profile_id": anonymous,
            "expected_known_revision": known_revision,
            "expected_anonymous_revision": anonymous_revision,
        }
        if lifecycle_supplied:
            request.update(
                {
                    "expected_link_revision": link_revision_expected,
                    "identity_evidence_sha256": authority_sha,
                    "audit_evidence_sha256": audit_sha,
                    "actor_sha256": actor_sha,
                    "retention_until": retained_until,
                }
            )
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        if retained_until is not None and retained_until <= now:
            raise ConsentValidationError("profile link retention must be in the future")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="profile.link",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                profiles = conn.execute(
                    "SELECT profile_id, identity_kind, subject_sha256, revision "
                    "FROM consent_profiles WHERE tenant = ? AND profile_id IN (?, ?)",
                    (tenant, known, anonymous),
                ).fetchall()
                indexed = {str(row["profile_id"]): row for row in profiles}
                if known not in indexed or anonymous not in indexed:
                    raise ConsentNotFound("one or both profiles do not exist in this tenant")
                known_row = indexed[known]
                anonymous_row = indexed[anonymous]
                if (
                    self._profile_lifecycle(conn, tenant, known)["status"] != "active"
                    or self._profile_lifecycle(conn, tenant, anonymous)["status"]
                    != "active"
                ):
                    raise ConsentConflict("deleted profiles cannot be linked")
                if known_row["identity_kind"] != "known":
                    raise ConsentValidationError("known_profile_id is not a known profile")
                if anonymous_row["identity_kind"] != "anonymous":
                    raise ConsentValidationError(
                        "anonymous_profile_id is not an anonymous profile"
                    )
                if text_equals(
                    str(known_row["subject_sha256"]),
                    str(anonymous_row["subject_sha256"]),
                ):
                    raise ConsentValidationError("linked subject digests must differ")
                if int(known_row["revision"]) != known_revision:
                    raise ConsentConflict("known profile revision changed")
                if int(anonymous_row["revision"]) != anonymous_revision:
                    raise ConsentConflict("anonymous profile revision changed")
                current_row = conn.execute(
                    "SELECT * FROM consent_profile_link_current WHERE tenant = ? "
                    "AND anonymous_profile_id = ?",
                    (tenant, anonymous),
                ).fetchone()
                current = self._link_current(current_row)
                if current is not None and current["status"] == "linked":
                    raise ConsentConflict("anonymous profile is already linked in this tenant")
                if current is not None:
                    if not lifecycle_supplied:
                        raise ConsentConflict(
                            "relink requires fresh verified identity and audit authority"
                        )
                    if current["revision"] != link_revision_expected:
                        raise ConsentConflict("profile link revision changed")
                    action = (
                        "relinked"
                        if current["known_profile_id"] == known
                        else "account_transition"
                    )
                    next_link_revision = int(current["revision"]) + 1
                else:
                    if lifecycle_supplied and link_revision_expected != 0:
                        raise ConsentConflict("profile link revision changed")
                    action = "linked"
                    next_link_revision = 1
                link_id = self._new_id("CP-LINK")
                link_body = {
                    "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                    "link_id": link_id,
                    "known_profile_id": known,
                    "anonymous_profile_id": anonymous,
                    "known_revision": known_revision + 1,
                    "anonymous_revision": anonymous_revision + 1,
                    "created_at": now,
                }
                if current is not None:
                    link_body.update(
                        {
                            "link_revision": next_link_revision,
                            "transition_type": action,
                            "identity_evidence_sha256": authority_sha,
                            "audit_evidence_sha256": audit_sha,
                        }
                    )
                link_sha = _sha256(link_body)
                if current is None:
                    conn.execute(
                        "INSERT INTO consent_profile_links(tenant, link_id, "
                        "known_profile_id, anonymous_profile_id, link_sha256, "
                        "created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (tenant, link_id, known, anonymous, link_sha, now),
                    )
                first = conn.execute(
                    "UPDATE consent_profiles SET revision = revision + 1 "
                    "WHERE tenant = ? AND profile_id = ? AND revision = ?",
                    (tenant, known, known_revision),
                )
                second = conn.execute(
                    "UPDATE consent_profiles SET revision = revision + 1 "
                    "WHERE tenant = ? AND profile_id = ? AND revision = ?",
                    (tenant, anonymous, anonymous_revision),
                )
                if first.rowcount != 1 or second.rowcount != 1:
                    raise ConsentConflict("profile link changed concurrently")
                current_body = self._link_current_body(
                    tenant=tenant,
                    anonymous_profile_id=anonymous,
                    known_profile_id=known,
                    link_id=link_id,
                    status="linked",
                    revision=next_link_revision,
                    link_sha256=link_sha,
                    authority_sha256=authority_sha,
                    audit_evidence_sha256=audit_sha,
                    operation_key_sha256=key_sha,
                    updated_at=now,
                    retention_until=retained_until,
                )
                current_sha = _sha256(current_body)
                if current is None:
                    self._insert_link_current(
                        conn,
                        tenant=tenant,
                        anonymous_profile_id=anonymous,
                        known_profile_id=known,
                        link_id=link_id,
                        status="linked",
                        revision=next_link_revision,
                        link_sha256=link_sha,
                        authority_sha256=authority_sha,
                        audit_evidence_sha256=audit_sha,
                        operation_key_sha256=key_sha,
                        updated_at=now,
                        retention_until=retained_until,
                    )
                else:
                    changed = conn.execute(
                        "UPDATE consent_profile_link_current SET known_profile_id = ?, "
                        "link_id = ?, status = 'linked', revision = ?, link_sha256 = ?, "
                        "authority_sha256 = ?, audit_evidence_sha256 = ?, "
                        "operation_key_sha256 = ?, record_sha256 = ?, updated_at = ?, "
                        "retention_until = ? WHERE tenant = ? AND anonymous_profile_id = ? "
                        "AND revision = ? AND record_sha256 = ?",
                        (
                            known,
                            link_id,
                            next_link_revision,
                            link_sha,
                            authority_sha,
                            audit_sha,
                            key_sha,
                            current_sha,
                            now,
                            retained_until,
                            tenant,
                            anonymous,
                            current["revision"],
                            current["record_sha256"],
                        ),
                    )
                    if changed.rowcount != 1:
                        raise ConsentConflict("profile link changed concurrently")
                event_sha = self._insert_link_event(
                    conn,
                    tenant=tenant,
                    anonymous_profile_id=anonymous,
                    known_profile_id=known,
                    link_id=link_id,
                    action=action,
                    link_revision=next_link_revision,
                    link_sha256=link_sha,
                    authority_sha256=authority_sha,
                    audit_evidence_sha256=audit_sha,
                    actor_sha256=actor_sha,
                    reason_sha256=None,
                    created_at=now,
                    retention_until=retained_until,
                )
                self._propagate_restoration_floor(
                    conn, tenant=tenant,
                    group=self._profile_group(conn, tenant, known), now=now,
                )
                result = {
                    **link_body,
                    "link_sha256": link_sha,
                    "link_status": "linked",
                    "link_revision": next_link_revision,
                    "transition_type": action,
                    "link_event_sha256": event_sha,
                    "receipt_histories_merged": False,
                }
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="profile.linked",
                    payload={
                        "link_id": link_id,
                        "known_profile_id": known,
                        "anonymous_profile_id": anonymous,
                        "known_revision": known_revision + 1,
                        "anonymous_revision": anonymous_revision + 1,
                        "link_sha256": link_sha,
                        "link_revision": next_link_revision,
                        "transition_type": action,
                        "receipt_histories_merged": False,
                    },
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="profile.link",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _profile_row(
        conn: sqlite3.Connection,
        tenant: str,
        profile_id: str,
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM consent_profiles WHERE tenant = ? AND profile_id = ?",
            (tenant, profile_id),
        ).fetchone()
        if row is None:
            raise ConsentNotFound("profile does not exist in this tenant")
        return row

    @staticmethod
    def _profile_lifecycle(
        conn: sqlite3.Connection,
        tenant: str,
        profile_id: str,
    ) -> dict[str, Any]:
        row = conn.execute(
            "SELECT status, reason_code, actor_sha256, record_sha256, updated_at "
            "FROM consent_profile_lifecycle WHERE tenant = ? AND profile_id = ?",
            (tenant, profile_id),
        ).fetchone()
        if row is None:
            return {
                "status": "active",
                "reason_code": None,
                "actor_sha256": None,
                "record_sha256": None,
                "updated_at": None,
            }
        body = {
            "profile_id": profile_id,
            "status": str(row["status"]),
            "reason_code": row["reason_code"],
            "actor_sha256": str(row["actor_sha256"]),
            "updated_at": float(row["updated_at"]),
        }
        if not text_equals(_sha256(body), str(row["record_sha256"])):
            raise ConsentPreferencesError("stored profile lifecycle integrity failed")
        return {**body, "record_sha256": str(row["record_sha256"])}

    def change_identifier_type(  # noqa: PLR0913 - explicit CAS authority
        self,
        tenant_id: str,
        profile_id: str,
        identity_kind: str,
        subject_sha256: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_sha256: str,
    ) -> dict[str, Any]:
        """Change a profile's pseudonymous identifier type under CAS.

        Immutable receipts keep the stable ``profile_id``.  Only the current
        digest and its declared known/anonymous type change.  Supplying a new
        digest for a deleted profile also restores its active lifecycle; the
        former digest is never returned or written to an event. Restoration
        requires a new consent receipt; retained receipts remain audit history.
        """

        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        if identity_kind not in _IDENTITY_KINDS:
            raise ConsentValidationError("identity_kind must be known or anonymous")
        subject = _digest(subject_sha256, "subject_sha256")
        revision = _expected_revision(expected_revision)
        actor = _digest(actor_sha256, "actor_sha256")
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "profile_id": profile,
            "identity_kind": identity_kind,
            "subject_sha256": subject,
            "expected_revision": revision,
            "actor_sha256": actor,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="profile.change_identifier_type",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                row = self._profile_row(conn, tenant, profile)
                if int(row["revision"]) != revision:
                    raise ConsentConflict("profile revision changed")
                restoring = self._profile_lifecycle(conn, tenant, profile)["status"] == "deleted"
                if str(row["identity_kind"]) != identity_kind:
                    linked = conn.execute(
                        "SELECT 1 FROM consent_profile_link_current WHERE tenant = ? "
                        "AND status = 'linked' AND "
                        "(known_profile_id = ? OR anonymous_profile_id = ?) LIMIT 1",
                        (tenant, profile, profile),
                    ).fetchone()
                    if linked is not None:
                        raise ConsentConflict(
                            "linked profile identity kind cannot be changed"
                        )
                try:
                    updated = conn.execute(
                        "UPDATE consent_profiles SET identity_kind = ?, "
                        "subject_sha256 = ?, revision = revision + 1 "
                        "WHERE tenant = ? AND profile_id = ? AND revision = ?",
                        (identity_kind, subject, tenant, profile, revision),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConsentConflict(
                        "profile identity already exists in this tenant"
                    ) from exc
                if updated.rowcount != 1:
                    raise ConsentConflict("profile revision changed")
                if restoring:
                    # Receipt sequence is global and never reused. Record the
                    # boundary in the same transaction that makes the profile
                    # active so no pre-restoration grant can regain authority.
                    last_receipt = conn.execute(
                        "SELECT COALESCE(MAX(sequence), 0) AS value FROM consent_receipts"
                    ).fetchone()
                    for linked_profile in self._profile_group(conn, tenant, profile):
                        linked_revision = (
                            revision + 1 if linked_profile == profile
                            else int(self._profile_row(conn, tenant, linked_profile)["revision"])
                        )
                        self._insert_restoration_floor(
                            conn, tenant=tenant, profile_id=linked_profile,
                            profile_revision=linked_revision,
                            receipt_sequence=int(last_receipt["value"]),
                            source="restoration", created_at=now,
                        )
                    conn.execute(
                        "INSERT OR IGNORE INTO consent_meta(key, value) "
                        "VALUES ('restoration_floor_backfill_v1', '1')"
                    )
                lifecycle_body = {
                    "profile_id": profile,
                    "status": "active",
                    "reason_code": None,
                    "actor_sha256": actor,
                    "updated_at": now,
                }
                lifecycle_sha = _sha256(lifecycle_body)
                conn.execute(
                    "INSERT INTO consent_profile_lifecycle(tenant, profile_id, status, "
                    "reason_code, actor_sha256, record_sha256, updated_at) "
                    "VALUES (?, ?, 'active', NULL, ?, ?, ?) "
                    "ON CONFLICT(tenant, profile_id) DO UPDATE SET status = 'active', "
                    "reason_code = NULL, actor_sha256 = excluded.actor_sha256, "
                    "record_sha256 = excluded.record_sha256, "
                    "updated_at = excluded.updated_at",
                    (tenant, profile, actor, lifecycle_sha, now),
                )
                result = {
                    "profile_id": profile,
                    "identity_kind": identity_kind,
                    "subject_sha256": subject,
                    "revision": revision + 1,
                    "status": "active",
                    "updated_at": now,
                }
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="profile.identifier_changed",
                    payload={
                        "profile_id": profile,
                        "identity_kind": identity_kind,
                        "revision": revision + 1,
                        "subject_sha256": subject,
                    },
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="profile.change_identifier_type",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def delete_subject(  # noqa: PLR0913 - explicit destructive authority
        self,
        tenant_id: str,
        profile_id: str,
        *,
        expected_revision: int,
        reason_code: str,
        idempotency_key: str,
        actor_sha256: str,
    ) -> dict[str, Any]:
        """Pseudonymize the live identifier and fail enforcement closed.

        Receipt and outbox evidence remain under their declared retention.  The
        original subject digest is overwritten in the live profile authority,
        never copied to the lifecycle record or returned to the caller.
        """

        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        revision = _expected_revision(expected_revision)
        reason = _text(reason_code, "reason_code")
        actor = _digest(actor_sha256, "actor_sha256")
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "profile_id": profile,
            "expected_revision": revision,
            "reason_code": reason,
            "actor_sha256": actor,
        }
        request_sha = _sha256(request)
        tombstone_sha = hashlib.sha256(
            (
                "lightwork.consent-subject-tombstone.v1:"
                f"{tenant}:{profile}:{request_sha}"
            ).encode()
        ).hexdigest()
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="profile.delete_subject",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                row = self._profile_row(conn, tenant, profile)
                if int(row["revision"]) != revision:
                    raise ConsentConflict("profile revision changed")
                lifecycle = self._profile_lifecycle(conn, tenant, profile)
                if lifecycle["status"] == "deleted":
                    raise ConsentConflict("profile subject is already deleted")
                try:
                    updated = conn.execute(
                        "UPDATE consent_profiles SET subject_sha256 = ?, "
                        "revision = revision + 1 WHERE tenant = ? AND profile_id = ? "
                        "AND revision = ?",
                        (tombstone_sha, tenant, profile, revision),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConsentConflict("profile tombstone collision") from exc
                if updated.rowcount != 1:
                    raise ConsentConflict("profile revision changed")
                lifecycle_body = {
                    "profile_id": profile,
                    "status": "deleted",
                    "reason_code": reason,
                    "actor_sha256": actor,
                    "updated_at": now,
                }
                lifecycle_sha = _sha256(lifecycle_body)
                conn.execute(
                    "INSERT INTO consent_profile_lifecycle(tenant, profile_id, status, "
                    "reason_code, actor_sha256, record_sha256, updated_at) "
                    "VALUES (?, ?, 'deleted', ?, ?, ?, ?) "
                    "ON CONFLICT(tenant, profile_id) DO UPDATE SET status = 'deleted', "
                    "reason_code = excluded.reason_code, actor_sha256 = excluded.actor_sha256, "
                    "record_sha256 = excluded.record_sha256, "
                    "updated_at = excluded.updated_at",
                    (tenant, profile, reason, actor, lifecycle_sha, now),
                )
                result = {
                    "profile_id": profile,
                    "status": "deleted",
                    "reason_code": reason,
                    "revision": revision + 1,
                    "tombstone_sha256": tombstone_sha,
                    "updated_at": now,
                }
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="profile.subject_deleted",
                    payload={
                        "profile_id": profile,
                        "revision": revision + 1,
                        "reason_code": reason,
                        "tombstone_sha256": tombstone_sha,
                    },
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="profile.delete_subject",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def _mutate_receipt_lifecycle(  # noqa: PLR0913 - exact authority pins
        self,
        tenant_id: str,
        profile_id: str,
        receipt_id: str,
        *,
        expected_revision: int,
        reactivation_at: float | None,
        clear_expiration: bool | None,
        idempotency_key: str,
        actor_sha256: str,
        namespace: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        receipt = _text(receipt_id, "receipt_id")
        revision = _expected_revision(expected_revision)
        actor = _digest(actor_sha256, "actor_sha256")
        reactivation = _timestamp(
            reactivation_at, "reactivation_at", allow_none=True
        )
        if clear_expiration is not None and type(clear_expiration) is not bool:
            raise ConsentValidationError("clear_expiration must be true or false")
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "profile_id": profile,
            "receipt_id": receipt,
            "expected_revision": revision,
            "reactivation_at": reactivation,
            "clear_expiration": clear_expiration,
            "actor_sha256": actor,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        if reactivation is not None and reactivation <= now:
            raise ConsentValidationError("reactivation_at must be in the future")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace=namespace,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                profile_row = self._profile_row(conn, tenant, profile)
                if int(profile_row["revision"]) != revision:
                    raise ConsentConflict("profile revision changed")
                lifecycle = self._profile_lifecycle(conn, tenant, profile)
                if lifecycle["status"] != "active":
                    raise ConsentConflict("deleted profile receipt cannot be changed")
                receipt_row = conn.execute(
                    "SELECT receipt_id, sequence FROM consent_receipts WHERE tenant = ? "
                    "AND profile_id = ? AND receipt_id = ?",
                    (tenant, profile, receipt),
                ).fetchone()
                if receipt_row is None:
                    raise ConsentNotFound(
                        "receipt does not exist for this profile in this tenant"
                    )
                group = self._profile_group(conn, tenant, profile)
                if int(receipt_row["sequence"]) <= self._restoration_receipt_floor(
                    conn, tenant, group
                ):
                    raise ConsentConflict(
                        "receipt predates subject restoration; collect new consent"
                    )
                prior = conn.execute(
                    "SELECT reactivation_at, clear_expiration, revision "
                    "FROM consent_receipt_lifecycle WHERE tenant = ? AND receipt_id = ?",
                    (tenant, receipt),
                ).fetchone()
                next_reactivation = (
                    reactivation
                    if reactivation is not None
                    else (
                        float(prior["reactivation_at"])
                        if prior is not None and prior["reactivation_at"] is not None
                        else None
                    )
                )
                next_clear = (
                    clear_expiration
                    if clear_expiration is not None
                    else bool(prior["clear_expiration"] if prior is not None else False)
                )
                lifecycle_revision = (
                    int(prior["revision"]) + 1 if prior is not None else 1
                )
                body = {
                    "receipt_id": receipt,
                    "profile_id": profile,
                    "reactivation_at": next_reactivation,
                    "clear_expiration": next_clear,
                    "revision": lifecycle_revision,
                    "actor_sha256": actor,
                    "updated_at": now,
                }
                record_sha = _sha256(body)
                conn.execute(
                    "INSERT INTO consent_receipt_lifecycle(tenant, receipt_id, profile_id, "
                    "reactivation_at, clear_expiration, revision, actor_sha256, "
                    "record_sha256, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(tenant, receipt_id) DO UPDATE SET "
                    "reactivation_at = excluded.reactivation_at, "
                    "clear_expiration = excluded.clear_expiration, "
                    "revision = excluded.revision, actor_sha256 = excluded.actor_sha256, "
                    "record_sha256 = excluded.record_sha256, "
                    "updated_at = excluded.updated_at",
                    (
                        tenant,
                        receipt,
                        profile,
                        next_reactivation,
                        int(next_clear),
                        lifecycle_revision,
                        actor,
                        record_sha,
                        now,
                    ),
                )
                updated = conn.execute(
                    "UPDATE consent_profiles SET revision = revision + 1 "
                    "WHERE tenant = ? AND profile_id = ? AND revision = ?",
                    (tenant, profile, revision),
                )
                if updated.rowcount != 1:
                    raise ConsentConflict("profile revision changed")
                result = {
                    **body,
                    "profile_revision": revision + 1,
                    "record_sha256": record_sha,
                }
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="receipt.lifecycle_changed",
                    payload={
                        "receipt_id": receipt,
                        "profile_id": profile,
                        "profile_revision": revision + 1,
                        "reactivation_at": next_reactivation,
                        "clear_expiration": next_clear,
                        "record_sha256": record_sha,
                    },
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace=namespace,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def set_receipt_reactivation(  # noqa: PLR0913 - explicit lifecycle contract
        self,
        tenant_id: str,
        profile_id: str,
        receipt_id: str,
        reactivation_at: float,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_sha256: str,
    ) -> dict[str, Any]:
        """Project a future ``reactivationDate`` without rewriting a receipt."""

        return self._mutate_receipt_lifecycle(
            tenant_id,
            profile_id,
            receipt_id,
            expected_revision=expected_revision,
            reactivation_at=reactivation_at,
            clear_expiration=None,
            idempotency_key=idempotency_key,
            actor_sha256=actor_sha256,
            namespace="receipt.set_reactivation",
        )

    def clear_receipt_expiration(  # noqa: PLR0913 - explicit lifecycle contract
        self,
        tenant_id: str,
        profile_id: str,
        receipt_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_sha256: str,
    ) -> dict[str, Any]:
        """Apply an auditable ``clearExpiration`` overlay to a receipt."""

        return self._mutate_receipt_lifecycle(
            tenant_id,
            profile_id,
            receipt_id,
            expected_revision=expected_revision,
            reactivation_at=None,
            clear_expiration=True,
            idempotency_key=idempotency_key,
            actor_sha256=actor_sha256,
            namespace="receipt.clear_expiration",
        )

    def get_receipt_lifecycle(
        self,
        tenant_id: str,
        receipt_id: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        receipt = _text(receipt_id, "receipt_id")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT profile_id, reactivation_at, clear_expiration, revision, "
                "actor_sha256, record_sha256, updated_at "
                "FROM consent_receipt_lifecycle WHERE tenant = ? AND receipt_id = ?",
                (tenant, receipt),
            ).fetchone()
        if row is None:
            raise ConsentNotFound("receipt lifecycle does not exist in this tenant")
        body = {
            "receipt_id": receipt,
            "profile_id": str(row["profile_id"]),
            "reactivation_at": (
                float(row["reactivation_at"])
                if row["reactivation_at"] is not None
                else None
            ),
            "clear_expiration": bool(row["clear_expiration"]),
            "revision": int(row["revision"]),
            "actor_sha256": str(row["actor_sha256"]),
            "updated_at": float(row["updated_at"]),
        }
        if not text_equals(_sha256(body), str(row["record_sha256"])):
            raise ConsentPreferencesError("stored receipt lifecycle integrity failed")
        return {**body, "record_sha256": str(row["record_sha256"])}

    def record_preferences(
        self,
        tenant_id: str,
        profile_id: str,
        policy_id: str,
        policy_version: int,
        context: ConsentContext,
        choices: Sequence[PreferenceChoice],
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_sha256: str,
        retention_until: float | None = None,
        signal: str | None = None,
    ) -> dict[str, Any]:
        """Append an immutable choice receipt and advance the profile revision."""

        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        policy = _text(policy_id, "policy_id")
        version = _positive_version(policy_version, "policy_version")
        revision = _expected_revision(expected_revision)
        actor = _digest(actor_sha256, "actor_sha256")
        if not isinstance(context, ConsentContext):
            raise ConsentValidationError("context must be a ConsentContext")
        normalized_context = context.normalized()
        if signal is not None and signal not in _PRIVACY_SIGNALS:
            raise ConsentValidationError("privacy signal must be gpc or dnt")
        normalized_context["privacy_signal"] = signal
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        retention = _timestamp(retention_until, "retention_until", allow_none=True)
        if retention is not None and retention <= now:
            raise ConsentValidationError("retention_until must be later than collection")
        normalized_choices = _normalize_choices(
            choices,
            now=now,
            signal=signal,
            retention_until=retention,
        )
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "profile_id": profile,
            "policy_id": policy,
            "policy_version": version,
            "context": normalized_context,
            "choices": normalized_choices,
            "expected_revision": revision,
            "actor_sha256": actor,
            "retention_until": retention,
        }
        request_sha = _sha256(request)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="preferences.record",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                profile_row = self._profile_row(conn, tenant, profile)
                lifecycle = self._profile_lifecycle(conn, tenant, profile)
                if lifecycle["status"] != "active":
                    raise ConsentConflict("deleted profile cannot record preferences")
                if int(profile_row["revision"]) != revision:
                    raise ConsentConflict(
                        f"profile revision is {profile_row['revision']}, expected {revision}"
                    )
                policy_row = self._active_policy(conn, tenant, policy, now)
                if policy_row is None or int(policy_row["version"]) != version:
                    raise ConsentStalePolicy(
                        "preference collection must bind the current effective policy version"
                    )
                purposes = _loads(policy_row["purposes_json"], "policy purposes")
                if not isinstance(purposes, dict):
                    raise ConsentPreferencesError("stored policy purposes are invalid")
                for choice in normalized_choices:
                    purpose_id = str(choice["purpose_id"])
                    if purpose_id not in purposes:
                        raise ConsentValidationError(
                            f"purpose {purpose_id!r} is not in the bound policy"
                        )
                    if purposes[purpose_id] != "consent":
                        raise ConsentValidationError(
                            "preference receipts cannot manufacture non-consent authority"
                        )
                previous = conn.execute(
                    "SELECT receipt_sha256 FROM consent_receipts "
                    "WHERE tenant = ? AND profile_id = ? ORDER BY sequence DESC LIMIT 1",
                    (tenant, profile),
                ).fetchone()
                previous_sha = (
                    str(previous["receipt_sha256"]) if previous is not None else None
                )
                receipt_id = self._new_id("CP-RCP")
                context_sha = _sha256(normalized_context)
                body = {
                    "schema": RECEIPT_SCHEMA,
                    "receipt_id": receipt_id,
                    "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
                    "profile_id": profile,
                    "profile_revision": revision + 1,
                    "policy_id": policy,
                    "policy_version": version,
                    "policy_sha256": str(policy_row["policy_sha256"]),
                    "context": normalized_context,
                    "context_sha256": context_sha,
                    "choices": normalized_choices,
                    "actor_sha256": actor,
                    "previous_receipt_sha256": previous_sha,
                    "created_at": now,
                    "retention_until": retention,
                }
                receipt_sha = _sha256(body)
                conn.execute(
                    "INSERT INTO consent_receipts(tenant, receipt_id, profile_id, "
                    "profile_revision, policy_id, policy_version, policy_sha256, "
                    "context_json, context_sha256, choices_json, actor_sha256, "
                    "previous_receipt_sha256, receipt_sha256, created_at, "
                    "retention_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        receipt_id,
                        profile,
                        revision + 1,
                        policy,
                        version,
                        str(policy_row["policy_sha256"]),
                        _canonical(normalized_context).decode("ascii"),
                        context_sha,
                        _canonical(normalized_choices).decode("ascii"),
                        actor,
                        previous_sha,
                        receipt_sha,
                        now,
                        retention,
                    ),
                )
                updated = conn.execute(
                    "UPDATE consent_profiles SET revision = revision + 1 "
                    "WHERE tenant = ? AND profile_id = ? AND revision = ?",
                    (tenant, profile, revision),
                )
                if updated.rowcount != 1:
                    raise ConsentConflict("profile preferences changed concurrently")
                result = {**body, "receipt_sha256": receipt_sha}
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="preferences.changed",
                    payload={
                        "profile_id": profile,
                        "profile_revision": revision + 1,
                        "receipt_id": receipt_id,
                        "receipt_sha256": receipt_sha,
                        "policy_id": policy,
                        "policy_version": version,
                        "context_sha256": context_sha,
                        "choices": normalized_choices,
                    },
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="preferences.record",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def ingest_privacy_signal(
        self,
        tenant_id: str,
        profile_id: str,
        signal: str,
        purposes: Sequence[str],
        policy_id: str,
        policy_version: int,
        context: ConsentContext,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_sha256: str,
    ) -> dict[str, Any]:
        """Record an asserted active GPC or DNT signal as explicit denials."""

        if signal not in _PRIVACY_SIGNALS:
            raise ConsentValidationError("signal must be gpc or dnt")
        if (
            isinstance(purposes, (str, bytes))
            or not isinstance(purposes, Sequence)
            or not 1 <= len(purposes) <= _MAX_PURPOSES
        ):
            raise ConsentValidationError("signal purposes are invalid")
        choices = [
            PreferenceChoice(purpose_id=_text(item, "purpose_id"), action="deny")
            for item in purposes
        ]
        return self.record_preferences(
            tenant_id,
            profile_id,
            policy_id,
            policy_version,
            context,
            choices,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            actor_sha256=actor_sha256,
            signal=signal,
        )

    def register_tracker(
        self,
        tenant_id: str,
        tracker_id: str,
        kind: str,
        vendor_id: str,
        purpose_ids: Sequence[str],
        status: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create or revise one tenant's tracker/SDK registry entry."""

        tenant = self._tenant(tenant_id)
        tracker = _text(tracker_id, "tracker_id")
        vendor = _text(vendor_id, "vendor_id")
        if kind not in _TRACKER_KINDS:
            raise ConsentValidationError("kind must be web_tracker or mobile_sdk")
        if status not in _TRACKER_STATUSES:
            raise ConsentValidationError("tracker status is invalid")
        revision = _expected_revision(expected_revision)
        if (
            isinstance(purpose_ids, (str, bytes))
            or not isinstance(purpose_ids, Sequence)
            or not 1 <= len(purpose_ids) <= _MAX_PURPOSES
        ):
            raise ConsentValidationError("purpose_ids must be a non-empty sequence")
        purposes = sorted({_text(item, "purpose_id") for item in purpose_ids})
        if len(purposes) != len(purpose_ids):
            raise ConsentValidationError("purpose_ids cannot contain duplicates")
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "tracker_id": tracker,
            "kind": kind,
            "vendor_id": vendor,
            "purpose_ids": purposes,
            "status": status,
            "expected_revision": revision,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="tracker.register",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                current = conn.execute(
                    "SELECT revision FROM consent_trackers "
                    "WHERE tenant = ? AND tracker_id = ?",
                    (tenant, tracker),
                ).fetchone()
                current_revision = int(current["revision"]) if current is not None else 0
                if current_revision != revision:
                    raise ConsentConflict(
                        f"tracker revision is {current_revision}, expected {revision}"
                    )
                next_revision = revision + 1
                body = {
                    "tracker_id": tracker,
                    "kind": kind,
                    "vendor_id": vendor,
                    "purpose_ids": purposes,
                    "status": status,
                    "revision": next_revision,
                    "updated_at": now,
                }
                record_sha = _sha256(body)
                if current is None:
                    conn.execute(
                        "INSERT INTO consent_trackers(tenant, tracker_id, kind, "
                        "vendor_id, purpose_ids_json, status, revision, record_sha256, "
                        "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            tracker,
                            kind,
                            vendor,
                            _canonical(purposes).decode("ascii"),
                            status,
                            next_revision,
                            record_sha,
                            now,
                        ),
                    )
                else:
                    updated = conn.execute(
                        "UPDATE consent_trackers SET kind = ?, vendor_id = ?, "
                        "purpose_ids_json = ?, status = ?, revision = ?, "
                        "record_sha256 = ?, updated_at = ? WHERE tenant = ? "
                        "AND tracker_id = ? AND revision = ?",
                        (
                            kind,
                            vendor,
                            _canonical(purposes).decode("ascii"),
                            status,
                            next_revision,
                            record_sha,
                            now,
                            tenant,
                            tracker,
                            revision,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise ConsentConflict("tracker changed concurrently")
                result = {**body, "record_sha256": record_sha}
                self._outbox(
                    conn,
                    tenant=tenant,
                    event_type="tracker.registry.changed",
                    payload=result,
                    now=now,
                )
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="tracker.register",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def admit_scan_observations(
        self,
        tenant_id: str,
        scan_id: str,
        observations: Sequence[TrackerObservation],
        observed_at: float,
        source_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Atomically admit a scan only when every observation is registered."""

        tenant = self._tenant(tenant_id)
        scan = _text(scan_id, "scan_id")
        observed = _timestamp(observed_at, "observed_at")
        assert observed is not None
        source = _digest(source_sha256, "source_sha256")
        if (
            isinstance(observations, (str, bytes))
            or not isinstance(observations, Sequence)
            or not 1 <= len(observations) <= _MAX_OBSERVATIONS
        ):
            raise ConsentValidationError("observations must be a non-empty bounded sequence")
        normalized: list[dict[str, str]] = []
        identities: set[tuple[str, str, str]] = set()
        for raw in observations:
            if not isinstance(raw, TrackerObservation):
                raise ConsentValidationError(
                    "every observation must be a TrackerObservation"
                )
            item = raw.normalized()
            identity = (item["asset_ref"], item["tracker_id"], item["location_ref"])
            if identity in identities:
                raise ConsentValidationError("scan observations cannot be duplicated")
            identities.add(identity)
            normalized.append(item)
        normalized.sort(
            key=lambda item: (item["asset_ref"], item["tracker_id"], item["location_ref"])
        )
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {
            "scan_id": scan,
            "observations": normalized,
            "observed_at": observed,
            "source_sha256": source,
        }
        request_sha = _sha256(request)
        admitted_at = _timestamp(self._clock(), "clock")
        assert admitted_at is not None
        if observed > admitted_at + 300:
            raise ConsentValidationError("observed_at is unreasonably in the future")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace="scan.admit",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                tracker_ids = sorted({item["tracker_id"] for item in normalized})
                registry: dict[str, sqlite3.Row] = {}
                for offset in range(0, len(tracker_ids), 100):
                    batch = tracker_ids[offset : offset + 100]
                    placeholders = ",".join("?" for _ in batch)
                    rows = conn.execute(
                        "SELECT tracker_id, status FROM consent_trackers "
                        f"WHERE tenant = ? AND tracker_id IN ({placeholders})",
                        (tenant, *batch),
                    ).fetchall()
                    registry.update({str(row["tracker_id"]): row for row in rows})
                rejected = [
                    tracker
                    for tracker in tracker_ids
                    if tracker not in registry or registry[tracker]["status"] != "approved"
                ]
                if rejected:
                    # Do not echo caller-controlled identifiers into an error or state.
                    raise ScanAdmissionError(
                        f"scan contains {len(rejected)} unknown or non-approved tracker(s)"
                    )
                observation_digests: list[str] = []
                for item in normalized:
                    body = {
                        "scan_id": scan,
                        **item,
                        "source_sha256": source,
                        "observed_at": observed,
                    }
                    observation_sha = _sha256(body)
                    observation_digests.append(observation_sha)
                    conn.execute(
                        "INSERT INTO consent_scan_observations(tenant, scan_id, "
                        "asset_ref, tracker_id, location_ref, evidence_sha256, "
                        "source_sha256, observed_at, admitted_at, observation_sha256) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            scan,
                            item["asset_ref"],
                            item["tracker_id"],
                            item["location_ref"],
                            item["evidence_sha256"],
                            source,
                            observed,
                            admitted_at,
                            observation_sha,
                        ),
                    )
                result = {
                    "scan_id": scan,
                    "admitted": True,
                    "admitted_count": len(normalized),
                    "observed_at": observed,
                    "admitted_at": admitted_at,
                    "source_sha256": source,
                    "scan_sha256": _sha256(
                        {
                            "scan_id": scan,
                            "observation_sha256": observation_digests,
                            "source_sha256": source,
                            "observed_at": observed,
                        }
                    ),
                }
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace="scan.admit",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=admitted_at,
                )
                conn.execute("COMMIT")
                return result
            except sqlite3.IntegrityError as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise ConsentConflict("scan observation already exists") from exc
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def _profile_group(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        profile_id: str,
    ) -> list[str]:
        self._profile_row(conn, tenant, profile_id)
        rows = conn.execute(
            "SELECT * FROM consent_profile_link_current WHERE tenant = ? AND "
            "status = 'linked' AND "
            "(known_profile_id = ? OR anonymous_profile_id = ?) "
            "ORDER BY known_profile_id, anonymous_profile_id LIMIT ?",
            (tenant, profile_id, profile_id, _MAX_LINKED_PROFILES + 1),
        ).fetchall()
        if len(rows) > _MAX_LINKED_PROFILES:
            raise ConsentPreferencesError("linked profile bound exceeded")
        profiles = {profile_id}
        known_profiles: set[str] = set()
        for row in rows:
            current = self._link_current(row)
            assert current is not None
            events = self._verified_link_events(
                conn,
                tenant,
                str(current["anonymous_profile_id"]),
            )
            self._assert_current_link_history(current, events)
            known = str(current["known_profile_id"])
            profiles.add(known)
            profiles.add(str(current["anonymous_profile_id"]))
            known_profiles.add(known)
        # An anonymous profile first resolves to its known profile, then to the
        # other anonymous profiles already linked to that authority.
        for known in known_profiles:
            siblings = conn.execute(
                "SELECT * FROM consent_profile_link_current "
                "WHERE tenant = ? AND known_profile_id = ? AND status = 'linked' "
                "ORDER BY anonymous_profile_id LIMIT ?",
                (tenant, known, _MAX_LINKED_PROFILES + 1),
            ).fetchall()
            if len(siblings) > _MAX_LINKED_PROFILES:
                raise ConsentPreferencesError("linked profile bound exceeded")
            for sibling in siblings:
                current = self._link_current(sibling)
                assert current is not None
                events = self._verified_link_events(
                    conn,
                    tenant,
                    str(current["anonymous_profile_id"]),
                )
                self._assert_current_link_history(current, events)
                profiles.add(str(current["anonymous_profile_id"]))
        if len(profiles) > _MAX_LINKED_PROFILES:
            raise ConsentPreferencesError("linked profile bound exceeded")
        return sorted(profiles)

    @staticmethod
    def _restoration_receipt_floor(
        conn: sqlite3.Connection, tenant: str, group: Sequence[str]
    ) -> int:
        """Exclude receipts predating any restored identity in this linked group."""
        placeholders = ",".join("?" for _ in group)
        rows = conn.execute(
            "SELECT tenant, profile_id, profile_revision, receipt_sequence, "
            "source, created_at, record_sha256 FROM consent_profile_restoration_floors "
            f"WHERE tenant = ? AND profile_id IN ({placeholders})",
            (tenant, *group),
        ).fetchall()
        highest = 0
        for row in rows:
            body = {
                "tenant": str(row["tenant"]),
                "profile_id": str(row["profile_id"]),
                "profile_revision": int(row["profile_revision"]),
                "receipt_sequence": int(row["receipt_sequence"]),
                "source": str(row["source"]),
                "created_at": float(row["created_at"]),
            }
            if not text_equals(_sha256(body), str(row["record_sha256"])):
                raise ConsentPreferencesError("stored consent restoration floor integrity failed")
            highest = max(highest, body["receipt_sequence"])
        return highest

    def _decide(
        self,
        tenant_id: str,
        profile_id: str,
        purpose_id: str,
        *,
        channel: str = "all",
        vendor_id: str = "all",
        policy_id: str | None = None,
        policy_version: int | None = None,
        tracker_id: str | None = None,
        at: float | None = None,
    ) -> EnforcementDecision:
        """Return an explicit allow only for a current, applicable grant."""

        try:
            tenant = self._tenant(tenant_id)
            profile = _text(profile_id, "profile_id")
            purpose = _text(purpose_id, "purpose_id")
            channel = _text(channel, "channel")
            vendor = _text(vendor_id, "vendor_id")
            policy = _text(policy_id, "policy_id") if policy_id is not None else None
            requested_version = (
                _positive_version(policy_version, "policy_version")
                if policy_version is not None
                else None
            )
            tracker = _text(tracker_id, "tracker_id") if tracker_id is not None else None
            evaluated = _timestamp(self._clock() if at is None else at, "at")
            assert evaluated is not None
        except ConsentValidationError:
            return EnforcementDecision(False, "invalid_request")

        with self._connect() as conn:
            try:
                profile_row = self._profile_row(conn, tenant, profile)
            except ConsentNotFound:
                return EnforcementDecision(False, "unknown_profile", evaluated_at=evaluated)
            lifecycle = self._profile_lifecycle(conn, tenant, profile)
            if lifecycle["status"] != "active":
                return EnforcementDecision(
                    False,
                    "subject_deleted",
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            if policy is None:
                rows = conn.execute(
                    "SELECT DISTINCT policy_id FROM consent_policies WHERE tenant = ? "
                    "AND effective_at <= ? AND (expires_at IS NULL OR expires_at > ?) "
                    "ORDER BY policy_id LIMIT 2",
                    (tenant, evaluated, evaluated),
                ).fetchall()
                if len(rows) != 1:
                    return EnforcementDecision(
                        False,
                        "policy_context_required",
                        profile_revision=int(profile_row["revision"]),
                        evaluated_at=evaluated,
                    )
                policy = str(rows[0]["policy_id"])
            policy_row = self._active_policy(conn, tenant, policy, evaluated)
            if policy_row is None:
                return EnforcementDecision(
                    False,
                    "no_current_policy",
                    policy_id=policy,
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            version = int(policy_row["version"])
            if requested_version is not None and requested_version != version:
                return EnforcementDecision(
                    False,
                    "stale_policy",
                    policy_id=policy,
                    policy_version=version,
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            purposes = _loads(policy_row["purposes_json"], "policy purposes")
            if not isinstance(purposes, dict) or purpose not in purposes:
                return EnforcementDecision(
                    False,
                    "unknown_purpose",
                    policy_id=policy,
                    policy_version=version,
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            if purposes[purpose] != "consent":
                return EnforcementDecision(
                    False,
                    "external_lawful_basis_required",
                    policy_id=policy,
                    policy_version=version,
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            if tracker is not None:
                tracker_row = conn.execute(
                    "SELECT vendor_id, purpose_ids_json, status FROM consent_trackers "
                    "WHERE tenant = ? AND tracker_id = ?",
                    (tenant, tracker),
                ).fetchone()
                if tracker_row is None or tracker_row["status"] != "approved":
                    return EnforcementDecision(
                        False,
                        "tracker_not_approved",
                        policy_id=policy,
                        policy_version=version,
                        profile_revision=int(profile_row["revision"]),
                        evaluated_at=evaluated,
                    )
                tracker_purposes = _loads(
                    tracker_row["purpose_ids_json"], "tracker purposes"
                )
                if (
                    not isinstance(tracker_purposes, list)
                    or purpose not in tracker_purposes
                    or (vendor != "all" and tracker_row["vendor_id"] != vendor)
                ):
                    return EnforcementDecision(
                        False,
                        "tracker_scope_mismatch",
                        policy_id=policy,
                        policy_version=version,
                        profile_revision=int(profile_row["revision"]),
                        evaluated_at=evaluated,
                    )
            try:
                group = self._profile_group(conn, tenant, profile)
            except ConsentPreferencesError:
                return EnforcementDecision(
                    False,
                    "identity_linkage_unavailable",
                    policy_id=policy,
                    policy_version=version,
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            if any(
                self._profile_lifecycle(conn, tenant, linked_profile)["status"]
                != "active"
                for linked_profile in group
            ):
                return EnforcementDecision(
                    False,
                    "linked_subject_deleted",
                    policy_id=policy,
                    policy_version=version,
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            placeholders = ",".join("?" for _ in group)
            receipt_floor = self._restoration_receipt_floor(conn, tenant, group)
            rows = conn.execute(
                "SELECT receipt_id, receipt_sha256, choices_json FROM consent_receipts "
                f"WHERE tenant = ? AND profile_id IN ({placeholders}) "
                "AND policy_id = ? AND policy_version = ? AND sequence > ? "
                "ORDER BY sequence DESC LIMIT ?",
                (tenant, *group, policy, version, receipt_floor,
                 _MAX_DECISION_RECEIPTS + 1),
            ).fetchall()
            if len(rows) > _MAX_DECISION_RECEIPTS:
                return EnforcementDecision(
                    False,
                    "receipt_history_bound_exceeded",
                    policy_id=policy,
                    policy_version=version,
                    profile_revision=int(profile_row["revision"]),
                    evaluated_at=evaluated,
                )
            lifecycle_overrides: dict[str, dict[str, Any]] = {}
            receipt_ids = [str(row["receipt_id"]) for row in rows]
            if receipt_ids:
                receipt_placeholders = ",".join("?" for _ in receipt_ids)
                override_rows = conn.execute(
                    "SELECT receipt_id, profile_id, reactivation_at, clear_expiration, "
                    "revision, actor_sha256, record_sha256, updated_at "
                    "FROM consent_receipt_lifecycle WHERE tenant = ? "
                    f"AND receipt_id IN ({receipt_placeholders})",
                    (tenant, *receipt_ids),
                ).fetchall()
                for override_row in override_rows:
                    body = {
                        "receipt_id": str(override_row["receipt_id"]),
                        "profile_id": str(override_row["profile_id"]),
                        "reactivation_at": (
                            float(override_row["reactivation_at"])
                            if override_row["reactivation_at"] is not None
                            else None
                        ),
                        "clear_expiration": bool(override_row["clear_expiration"]),
                        "revision": int(override_row["revision"]),
                        "actor_sha256": str(override_row["actor_sha256"]),
                        "updated_at": float(override_row["updated_at"]),
                    }
                    if not text_equals(
                        _sha256(body), str(override_row["record_sha256"])
                    ):
                        raise ConsentPreferencesError(
                            "stored receipt lifecycle integrity failed"
                        )
                    lifecycle_overrides[body["receipt_id"]] = body
            decision = _decision_from_receipts(
                rows,
                purpose=purpose,
                channel=channel,
                vendor=vendor,
                policy=policy,
                version=version,
                profile_revision=int(profile_row["revision"]),
                evaluated=evaluated,
                lifecycle_overrides=lifecycle_overrides,
            )
            if decision is not None:
                return decision
            return EnforcementDecision(
                False,
                "no_current_explicit_grant",
                policy_id=policy,
                policy_version=version,
                profile_revision=int(profile_row["revision"]),
                evaluated_at=evaluated,
            )

    def decide(
        self,
        tenant_id: str,
        profile_id: str,
        purpose_id: str,
        *,
        channel: str = "all",
        vendor_id: str = "all",
        policy_id: str | None = None,
        policy_version: int | None = None,
        tracker_id: str | None = None,
        at: float | None = None,
    ) -> EnforcementDecision:
        """Fail closed when authority state is absent, corrupt, or unavailable."""

        try:
            return self._decide(
                tenant_id,
                profile_id,
                purpose_id,
                channel=channel,
                vendor_id=vendor_id,
                policy_id=policy_id,
                policy_version=policy_version,
                tracker_id=tracker_id,
                at=at,
            )
        except (ConsentPreferencesError, OSError, sqlite3.Error, ValueError):
            try:
                evaluated = _timestamp(self._clock() if at is None else at, "at")
            except (ConsentPreferencesError, ValueError):
                evaluated = None
            return EnforcementDecision(
                False,
                "authority_unavailable",
                evaluated_at=evaluated,
            )

    def outbox_watermark(self, tenant_id: str) -> int:
        """Current native sequence for an explicit future-only subscription."""
        tenant = self._tenant(tenant_id)
        with self._connect() as conn:
            return int(conn.execute("SELECT COALESCE(MAX(sequence),0) FROM consent_outbox WHERE tenant=?", (tenant,)).fetchone()[0])

    def read_outbox(
        self,
        tenant_id: str,
        destination_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
        include_acked: bool = False,
    ) -> dict[str, Any]:
        """Read a bounded outbox page; old sequence cursors enable exact replay."""

        tenant = self._tenant(tenant_id)
        destination = _text(destination_id, "destination_id")
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or after_sequence < 0
        ):
            raise ConsentValidationError("after_sequence must be non-negative")
        page_size = _limit(limit)
        with self._connect() as conn:
            if include_acked:
                rows = conn.execute(
                    "SELECT sequence, payload_json, payload_sha256 FROM consent_outbox "
                    "WHERE tenant = ? AND sequence > ? ORDER BY sequence LIMIT ?",
                    (tenant, after_sequence, page_size + 1),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT o.sequence, o.payload_json, o.payload_sha256 "
                    "FROM consent_outbox AS o WHERE o.tenant = ? AND o.sequence > ? "
                    "AND NOT EXISTS (SELECT 1 FROM consent_outbox_acks AS a "
                    "WHERE a.tenant = o.tenant AND a.destination_id = ? "
                    "AND a.event_id = o.event_id) ORDER BY o.sequence LIMIT ?",
                    (tenant, after_sequence, destination, page_size + 1),
                ).fetchall()
        truncated = len(rows) > page_size
        rows = rows[:page_size]
        events: list[dict[str, Any]] = []
        for row in rows:
            body = _loads(row["payload_json"], "outbox event")
            if not isinstance(body, dict) or not text_equals(
                _sha256(body), str(row["payload_sha256"])
            ):
                raise ConsentPreferencesError("stored outbox event integrity failed")
            events.append(
                {
                    **body,
                    "sequence": int(row["sequence"]),
                    "payload_sha256": str(row["payload_sha256"]),
                }
            )
        return {
            "destination_id": destination,
            "after_sequence": after_sequence,
            "events": events,
            "truncated": truncated,
            "next_sequence": (
                int(events[-1]["sequence"]) if events else after_sequence
            ),
            "replay": include_acked,
        }

    def ack_outbox(
        self,
        tenant_id: str,
        destination_id: str,
        event_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Idempotently acknowledge delivery to one destination."""

        tenant = self._tenant(tenant_id)
        destination = _text(destination_id, "destination_id")
        event = _text(event_id, "event_id")
        _raw_idem, key_sha = self._idem_key(idempotency_key)
        request = {"destination_id": destination, "event_id": event}
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        namespace = f"outbox.ack:{destination}"
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    conn,
                    tenant=tenant,
                    namespace=namespace,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    conn.execute("COMMIT")
                    return replay
                outbox = conn.execute(
                    "SELECT sequence, payload_sha256 FROM consent_outbox "
                    "WHERE tenant = ? AND event_id = ?",
                    (tenant, event),
                ).fetchone()
                if outbox is None:
                    raise ConsentNotFound("outbox event does not exist in this tenant")
                prior = conn.execute(
                    "SELECT event_sequence, acknowledged_at, ack_sha256 "
                    "FROM consent_outbox_acks WHERE tenant = ? AND destination_id = ? "
                    "AND event_id = ?",
                    (tenant, destination, event),
                ).fetchone()
                if prior is None:
                    body = {
                        "destination_id": destination,
                        "event_id": event,
                        "event_sequence": int(outbox["sequence"]),
                        "event_payload_sha256": str(outbox["payload_sha256"]),
                        "acknowledged_at": now,
                    }
                    ack_sha = _sha256(body)
                    conn.execute(
                        "INSERT INTO consent_outbox_acks(tenant, destination_id, "
                        "event_id, event_sequence, acknowledged_at, ack_sha256) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            destination,
                            event,
                            int(outbox["sequence"]),
                            now,
                            ack_sha,
                        ),
                    )
                    result = {**body, "ack_sha256": ack_sha}
                else:
                    result = {
                        "destination_id": destination,
                        "event_id": event,
                        "event_sequence": int(prior["event_sequence"]),
                        "event_payload_sha256": str(outbox["payload_sha256"]),
                        "acknowledged_at": float(prior["acknowledged_at"]),
                        "ack_sha256": str(prior["ack_sha256"]),
                    }
                self._save_idempotency(
                    conn,
                    tenant=tenant,
                    namespace=namespace,
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                conn.execute("COMMIT")
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def export_profile(
        self,
        tenant_id: str,
        profile_id: str,
        *,
        actor_sha256: str,
        access_purpose: str,
        receipt_limit: int = 100,
        before_sequence: int | None = None,
    ) -> dict[str, Any]:
        """Export bounded linked-profile state and append an access log."""

        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        actor = _digest(actor_sha256, "actor_sha256")
        purpose = _text(access_purpose, "access_purpose")
        page_size = _limit(receipt_limit)
        if before_sequence is not None and (isinstance(before_sequence, bool) or not isinstance(before_sequence, int) or before_sequence < 1):
            raise ConsentValidationError("Choose a valid earlier records page.")
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                group = self._profile_group(conn, tenant, profile)
                placeholders = ",".join("?" for _ in group)
                profile_rows = conn.execute(
                    "SELECT profile_id, identity_kind, subject_sha256, revision, "
                    "created_at FROM consent_profiles WHERE tenant = ? "
                    f"AND profile_id IN ({placeholders}) ORDER BY profile_id",
                    (tenant, *group),
                ).fetchall()
                before = " AND sequence < ?" if before_sequence is not None else ""
                receipt_rows = conn.execute(
                    "SELECT * FROM consent_receipts WHERE tenant = ? "
                    f"AND profile_id IN ({placeholders})" + before + " "
                    "ORDER BY sequence DESC LIMIT ?",
                    (tenant, *group, *((before_sequence,) if before_sequence is not None else ()), page_size + 1),
                ).fetchall()
                truncated = len(receipt_rows) > page_size
                receipt_rows = receipt_rows[:page_size]
                receipts = [self._receipt_output(row, tenant=tenant) for row in receipt_rows]
                body = {
                    "schema": EXPORT_SCHEMA,
                    "requested_profile_id": profile,
                    "profiles": [
                        {
                            "profile_id": str(row["profile_id"]),
                            "identity_kind": str(row["identity_kind"]),
                            "subject_sha256": str(row["subject_sha256"]),
                            "revision": int(row["revision"]),
                            "created_at": float(row["created_at"]),
                        }
                        for row in profile_rows
                    ],
                    "receipts": receipts,
                    "receipts_truncated": truncated,
                    "next_before_sequence": int(receipt_rows[-1]["sequence"]) if truncated else None,
                    "generated_at": now,
                }
                export_sha = _sha256(body)
                access_body = {
                    "profile_id": profile,
                    "actor_sha256": actor,
                    "access_purpose": purpose,
                    "export_sha256": export_sha,
                    "accessed_at": now,
                }
                access_sha = _sha256(access_body)
                conn.execute(
                    "INSERT INTO consent_access_log(tenant, profile_id, actor_sha256, "
                    "access_purpose, export_sha256, accessed_at, access_sha256) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tenant, profile, actor, purpose, export_sha, now, access_sha),
                )
                conn.execute("COMMIT")
                return {**body, "export_sha256": export_sha}
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _receipt_output(row: sqlite3.Row, *, tenant: str) -> dict[str, Any]:
        context = _loads(row["context_json"], "receipt context")
        choices = _loads(row["choices_json"], "receipt choices")
        if not isinstance(context, dict) or not isinstance(choices, list):
            raise ConsentPreferencesError("stored receipt shape is invalid")
        return {
            "schema": RECEIPT_SCHEMA,
            "receipt_id": str(row["receipt_id"]),
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "profile_id": str(row["profile_id"]),
            "profile_revision": int(row["profile_revision"]),
            "policy_id": str(row["policy_id"]),
            "policy_version": int(row["policy_version"]),
            "policy_sha256": str(row["policy_sha256"]),
            "context": context,
            "context_sha256": str(row["context_sha256"]),
            "choices": choices,
            "actor_sha256": str(row["actor_sha256"]),
            "previous_receipt_sha256": row["previous_receipt_sha256"],
            "receipt_sha256": str(row["receipt_sha256"]),
            "created_at": float(row["created_at"]),
            "retention_until": (
                float(row["retention_until"])
                if row["retention_until"] is not None
                else None
            ),
        }

    def get_receipt(self, tenant_id: str, receipt_id: str) -> dict[str, Any]:
        """Return one immutable tenant-scoped receipt after integrity checks.

        Delivery and audit integrations use this narrow lookup instead of a
        bounded profile export so an older outbox event cannot be paired with
        the wrong receipt when a profile has a long history.
        """

        tenant = self._tenant(tenant_id)
        receipt = _text(receipt_id, "receipt_id")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM consent_receipts WHERE tenant = ? AND receipt_id = ?",
                (tenant, receipt),
            ).fetchone()
        if row is None:
            raise ConsentNotFound("receipt does not exist in this tenant")
        result = self._receipt_output(row, tenant=tenant)
        body = {key: value for key, value in result.items() if key != "receipt_sha256"}
        if not text_equals(_sha256(body), result["receipt_sha256"]):
            raise ConsentPreferencesError("stored receipt integrity failed")
        return result

    def list_access_log(
        self,
        tenant_id: str,
        profile_id: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        page_size = _limit(limit)
        with self._connect() as conn:
            self._profile_row(conn, tenant, profile)
            rows = conn.execute(
                "SELECT sequence, actor_sha256, access_purpose, export_sha256, "
                "accessed_at, access_sha256 FROM consent_access_log "
                "WHERE tenant = ? AND profile_id = ? ORDER BY sequence DESC LIMIT ?",
                (tenant, profile, page_size + 1),
            ).fetchall()
        return {
            "profile_id": profile,
            "events": [dict(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }

    def retention_due(
        self,
        tenant_id: str,
        *,
        before: float,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List immutable receipts whose declared retention review is due."""

        tenant = self._tenant(tenant_id)
        cutoff = _timestamp(before, "before")
        assert cutoff is not None
        page_size = _limit(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT receipt_id, profile_id, receipt_sha256, retention_until "
                "FROM consent_receipts WHERE tenant = ? AND retention_until IS NOT NULL "
                "AND retention_until <= ? ORDER BY retention_until, sequence LIMIT ?",
                (tenant, cutoff, page_size + 1),
            ).fetchall()
        return {
            "before": cutoff,
            "receipts": [dict(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
            "action_required": "external_legal_retention_or_crypto_erasure_review",
            "receipts_deleted": False,
        }

    def purge_operational_data(
        self,
        tenant_id: str,
        *,
        before: float,
        limit: int = 100,
    ) -> dict[str, int]:
        """Bound retention of non-receipt scan and access telemetry.

        Consent receipts, policies, links, and idempotency claims remain
        immutable.  Their retention deadlines are surfaced by
        :meth:`retention_due` for the deployment's legal/crypto-erasure
        authority; this method never silently destroys proof of consent.
        """

        tenant = self._tenant(tenant_id)
        cutoff = _timestamp(before, "before")
        assert cutoff is not None
        page_size = _limit(limit)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                scan_rows = conn.execute(
                    "SELECT sequence FROM consent_scan_observations "
                    "WHERE tenant = ? AND admitted_at < ? ORDER BY sequence LIMIT ?",
                    (tenant, cutoff, page_size),
                ).fetchall()
                access_rows = conn.execute(
                    "SELECT sequence FROM consent_access_log WHERE tenant = ? "
                    "AND accessed_at < ? ORDER BY sequence LIMIT ?",
                    (tenant, cutoff, page_size),
                ).fetchall()
                if scan_rows:
                    conn.executemany(
                        "DELETE FROM consent_scan_observations "
                        "WHERE tenant = ? AND sequence = ?",
                        [(tenant, int(row["sequence"])) for row in scan_rows],
                    )
                if access_rows:
                    conn.executemany(
                        "DELETE FROM consent_access_log WHERE tenant = ? AND sequence = ?",
                        [(tenant, int(row["sequence"])) for row in access_rows],
                    )
                conn.execute("COMMIT")
                return {
                    "scan_observations_deleted": len(scan_rows),
                    "access_events_deleted": len(access_rows),
                    "receipts_deleted": 0,
                }
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def unified_audit_records(self, tenant_id: str):
        """Return a digest-only chain over the durable consent outbox.

        Policy publication, scan admission, decisions and retention purges are
        not all represented in this canonical replay history.  Callers must
        therefore retain a suite-level ``source_history_incomplete`` limit.
        """

        from .unified_audit import GENESIS_SHA256, build_source_record

        tenant = self._tenant(tenant_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT sequence,event_id,event_type,payload_json,payload_sha256,"
                "created_at FROM consent_outbox WHERE tenant=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        actions = {
            "profile.created": "record_created",
            "profile.linked": "relationship_changed",
            "profile.unlinked": "relationship_changed",
            "profile.identifier_changed": "record_updated",
            "profile.subject_deleted": "record_deleted",
            "receipt.lifecycle_changed": "status_changed",
            "preferences.changed": "consent_recorded",
            "tracker.registry.changed": "policy_changed",
        }
        actor_sha256 = hashlib.sha256(
            b"lightwork.consent-preferences.outbox-authority.v1"
        ).hexdigest()
        previous = GENESIS_SHA256
        records = []
        for sequence, row in enumerate(rows, start=1):
            event_type = str(row["event_type"])
            action = actions.get(event_type)
            if action is None:
                raise ConsentPreferencesError(
                    "stored consent outbox event type is unsupported"
                )
            body = _loads(row["payload_json"], "consent outbox payload")
            if (
                not isinstance(body, dict)
                or body.get("schema") != OUTBOX_SCHEMA
                or body.get("event_id") != row["event_id"]
                or body.get("event_type") != event_type
                or body.get("created_at") != row["created_at"]
                or _canonical(body).decode("ascii") != row["payload_json"]
            ):
                raise ConsentPreferencesError(
                    "stored consent outbox payload is invalid"
                )
            payload_sha256 = str(row["payload_sha256"])
            if not text_equals(payload_sha256, _sha256(body)):
                raise ConsentPreferencesError(
                    "stored consent outbox payload failed integrity verification"
                )
            event_id = str(row["event_id"])
            record = build_source_record(
                sequence=sequence,
                occurred_at=float(row["created_at"]),
                action=action,
                actor_sha256=actor_sha256,
                resource_sha256=hashlib.sha256(event_id.encode("utf-8")).hexdigest(),
                payload_sha256=payload_sha256,
                previous_sha256=previous,
            )
            records.append(record)
            previous = record.record_sha256
        return tuple(records)

    def summary(self, tenant_id: str) -> dict[str, Any]:
        """Return privacy-safe tenant counts for an operator overview."""

        tenant = self._tenant(tenant_id)
        with self._connect() as conn:
            counts = {
                "policies": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_policies WHERE tenant = ?",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "profiles": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_profiles WHERE tenant = ?",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "identity_links_current": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_profile_link_current "
                        "WHERE tenant = ? AND status = 'linked'",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "identity_links_unlinked": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_profile_link_current "
                        "WHERE tenant = ? AND status = 'unlinked'",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "identity_link_events": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_profile_link_events "
                        "WHERE tenant = ?",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "receipts": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_receipts WHERE tenant = ?",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "trackers": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_trackers WHERE tenant = ?",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "scan_observations": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_scan_observations WHERE tenant = ?",
                        (tenant,),
                    ).fetchone()[0]
                ),
                "outbox_events": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM consent_outbox WHERE tenant = ?",
                        (tenant,),
                    ).fetchone()[0]
                ),
            }
        return {
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            **counts,
        }

    @staticmethod
    def _policy_from_row(row: sqlite3.Row) -> dict[str, Any]:
        purposes = _loads(row["purposes_json"], "policy purposes")
        if not isinstance(purposes, dict):
            raise ConsentPreferencesError("stored policy purposes are invalid")
        return {
            "policy_id": str(row["policy_id"]),
            "version": int(row["version"]),
            "purposes": purposes,
            "notice_sha256": str(row["notice_sha256"]),
            "policy_sha256": str(row["policy_sha256"]),
            "effective_at": float(row["effective_at"]),
            "expires_at": float(row["expires_at"]) if row["expires_at"] is not None else None,
            "created_at": float(row["created_at"]),
        }

    def get_active_policy(
        self, tenant_id: str, policy_id: str, *, at: float, version: int | None = None,
    ) -> dict[str, Any] | None:
        """Resolve one policy independently of the bounded history listing.

        Without ``version``, return the newest version effective at ``at``.
        A specified version supports historical receipt checks without
        confusing a still-effective old version with current client authority.
        """
        tenant = self._tenant(tenant_id)
        policy = _text(policy_id, "policy_id")
        evaluated_at = _timestamp(at, "at")
        assert evaluated_at is not None
        if version is not None:
            version = _positive_version(version)
        with self._connect() as conn:
            if version is None:
                row = self._active_policy(conn, tenant, policy, evaluated_at)
            else:
                row = conn.execute(
                    "SELECT * FROM consent_policies WHERE tenant = ? AND policy_id = ? "
                    "AND version = ? AND effective_at <= ? "
                    "AND (expires_at IS NULL OR expires_at > ?)",
                    (tenant, policy, version, evaluated_at, evaluated_at),
                ).fetchone()
        return self._policy_from_row(row) if row is not None else None

    def list_policies(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        page_size = _limit(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT policy_id, version, purposes_json, notice_sha256, "
                "policy_sha256, effective_at, expires_at, created_at "
                "FROM consent_policies WHERE tenant = ? "
                "ORDER BY policy_id, version DESC LIMIT ?",
                (tenant, page_size + 1),
            ).fetchall()
        policies = [self._policy_from_row(row) for row in rows[:page_size]]
        return {"policies": policies, "truncated": len(rows) > page_size}

    def list_profiles(self, tenant_id: str, *, limit: int = 100,
                      after: str | None = None, search: str = "") -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        page_size = _limit(limit)
        if after is not None:
            after = _text(after, "profile page")
        if not isinstance(search, str) or len(search) > 128 or _CONTROL_RE.search(search):
            raise ConsentValidationError("Search must be at most 128 characters without control characters.")
        pattern = "%" + search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where, values = "tenant = ?", [tenant]
        if after is not None:
            where += " AND profile_id > ?"
            values.append(after)
        if search.strip():
            where += " AND profile_id LIKE ? ESCAPE '\\'"
            values.append(pattern)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT profile_id, identity_kind, subject_sha256, revision, created_at "
                "FROM consent_profiles WHERE " + where + " ORDER BY profile_id LIMIT ?",
                (*values, page_size + 1),
            ).fetchall()
        return {
            "profiles": [dict(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
            "next_after": str(rows[page_size - 1]["profile_id"]) if len(rows) > page_size else None,
        }

    def lookup_profiles(self, tenant_id: str, profile_ids: list[str]) -> dict[str, Any]:
        """Resolve a bounded exact selection without scanning the first list page."""
        tenant = self._tenant(tenant_id)
        if (not isinstance(profile_ids, list) or not 1 <= len(profile_ids) <= 100
                or any(not isinstance(value, str) for value in profile_ids)
                or len(set(profile_ids)) != len(profile_ids)):
            raise ConsentValidationError("Choose between 1 and 100 different people per lookup.")
        selected = [_text(value, "person reference") for value in profile_ids]
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT profile_id, identity_kind, revision, created_at FROM consent_profiles "
                "WHERE tenant = ? AND profile_id IN (" + ",".join("?" for _ in selected) + ")",
                (tenant, *selected),
            ).fetchall()
        found = {str(row["profile_id"]): dict(row) for row in rows}
        return {"profiles": [found[value] for value in selected if value in found],
                "missing": [value for value in selected if value not in found]}

    def get_profile_authority(
        self,
        tenant_id: str,
        profile_id: str,
    ) -> dict[str, Any]:
        """Resolve one profile and its current, integrity-bound link authority.

        This deliberately exposes no lookup by subject digest.  Federation
        callers already hold a tenant-scoped profile capability and need an
        exact revision for the existing :meth:`link_profiles` CAS contract;
        making that a first-class point lookup avoids a bounded list scan that
        would become fail-closed merely because a tenant has many profiles.
        """

        tenant = self._tenant(tenant_id)
        profile = _text(profile_id, "profile_id")
        with self._connect() as conn:
            row = self._profile_row(conn, tenant, profile)
            lifecycle = self._profile_lifecycle(conn, tenant, profile)
            if row["identity_kind"] == "anonymous":
                current_row = conn.execute(
                    "SELECT * FROM consent_profile_link_current WHERE tenant = ? "
                    "AND anonymous_profile_id = ?",
                    (tenant, profile),
                ).fetchone()
                current = self._link_current(current_row)
                if current is not None:
                    events = self._verified_link_events(conn, tenant, profile)
                    self._assert_current_link_history(current, events)
                else:
                    events = []
            else:
                current = None
                events = []
        linked = current is not None and current["status"] == "linked"
        linked_at = events[-1]["created_at"] if linked and events else None
        return {
            "profile_id": str(row["profile_id"]),
            "identity_kind": str(row["identity_kind"]),
            "subject_sha256": str(row["subject_sha256"]),
            "revision": int(row["revision"]),
            "created_at": float(row["created_at"]),
            "linked_known_profile_id": (
                str(current["known_profile_id"]) if linked else None
            ),
            "link_id": str(current["link_id"]) if linked else None,
            "link_sha256": str(current["link_sha256"]) if linked else None,
            "linked_at": linked_at,
            "link_status": str(current["status"]) if current is not None else "never_linked",
            "link_revision": int(current["revision"]) if current is not None else 0,
            "last_known_profile_id": (
                str(current["known_profile_id"]) if current is not None else None
            ),
            "last_link_id": str(current["link_id"]) if current is not None else None,
            "last_link_sha256": (
                str(current["link_sha256"]) if current is not None else None
            ),
            "link_authority_sha256": (
                str(current["authority_sha256"]) if current is not None else None
            ),
            "link_audit_evidence_sha256": (
                str(current["audit_evidence_sha256"])
                if current is not None
                else None
            ),
            "link_record_sha256": (
                str(current["record_sha256"]) if current is not None else None
            ),
            "link_retention_until": (
                current["retention_until"] if current is not None else None
            ),
            "lifecycle": lifecycle,
        }

    def get_profile_link_history(
        self,
        tenant_id: str,
        anonymous_profile_id: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Return bounded immutable lifecycle evidence for one anonymous profile."""

        tenant = self._tenant(tenant_id)
        anonymous = _text(anonymous_profile_id, "anonymous_profile_id")
        page_size = _limit(limit)
        with self._connect() as conn:
            profile = self._profile_row(conn, tenant, anonymous)
            if profile["identity_kind"] != "anonymous":
                raise ConsentValidationError("profile is not anonymous")
            current_row = conn.execute(
                "SELECT * FROM consent_profile_link_current WHERE tenant = ? "
                "AND anonymous_profile_id = ?",
                (tenant, anonymous),
            ).fetchone()
            current = self._link_current(current_row)
            events = self._verified_link_events(conn, tenant, anonymous)
            if current is None and events:
                raise ConsentPreferencesError("profile link authority is missing")
            if current is not None:
                self._assert_current_link_history(current, events)
        selected = list(reversed(events))[:page_size]
        return {
            "profile_id": anonymous,
            "current": (
                {
                    "status": current["status"],
                    "revision": current["revision"],
                    "known_profile_id": current["known_profile_id"],
                    "link_id": current["link_id"],
                    "link_sha256": current["link_sha256"],
                    "authority_sha256": current["authority_sha256"],
                    "audit_evidence_sha256": current["audit_evidence_sha256"],
                    "record_sha256": current["record_sha256"],
                    "updated_at": current["updated_at"],
                    "retention_until": current["retention_until"],
                }
                if current is not None
                else {"status": "never_linked", "revision": 0}
            ),
            "events": selected,
            "truncated": len(events) > page_size,
            "receipt_histories_merged": False,
        }

    def verify_profile_link_integrity(
        self,
        tenant_id: str,
        *,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Verify a bounded tenant slice of current authorities and event chains."""

        tenant = self._tenant(tenant_id)
        page_size = _limit(limit)
        authorities = events_verified = 0
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM consent_profile_link_current WHERE tenant = ? "
                "ORDER BY anonymous_profile_id LIMIT ?",
                (tenant, page_size + 1),
            ).fetchall()
            for row in rows[:page_size]:
                current = self._link_current(row)
                assert current is not None
                events = self._verified_link_events(
                    conn,
                    tenant,
                    str(current["anonymous_profile_id"]),
                )
                self._assert_current_link_history(current, events)
                authorities += 1
                events_verified += len(events)
        return {
            "authorities_verified": authorities,
            "events_verified": events_verified,
            "truncated": len(rows) > page_size,
        }

    def list_trackers(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        page_size = _limit(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT tracker_id, kind, vendor_id, purpose_ids_json, status, "
                "revision, record_sha256, updated_at FROM consent_trackers "
                "WHERE tenant = ? ORDER BY tracker_id LIMIT ?",
                (tenant, page_size + 1),
            ).fetchall()
        trackers: list[dict[str, Any]] = []
        for row in rows[:page_size]:
            purposes = _loads(row["purpose_ids_json"], "tracker purposes")
            if not isinstance(purposes, list):
                raise ConsentPreferencesError("stored tracker purposes are invalid")
            trackers.append(
                {
                    "tracker_id": str(row["tracker_id"]),
                    "kind": str(row["kind"]),
                    "vendor_id": str(row["vendor_id"]),
                    "purpose_ids": purposes,
                    "status": str(row["status"]),
                    "revision": int(row["revision"]),
                    "record_sha256": str(row["record_sha256"]),
                    "updated_at": float(row["updated_at"]),
                }
            )
        return {"trackers": trackers, "truncated": len(rows) > page_size}

    def list_scan_observations(
        self,
        tenant_id: str,
        scan_id: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        scan = _text(scan_id, "scan_id")
        page_size = _limit(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT asset_ref, tracker_id, location_ref, evidence_sha256, "
                "source_sha256, observed_at, admitted_at, observation_sha256 "
                "FROM consent_scan_observations WHERE tenant = ? AND scan_id = ? "
                "ORDER BY sequence LIMIT ?",
                (tenant, scan, page_size + 1),
            ).fetchall()
        return {
            "scan_id": scan,
            "observations": [dict(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }


__all__ = [
    "ConsentConflict",
    "ConsentContext",
    "ConsentIdempotencyConflict",
    "ConsentNotFound",
    "ConsentPreferenceStore",
    "ConsentPreferencesConfigError",
    "ConsentPreferencesError",
    "ConsentStalePolicy",
    "ConsentValidationError",
    "EnforcementDecision",
    "PreferenceChoice",
    "ScanAdmissionError",
    "TrackerObservation",
    "enabled",
    "require_enabled",
]
