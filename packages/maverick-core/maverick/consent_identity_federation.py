"""Verified consent identity federation and one-time device pairing.

The durable consent authority remains :class:`ConsentPreferenceStore`.  This
module stores only short-lived pairing workflow state and an immutable audit
chain; successful identity joins are committed through the existing
``link_profiles`` CAS contract so receipt ordering and latest-negative
semantics stay in one ledger.

OIDC verification is deliberately injected.  ``InjectedConsentOIDCVerifier``
can use a deployment-owned, DNS/JWKS-pinned key resolver without this module
performing network discovery or taking custody of provider credentials.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from . import consent_storage
from .consent_preferences import (
    ConsentConflict,
    ConsentNotFound,
    ConsentPreferenceStore,
)
from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file

SCHEMA_VERSION = 1
PAIRING_SCHEMA = "lightwork.consent.identity-pairing.v1"
PAIRING_AUDIT_SCHEMA = "lightwork.consent.identity-pairing-audit.v1"
MAX_PAIRING_TTL_SECONDS = 600
DEFAULT_RETENTION_SECONDS = 90 * 24 * 60 * 60
OIDC_CLOCK_SKEW_SECONDS = 30

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$")
_KID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+=@-]{0,255}$")
_PKCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_CAPABILITY_RE = re.compile(r"^lwcp1\.[A-Za-z0-9_-]{32,192}$")
_STATUSES = {"pending", "authorizing", "authorized", "redeemed", "revoked", "expired"}
_TERMINAL = {"redeemed", "revoked", "expired"}


class ConsentIdentityFederationError(RuntimeError):
    """Base error for the bounded federation workflow."""


class ConsentIdentityFederationConfigError(ConsentIdentityFederationError):
    """Raised when the default-off runtime contract is incomplete."""


class ConsentIdentityFederationDenied(ConsentIdentityFederationError):
    """Raised for opaque authentication, expiry, replay, or binding failures."""


class ConsentIdentityFederationConflict(ConsentIdentityFederationError):
    """Raised when an enrolled authority or CAS revision has drifted."""


class ConsentIdentityFederationIntegrityError(ConsentIdentityFederationError):
    """Raised when persisted workflow or audit material fails verification."""


@dataclass(frozen=True)
class ConsentIdentitySettings:
    enabled: bool
    issuer: str
    audience: str
    jwks_origin: str
    token_ttl_seconds: int
    link_lifecycle_retention_seconds: int = DEFAULT_RETENTION_SECONDS

    def normalized(self) -> ConsentIdentitySettings:
        if self.enabled is not True:
            raise ConsentIdentityFederationConfigError("consent identity is disabled")
        if (
            not isinstance(self.issuer, str)
            or not self.issuer.strip()
            or self.issuer != self.issuer.strip()
        ):
            raise ConsentIdentityFederationConfigError("OIDC issuer is invalid")
        if (
            not isinstance(self.audience, str)
            or not self.audience.strip()
            or self.audience != self.audience.strip()
        ):
            raise ConsentIdentityFederationConfigError("OIDC audience is invalid")
        if (
            not isinstance(self.token_ttl_seconds, int)
            or isinstance(self.token_ttl_seconds, bool)
            or not 60 <= self.token_ttl_seconds <= 86_400
        ):
            raise ConsentIdentityFederationConfigError("OIDC token TTL is invalid")
        if (
            not isinstance(self.link_lifecycle_retention_seconds, int)
            or isinstance(self.link_lifecycle_retention_seconds, bool)
            or not 3_600 <= self.link_lifecycle_retention_seconds <= 315_360_000
            or self.link_lifecycle_retention_seconds < self.token_ttl_seconds
        ):
            raise ConsentIdentityFederationConfigError(
                "consent identity link lifecycle retention is invalid"
            )
        return replace(self, jwks_origin=_origin(self.jwks_origin))


@dataclass(frozen=True)
class ConsentOIDCExpectation:
    issuer: str
    audience: str
    jwks_origin: str
    nonce: str
    now: float
    max_token_ttl_seconds: int


@dataclass(frozen=True)
class VerifiedConsentOIDCClaims:
    """Ephemeral verified claims returned by a deployment-owned verifier.

    ``subject`` and ``nonce`` are intentionally present only at the in-memory
    trust boundary.  The federation store persists their keyed/digest forms,
    never these raw values or the raw token.
    """

    subject: str
    issuer: str
    audiences: tuple[str, ...]
    nonce: str
    issued_at: float
    expires_at: float
    not_before: float | None
    key_id: str
    token_sha256: str


class ConsentOIDCVerifier(Protocol):
    def __call__(
        self,
        token: str,
        expectation: ConsentOIDCExpectation,
    ) -> VerifiedConsentOIDCClaims: ...


@dataclass(frozen=True)
class ConsentPairingContext:
    """Exact server-resolved authority pins for one caller capability."""

    tenant_id: str
    property_id: str
    profile_id: str
    profile_revision: int
    client_credential_sha256: str
    client_revision: int
    client_record_sha256: str
    profile_credential_sha256: str
    profile_binding_sha256: str
    property_revision: int
    property_sha256: str
    publication_sha256: str
    bundle_sha256: str
    configuration_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    channel_kind: str
    channel_binding_sha256: str

    def normalized(self) -> ConsentPairingContext:
        for name in ("tenant_id", "property_id", "profile_id", "policy_id"):
            _ref(getattr(self, name), name)
        for name in (
            "client_credential_sha256",
            "client_record_sha256",
            "profile_credential_sha256",
            "profile_binding_sha256",
            "property_sha256",
            "publication_sha256",
            "bundle_sha256",
            "configuration_sha256",
            "policy_sha256",
            "channel_binding_sha256",
        ):
            _digest(getattr(self, name), name)
        if self.channel_kind not in {"browser-origin", "service-client"}:
            raise ConsentIdentityFederationDenied("pairing authority is unavailable")
        for name in (
            "profile_revision",
            "client_revision",
            "property_revision",
            "policy_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ConsentIdentityFederationDenied("pairing authority is unavailable")
        if self.policy_version < 1:
            raise ConsentIdentityFederationDenied("pairing authority is unavailable")
        return self

    @property
    def fingerprint(self) -> str:
        return _sha256(asdict(self.normalized()))


@dataclass(frozen=True)
class PairingChallenge:
    pairing_id: str
    pairing_code: str
    oidc_nonce: str
    expires_at: float
    revision: int


@dataclass(frozen=True)
class PairingAuthorization:
    pairing_id: str
    status: str
    expires_at: float
    revision: int
    source_link_sha256: str


@dataclass(frozen=True)
class PairingRedemption:
    pairing_id: str
    status: str
    revision: int
    target_link_sha256: str
    linked_profile_id: str


@dataclass(frozen=True)
class ConsentIdentityEvidence:
    """Fresh digest-only OIDC/pairing proof for one exact linked device context."""

    schema: str
    tenant_id: str
    target_fingerprint: str
    source_fingerprint: str
    subject_binding_sha256: str
    oidc_verification_sha256: str
    source_link_sha256: str
    target_link_sha256: str
    pairing_revision: int
    valid_until: float
    evidence_sha256: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ConsentIdentityFederationDenied("pairing material is invalid") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ConsentIdentityFederationDenied(f"{field} is invalid")
    return value


def _ref(value: object, field: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise ConsentIdentityFederationDenied(f"{field} is invalid")
    return value


def _timestamp(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConsentIdentityFederationDenied(f"{field} is invalid")
    result = float(value)
    if not 0 < result < 32_503_680_000:
        raise ConsentIdentityFederationDenied(f"{field} is invalid")
    return result


def _origin(value: object) -> str:
    from urllib.parse import urlsplit

    if not isinstance(value, str) or not value:
        raise ConsentIdentityFederationConfigError("OIDC JWKS origin is missing")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ConsentIdentityFederationConfigError(
            "OIDC JWKS authority must be an exact HTTPS origin"
        )
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port
    return f"https://{host}" + (f":{port}" if port is not None else "")


def load_consent_identity_settings(
    config: Mapping[str, Any] | None = None,
) -> ConsentIdentitySettings:
    """Resolve the existing ``[consent_preferences.identity]`` contract."""

    if config is None:
        try:
            from .config import load_config

            loaded = load_config() or {}
        except Exception as exc:
            raise ConsentIdentityFederationConfigError(
                "consent identity configuration is unavailable"
            ) from exc
    else:
        loaded = config
    if not isinstance(loaded, Mapping):
        raise ConsentIdentityFederationConfigError("consent identity is disabled")
    consent = loaded.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        raise ConsentIdentityFederationConfigError("consent identity is disabled")
    for required in ("publishing", "public_api"):
        section = consent.get(required)
        if not isinstance(section, Mapping) or section.get("enable") is not True:
            raise ConsentIdentityFederationConfigError("consent identity is disabled")
    identity = consent.get("identity")
    if not isinstance(identity, Mapping) or identity.get("enable") is not True:
        raise ConsentIdentityFederationConfigError("consent identity is disabled")
    issuer = identity.get("issuer")
    audience = identity.get("audience")
    if not isinstance(issuer, str) or not issuer.strip() or issuer != issuer.strip():
        raise ConsentIdentityFederationConfigError("OIDC issuer is invalid")
    if not isinstance(audience, str) or not audience.strip() or audience != audience.strip():
        raise ConsentIdentityFederationConfigError("OIDC audience is invalid")
    ttl = identity.get("token_ttl_seconds", 600)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= 86_400:
        raise ConsentIdentityFederationConfigError("OIDC token TTL is invalid")
    lifecycle_retention = identity.get(
        "link_lifecycle_retention_seconds",
        DEFAULT_RETENTION_SECONDS,
    )
    if (
        not isinstance(lifecycle_retention, int)
        or isinstance(lifecycle_retention, bool)
        or not 3_600 <= lifecycle_retention <= 315_360_000
        or lifecycle_retention < ttl
    ):
        raise ConsentIdentityFederationConfigError(
            "consent identity link lifecycle retention is invalid"
        )
    return ConsentIdentitySettings(
        enabled=True,
        issuer=issuer,
        audience=audience,
        jwks_origin=_origin(identity.get("jwks_origin")),
        token_ttl_seconds=ttl,
        link_lifecycle_retention_seconds=lifecycle_retention,
    ).normalized()


def consent_identity_enabled(config: Mapping[str, Any] | None = None) -> bool:
    try:
        return load_consent_identity_settings(config).enabled
    except Exception:
        return False


class InjectedConsentOIDCVerifier:
    """Verify an ID token using an injected, deployment-custodied key resolver.

    ``signing_key_for`` receives the configured exact JWKS origin and the JWT
    ``kid``.  It must return an already fetched/pinned key.  This class never
    discovers or fetches keys and therefore cannot silently weaken DNS/JWKS
    custody.
    """

    def __init__(self, signing_key_for: Callable[[str, str], Any]) -> None:
        self._signing_key_for = signing_key_for

    def __call__(
        self,
        token: str,
        expectation: ConsentOIDCExpectation,
    ) -> VerifiedConsentOIDCClaims:
        try:
            import jwt

            from .oidc import OIDCConfig, verify_oidc_token

            header = jwt.get_unverified_header(token)
            kid = header.get("kid") if isinstance(header, dict) else None
            if not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
                raise ConsentIdentityFederationDenied("identity verification failed")
            key = self._signing_key_for(expectation.jwks_origin, kid)
            principal = verify_oidc_token(
                token,
                config=OIDCConfig(
                    enabled=True,
                    issuer=expectation.issuer,
                    audience=expectation.audience,
                    jwks_uri=expectation.jwks_origin,
                ),
                signing_key=key,
            )
            claims = principal.claims
            aud = claims.get("aud")
            audiences = (aud,) if isinstance(aud, str) else tuple(aud or ())
            return VerifiedConsentOIDCClaims(
                subject=principal.sub,
                issuer=principal.issuer,
                audiences=audiences,
                nonce=claims.get("nonce"),
                issued_at=float(claims.get("iat")),
                expires_at=float(claims.get("exp")),
                not_before=(float(claims["nbf"]) if claims.get("nbf") is not None else None),
                key_id=kid,
                token_sha256=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            )
        except ConsentIdentityFederationDenied:
            raise
        except Exception as exc:
            raise ConsentIdentityFederationDenied("identity verification failed") from exc


def _validate_verified_claims(
    token: str,
    claims: VerifiedConsentOIDCClaims,
    expectation: ConsentOIDCExpectation,
) -> None:
    if not isinstance(claims, VerifiedConsentOIDCClaims):
        raise ConsentIdentityFederationDenied("identity verification failed")
    if claims.issuer != expectation.issuer or claims.audiences != (expectation.audience,):
        raise ConsentIdentityFederationDenied("identity verification failed")
    if (
        not isinstance(claims.subject, str)
        or not 1 <= len(claims.subject) <= 512
        or claims.subject != claims.subject.strip()
        or not claims.subject.isprintable()
        or not isinstance(claims.nonce, str)
        or not text_equals(claims.nonce, expectation.nonce)
        or not isinstance(claims.key_id, str)
        or not _KID_RE.fullmatch(claims.key_id)
    ):
        raise ConsentIdentityFederationDenied("identity verification failed")
    issued = _timestamp(claims.issued_at, "issued_at")
    expires = _timestamp(claims.expires_at, "expires_at")
    now = _timestamp(expectation.now, "now")
    if (
        issued > now + OIDC_CLOCK_SKEW_SECONDS
        or expires <= now
        or expires <= issued
        or expires - issued > expectation.max_token_ttl_seconds
        or now - issued > expectation.max_token_ttl_seconds
    ):
        raise ConsentIdentityFederationDenied("identity verification failed")
    if claims.not_before is not None:
        not_before = _timestamp(claims.not_before, "not_before")
        if not_before > now + OIDC_CLOCK_SKEW_SECONDS or not_before > expires:
            raise ConsentIdentityFederationDenied("identity verification failed")
    expected_token = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(expected_token, claims.token_sha256):
        raise ConsentIdentityFederationDenied("identity verification failed")


def _pkce_challenge(verifier: str) -> str:
    if (
        not isinstance(verifier, str)
        or not 43 <= len(verifier) <= 128
        or not re.fullmatch(r"[A-Za-z0-9._~-]+", verifier)
    ):
        raise ConsentIdentityFederationDenied("pairing verification failed")
    raw = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class ConsentIdentityFederationStore:
    """Digest-only pairing workflow joined to the existing consent store."""

    def __init__(
        self,
        path: Path,
        *,
        preference_store_for: Callable[[str], ConsentPreferenceStore],
        context_resolver: Callable[[ConsentPairingContext], ConsentPairingContext],
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        secret_factory: Callable[[int], str] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self._preference_store_for = preference_store_for
        self._context_resolver = context_resolver
        self._clock = clock
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{secrets.token_urlsafe(18)}")
        self._secret_factory = secret_factory or secrets.token_urlsafe
        ensure_private_directory(self.path.parent)
        self._initialize()

    @contextlib.contextmanager
    def _connect(self):
        with consent_storage.authority_connection(
            self.path, ensure_directory=ensure_private_directory,
            ensure_file=ensure_private_file, foreign_keys=False,
        ) as connection:
            yield connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS consent_identity_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consent_identity_pairings(
                    pairing_id TEXT PRIMARY KEY,
                    code_sha256 TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    retention_until REAL NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS consent_identity_pairing_tenant
                    ON consent_identity_pairings(tenant_id, updated_at);
                CREATE TABLE IF NOT EXISTS consent_identity_evidence_current(
                    tenant_id TEXT NOT NULL,
                    target_fingerprint TEXT NOT NULL,
                    pairing_id TEXT NOT NULL UNIQUE,
                    revision INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    binding_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,target_fingerprint)
                );
                CREATE TABLE IF NOT EXISTS consent_identity_unlink_operations(
                    tenant_id TEXT NOT NULL,
                    operation_key_sha256 TEXT NOT NULL,
                    target_fingerprint TEXT NOT NULL,
                    pairing_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('prepared','completed')),
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    retention_until REAL NOT NULL,
                    PRIMARY KEY(tenant_id,operation_key_sha256)
                );
                CREATE INDEX IF NOT EXISTS consent_identity_unlink_retention
                    ON consent_identity_unlink_operations(status,retention_until);
                CREATE TABLE IF NOT EXISTS consent_identity_pairing_events(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    pairing_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS consent_identity_events_no_update
                    BEFORE UPDATE ON consent_identity_pairing_events
                    BEGIN SELECT RAISE(ABORT, 'pairing audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_identity_events_no_delete
                    BEFORE DELETE ON consent_identity_pairing_events
                    BEGIN SELECT RAISE(ABORT, 'pairing audit is immutable'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO consent_identity_meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM consent_identity_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise ConsentIdentityFederationIntegrityError(
                    "unsupported consent identity store schema"
                )

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        try:
            record = json.loads(str(row["record_json"]))
        except (TypeError, ValueError) as exc:
            raise ConsentIdentityFederationIntegrityError(
                "stored pairing material is invalid"
            ) from exc
        if not isinstance(record, dict):
            raise ConsentIdentityFederationIntegrityError("stored pairing material is invalid")
        digest = _sha256(record)
        if (
            not text_equals(digest, str(row["record_sha256"]))
            or record.get("pairing_id") != row["pairing_id"]
            or record.get("code_sha256") != row["code_sha256"]
            or record.get("tenant_id") != row["tenant_id"]
            or record.get("status") != row["status"]
            or record.get("revision") != row["revision"]
        ):
            raise ConsentIdentityFederationIntegrityError("stored pairing material changed")
        return record

    @staticmethod
    def _unlink_operation(row: sqlite3.Row) -> dict[str, Any]:
        try:
            record = json.loads(str(row["record_json"]))
        except (TypeError, ValueError) as exc:
            raise ConsentIdentityFederationIntegrityError(
                "stored identity unlink operation is invalid"
            ) from exc
        if not isinstance(record, dict):
            raise ConsentIdentityFederationIntegrityError(
                "stored identity unlink operation is invalid"
            )
        if (
            record.get("schema") != "lightwork.consent.identity-unlink-operation.v1"
            or record.get("tenant_id") != row["tenant_id"]
            or record.get("operation_key_sha256") != row["operation_key_sha256"]
            or record.get("target_fingerprint") != row["target_fingerprint"]
            or record.get("pairing_id") != row["pairing_id"]
            or record.get("request_sha256") != row["request_sha256"]
            or record.get("status") != row["status"]
            or record.get("revision") != row["revision"]
            or record.get("updated_at") != row["updated_at"]
            or record.get("retention_until") != row["retention_until"]
            or not text_equals(_sha256(record), str(row["record_sha256"]))
        ):
            raise ConsentIdentityFederationIntegrityError(
                "stored identity unlink operation changed"
            )
        return record

    @staticmethod
    def _current_evidence_pointer(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "tenant_id": str(row["tenant_id"]),
            "target_fingerprint": str(row["target_fingerprint"]),
            "pairing_id": str(row["pairing_id"]),
            "revision": int(row["revision"]),
            "updated_at": float(row["updated_at"]),
        }
        if (
            not _DIGEST_RE.fullmatch(body["target_fingerprint"])
            or body["revision"] < 1
            or not text_equals(
                _sha256(body),
                str(row["binding_sha256"]),
            )
        ):
            raise ConsentIdentityFederationIntegrityError(
                "current identity evidence pointer changed"
            )
        return body

    def _set_current_evidence(
        self,
        connection: sqlite3.Connection,
        record: Mapping[str, Any],
        *,
        now: float,
    ) -> None:
        tenant = _ref(record.get("tenant_id"), "tenant_id")
        fingerprint = _digest(record.get("target_fingerprint"), "target_fingerprint")
        pairing_id = _ref(record.get("pairing_id"), "pairing_id")
        current = connection.execute(
            "SELECT * FROM consent_identity_evidence_current "
            "WHERE tenant_id=? AND target_fingerprint=?",
            (tenant, fingerprint),
        ).fetchone()
        revision = (
            1
            if current is None
            else int(self._current_evidence_pointer(current)["revision"]) + 1
        )
        body = {
            "tenant_id": tenant,
            "target_fingerprint": fingerprint,
            "pairing_id": pairing_id,
            "revision": revision,
            "updated_at": now,
        }
        connection.execute(
            "INSERT INTO consent_identity_evidence_current "
            "(tenant_id,target_fingerprint,pairing_id,revision,updated_at,binding_sha256) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,target_fingerprint) DO UPDATE SET "
            "pairing_id=excluded.pairing_id,revision=excluded.revision,"
            "updated_at=excluded.updated_at,binding_sha256=excluded.binding_sha256",
            (
                body["tenant_id"],
                body["target_fingerprint"],
                body["pairing_id"],
                body["revision"],
                body["updated_at"],
                _sha256(body),
            ),
        )

    def _delete_current_evidence(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        target_fingerprint: str,
        pairing_id: str,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM consent_identity_evidence_current "
            "WHERE tenant_id=? AND target_fingerprint=?",
            (tenant_id, target_fingerprint),
        ).fetchone()
        if row is None:
            return
        pointer = self._current_evidence_pointer(row)
        if pointer["pairing_id"] != pairing_id:
            return
        deleted = connection.execute(
            "DELETE FROM consent_identity_evidence_current WHERE tenant_id=? "
            "AND target_fingerprint=? AND pairing_id=? AND binding_sha256=?",
            (
                tenant_id,
                target_fingerprint,
                pairing_id,
                str(row["binding_sha256"]),
            ),
        )
        if deleted.rowcount != 1:
            raise ConsentIdentityFederationConflict(
                "current identity evidence changed concurrently"
            )

    def _write_event(
        self,
        connection: sqlite3.Connection,
        *,
        pairing_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT event_sha256 FROM consent_identity_pairing_events "
            "WHERE pairing_id=? ORDER BY sequence DESC LIMIT 1",
            (pairing_id,),
        ).fetchone()
        previous_sha = str(previous["event_sha256"]) if previous is not None else None
        payload_sha = _sha256(dict(payload))
        body = {
            "schema": PAIRING_AUDIT_SCHEMA,
            "pairing_id": pairing_id,
            "event_type": event_type,
            "payload_sha256": payload_sha,
            "previous_event_sha256": previous_sha,
            "created_at": now,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO consent_identity_pairing_events(pairing_id,event_type,"
            "payload_json,payload_sha256,previous_event_sha256,event_sha256,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                pairing_id,
                event_type,
                _canonical(dict(payload)).decode("ascii"),
                payload_sha,
                previous_sha,
                event_sha,
                now,
            ),
        )

    def _save_record(
        self,
        connection: sqlite3.Connection,
        record: Mapping[str, Any],
        *,
        expected_revision: int,
        now: float,
    ) -> dict[str, Any]:
        updated = dict(record)
        updated["revision"] = expected_revision + 1
        updated["updated_at"] = now
        digest = _sha256(updated)
        cursor = connection.execute(
            "UPDATE consent_identity_pairings SET status=?,expires_at=?,"
            "retention_until=?,record_json=?,record_sha256=?,revision=?,updated_at=? "
            "WHERE pairing_id=? AND revision=?",
            (
                updated["status"],
                updated["expires_at"],
                updated["retention_until"],
                _canonical(updated).decode("ascii"),
                digest,
                updated["revision"],
                now,
                updated["pairing_id"],
                expected_revision,
            ),
        )
        if cursor.rowcount != 1:
            raise ConsentIdentityFederationConflict("pairing changed concurrently")
        return updated

    def _resolve_context(self, expected: ConsentPairingContext) -> ConsentPairingContext:
        expected = expected.normalized()
        try:
            current = self._context_resolver(expected)
        except Exception as exc:
            raise ConsentIdentityFederationConflict("pairing authority changed") from exc
        if not isinstance(current, ConsentPairingContext):
            raise ConsentIdentityFederationConflict("pairing authority changed")
        current = current.normalized()
        if not hmac.compare_digest(current.fingerprint, expected.fingerprint):
            raise ConsentIdentityFederationConflict("pairing authority changed")
        return current

    def _profile(
        self,
        context: ConsentPairingContext,
        *,
        identity_kind: str,
    ) -> tuple[ConsentPreferenceStore, dict[str, Any]]:
        store = self._preference_store_for(context.tenant_id)
        try:
            profile = store.get_profile_authority(context.tenant_id, context.profile_id)
        except (ConsentNotFound, OSError, sqlite3.Error) as exc:
            raise ConsentIdentityFederationConflict("pairing profile authority changed") from exc
        if (
            profile.get("identity_kind") != identity_kind
            or profile.get("revision") != context.profile_revision
        ):
            raise ConsentIdentityFederationConflict("pairing profile authority changed")
        return store, profile

    @staticmethod
    def _decode_context(value: object) -> ConsentPairingContext:
        if not isinstance(value, dict):
            raise ConsentIdentityFederationIntegrityError("stored pairing context is invalid")
        try:
            return ConsentPairingContext(**value).normalized()
        except (TypeError, ConsentIdentityFederationError) as exc:
            raise ConsentIdentityFederationIntegrityError(
                "stored pairing context is invalid"
            ) from exc

    def begin_pairing(
        self,
        target: ConsentPairingContext,
        *,
        code_challenge: str,
        ttl_seconds: int,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
    ) -> PairingChallenge:
        target = self._resolve_context(target)
        self._profile(target, identity_kind="anonymous")
        if not isinstance(code_challenge, str) or not _PKCE_RE.fullmatch(code_challenge):
            raise ConsentIdentityFederationDenied("PKCE challenge is invalid")
        if (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 60 <= ttl_seconds <= MAX_PAIRING_TTL_SECONDS
        ):
            raise ConsentIdentityFederationDenied("pairing TTL is invalid")
        if (
            not isinstance(retention_seconds, int)
            or isinstance(retention_seconds, bool)
            or retention_seconds < ttl_seconds
        ):
            raise ConsentIdentityFederationDenied("pairing retention is invalid")
        now = _timestamp(self._clock(), "clock")
        raw_code = f"lwcp1.{self._secret_factory(32)}"
        if not _CAPABILITY_RE.fullmatch(raw_code):
            raise ConsentIdentityFederationDenied("pairing capability generation failed")
        nonce = self._secret_factory(32)
        if not isinstance(nonce, str) or len(nonce) < 32:
            raise ConsentIdentityFederationDenied("pairing nonce generation failed")
        pairing_id = _ref(self._id_factory("CP-PAIR"), "pairing_id")
        code_sha = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
        record = {
            "schema": PAIRING_SCHEMA,
            "pairing_id": pairing_id,
            "code_sha256": code_sha,
            "tenant_id": target.tenant_id,
            "status": "pending",
            "target": asdict(target),
            "target_fingerprint": target.fingerprint,
            "source": None,
            "source_fingerprint": None,
            "code_challenge": code_challenge,
            "nonce_sha256": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
            "known_profile_id": None,
            "subject_binding_sha256": None,
            "oidc_verification_sha256": None,
            "oidc_expires_at": None,
            "source_link_sha256": None,
            "target_link_sha256": None,
            "expires_at": now + ttl_seconds,
            "retention_until": now + retention_seconds,
            "revision": 0,
            "created_at": now,
            "updated_at": now,
        }
        record_sha = _sha256(record)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO consent_identity_pairings(pairing_id,code_sha256,tenant_id,"
                    "status,expires_at,retention_until,record_json,record_sha256,revision,"
                    "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        pairing_id,
                        code_sha,
                        target.tenant_id,
                        "pending",
                        record["expires_at"],
                        record["retention_until"],
                        _canonical(record).decode("ascii"),
                        record_sha,
                        0,
                        now,
                        now,
                    ),
                )
                self._write_event(
                    connection,
                    pairing_id=pairing_id,
                    event_type="pairing.started",
                    payload={
                        "target_fingerprint": target.fingerprint,
                        "code_sha256": code_sha,
                        "nonce_sha256": record["nonce_sha256"],
                        "expires_at": record["expires_at"],
                    },
                    now=now,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return PairingChallenge(pairing_id, raw_code, nonce, record["expires_at"], 0)

    def _load_capability(
        self,
        connection: sqlite3.Connection,
        raw_code: str,
    ) -> tuple[sqlite3.Row, dict[str, Any]]:
        if not isinstance(raw_code, str) or not _CAPABILITY_RE.fullmatch(raw_code):
            raise ConsentIdentityFederationDenied("pairing capability is invalid")
        code_sha = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
        row = connection.execute(
            "SELECT * FROM consent_identity_pairings WHERE code_sha256=?",
            (code_sha,),
        ).fetchone()
        if row is None:
            raise ConsentIdentityFederationDenied("pairing capability is invalid")
        return row, self._record(row)

    def _expire_if_needed(
        self,
        connection: sqlite3.Connection,
        record: dict[str, Any],
        now: float,
    ) -> dict[str, Any]:
        """Expire an overdue pairing and commit that before the caller denies it.

        Every caller refuses an expired pairing by raising, and its handler
        rolls back whatever is still open. The expiry is therefore committed
        here, so the state change and its audit event outlive the denial.
        """
        if record["status"] not in _TERMINAL and float(record["expires_at"]) <= now:
            expired = {**record, "status": "expired"}
            expired = self._save_record(
                connection,
                expired,
                expected_revision=int(record["revision"]),
                now=now,
            )
            self._write_event(
                connection,
                pairing_id=str(record["pairing_id"]),
                event_type="pairing.expired",
                payload={"prior_status": record["status"]},
                now=now,
            )
            connection.execute("COMMIT")
            return expired
        return record

    def authorize_pairing(  # noqa: C901 - one fail-closed state transition
        self,
        raw_code: str,
        *,
        oidc_nonce: str,
        oidc_token: str,
        source: ConsentPairingContext,
        settings: ConsentIdentitySettings,
        oidc_verifier: ConsentOIDCVerifier,
        subject_digest_key: bytes,
    ) -> PairingAuthorization:
        settings = settings.normalized()
        if not isinstance(subject_digest_key, bytes) or len(subject_digest_key) < 32:
            raise ConsentIdentityFederationConfigError(
                "consent identity subject digest key is unavailable"
            )
        if not isinstance(oidc_nonce, str) or not isinstance(oidc_token, str):
            raise ConsentIdentityFederationDenied("identity verification failed")
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                _row, record = self._load_capability(connection, raw_code)
                record = self._expire_if_needed(connection, record, now)
                if record["status"] not in {"pending", "authorizing"}:
                    raise ConsentIdentityFederationDenied("pairing cannot be authorized")
                recovering = record["status"] == "authorizing"
                if not text_equals(
                    hashlib.sha256(oidc_nonce.encode("utf-8")).hexdigest(),
                    str(record["nonce_sha256"]),
                ):
                    raise ConsentIdentityFederationDenied("identity verification failed")
                target = self._decode_context(record["target"])
                if source.tenant_id != target.tenant_id:
                    raise ConsentIdentityFederationDenied("pairing authority is invalid")
                source = self._resolve_context(source)
                self._resolve_context(target)
                _source_store, source_profile = self._profile(
                    source,
                    identity_kind="anonymous",
                )
                self._profile(target, identity_kind="anonymous")
                if source.fingerprint == target.fingerprint:
                    raise ConsentIdentityFederationDenied("pairing endpoints must differ")
                if recovering:
                    stored_source = self._decode_context(record.get("source"))
                    same_static_authority = hmac.compare_digest(
                        replace(
                            stored_source,
                            profile_revision=source.profile_revision,
                        ).fingerprint,
                        source.fingerprint,
                    )
                    link_recovered = (
                        source.profile_revision == stored_source.profile_revision + 1
                        and source_profile.get("linked_known_profile_id")
                        == record.get("known_profile_id")
                    )
                    link_not_started = (
                        source.profile_revision == stored_source.profile_revision
                        and source_profile.get("linked_known_profile_id") is None
                    )
                    if not same_static_authority or not (link_recovered or link_not_started):
                        raise ConsentIdentityFederationConflict("source recovery authority changed")
                expectation = ConsentOIDCExpectation(
                    issuer=settings.issuer,
                    audience=settings.audience,
                    jwks_origin=settings.jwks_origin,
                    nonce=oidc_nonce,
                    now=now,
                    max_token_ttl_seconds=settings.token_ttl_seconds,
                )
                try:
                    claims = oidc_verifier(oidc_token, expectation)
                except ConsentIdentityFederationError:
                    raise
                except Exception as exc:
                    raise ConsentIdentityFederationDenied("identity verification failed") from exc
                _validate_verified_claims(oidc_token, claims, expectation)
                subject_binding = hmac.new(
                    subject_digest_key,
                    (
                        f"consent-identity\0{source.tenant_id}\0{settings.issuer}\0"
                        f"{settings.audience}\0{claims.subject}"
                    ).encode(),
                    hashlib.sha256,
                ).hexdigest()
                known_profile_id = f"CP-KNOWN-{subject_binding[:32]}"
                verification_sha = _sha256(
                    {
                        "issuer": claims.issuer,
                        "audiences": list(claims.audiences),
                        "issued_at": claims.issued_at,
                        "expires_at": claims.expires_at,
                        "not_before": claims.not_before,
                        "key_id_sha256": hashlib.sha256(claims.key_id.encode("utf-8")).hexdigest(),
                        "token_sha256": claims.token_sha256,
                        "nonce_sha256": record["nonce_sha256"],
                    }
                )
                if recovering:
                    if (
                        record.get("known_profile_id") != known_profile_id
                        or not text_equals(
                            str(record.get("subject_binding_sha256", "")),
                            subject_binding,
                        )
                        or not text_equals(
                            str(record.get("oidc_verification_sha256", "")),
                            verification_sha,
                        )
                    ):
                        raise ConsentIdentityFederationDenied(
                            "identity recovery verification failed"
                        )
                else:
                    authorizing = {
                        **record,
                        "status": "authorizing",
                        "source": asdict(source),
                        "source_fingerprint": source.fingerprint,
                        "known_profile_id": known_profile_id,
                        "subject_binding_sha256": subject_binding,
                        "oidc_verification_sha256": verification_sha,
                        "oidc_expires_at": claims.expires_at,
                    }
                    self._save_record(
                        connection,
                        authorizing,
                        expected_revision=int(record["revision"]),
                        now=now,
                    )
                    self._write_event(
                        connection,
                        pairing_id=str(record["pairing_id"]),
                        event_type="identity.verified",
                        payload={
                            "source_fingerprint": source.fingerprint,
                            "subject_binding_sha256": subject_binding,
                            "oidc_verification_sha256": verification_sha,
                        },
                        now=now,
                    )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

        preference_store = self._preference_store_for(source.tenant_id)
        try:
            known = preference_store.get_profile_authority(
                source.tenant_id,
                known_profile_id,
            )
            if known.get("identity_kind") != "known" or not text_equals(
                str(known.get("subject_sha256", "")), subject_binding
            ):
                raise ConsentIdentityFederationConflict(
                    "known identity authority changed"
                ) from None
        except ConsentNotFound:
            try:
                preference_store.create_profile(
                    source.tenant_id,
                    known_profile_id,
                    "known",
                    subject_binding,
                    f"identity-known-{record['pairing_id']}",
                )
            except ConsentConflict:
                pass
            known = preference_store.get_profile_authority(
                source.tenant_id,
                known_profile_id,
            )
            if known.get("identity_kind") != "known" or not text_equals(
                str(known.get("subject_sha256", "")), subject_binding
            ):
                raise ConsentIdentityFederationConflict(
                    "known identity authority changed"
                ) from None

        current_source = preference_store.get_profile_authority(
            source.tenant_id,
            source.profile_id,
        )
        linked_known = current_source.get("linked_known_profile_id")
        if linked_known is None:
            source_audit_sha = _sha256(
                {
                    "schema": "lightwork.consent.identity-link-audit.v1",
                    "pairing_id": record["pairing_id"],
                    "code_sha256": record["code_sha256"],
                    "role": "source",
                    "context_fingerprint": source.fingerprint,
                }
            )
            try:
                link = preference_store.link_profiles(
                    source.tenant_id,
                    known_profile_id,
                    source.profile_id,
                    expected_known_revision=int(known["revision"]),
                    expected_anonymous_revision=source.profile_revision,
                    idempotency_key=f"identity-source-{record['pairing_id']}",
                    expected_link_revision=int(current_source.get("link_revision", 0)),
                    identity_evidence_sha256=verification_sha,
                    audit_evidence_sha256=source_audit_sha,
                    actor_sha256=source.fingerprint,
                    retention_until=float(record["retention_until"]),
                )
            except (ConsentConflict, ConsentNotFound) as exc:
                raise ConsentIdentityFederationConflict(
                    "source profile link changed concurrently"
                ) from exc
            source_link_sha = str(link["link_sha256"])
        elif linked_known == known_profile_id:
            source_link_sha = _digest(current_source.get("link_sha256"), "link_sha256")
        else:
            raise ConsentIdentityFederationConflict("source profile is already linked")

        current_source = preference_store.get_profile_authority(
            source.tenant_id,
            source.profile_id,
        )
        source_after = replace(source, profile_revision=int(current_source["revision"]))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                _row, current = self._load_capability(connection, raw_code)
                if (
                    current["status"] != "authorizing"
                    or current.get("known_profile_id") != known_profile_id
                    or not text_equals(
                        str(current.get("subject_binding_sha256", "")), subject_binding
                    )
                ):
                    raise ConsentIdentityFederationConflict("pairing changed concurrently")
                authorized = {
                    **current,
                    "status": "authorized",
                    "source": asdict(source_after),
                    "source_fingerprint": source_after.fingerprint,
                    "source_link_sha256": source_link_sha,
                }
                authorized = self._save_record(
                    connection,
                    authorized,
                    expected_revision=int(current["revision"]),
                    now=now,
                )
                self._write_event(
                    connection,
                    pairing_id=str(current["pairing_id"]),
                    event_type="source.linked",
                    payload={
                        "known_profile_id_sha256": hashlib.sha256(
                            known_profile_id.encode("utf-8")
                        ).hexdigest(),
                        "source_fingerprint": source_after.fingerprint,
                        "source_link_sha256": source_link_sha,
                    },
                    now=now,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return PairingAuthorization(
            pairing_id=str(authorized["pairing_id"]),
            status="authorized",
            expires_at=float(authorized["expires_at"]),
            revision=int(authorized["revision"]),
            source_link_sha256=source_link_sha,
        )

    def redeem_pairing(
        self,
        raw_code: str,
        *,
        code_verifier: str,
        target: ConsentPairingContext,
    ) -> PairingRedemption:
        challenge = _pkce_challenge(code_verifier)
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                _row, record = self._load_capability(connection, raw_code)
                record = self._expire_if_needed(connection, record, now)
                if record["status"] != "authorized" or not text_equals(
                    challenge, str(record["code_challenge"])
                ):
                    raise ConsentIdentityFederationDenied("pairing cannot be redeemed")
                stored_target = self._decode_context(record["target"])
                same_static_authority = hmac.compare_digest(
                    replace(
                        stored_target,
                        profile_revision=target.profile_revision,
                    ).fingerprint,
                    target.fingerprint,
                )
                if not same_static_authority:
                    raise ConsentIdentityFederationDenied("pairing target is invalid")
                target = self._resolve_context(target)
                source = self._decode_context(record["source"])
                self._resolve_context(source)
                preference_store, target_profile = self._profile(
                    target,
                    identity_kind="anonymous",
                )
                target_link_recovered = (
                    target.profile_revision == stored_target.profile_revision + 1
                    and target_profile.get("linked_known_profile_id") == record["known_profile_id"]
                )
                target_link_not_started = (
                    target.profile_revision == stored_target.profile_revision
                    and target_profile.get("linked_known_profile_id") is None
                )
                if not (target_link_recovered or target_link_not_started):
                    raise ConsentIdentityFederationConflict("target recovery authority changed")
                source_profile = preference_store.get_profile_authority(
                    source.tenant_id,
                    source.profile_id,
                )
                if (
                    source_profile.get("revision") != source.profile_revision
                    or source_profile.get("linked_known_profile_id") != record["known_profile_id"]
                ):
                    raise ConsentIdentityFederationConflict("source link authority changed")
                known = (
                    preference_store.get_profile_authority(
                        target.tenant_id,
                        str(record["known_profile_id"]),
                    )
                    if target_link_not_started
                    else None
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

        if target_link_not_started:
            assert known is not None
            target_audit_sha = _sha256(
                {
                    "schema": "lightwork.consent.identity-link-audit.v1",
                    "pairing_id": record["pairing_id"],
                    "code_sha256": record["code_sha256"],
                    "role": "target",
                    "context_fingerprint": target.fingerprint,
                }
            )
            try:
                link = preference_store.link_profiles(
                    target.tenant_id,
                    str(record["known_profile_id"]),
                    target.profile_id,
                    expected_known_revision=int(known["revision"]),
                    expected_anonymous_revision=int(target_profile["revision"]),
                    idempotency_key=f"identity-target-{record['pairing_id']}",
                    expected_link_revision=int(target_profile.get("link_revision", 0)),
                    identity_evidence_sha256=_digest(
                        record.get("oidc_verification_sha256"),
                        "oidc_verification_sha256",
                    ),
                    audit_evidence_sha256=target_audit_sha,
                    actor_sha256=target.fingerprint,
                    retention_until=float(record["retention_until"]),
                )
            except (ConsentConflict, ConsentNotFound) as exc:
                raise ConsentIdentityFederationConflict(
                    "target profile link changed concurrently"
                ) from exc
            target_link_sha = str(link["link_sha256"])
        else:
            target_link_sha = _digest(
                target_profile.get("link_sha256"),
                "link_sha256",
            )
        current_target = preference_store.get_profile_authority(
            target.tenant_id,
            target.profile_id,
        )
        if (
            current_target.get("linked_known_profile_id") != record["known_profile_id"]
            or not hmac.compare_digest(
                str(current_target.get("link_sha256", "")),
                target_link_sha,
            )
        ):
            raise ConsentIdentityFederationConflict("target link authority changed")
        target_after = replace(target, profile_revision=int(current_target["revision"]))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                _row, current = self._load_capability(connection, raw_code)
                if current["status"] != "authorized":
                    raise ConsentIdentityFederationDenied("pairing cannot be redeemed")
                redeemed = {
                    **current,
                    "status": "redeemed",
                    "target": asdict(target_after),
                    "target_fingerprint": target_after.fingerprint,
                    "target_link_sha256": target_link_sha,
                }
                redeemed = self._save_record(
                    connection,
                    redeemed,
                    expected_revision=int(current["revision"]),
                    now=now,
                )
                self._set_current_evidence(connection, redeemed, now=now)
                self._write_event(
                    connection,
                    pairing_id=str(current["pairing_id"]),
                    event_type="target.linked",
                    payload={
                        "target_link_sha256": target_link_sha,
                        "target_fingerprint": target_after.fingerprint,
                    },
                    now=now,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return PairingRedemption(
            pairing_id=str(redeemed["pairing_id"]),
            status="redeemed",
            revision=int(redeemed["revision"]),
            target_link_sha256=target_link_sha,
            linked_profile_id=str(record["known_profile_id"]),
        )

    def resolve_redeemed_identity_evidence(
        self,
        target: ConsentPairingContext,
    ) -> ConsentIdentityEvidence:
        """Resolve a current, unexpired OIDC proof without a consumer selector.

        The exact re-resolved target fingerprint is used internally. Raw pairing
        codes, OIDC subjects, tokens, and device identifiers are neither accepted
        nor returned.
        """

        target = self._resolve_context(target)
        preference_store, target_profile = self._profile(target, identity_kind="anonymous")
        known_profile_id = target_profile.get("linked_known_profile_id")
        if not isinstance(known_profile_id, str):
            raise ConsentIdentityFederationDenied("fresh identity evidence is unavailable")
        target_link = _digest(target_profile.get("link_sha256"), "link_sha256")
        with self._connect() as connection:
            pointer_row = connection.execute(
                "SELECT * FROM consent_identity_evidence_current "
                "WHERE tenant_id=? AND target_fingerprint=?",
                (target.tenant_id, target.fingerprint),
            ).fetchone()
            if pointer_row is None:
                raise ConsentIdentityFederationDenied(
                    "fresh identity evidence is unavailable"
                )
            pointer = self._current_evidence_pointer(pointer_row)
            row = connection.execute(
                "SELECT * FROM consent_identity_pairings WHERE pairing_id=?",
                (pointer["pairing_id"],),
            ).fetchone()
            if row is None:
                raise ConsentIdentityFederationIntegrityError(
                    "current identity evidence record is missing"
                )
            record = self._record(row)
        now = _timestamp(self._clock(), "clock")
        try:
            stored_target = self._decode_context(record.get("target"))
            source = self._decode_context(record.get("source"))
            subject_binding = _digest(
                record.get("subject_binding_sha256"),
                "subject_binding_sha256",
            )
            verification = _digest(
                record.get("oidc_verification_sha256"),
                "oidc_verification_sha256",
            )
            source_link = _digest(
                record.get("source_link_sha256"),
                "source_link_sha256",
            )
            stored_target_link = _digest(
                record.get("target_link_sha256"),
                "target_link_sha256",
            )
            oidc_expires = _timestamp(record.get("oidc_expires_at"), "oidc_expires_at")
            pairing_expires = _timestamp(record.get("expires_at"), "expires_at")
        except ConsentIdentityFederationError as exc:
            raise ConsentIdentityFederationDenied(
                "fresh identity evidence is unavailable"
            ) from exc
        if (
            record.get("status") != "redeemed"
            or record.get("known_profile_id") != known_profile_id
            or not hmac.compare_digest(stored_target.fingerprint, target.fingerprint)
            or not hmac.compare_digest(stored_target_link, target_link)
        ):
            raise ConsentIdentityFederationDenied("fresh identity evidence is unavailable")
        valid_until = min(oidc_expires, pairing_expires)
        if valid_until <= now:
            raise ConsentIdentityFederationDenied("fresh identity evidence is unavailable")
        try:
            source = self._resolve_context(source)
            _source_store, source_profile = self._profile(
                source,
                identity_kind="anonymous",
            )
            known_profile = preference_store.get_profile_authority(
                target.tenant_id,
                known_profile_id,
            )
        except (ConsentIdentityFederationError, ConsentNotFound) as exc:
            raise ConsentIdentityFederationDenied(
                "fresh identity evidence is unavailable"
            ) from exc
        if (
            source_profile.get("linked_known_profile_id") != known_profile_id
            or not hmac.compare_digest(
                str(source_profile.get("link_sha256", "")), source_link
            )
            or known_profile.get("identity_kind") != "known"
            or not text_equals(
                str(known_profile.get("subject_sha256", "")), subject_binding
            )
        ):
            raise ConsentIdentityFederationDenied("fresh identity evidence is unavailable")
        body = {
            "schema": "lightwork.consent.identity-evidence.v1",
            "tenant_id": target.tenant_id,
            "target_fingerprint": target.fingerprint,
            "source_fingerprint": source.fingerprint,
            "subject_binding_sha256": subject_binding,
            "oidc_verification_sha256": verification,
            "source_link_sha256": source_link,
            "target_link_sha256": target_link,
            "pairing_revision": int(record["revision"]),
            "valid_until": valid_until,
        }
        return ConsentIdentityEvidence(**body | {"evidence_sha256": _sha256(body)})

    def unlink_current_identity(  # noqa: C901, PLR0912, PLR0913
        self,
        target: ConsentPairingContext,
        *,
        expected_profile_revision: int,
        expected_link_revision: int,
        idempotency_key: str,
        reason_sha256: str,
        settings: ConsentIdentitySettings,
    ) -> dict[str, Any]:
        """Unlink the current device profile using fresh redeemed identity proof.

        A digest-only preparation record bridges the pairing and preference
        stores.  If the process stops after the core CAS but before pairing
        revocation, the same exact operation resumes; rebinding the key fails.
        """

        settings = settings.normalized()
        target = self._resolve_context(target)
        if (
            not isinstance(expected_profile_revision, int)
            or isinstance(expected_profile_revision, bool)
            or expected_profile_revision < 0
            or not isinstance(expected_link_revision, int)
            or isinstance(expected_link_revision, bool)
            or expected_link_revision < 1
        ):
            raise ConsentIdentityFederationDenied("identity unlink revision is invalid")
        operation_key = _ref(idempotency_key, "idempotency_key")
        operation_sha = hashlib.sha256(operation_key.encode("utf-8")).hexdigest()
        reason = _digest(reason_sha256, "reason_sha256")
        expected_target = replace(
            target,
            profile_revision=expected_profile_revision,
        ).normalized()
        request = {
            "schema": "lightwork.consent.identity-unlink-request.v1",
            "tenant_id": target.tenant_id,
            "target_fingerprint": expected_target.fingerprint,
            "expected_profile_revision": expected_profile_revision,
            "expected_link_revision": expected_link_revision,
            "operation_key_sha256": operation_sha,
            "reason_sha256": reason,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        prepared: dict[str, Any] | None = None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM consent_identity_unlink_operations WHERE tenant_id=? "
                "AND operation_key_sha256=?",
                (target.tenant_id, operation_sha),
            ).fetchone()
            if row is not None:
                prepared = self._unlink_operation(row)
                if not text_equals(
                    str(prepared.get("request_sha256", "")),
                    request_sha,
                ):
                    raise ConsentIdentityFederationConflict(
                        "identity unlink idempotency key was rebound"
                    )
                if prepared["status"] == "completed":
                    result = prepared.get("core_result")
                    if not isinstance(result, dict) or not text_equals(
                        _sha256(result),
                        str(prepared.get("core_result_sha256", "")),
                    ):
                        raise ConsentIdentityFederationIntegrityError(
                            "stored identity unlink result changed"
                        )
                    return result
        if target.profile_revision not in {
            expected_profile_revision,
            expected_profile_revision + 1,
        }:
            raise ConsentIdentityFederationConflict("identity unlink recovery authority changed")

        preference_store = self._preference_store_for(target.tenant_id)
        if prepared is None:
            if target.profile_revision != expected_profile_revision:
                raise ConsentIdentityFederationConflict(
                    "identity unlink preparation is missing"
                )
            _store, profile = self._profile(target, identity_kind="anonymous")
            if (
                profile.get("link_status") != "linked"
                or profile.get("link_revision") != expected_link_revision
                or not isinstance(profile.get("linked_known_profile_id"), str)
            ):
                raise ConsentIdentityFederationConflict("identity link authority changed")
            evidence = self.resolve_redeemed_identity_evidence(target)
            known_profile_id = str(profile["linked_known_profile_id"])
            known = preference_store.get_profile_authority(
                target.tenant_id,
                known_profile_id,
            )
            if known.get("identity_kind") != "known":
                raise ConsentIdentityFederationConflict("known identity authority changed")
            with self._connect() as connection:
                pointer_row = connection.execute(
                    "SELECT * FROM consent_identity_evidence_current WHERE tenant_id=? "
                    "AND target_fingerprint=?",
                    (target.tenant_id, target.fingerprint),
                ).fetchone()
                if pointer_row is None:
                    raise ConsentIdentityFederationDenied(
                        "fresh identity evidence is unavailable"
                    )
                pointer = self._current_evidence_pointer(pointer_row)
                pairing_row = connection.execute(
                    "SELECT * FROM consent_identity_pairings WHERE pairing_id=?",
                    (pointer["pairing_id"],),
                ).fetchone()
                if pairing_row is None:
                    raise ConsentIdentityFederationIntegrityError(
                        "current identity evidence record is missing"
                    )
                pairing = self._record(pairing_row)
            audit_evidence = _sha256(
                {
                    "schema": "lightwork.consent.identity-unlink-audit.v1",
                    "pairing_id": pairing["pairing_id"],
                    "pairing_revision": pairing["revision"],
                    "target_fingerprint": target.fingerprint,
                    "identity_evidence_sha256": evidence.evidence_sha256,
                    "operation_key_sha256": operation_sha,
                    "reason_sha256": reason,
                }
            )
            retention_until = now + settings.link_lifecycle_retention_seconds
            prepared = {
                "schema": "lightwork.consent.identity-unlink-operation.v1",
                "tenant_id": target.tenant_id,
                "operation_key_sha256": operation_sha,
                "target_fingerprint": target.fingerprint,
                "pairing_id": pairing["pairing_id"],
                "request_sha256": request_sha,
                "status": "prepared",
                "expected_profile_revision": expected_profile_revision,
                "expected_link_revision": expected_link_revision,
                "known_profile_id": known_profile_id,
                "known_profile_revision": int(known["revision"]),
                "identity_evidence_sha256": evidence.evidence_sha256,
                "audit_evidence_sha256": audit_evidence,
                "actor_sha256": target.fingerprint,
                "reason_sha256": reason,
                "core_result": None,
                "core_result_sha256": None,
                "revision": 0,
                "created_at": now,
                "updated_at": now,
                "retention_until": retention_until,
            }
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    pairing_row = connection.execute(
                        "SELECT * FROM consent_identity_pairings WHERE pairing_id=?",
                        (prepared["pairing_id"],),
                    ).fetchone()
                    if pairing_row is None or self._record(pairing_row)["status"] != "redeemed":
                        raise ConsentIdentityFederationConflict(
                            "fresh identity evidence changed"
                        )
                    connection.execute(
                        "INSERT INTO consent_identity_unlink_operations(tenant_id,"
                        "operation_key_sha256,target_fingerprint,pairing_id,request_sha256,"
                        "status,record_json,record_sha256,revision,updated_at,"
                        "retention_until) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            prepared["tenant_id"],
                            prepared["operation_key_sha256"],
                            prepared["target_fingerprint"],
                            prepared["pairing_id"],
                            prepared["request_sha256"],
                            prepared["status"],
                            _canonical(prepared).decode("ascii"),
                            _sha256(prepared),
                            prepared["revision"],
                            prepared["updated_at"],
                            prepared["retention_until"],
                        ),
                    )
                    self._write_event(
                        connection,
                        pairing_id=str(prepared["pairing_id"]),
                        event_type="identity.unlink_prepared",
                        payload={
                            "operation_key_sha256": operation_sha,
                            "target_fingerprint": target.fingerprint,
                            "identity_evidence_sha256": evidence.evidence_sha256,
                            "audit_evidence_sha256": audit_evidence,
                            "reason_sha256": reason,
                        },
                        now=now,
                    )
                    connection.execute("COMMIT")
                except sqlite3.IntegrityError as exc:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise ConsentIdentityFederationConflict(
                        "identity unlink operation changed concurrently"
                    ) from exc
                except BaseException:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise

        assert prepared is not None
        try:
            result = preference_store.unlink_profile(
                target.tenant_id,
                target.profile_id,
                expected_anonymous_revision=int(prepared["expected_profile_revision"]),
                expected_known_revision=int(prepared["known_profile_revision"]),
                expected_link_revision=int(prepared["expected_link_revision"]),
                idempotency_key=f"identity-unlink-{operation_sha}",
                identity_evidence_sha256=_digest(
                    prepared.get("identity_evidence_sha256"),
                    "identity_evidence_sha256",
                ),
                audit_evidence_sha256=_digest(
                    prepared.get("audit_evidence_sha256"),
                    "audit_evidence_sha256",
                ),
                actor_sha256=_digest(
                    prepared.get("actor_sha256"),
                    "actor_sha256",
                ),
                reason_sha256=reason,
                retention_until=float(prepared["retention_until"]),
            )
        except (ConsentConflict, ConsentNotFound) as exc:
            raise ConsentIdentityFederationConflict(
                "identity unlink authority changed concurrently"
            ) from exc
        result_sha = _sha256(result)
        finished_at = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                operation_row = connection.execute(
                    "SELECT * FROM consent_identity_unlink_operations WHERE tenant_id=? "
                    "AND operation_key_sha256=?",
                    (target.tenant_id, operation_sha),
                ).fetchone()
                if operation_row is None:
                    raise ConsentIdentityFederationIntegrityError(
                        "identity unlink recovery record is missing"
                    )
                current_operation = self._unlink_operation(operation_row)
                if current_operation["status"] == "completed":
                    stored = current_operation.get("core_result")
                    if not isinstance(stored, dict) or not text_equals(
                        _sha256(stored),
                        str(current_operation.get("core_result_sha256", "")),
                    ):
                        raise ConsentIdentityFederationIntegrityError(
                            "stored identity unlink result changed"
                        )
                    connection.execute("COMMIT")
                    return stored
                pairing_row = connection.execute(
                    "SELECT * FROM consent_identity_pairings WHERE pairing_id=?",
                    (prepared["pairing_id"],),
                ).fetchone()
                if pairing_row is None:
                    raise ConsentIdentityFederationIntegrityError(
                        "identity unlink pairing is missing"
                    )
                pairing = self._record(pairing_row)
                if pairing["status"] == "redeemed":
                    revoked = {
                        **pairing,
                        "status": "revoked",
                        "unlink_operation_key_sha256": operation_sha,
                        "unlink_result_sha256": result_sha,
                    }
                    self._save_record(
                        connection,
                        revoked,
                        expected_revision=int(pairing["revision"]),
                        now=finished_at,
                    )
                    self._delete_current_evidence(
                        connection,
                        tenant_id=target.tenant_id,
                        target_fingerprint=str(prepared["target_fingerprint"]),
                        pairing_id=str(prepared["pairing_id"]),
                    )
                    self._write_event(
                        connection,
                        pairing_id=str(prepared["pairing_id"]),
                        event_type="identity.unlinked",
                        payload={
                            "operation_key_sha256": operation_sha,
                            "target_fingerprint": prepared["target_fingerprint"],
                            "link_event_sha256": result["link_event_sha256"],
                            "link_revision": result["link_revision"],
                            "reason_sha256": reason,
                        },
                        now=finished_at,
                    )
                elif (
                    pairing["status"] != "revoked"
                    or pairing.get("unlink_operation_key_sha256") != operation_sha
                    or not text_equals(
                        str(pairing.get("unlink_result_sha256", "")),
                        result_sha,
                    )
                ):
                    raise ConsentIdentityFederationConflict(
                        "identity unlink pairing changed concurrently"
                    )
                completed = {
                    **current_operation,
                    "status": "completed",
                    "core_result": result,
                    "core_result_sha256": result_sha,
                    "revision": int(current_operation["revision"]) + 1,
                    "updated_at": finished_at,
                }
                updated = connection.execute(
                    "UPDATE consent_identity_unlink_operations SET status='completed',"
                    "record_json=?,record_sha256=?,revision=?,updated_at=? WHERE "
                    "tenant_id=? AND operation_key_sha256=? AND status='prepared' "
                    "AND revision=? AND record_sha256=?",
                    (
                        _canonical(completed).decode("ascii"),
                        _sha256(completed),
                        completed["revision"],
                        completed["updated_at"],
                        target.tenant_id,
                        operation_sha,
                        current_operation["revision"],
                        str(operation_row["record_sha256"]),
                    ),
                )
                if updated.rowcount != 1:
                    raise ConsentIdentityFederationConflict(
                        "identity unlink operation changed concurrently"
                    )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return result

    def revoke_pairing(
        self,
        raw_code: str,
        *,
        authority: ConsentPairingContext,
        reason_sha256: str,
    ) -> dict[str, Any]:
        reason = _digest(reason_sha256, "reason_sha256")
        now = _timestamp(self._clock(), "clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                _row, record = self._load_capability(connection, raw_code)
                record = self._expire_if_needed(connection, record, now)
                if record["status"] not in {"pending", "authorized", "redeemed"}:
                    raise ConsentIdentityFederationDenied("pairing cannot be revoked")
                allowed = [self._decode_context(record["target"])]
                if record.get("source") is not None:
                    allowed.append(self._decode_context(record["source"]))
                if not any(
                    hmac.compare_digest(authority.fingerprint, item.fingerprint) for item in allowed
                ):
                    raise ConsentIdentityFederationDenied("pairing authority is invalid")
                self._resolve_context(authority)
                revoked = {**record, "status": "revoked"}
                revoked = self._save_record(
                    connection,
                    revoked,
                    expected_revision=int(record["revision"]),
                    now=now,
                )
                if record["status"] == "redeemed":
                    self._delete_current_evidence(
                        connection,
                        tenant_id=str(record["tenant_id"]),
                        target_fingerprint=_digest(
                            record.get("target_fingerprint"),
                            "target_fingerprint",
                        ),
                        pairing_id=str(record["pairing_id"]),
                    )
                self._write_event(
                    connection,
                    pairing_id=str(record["pairing_id"]),
                    event_type="pairing.revoked",
                    payload={
                        "authority_fingerprint": authority.fingerprint,
                        "reason_sha256": reason,
                    },
                    now=now,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {
            "pairing_id": revoked["pairing_id"],
            "status": "revoked",
            "revision": revoked["revision"],
        }

    def verify_integrity(self) -> dict[str, int]:
        """Verify every retained workflow row and the global immutable event chain."""

        pairings = events = 0
        previous_by_pairing: dict[str, str | None] = {}
        with self._connect() as connection:
            for row in connection.execute(
                "SELECT * FROM consent_identity_unlink_operations "
                "ORDER BY tenant_id,operation_key_sha256"
            ):
                operation = self._unlink_operation(row)
                pairing_row = connection.execute(
                    "SELECT * FROM consent_identity_pairings WHERE pairing_id=?",
                    (operation["pairing_id"],),
                ).fetchone()
                if pairing_row is None:
                    raise ConsentIdentityFederationIntegrityError(
                        "identity unlink pairing is missing"
                    )
                pairing = self._record(pairing_row)
                if operation["status"] == "completed":
                    result = operation.get("core_result")
                    if (
                        pairing.get("status") != "revoked"
                        or pairing.get("unlink_operation_key_sha256")
                        != operation["operation_key_sha256"]
                        or not isinstance(result, dict)
                        or not text_equals(
                            _sha256(result),
                            str(operation.get("core_result_sha256", "")),
                        )
                    ):
                        raise ConsentIdentityFederationIntegrityError(
                            "completed identity unlink operation is invalid"
                        )
                elif pairing.get("status") != "redeemed":
                    raise ConsentIdentityFederationIntegrityError(
                        "prepared identity unlink operation is invalid"
                    )
            for row in connection.execute(
                "SELECT * FROM consent_identity_evidence_current "
                "ORDER BY tenant_id,target_fingerprint"
            ):
                pointer = self._current_evidence_pointer(row)
                pairing = connection.execute(
                    "SELECT * FROM consent_identity_pairings WHERE pairing_id=?",
                    (pointer["pairing_id"],),
                ).fetchone()
                if pairing is None:
                    raise ConsentIdentityFederationIntegrityError(
                        "current identity evidence record is missing"
                    )
                record = self._record(pairing)
                if (
                    record.get("status") != "redeemed"
                    or record.get("tenant_id") != pointer["tenant_id"]
                    or record.get("target_fingerprint")
                    != pointer["target_fingerprint"]
                ):
                    raise ConsentIdentityFederationIntegrityError(
                        "current identity evidence pointer is invalid"
                    )
            for row in connection.execute(
                "SELECT * FROM consent_identity_pairings ORDER BY pairing_id"
            ):
                record = self._record(row)
                if record.get("status") not in _STATUSES:
                    raise ConsentIdentityFederationIntegrityError(
                        "stored pairing status is invalid"
                    )
                self._decode_context(record.get("target"))
                if record.get("source") is not None:
                    self._decode_context(record.get("source"))
                pairings += 1
            for row in connection.execute(
                "SELECT * FROM consent_identity_pairing_events ORDER BY sequence"
            ):
                try:
                    payload = json.loads(str(row["payload_json"]))
                except (TypeError, ValueError) as exc:
                    raise ConsentIdentityFederationIntegrityError(
                        "stored pairing audit is invalid"
                    ) from exc
                payload_sha = _sha256(payload)
                pairing_id = str(row["pairing_id"])
                previous = previous_by_pairing.get(pairing_id)
                body = {
                    "schema": PAIRING_AUDIT_SCHEMA,
                    "pairing_id": pairing_id,
                    "event_type": str(row["event_type"]),
                    "payload_sha256": payload_sha,
                    "previous_event_sha256": previous,
                    "created_at": float(row["created_at"]),
                }
                event_sha = _sha256(body)
                if (
                    not text_equals(payload_sha, str(row["payload_sha256"]))
                    or row["previous_event_sha256"] != previous
                    or not text_equals(event_sha, str(row["event_sha256"]))
                ):
                    raise ConsentIdentityFederationIntegrityError("stored pairing audit changed")
                previous_by_pairing[pairing_id] = event_sha
                events += 1
        return {"pairings_verified": pairings, "events_verified": events}

    def purge_terminal(self, *, before: float, limit: int = 100) -> dict[str, int]:
        """Purge bounded terminal workflow state; immutable digest-only audit remains."""

        cutoff = _timestamp(before, "before")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ConsentIdentityFederationDenied("limit is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT pairing_id FROM consent_identity_pairings "
                    "WHERE status IN ('redeemed','revoked','expired') "
                    "AND retention_until<=? ORDER BY retention_until LIMIT ?",
                    (cutoff, limit),
                ).fetchall()
                connection.executemany(
                    "DELETE FROM consent_identity_evidence_current WHERE pairing_id=?",
                    [(str(row["pairing_id"]),) for row in rows],
                )
                connection.executemany(
                    "DELETE FROM consent_identity_pairings WHERE pairing_id=?",
                    [(str(row["pairing_id"]),) for row in rows],
                )
                connection.execute(
                    "DELETE FROM consent_identity_unlink_operations "
                    "WHERE status='completed' AND retention_until<=?",
                    (cutoff,),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {"pairings_deleted": len(rows), "audit_events_deleted": 0}


__all__ = [
    "ConsentIdentityFederationConfigError",
    "ConsentIdentityFederationConflict",
    "ConsentIdentityFederationDenied",
    "ConsentIdentityFederationError",
    "ConsentIdentityFederationIntegrityError",
    "ConsentIdentityEvidence",
    "ConsentIdentityFederationStore",
    "ConsentIdentitySettings",
    "ConsentOIDCExpectation",
    "ConsentOIDCVerifier",
    "ConsentPairingContext",
    "InjectedConsentOIDCVerifier",
    "MAX_PAIRING_TTL_SECONDS",
    "PairingAuthorization",
    "PairingChallenge",
    "PairingRedemption",
    "VerifiedConsentOIDCClaims",
    "consent_identity_enabled",
    "load_consent_identity_settings",
]
