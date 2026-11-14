"""Narrow public API for consumer consent and preference collection.

The public credential is the authority.  It resolves the tenant, property,
published configuration, and consent policy before request data is parsed or
used.  No route accepts a tenant, property, or profile identifier from the
caller.  A separate opaque profile capability selects one anonymous profile;
only capability digests are stored.

This module exposes a router factory so the application can mount it only at
an explicitly selected self-authenticating boundary.  It intentionally has no
enrollment, listing, export, linking, or administration endpoint.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi import Path as ApiPath
from fastapi.responses import FileResponse
from maverick import consent_storage
from maverick.file_lock import (
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

_SCHEMA_VERSION = 3
_AUTH_DETAIL = "invalid public consent credential"
_CONTRACT_DETAIL = "consent contract unavailable"
_PREFERENCE_DETAIL = "preference state changed"
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_RIGHTS_PACKAGE_BYTES = 16 * 1024 * 1024
_MAX_RATE_BUCKETS = 10_000
_RATE_WINDOW_SECONDS = 60.0
# Visitor sessions ([consent_preferences.public_api] token_ttl_seconds).
_SESSION_TTL_BOUNDS = (60, 86_400)
_SESSION_PREFIX = "lwcs_"
_SESSION_HEADER = "x-lightwork-consent-session"
_SESSION_REQUIRED_DETAIL = "consent session required"
_SESSION_INVALID_DETAIL = "consent session expired or invalid"
_SESSION_REPLACED_GRACE_SECONDS = 30.0
_MAX_LIVE_SESSIONS = 200_000
# One site key's share of the live sessions, so a single (public) key cannot
# use up the installation-wide capacity for every other site.
_MAX_LIVE_SESSIONS_PER_CLIENT = 50_000
_MOBILE_PLATFORMS = frozenset({"android", "fireos", "ios", "roku", "tizen", "tvos", "webos"})
_PUBLIC_EXPERIMENT_LAYOUTS = frozenset({"compact", "inline", "stacked"})
_PUBLIC_EXPERIMENT_ACTIONS = frozenset({"accept_all", "reject_all", "save_preferences"})
_PUBLIC_EXPERIMENT_REASONS = frozenset(
    {
        "accessibility_guardrail",
        "assigned",
        "choice_parity_guardrail",
        "ended",
        "experiment_disabled",
        "experiment_integrity_failure",
        "experiment_unavailable",
        "holdout",
        "killed",
        "legal_signal_precedence",
        "max_exposures",
        "not_active",
        "not_started",
        "outside_audience",
        "outside_traffic",
        "paused",
        "required_purpose_precedence",
        "rolled_back",
        "unsafe_variant_definition",
    }
)

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{23,255}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_LOCALE_RE = re.compile(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}\Z")
_COUNTRY_RE = re.compile(r"[A-Z]{2}\Z")
_REGION_RE = re.compile(r"(?:[A-Z0-9][A-Z0-9-]{0,31})?\Z")
_JURISDICTION_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_BUNDLE_RE = re.compile(
    r"(?=.{3,255}\Z)[A-Za-z][A-Za-z0-9_-]*"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+\Z"
)


class PublicConsentError(RuntimeError):
    """Base error for the public consent integration boundary."""


class PublicConsentValidationError(PublicConsentError, ValueError):
    """Enrollment or registry input is invalid."""


class PublicConsentCredentialError(PublicConsentError):
    """A public client or profile capability was not admitted."""


class PublicConsentConflict(PublicConsentError):
    """A registry CAS or exact replay precondition failed."""


class PublicConsentRateLimitExceeded(PublicConsentError):
    """A verified credential exhausted its bounded request window."""


def _canonical(value: object, *, maximum: int = _MAX_RESPONSE_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise PublicConsentValidationError("public consent data must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise PublicConsentValidationError("public consent data exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise PublicConsentValidationError(f"{label} is not an opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PublicConsentValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise PublicConsentValidationError(f"{label} is not a bounded opaque credential")
    return value


def _idempotency(value: object) -> str:
    if not isinstance(value, str) or not _IDEMPOTENCY_RE.fullmatch(value):
        raise PublicConsentValidationError("idempotency_key is invalid")
    return value


def _revision(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise PublicConsentValidationError(f"{label} must be a non-negative integer")
    return value


def _version(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1:
        raise PublicConsentValidationError(f"{label} must be a positive integer")
    return value


def _timestamp(value: object, label: str, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise PublicConsentValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _locale(value: object) -> str:
    if not isinstance(value, str) or not _LOCALE_RE.fullmatch(value):
        raise PublicConsentValidationError("locale is invalid")
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


def _country(value: object) -> str:
    if not isinstance(value, str):
        raise PublicConsentValidationError("country_code is invalid")
    normalized = value.upper()
    if not _COUNTRY_RE.fullmatch(normalized):
        raise PublicConsentValidationError("country_code is invalid")
    return normalized


def _region(value: object) -> str:
    if not isinstance(value, str):
        raise PublicConsentValidationError("region_code is invalid")
    normalized = value.upper()
    if not _REGION_RE.fullmatch(normalized):
        raise PublicConsentValidationError("region_code is invalid")
    return normalized


def _jurisdiction(value: object) -> str:
    if not isinstance(value, str):
        raise PublicConsentValidationError("jurisdiction is invalid")
    normalized = value.lower()
    if not _JURISDICTION_RE.fullmatch(normalized):
        raise PublicConsentValidationError("jurisdiction is invalid")
    return normalized


def _origin(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or "*" in value:
        raise PublicConsentValidationError("origin must be one exact HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PublicConsentValidationError("origin must be one exact HTTPS origin") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise PublicConsentValidationError("origin must be one exact HTTPS origin")
    host = parsed.hostname.lower()
    if not _DOMAIN_RE.fullmatch(host):
        raise PublicConsentValidationError("origin must use an exact DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise PublicConsentValidationError("origin cannot use an IP address")
    if port is not None and not 1 <= port <= 65535:
        raise PublicConsentValidationError("origin port is invalid")
    return f"https://{host}" + (f":{port}" if port is not None else "")


def _bundle_id(value: object) -> str:
    if not isinstance(value, str) or "*" in value or not _BUNDLE_RE.fullmatch(value):
        raise PublicConsentValidationError("bundle id is invalid")
    return value


@dataclass(frozen=True)
class PublicClientBinding:
    credential_id: str
    credential_sha256: str
    tenant_id: str
    property_id: str
    client_kind: str
    browser_origin: str | None
    service_client_id: str | None
    target_origin: str | None
    target_bundle_id: str | None
    target_platform: str | None
    jurisdiction: str
    country_code: str
    region_code: str
    default_locale: str
    property_revision: int
    property_sha256: str
    rule_group_id: str
    rule_group_version: int
    publication_sha256: str
    bundle_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    expires_at: float | None
    revision: int
    record_sha256: str


@dataclass(frozen=True)
class PublicProfileBinding:
    credential_sha256: str
    client_credential_sha256: str
    tenant_id: str
    property_id: str
    profile_id: str
    subject_binding_sha256: str
    binding_sha256: str


@dataclass(frozen=True)
class PublicRightsIntakeContextBinding:
    """Digest-only registry link used by the operator provisioning workflow."""

    context_ref: str
    tenant_id: str
    client_credential_sha256: str
    client_revision: int
    client_record_sha256: str
    profile_credential_sha256: str
    profile_binding_sha256: str
    created_at: float
    binding_sha256: str


@dataclass(frozen=True)
class PublicRequestContext:
    jurisdiction: str
    country_code: str
    region_code: str
    locale: str


class PublicConsentCredentialStore:
    """Private registry containing credential digests, never raw credentials."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self._id_factory = id_factory or (lambda: f"public-client-{secrets.token_urlsafe(12)}")
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    @contextlib.contextmanager
    def _connect(self):
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=10.0)
        else:
            ensure_private_directory(self.path.parent)
            if not self.path.exists():
                try:
                    descriptor = os.open(
                        self.path,
                        os.O_CREAT | os.O_EXCL | os.O_RDWR,
                        0o600,
                    )
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            ensure_private_file(self.path, 0o600)
            connection = sqlite3.connect(
                str(self.path),
                isolation_level=None,
                timeout=10.0,
            )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA secure_delete=ON")
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS public_consent_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """,
            # Short-lived visitor sessions: token digests only, never tokens.
            """
            CREATE TABLE IF NOT EXISTS public_consent_sessions (
                token_sha256 TEXT PRIMARY KEY,
                credential_sha256 TEXT NOT NULL,
                client_record_sha256 TEXT NOT NULL,
                audience TEXT NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                replaced_at REAL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS public_consent_sessions_expiry
            ON public_consent_sessions(expires_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS public_consent_sessions_client
            ON public_consent_sessions(credential_sha256)
            """,
            """
            CREATE TABLE IF NOT EXISTS public_consent_clients (
                credential_sha256 TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                client_kind TEXT NOT NULL CHECK (client_kind IN ('browser', 'service')),
                browser_origin TEXT,
                service_client_id TEXT,
                target_origin TEXT,
                target_bundle_id TEXT,
                target_platform TEXT,
                jurisdiction TEXT NOT NULL,
                country_code TEXT NOT NULL,
                region_code TEXT NOT NULL,
                default_locale TEXT NOT NULL,
                property_revision INTEGER NOT NULL,
                property_sha256 TEXT NOT NULL,
                rule_group_id TEXT NOT NULL,
                rule_group_version INTEGER NOT NULL,
                publication_sha256 TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                policy_sha256 TEXT NOT NULL,
                expires_at REAL,
                status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
                revision INTEGER NOT NULL,
                record_sha256 TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS public_consent_profiles (
                credential_sha256 TEXT PRIMARY KEY,
                client_credential_sha256 TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                subject_binding_sha256 TEXT NOT NULL,
                binding_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE (tenant_id, property_id, profile_id),
                FOREIGN KEY (client_credential_sha256)
                    REFERENCES public_consent_clients(credential_sha256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS public_consent_profile_revocations (
                credential_sha256 TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                actor_sha256 TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                revoked_at REAL NOT NULL,
                revocation_sha256 TEXT NOT NULL,
                UNIQUE (tenant_id, property_id, profile_id),
                FOREIGN KEY (credential_sha256)
                    REFERENCES public_consent_profiles(credential_sha256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS public_consent_idempotency (
                client_credential_sha256 TEXT NOT NULL,
                key_sha256 TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (client_credential_sha256, key_sha256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS public_consent_rights_intake_contexts (
                context_ref TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                client_credential_sha256 TEXT NOT NULL,
                client_revision INTEGER NOT NULL,
                client_record_sha256 TEXT NOT NULL,
                profile_credential_sha256 TEXT NOT NULL,
                profile_binding_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                binding_sha256 TEXT NOT NULL,
                UNIQUE (tenant_id, client_credential_sha256, profile_credential_sha256),
                FOREIGN KEY (client_credential_sha256)
                    REFERENCES public_consent_clients(credential_sha256),
                FOREIGN KEY (profile_credential_sha256)
                    REFERENCES public_consent_profiles(credential_sha256)
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_profiles_no_update
            BEFORE UPDATE ON public_consent_profiles
            BEGIN SELECT RAISE(ABORT, 'profile bindings are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_profiles_no_delete
            BEFORE DELETE ON public_consent_profiles
            BEGIN SELECT RAISE(ABORT, 'profile bindings are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_idempotency_no_update
            BEFORE UPDATE ON public_consent_idempotency
            BEGIN SELECT RAISE(ABORT, 'idempotency claims are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_idempotency_no_delete
            BEFORE DELETE ON public_consent_idempotency
            BEGIN SELECT RAISE(ABORT, 'idempotency claims are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_profile_revocations_no_update
            BEFORE UPDATE ON public_consent_profile_revocations
            BEGIN SELECT RAISE(ABORT, 'profile revocations are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_profile_revocations_no_delete
            BEFORE DELETE ON public_consent_profile_revocations
            BEGIN SELECT RAISE(ABORT, 'profile revocations are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_rights_intake_contexts_no_update
            BEFORE UPDATE ON public_consent_rights_intake_contexts
            BEGIN SELECT RAISE(ABORT, 'rights intake context bindings are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS public_consent_rights_intake_contexts_no_delete
            BEFORE DELETE ON public_consent_rights_intake_contexts
            BEGIN SELECT RAISE(ABORT, 'rights intake context bindings are immutable'); END
            """,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in statements:
                    connection.execute(statement)
                connection.execute(
                    "INSERT OR IGNORE INTO public_consent_meta(key, value) "
                    "VALUES ('schema_version', ?)",
                    (str(_SCHEMA_VERSION),),
                )
                row = connection.execute(
                    "SELECT value FROM public_consent_meta WHERE key = 'schema_version'"
                ).fetchone()
                if row is not None and row["value"] == "2":
                    columns = {
                        str(item["name"])
                        for item in connection.execute(
                            "PRAGMA table_info(public_consent_rights_intake_contexts)"
                        ).fetchall()
                    }
                    required = {
                        "client_revision",
                        "client_record_sha256",
                        "profile_binding_sha256",
                    }
                    if not required.issubset(columns):
                        connection.execute(
                            "DROP TRIGGER IF EXISTS "
                            "public_consent_rights_intake_contexts_no_update"
                        )
                        for name, sql_type in (
                            ("client_revision", "INTEGER"),
                            ("client_record_sha256", "TEXT"),
                            ("profile_binding_sha256", "TEXT"),
                        ):
                            if name not in columns:
                                connection.execute(
                                    "ALTER TABLE public_consent_rights_intake_contexts "
                                    f"ADD COLUMN {name} {sql_type}"
                                )
                        legacy = connection.execute(
                            "SELECT r.*,c.revision AS resolved_client_revision,"
                            "c.record_sha256 AS resolved_client_record_sha256,"
                            "p.binding_sha256 AS resolved_profile_binding_sha256 "
                            "FROM public_consent_rights_intake_contexts r "
                            "JOIN public_consent_clients c ON "
                            "c.credential_sha256=r.client_credential_sha256 "
                            "JOIN public_consent_profiles p ON "
                            "p.credential_sha256=r.profile_credential_sha256"
                        ).fetchall()
                        count = connection.execute(
                            "SELECT COUNT(*) AS count FROM "
                            "public_consent_rights_intake_contexts"
                        ).fetchone()
                        if count is None or int(count["count"]) != len(legacy):
                            raise PublicConsentError(
                                "legacy rights intake context authority is incomplete"
                            )
                        for item in legacy:
                            body = {
                                "context_ref": str(item["context_ref"]),
                                "tenant_id": str(item["tenant_id"]),
                                "client_credential_sha256": str(
                                    item["client_credential_sha256"]
                                ),
                                "client_revision": int(item["resolved_client_revision"]),
                                "client_record_sha256": str(
                                    item["resolved_client_record_sha256"]
                                ),
                                "profile_credential_sha256": str(
                                    item["profile_credential_sha256"]
                                ),
                                "profile_binding_sha256": str(
                                    item["resolved_profile_binding_sha256"]
                                ),
                                "created_at": float(item["created_at"]),
                            }
                            connection.execute(
                                "UPDATE public_consent_rights_intake_contexts SET "
                                "client_revision=?,client_record_sha256=?,"
                                "profile_binding_sha256=?,binding_sha256=? "
                                "WHERE context_ref=?",
                                (
                                    body["client_revision"],
                                    body["client_record_sha256"],
                                    body["profile_binding_sha256"],
                                    _sha256(body),
                                    body["context_ref"],
                                ),
                            )
                        connection.execute(
                            "CREATE TRIGGER "
                            "public_consent_rights_intake_contexts_no_update "
                            "BEFORE UPDATE ON public_consent_rights_intake_contexts "
                            "BEGIN SELECT RAISE(ABORT, "
                            "'rights intake context bindings are immutable'); END"
                        )
                if row is not None and row["value"] in {"1", "2"}:
                    connection.execute(
                        "UPDATE public_consent_meta SET value=? WHERE key='schema_version'",
                        (str(_SCHEMA_VERSION),),
                    )
                    row = connection.execute(
                        "SELECT value FROM public_consent_meta WHERE key = 'schema_version'"
                    ).fetchone()
                if row is None or row["value"] != str(_SCHEMA_VERSION):
                    raise PublicConsentError("unsupported public consent registry schema")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _client_body(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "credential_id": str(row["credential_id"]),
            "credential_sha256": str(row["credential_sha256"]),
            "tenant_id": str(row["tenant_id"]),
            "property_id": str(row["property_id"]),
            "client_kind": str(row["client_kind"]),
            "browser_origin": row["browser_origin"],
            "service_client_id": row["service_client_id"],
            "target_origin": row["target_origin"],
            "target_bundle_id": row["target_bundle_id"],
            "target_platform": row["target_platform"],
            "jurisdiction": str(row["jurisdiction"]),
            "country_code": str(row["country_code"]),
            "region_code": str(row["region_code"]),
            "default_locale": str(row["default_locale"]),
            "property_revision": int(row["property_revision"]),
            "property_sha256": str(row["property_sha256"]),
            "rule_group_id": str(row["rule_group_id"]),
            "rule_group_version": int(row["rule_group_version"]),
            "publication_sha256": str(row["publication_sha256"]),
            "bundle_sha256": str(row["bundle_sha256"]),
            "policy_id": str(row["policy_id"]),
            "policy_version": int(row["policy_version"]),
            "policy_sha256": str(row["policy_sha256"]),
            "expires_at": (float(row["expires_at"]) if row["expires_at"] is not None else None),
            "revision": int(row["revision"]),
        }

    @classmethod
    def _client_binding(cls, row: sqlite3.Row) -> PublicClientBinding:
        body = cls._client_body(row)
        expected = _sha256(body)
        if not hmac.compare_digest(expected, str(row["record_sha256"])):
            raise PublicConsentCredentialError(_AUTH_DETAIL)
        return PublicClientBinding(
            **body,
            record_sha256=expected,
        )

    def enroll_client(
        self,
        credential: str,
        *,
        tenant_id: str,
        property_id: str,
        client_kind: Literal["browser", "service"],
        jurisdiction: str,
        country_code: str,
        region_code: str,
        default_locale: str,
        property_revision: int,
        property_sha256: str,
        rule_group_id: str,
        rule_group_version: int,
        publication_sha256: str,
        bundle_sha256: str,
        policy_id: str,
        policy_version: int,
        policy_sha256: str,
        expected_revision: int,
        browser_origin: str | None = None,
        service_client_id: str | None = None,
        target_origin: str | None = None,
        target_bundle_id: str | None = None,
        target_platform: str | None = None,
        expires_at: float | None = None,
    ) -> PublicClientBinding:
        """Enroll or CAS-rebind one credential; the raw value is never stored."""

        raw_credential = _token(credential, "credential")
        credential_sha = hashlib.sha256(raw_credential.encode("utf-8")).hexdigest()
        tenant = _ref(tenant_id, "tenant_id")
        property_ref = _ref(property_id, "property_id")
        expected = _revision(expected_revision, "expected_revision")
        if client_kind not in {"browser", "service"}:
            raise PublicConsentValidationError("client_kind is invalid")
        normalized_browser_origin = _origin(browser_origin) if browser_origin is not None else None
        normalized_target_origin = _origin(target_origin) if target_origin is not None else None
        normalized_bundle = _bundle_id(target_bundle_id) if target_bundle_id is not None else None
        normalized_service = (
            _ref(service_client_id, "service_client_id") if service_client_id is not None else None
        )
        if target_platform is not None:
            if target_platform not in _MOBILE_PLATFORMS:
                raise PublicConsentValidationError("target_platform is invalid")
            normalized_platform = target_platform
        else:
            normalized_platform = None
        if client_kind == "browser":
            if (
                normalized_browser_origin is None
                or normalized_service is not None
                or normalized_bundle is not None
                or normalized_platform is not None
            ):
                raise PublicConsentValidationError("browser binding is invalid")
            if normalized_target_origin not in {None, normalized_browser_origin}:
                raise PublicConsentValidationError(
                    "browser target origin must equal its enrolled origin"
                )
            normalized_target_origin = normalized_browser_origin
        else:
            if normalized_browser_origin is not None or normalized_service is None:
                raise PublicConsentValidationError("service binding is invalid")
            web_target = (
                normalized_target_origin is not None
                and normalized_bundle is None
                and normalized_platform is None
            )
            mobile_target = (
                normalized_target_origin is None
                and normalized_bundle is not None
                and normalized_platform is not None
            )
            if web_target == mobile_target:
                raise PublicConsentValidationError(
                    "service binding needs exactly one web or mobile target"
                )
        normalized_expiry = _timestamp(expires_at, "expires_at", allow_none=True)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        if normalized_expiry is not None and normalized_expiry <= now:
            raise PublicConsentValidationError("expires_at must be in the future")
        fixed = {
            "credential_sha256": credential_sha,
            "tenant_id": tenant,
            "property_id": property_ref,
            "client_kind": client_kind,
            "browser_origin": normalized_browser_origin,
            "service_client_id": normalized_service,
            "target_origin": normalized_target_origin,
            "target_bundle_id": normalized_bundle,
            "target_platform": normalized_platform,
            "jurisdiction": _jurisdiction(jurisdiction),
            "country_code": _country(country_code),
            "region_code": _region(region_code),
            "default_locale": _locale(default_locale),
            "property_revision": _version(property_revision, "property_revision"),
            "property_sha256": _digest(property_sha256, "property_sha256"),
            "rule_group_id": _ref(rule_group_id, "rule_group_id"),
            "rule_group_version": _version(
                rule_group_version,
                "rule_group_version",
            ),
            "publication_sha256": _digest(
                publication_sha256,
                "publication_sha256",
            ),
            "bundle_sha256": _digest(bundle_sha256, "bundle_sha256"),
            "policy_id": _ref(policy_id, "policy_id"),
            "policy_version": _version(policy_version, "policy_version"),
            "policy_sha256": _digest(policy_sha256, "policy_sha256"),
            "expires_at": normalized_expiry,
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT credential_id, revision FROM public_consent_clients "
                    "WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
                current = int(row["revision"]) if row is not None else 0
                if current != expected:
                    raise PublicConsentConflict(
                        f"credential revision is {current}, expected {expected}"
                    )
                credential_id = (
                    str(row["credential_id"])
                    if row is not None
                    else _ref(self._id_factory(), "credential_id")
                )
                body = {
                    "credential_id": credential_id,
                    **fixed,
                    "revision": current + 1,
                }
                record_sha = _sha256(body)
                values = (
                    credential_id,
                    tenant,
                    property_ref,
                    client_kind,
                    normalized_browser_origin,
                    normalized_service,
                    normalized_target_origin,
                    normalized_bundle,
                    normalized_platform,
                    body["jurisdiction"],
                    body["country_code"],
                    body["region_code"],
                    body["default_locale"],
                    body["property_revision"],
                    body["property_sha256"],
                    body["rule_group_id"],
                    body["rule_group_version"],
                    body["publication_sha256"],
                    body["bundle_sha256"],
                    body["policy_id"],
                    body["policy_version"],
                    body["policy_sha256"],
                    normalized_expiry,
                    current + 1,
                    record_sha,
                    now,
                )
                if row is None:
                    connection.execute(
                        "INSERT INTO public_consent_clients(credential_sha256, "
                        "credential_id, tenant_id, property_id, client_kind, "
                        "browser_origin, service_client_id, target_origin, "
                        "target_bundle_id, target_platform, jurisdiction, "
                        "country_code, region_code, default_locale, "
                        "property_revision, property_sha256, rule_group_id, "
                        "rule_group_version, publication_sha256, bundle_sha256, "
                        "policy_id, policy_version, policy_sha256, "
                        "expires_at, status, revision, record_sha256, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                        "?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                        (credential_sha, *values),
                    )
                else:
                    updated = connection.execute(
                        "UPDATE public_consent_clients SET credential_id = ?, "
                        "tenant_id = ?, property_id = ?, client_kind = ?, "
                        "browser_origin = ?, service_client_id = ?, "
                        "target_origin = ?, target_bundle_id = ?, target_platform = ?, "
                        "jurisdiction = ?, country_code = ?, region_code = ?, "
                        "default_locale = ?, property_revision = ?, "
                        "property_sha256 = ?, rule_group_id = ?, "
                        "rule_group_version = ?, publication_sha256 = ?, "
                        "bundle_sha256 = ?, policy_id = ?, policy_version = ?, "
                        "policy_sha256 = ?, expires_at = ?, status = 'active', "
                        "revision = ?, record_sha256 = ?, updated_at = ? "
                        "WHERE credential_sha256 = ? AND revision = ?",
                        (*values, credential_sha, current),
                    )
                    if updated.rowcount != 1:
                        raise PublicConsentConflict("credential changed concurrently")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return PublicClientBinding(**body, record_sha256=record_sha)

    def revoke_client(self, credential: str, *, expected_revision: int) -> None:
        """CAS-revoke one public credential without exposing an HTTP endpoint."""

        credential_sha = hashlib.sha256(
            _token(credential, "credential").encode("utf-8")
        ).hexdigest()
        expected = _revision(expected_revision, "expected_revision")
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM public_consent_clients WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
                if row is None or row["status"] != "active":
                    raise PublicConsentConflict("credential revocation precondition failed")
                binding = self._client_binding(row)
                if binding.revision != expected:
                    raise PublicConsentConflict("credential revocation precondition failed")
                body = {
                    **self._client_body(row),
                    "revision": expected + 1,
                }
                record_sha = _sha256(body)
                updated = connection.execute(
                    "UPDATE public_consent_clients SET status = 'revoked', "
                    "revision = revision + 1, record_sha256 = ?, updated_at = ? "
                    "WHERE credential_sha256 = ? "
                    "AND revision = ? AND status = 'active'",
                    (record_sha, now, credential_sha, expected),
                )
                if updated.rowcount != 1:
                    raise PublicConsentConflict("credential revocation precondition failed")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def list_clients(
        self, tenant_id: str, *, limit: int = 100, offset: int = 0
    ) -> dict[str, Any]:
        """List bounded safe client metadata without credential digests."""

        tenant = _ref(tenant_id, "tenant_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise PublicConsentValidationError("limit must be between 1 and 500")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise PublicConsentValidationError("offset must be a non-negative integer")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM public_consent_clients WHERE tenant_id = ? "
                "ORDER BY updated_at DESC, credential_id LIMIT ? OFFSET ?",
                (tenant, limit + 1, offset),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows[:limit]:
            binding = self._client_binding(row)
            body = dict(binding.__dict__)
            body.pop("credential_sha256", None)
            body["status"] = str(row["status"])
            body["updated_at"] = float(row["updated_at"])
            items.append(body)
        truncated = len(rows) > limit
        return {
            "items": items,
            "truncated": truncated,
            "next_offset": offset + limit if truncated else None,
        }

    def iter_clients(self, tenant_id: str) -> Iterator[dict[str, Any]]:
        """Read every page of safe client metadata for one tenant."""

        offset = 0
        while True:
            page = self.list_clients(tenant_id, limit=500, offset=offset)
            yield from page["items"]
            if not page["truncated"]:
                return
            offset = page["next_offset"]

    def list_profile_bindings(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List safe operator selectors without subject or credential digests."""

        tenant = _ref(tenant_id, "tenant_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise PublicConsentValidationError("limit must be between 1 and 500")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT p.*,r.revocation_sha256 "
                "FROM public_consent_profiles p "
                "LEFT JOIN public_consent_profile_revocations r ON "
                "r.credential_sha256=p.credential_sha256 "
                "WHERE p.tenant_id=? ORDER BY p.created_at DESC,p.profile_id LIMIT ?",
                (tenant, limit + 1),
            ).fetchall()
            items: list[dict[str, Any]] = []
            for row in rows[:limit]:
                profile = self._profile_binding(row)
                client_row = connection.execute(
                    "SELECT * FROM public_consent_clients WHERE credential_sha256=?",
                    (profile.client_credential_sha256,),
                ).fetchone()
                if client_row is None:
                    raise PublicConsentError("public profile client authority changed")
                client = self._client_binding(client_row)
                if (
                    profile.tenant_id != tenant
                    or client.tenant_id != tenant
                    or client.property_id != profile.property_id
                ):
                    raise PublicConsentError("public profile tenant authority changed")
                items.append(
                    {
                        "client_credential_id": client.credential_id,
                        "client_revision": client.revision,
                        "client_status": str(client_row["status"]),
                        "property_id": profile.property_id,
                        "profile_id": profile.profile_id,
                        "profile_status": (
                            "revoked"
                            if row["revocation_sha256"] is not None
                            else "active"
                        ),
                        "created_at": float(row["created_at"]),
                    }
                )
        return {"items": items, "truncated": len(rows) > limit}

    def browser_origin_allowed(self, origin: str) -> bool:
        """Return whether an exact origin has an active browser enrollment."""

        try:
            normalized = _origin(origin)
            now = _timestamp(self._clock(), "clock")
            assert now is not None
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT 1 FROM public_consent_clients WHERE client_kind='browser' "
                    "AND browser_origin=? AND status='active' "
                    "AND (expires_at IS NULL OR expires_at>?) LIMIT 1",
                    (normalized, now),
                ).fetchone()
            return row is not None
        except (OSError, PublicConsentError, sqlite3.Error, TypeError, ValueError):
            return False

    def revoke_client_id(
        self,
        tenant_id: str,
        credential_id: str,
        *,
        expected_revision: int,
    ) -> dict[str, Any]:
        """CAS-revoke a client by safe administrative identifier."""

        tenant = _ref(tenant_id, "tenant_id")
        credential_ref = _ref(credential_id, "credential_id")
        expected = _revision(expected_revision, "expected_revision")
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM public_consent_clients WHERE tenant_id = ? "
                    "AND credential_id = ?",
                    (tenant, credential_ref),
                ).fetchone()
                if row is None:
                    raise PublicConsentCredentialError(_AUTH_DETAIL)
                binding = self._client_binding(row)
                if row["status"] != "active" or binding.revision != expected:
                    raise PublicConsentConflict("credential revocation precondition failed")
                body = {**self._client_body(row), "revision": expected + 1}
                record_sha = _sha256(body)
                updated = connection.execute(
                    "UPDATE public_consent_clients SET status='revoked',revision=?,"
                    "record_sha256=?,updated_at=? WHERE tenant_id=? AND credential_id=? "
                    "AND status='active' AND revision=?",
                    (
                        expected + 1,
                        record_sha,
                        now,
                        tenant,
                        credential_ref,
                        expected,
                    ),
                )
                if updated.rowcount != 1:
                    raise PublicConsentConflict("credential revocation precondition failed")
                connection.execute("COMMIT")
                return {
                    "credential_id": credential_ref,
                    "status": "revoked",
                    "revision": expected + 1,
                    "revoked_at": now,
                }
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def resolve_client(self, credential: str) -> PublicClientBinding:
        """Resolve one active digest-bound credential with generic failures."""

        try:
            credential_sha = hashlib.sha256(
                _token(credential, "credential").encode("utf-8")
            ).hexdigest()
            now = _timestamp(self._clock(), "clock")
            assert now is not None
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM public_consent_clients WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
            if row is None or row["status"] != "active":
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            binding = self._client_binding(row)
            if binding.expires_at is not None and binding.expires_at <= now:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            return binding
        except (
            OSError,
            PublicConsentError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ) as exc:
            raise PublicConsentCredentialError(_AUTH_DETAIL) from exc

    def resolve_client_authority(self, credential_sha256: str) -> PublicClientBinding:
        """Re-resolve an enrolled client by its already-authenticated digest.

        This is a server-side drift check for short-lived workflows such as
        device pairing.  Public callers still authenticate with the raw opaque
        capability through :meth:`resolve_client`; no digest becomes a bearer
        credential.
        """

        try:
            credential_sha = _digest(credential_sha256, "credential_sha256")
            now = _timestamp(self._clock(), "clock")
            assert now is not None
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM public_consent_clients WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
            if row is None or row["status"] != "active":
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            binding = self._client_binding(row)
            if binding.expires_at is not None and binding.expires_at <= now:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            return binding
        except (
            OSError,
            PublicConsentError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ) as exc:
            raise PublicConsentCredentialError(_AUTH_DETAIL) from exc

    @staticmethod
    def _profile_binding(row: sqlite3.Row) -> PublicProfileBinding:
        body = {
            "credential_sha256": str(row["credential_sha256"]),
            "client_credential_sha256": str(row["client_credential_sha256"]),
            "tenant_id": str(row["tenant_id"]),
            "property_id": str(row["property_id"]),
            "profile_id": str(row["profile_id"]),
            "subject_binding_sha256": str(row["subject_binding_sha256"]),
        }
        expected = _sha256(body)
        if not hmac.compare_digest(expected, str(row["binding_sha256"])):
            raise PublicConsentCredentialError(_AUTH_DETAIL)
        return PublicProfileBinding(**body, binding_sha256=expected)

    def resolve_profile(
        self,
        credential: str,
        client: PublicClientBinding,
    ) -> PublicProfileBinding:
        try:
            credential_sha = hashlib.sha256(
                _token(credential, "profile credential").encode("utf-8")
            ).hexdigest()
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM public_consent_profiles WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
                revoked = connection.execute(
                    "SELECT revocation_sha256 FROM public_consent_profile_revocations "
                    "WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
            if row is None or revoked is not None:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            binding = self._profile_binding(row)
            if (
                binding.client_credential_sha256 != client.credential_sha256
                or binding.tenant_id != client.tenant_id
                or binding.property_id != client.property_id
            ):
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            return binding
        except (
            OSError,
            PublicConsentError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ) as exc:
            raise PublicConsentCredentialError(_AUTH_DETAIL) from exc

    def resolve_profile_authority(
        self,
        credential_sha256: str,
        client: PublicClientBinding,
    ) -> PublicProfileBinding:
        """Re-resolve a profile capability digest against one exact client."""

        try:
            credential_sha = _digest(credential_sha256, "credential_sha256")
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM public_consent_profiles WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
                revoked = connection.execute(
                    "SELECT revocation_sha256 FROM public_consent_profile_revocations "
                    "WHERE credential_sha256 = ?",
                    (credential_sha,),
                ).fetchone()
            if row is None or revoked is not None:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            binding = self._profile_binding(row)
            if (
                binding.client_credential_sha256 != client.credential_sha256
                or binding.tenant_id != client.tenant_id
                or binding.property_id != client.property_id
            ):
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            return binding
        except (
            OSError,
            PublicConsentError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ) as exc:
            raise PublicConsentCredentialError(_AUTH_DETAIL) from exc

    def resolve_pairing_authority_by_admin_refs(
        self,
        tenant_id: str,
        credential_id: str,
        property_id: str,
        profile_id: str,
        *,
        expected_client_revision: int | None = None,
    ) -> tuple[PublicClientBinding, PublicProfileBinding]:
        """Resolve an exact active client/profile pair from non-secret admin refs."""

        try:
            tenant = _ref(tenant_id, "tenant_id")
            credential_ref = _ref(credential_id, "credential_id")
            property_ref = _ref(property_id, "property_id")
            profile_ref = _ref(profile_id, "profile_id")
            expected_revision = (
                None
                if expected_client_revision is None
                else _revision(expected_client_revision, "expected_client_revision")
            )
            now = _timestamp(self._clock(), "clock")
            assert now is not None
            with self._connect() as connection:
                client_row = connection.execute(
                    "SELECT * FROM public_consent_clients WHERE tenant_id=? "
                    "AND credential_id=? AND property_id=?",
                    (tenant, credential_ref, property_ref),
                ).fetchone()
                if client_row is None or client_row["status"] != "active":
                    raise PublicConsentCredentialError(_AUTH_DETAIL)
                client = self._client_binding(client_row)
                if expected_revision is not None and client.revision != expected_revision:
                    raise PublicConsentConflict("public client authority changed")
                if client.expires_at is not None and client.expires_at <= now:
                    raise PublicConsentCredentialError(_AUTH_DETAIL)
                profile_row = connection.execute(
                    "SELECT * FROM public_consent_profiles WHERE tenant_id=? "
                    "AND property_id=? AND profile_id=? AND client_credential_sha256=?",
                    (tenant, property_ref, profile_ref, client.credential_sha256),
                ).fetchone()
                if profile_row is None:
                    raise PublicConsentCredentialError(_AUTH_DETAIL)
                revoked = connection.execute(
                    "SELECT 1 FROM public_consent_profile_revocations "
                    "WHERE credential_sha256=?",
                    (profile_row["credential_sha256"],),
                ).fetchone()
                if revoked is not None:
                    raise PublicConsentCredentialError(_AUTH_DETAIL)
                profile = self._profile_binding(profile_row)
            return client, profile
        except (
            OSError,
            PublicConsentError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ) as exc:
            raise PublicConsentCredentialError(_AUTH_DETAIL) from exc

    @staticmethod
    def _rights_intake_context_binding(
        row: Mapping[str, Any],
    ) -> PublicRightsIntakeContextBinding:
        body = {
            "context_ref": str(row["context_ref"]),
            "tenant_id": str(row["tenant_id"]),
            "client_credential_sha256": str(row["client_credential_sha256"]),
            "client_revision": int(row["client_revision"]),
            "client_record_sha256": str(row["client_record_sha256"]),
            "profile_credential_sha256": str(row["profile_credential_sha256"]),
            "profile_binding_sha256": str(row["profile_binding_sha256"]),
            "created_at": float(row["created_at"]),
        }
        supplied = str(row["binding_sha256"])
        if not hmac.compare_digest(_sha256(body), supplied):
            raise PublicConsentError("stored rights intake context binding changed")
        return PublicRightsIntakeContextBinding(**body, binding_sha256=supplied)

    def register_rights_intake_context(
        self,
        context_ref: str,
        client: PublicClientBinding,
        profile: PublicProfileBinding,
    ) -> PublicRightsIntakeContextBinding:
        """Persist one immutable digest-only link for later public resolution."""

        if not isinstance(client, PublicClientBinding) or not isinstance(
            profile, PublicProfileBinding
        ):
            raise PublicConsentValidationError(
                "rights intake context requires server-resolved authority"
            )
        ref = _ref(context_ref, "context_ref")
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        current_client, current_profile = self.resolve_pairing_authority_by_admin_refs(
            client.tenant_id,
            client.credential_id,
            client.property_id,
            profile.profile_id,
        )
        if current_client != client or current_profile != profile:
            raise PublicConsentConflict("public pairing authority changed")
        body = {
            "context_ref": ref,
            "tenant_id": client.tenant_id,
            "client_credential_sha256": client.credential_sha256,
            "client_revision": client.revision,
            "client_record_sha256": client.record_sha256,
            "profile_credential_sha256": profile.credential_sha256,
            "profile_binding_sha256": profile.binding_sha256,
            "created_at": now,
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                # Re-read the exact authority under the same writer lock as the
                # immutable insert.  A revocation or CAS rebind cannot race the
                # registration and leave a newly admitted stale binding.
                client_row = connection.execute(
                    "SELECT * FROM public_consent_clients WHERE tenant_id=? "
                    "AND credential_id=? AND property_id=?",
                    (client.tenant_id, client.credential_id, client.property_id),
                ).fetchone()
                profile_row = connection.execute(
                    "SELECT * FROM public_consent_profiles WHERE tenant_id=? "
                    "AND property_id=? AND profile_id=? AND client_credential_sha256=?",
                    (
                        client.tenant_id,
                        client.property_id,
                        profile.profile_id,
                        client.credential_sha256,
                    ),
                ).fetchone()
                revoked = (
                    None
                    if profile_row is None
                    else connection.execute(
                        "SELECT 1 FROM public_consent_profile_revocations "
                        "WHERE credential_sha256=?",
                        (profile_row["credential_sha256"],),
                    ).fetchone()
                )
                if (
                    client_row is None
                    or client_row["status"] != "active"
                    or profile_row is None
                    or revoked is not None
                    or self._client_binding(client_row) != client
                    or self._profile_binding(profile_row) != profile
                ):
                    raise PublicConsentConflict("public pairing authority changed")
                prior = connection.execute(
                    "SELECT * FROM public_consent_rights_intake_contexts "
                    "WHERE context_ref=? OR (tenant_id=? AND client_credential_sha256=? "
                    "AND profile_credential_sha256=?)",
                    (
                        ref,
                        client.tenant_id,
                        client.credential_sha256,
                        profile.credential_sha256,
                    ),
                ).fetchall()
                if prior:
                    if len(prior) != 1:
                        raise PublicConsentError(
                            "rights intake context registry is inconsistent"
                        )
                    existing = self._rights_intake_context_binding(prior[0])
                    if (
                        existing.context_ref != ref
                        or existing.tenant_id != client.tenant_id
                        or existing.client_credential_sha256
                        != client.credential_sha256
                        or existing.client_revision != client.revision
                        or existing.client_record_sha256 != client.record_sha256
                        or existing.profile_credential_sha256
                        != profile.credential_sha256
                        or existing.profile_binding_sha256 != profile.binding_sha256
                    ):
                        raise PublicConsentConflict(
                            "rights intake context is bound to another authority"
                        )
                    connection.execute("COMMIT")
                    return existing
                digest = _sha256(body)
                connection.execute(
                    "INSERT INTO public_consent_rights_intake_contexts "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        ref,
                        client.tenant_id,
                        client.credential_sha256,
                        client.revision,
                        client.record_sha256,
                        profile.credential_sha256,
                        profile.binding_sha256,
                        now,
                        digest,
                    ),
                )
                connection.execute("COMMIT")
                return PublicRightsIntakeContextBinding(
                    **body,
                    binding_sha256=digest,
                )
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def resolve_rights_intake_context(
        self,
        tenant_id: str,
        context_ref: str,
    ) -> tuple[PublicClientBinding, PublicProfileBinding]:
        """Re-resolve an immutable context link and all current revocation state."""

        try:
            tenant = _ref(tenant_id, "tenant_id")
            ref = _ref(context_ref, "context_ref")
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM public_consent_rights_intake_contexts "
                    "WHERE tenant_id=? AND context_ref=?",
                    (tenant, ref),
                ).fetchone()
            if row is None:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            binding = self._rights_intake_context_binding(row)
            client = self.resolve_client_authority(binding.client_credential_sha256)
            profile = self.resolve_profile_authority(
                binding.profile_credential_sha256,
                client,
            )
            if (
                client.tenant_id != tenant
                or client.revision != binding.client_revision
                or not hmac.compare_digest(
                    client.record_sha256,
                    binding.client_record_sha256,
                )
                or not hmac.compare_digest(
                    profile.binding_sha256,
                    binding.profile_binding_sha256,
                )
            ):
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            return client, profile
        except (
            OSError,
            PublicConsentError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ) as exc:
            raise PublicConsentCredentialError(_AUTH_DETAIL) from exc

    def verify_integrity(self) -> Mapping[str, int]:
        """Verify the digest-only public credential registry and its links."""

        with self._connect() as connection:
            meta = connection.execute(
                "SELECT value FROM public_consent_meta WHERE key='schema_version'"
            ).fetchone()
            clients = connection.execute(
                "SELECT * FROM public_consent_clients ORDER BY credential_sha256"
            ).fetchall()
            profiles = connection.execute(
                "SELECT * FROM public_consent_profiles ORDER BY credential_sha256"
            ).fetchall()
            revocations = connection.execute(
                "SELECT * FROM public_consent_profile_revocations "
                "ORDER BY credential_sha256"
            ).fetchall()
            contexts = connection.execute(
                "SELECT * FROM public_consent_rights_intake_contexts ORDER BY context_ref"
            ).fetchall()
        if meta is None or meta["value"] != str(_SCHEMA_VERSION):
            raise PublicConsentError("public consent registry schema changed")
        client_by_sha = {
            binding.credential_sha256: binding
            for binding in (self._client_binding(row) for row in clients)
        }
        profile_by_sha = {
            binding.credential_sha256: binding
            for binding in (self._profile_binding(row) for row in profiles)
        }
        for profile in profile_by_sha.values():
            client = client_by_sha.get(profile.client_credential_sha256)
            if (
                client is None
                or client.tenant_id != profile.tenant_id
                or client.property_id != profile.property_id
            ):
                raise PublicConsentError("public profile authority link changed")
        for row in revocations:
            body = {
                "credential_sha256": str(row["credential_sha256"]),
                "tenant_id": str(row["tenant_id"]),
                "property_id": str(row["property_id"]),
                "profile_id": str(row["profile_id"]),
                "actor_sha256": str(row["actor_sha256"]),
                "evidence_sha256": str(row["evidence_sha256"]),
                "revoked_at": float(row["revoked_at"]),
            }
            profile = profile_by_sha.get(body["credential_sha256"])
            if (
                profile is None
                or profile.tenant_id != body["tenant_id"]
                or profile.property_id != body["property_id"]
                or profile.profile_id != body["profile_id"]
                or not hmac.compare_digest(
                    _sha256(body),
                    str(row["revocation_sha256"]),
                )
            ):
                raise PublicConsentError("public profile revocation changed")
        for row in contexts:
            binding = self._rights_intake_context_binding(row)
            client = client_by_sha.get(binding.client_credential_sha256)
            profile = profile_by_sha.get(binding.profile_credential_sha256)
            if (
                client is None
                or profile is None
                or client.tenant_id != binding.tenant_id
                or profile.tenant_id != binding.tenant_id
                or profile.client_credential_sha256 != client.credential_sha256
                or client.revision != binding.client_revision
                or not hmac.compare_digest(
                    client.record_sha256,
                    binding.client_record_sha256,
                )
                or not hmac.compare_digest(
                    profile.binding_sha256,
                    binding.profile_binding_sha256,
                )
            ):
                raise PublicConsentError("rights intake context authority link changed")
        return {
            "clients": len(clients),
            "profiles": len(profiles),
            "profile_revocations": len(revocations),
            "rights_intake_contexts": len(contexts),
        }

    def revoke_profile(
        self,
        tenant_id: str,
        property_id: str,
        profile_id: str,
        *,
        actor_sha256: str,
        evidence_sha256: str,
    ) -> dict[str, Any]:
        """Idempotently revoke one profile capability by authority identifiers."""

        tenant = _ref(tenant_id, "tenant_id")
        property_ref = _ref(property_id, "property_id")
        profile_ref = _ref(profile_id, "profile_id")
        actor = _digest(actor_sha256, "actor_sha256")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT credential_sha256 FROM public_consent_profiles "
                    "WHERE tenant_id=? AND property_id=? AND profile_id=?",
                    (tenant, property_ref, profile_ref),
                ).fetchone()
                if row is None:
                    raise PublicConsentCredentialError(_AUTH_DETAIL)
                credential_sha = str(row["credential_sha256"])
                prior = connection.execute(
                    "SELECT * FROM public_consent_profile_revocations WHERE credential_sha256=?",
                    (credential_sha,),
                ).fetchone()
                body = {
                    "credential_sha256": credential_sha,
                    "tenant_id": tenant,
                    "property_id": property_ref,
                    "profile_id": profile_ref,
                    "actor_sha256": actor,
                    "evidence_sha256": evidence,
                    "revoked_at": now,
                }
                if prior is None:
                    digest = _sha256(body)
                    connection.execute(
                        "INSERT INTO public_consent_profile_revocations("
                        "credential_sha256,tenant_id,property_id,profile_id,actor_sha256,"
                        "evidence_sha256,revoked_at,revocation_sha256) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (
                            credential_sha,
                            tenant,
                            property_ref,
                            profile_ref,
                            actor,
                            evidence,
                            now,
                            digest,
                        ),
                    )
                    result = {**body, "revocation_sha256": digest}
                else:
                    stored = {
                        "credential_sha256": str(prior["credential_sha256"]),
                        "tenant_id": str(prior["tenant_id"]),
                        "property_id": str(prior["property_id"]),
                        "profile_id": str(prior["profile_id"]),
                        "actor_sha256": str(prior["actor_sha256"]),
                        "evidence_sha256": str(prior["evidence_sha256"]),
                        "revoked_at": float(prior["revoked_at"]),
                    }
                    digest = _sha256(stored)
                    if not hmac.compare_digest(digest, str(prior["revocation_sha256"])):
                        raise PublicConsentError("stored profile revocation changed")
                    result = {**stored, "revocation_sha256": digest}
                connection.execute("COMMIT")
                result.pop("credential_sha256", None)
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _session_ttl(value: object) -> int:
        lower, upper = _SESSION_TTL_BOUNDS
        if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
            raise PublicConsentValidationError("session lifetime is outside its bounds")
        return value

    @staticmethod
    def _session_audience(value: object) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 300:
            raise PublicConsentValidationError("session audience is invalid")
        return value

    def _insert_session(
        self,
        connection: sqlite3.Connection,
        client: PublicClientBinding,
        audience: str,
        ttl: int,
        now: float,
    ) -> tuple[str, float]:
        connection.execute(
            "DELETE FROM public_consent_sessions WHERE expires_at <= ?",
            (now,),
        )
        live = connection.execute("SELECT COUNT(*) FROM public_consent_sessions").fetchone()[0]
        if int(live) >= _MAX_LIVE_SESSIONS:
            raise PublicConsentRateLimitExceeded("session capacity reached")
        mine = connection.execute(
            "SELECT COUNT(*) FROM public_consent_sessions WHERE credential_sha256 = ?",
            (client.credential_sha256,),
        ).fetchone()[0]
        if int(mine) >= _MAX_LIVE_SESSIONS_PER_CLIENT:
            raise PublicConsentRateLimitExceeded("session capacity reached for this site key")
        raw = _SESSION_PREFIX + secrets.token_urlsafe(32)
        expires_at = now + ttl
        connection.execute(
            "INSERT INTO public_consent_sessions(token_sha256, credential_sha256, "
            "client_record_sha256, audience, issued_at, expires_at, replaced_at) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (
                hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                client.credential_sha256,
                client.record_sha256,
                audience,
                now,
                expires_at,
            ),
        )
        return raw, expires_at

    def _live_session(
        self,
        connection: sqlite3.Connection,
        token: str,
        client: PublicClientBinding,
        audience: str,
        now: float,
        *,
        renewable: bool,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM public_consent_sessions WHERE token_sha256 = ?",
            (hashlib.sha256(_token(token, "session").encode("utf-8")).hexdigest(),),
        ).fetchone()
        if (
            row is None
            or float(row["expires_at"]) <= now
            or (renewable and row["replaced_at"] is not None)
            or not hmac.compare_digest(str(row["credential_sha256"]), client.credential_sha256)
            or not hmac.compare_digest(
                str(row["client_record_sha256"]), client.record_sha256
            )
            or not hmac.compare_digest(str(row["audience"]), audience)
        ):
            raise PublicConsentCredentialError(_AUTH_DETAIL)
        return row

    def issue_session(
        self,
        client: PublicClientBinding,
        *,
        audience: str,
        ttl_seconds: int,
    ) -> tuple[str, float]:
        """Start a visitor session for an admitted client; only the digest is kept."""

        ttl = self._session_ttl(ttl_seconds)
        bound = self._session_audience(audience)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                result = self._insert_session(connection, client, bound, ttl, now)
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def renew_session(
        self,
        token: str,
        client: PublicClientBinding,
        *,
        audience: str,
        ttl_seconds: int,
    ) -> tuple[str, float]:
        """Replace a live session before it ends; an ended one is refused.

        The replaced token keeps working for a few seconds (never past its own
        end) so requests already on their way are not lost.
        """

        ttl = self._session_ttl(ttl_seconds)
        bound = self._session_audience(audience)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._live_session(connection, token, client, bound, now, renewable=True)
                connection.execute(
                    "UPDATE public_consent_sessions SET replaced_at = ?, expires_at = ? "
                    "WHERE token_sha256 = ? AND replaced_at IS NULL",
                    (
                        now,
                        min(float(row["expires_at"]), now + _SESSION_REPLACED_GRACE_SECONDS),
                        row["token_sha256"],
                    ),
                )
                result = self._insert_session(connection, client, bound, ttl, now)
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def resolve_session(
        self,
        token: str,
        client: PublicClientBinding,
        *,
        audience: str,
    ) -> float:
        """The end time of a live session bound to this client and site, or refuse."""

        try:
            bound = self._session_audience(audience)
            now = _timestamp(self._clock(), "clock")
            assert now is not None
            with self._connect() as connection:
                row = self._live_session(connection, token, client, bound, now, renewable=False)
            return float(row["expires_at"])
        except (OSError, PublicConsentError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PublicConsentCredentialError(_AUTH_DETAIL) from exc

    def bootstrap_profile(
        self,
        client: PublicClientBinding,
        *,
        subject_sha256: str,
        profile_credential_sha256: str,
        idempotency_key: str,
        create_profile: Callable[[str, str, str], Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Bind a caller-created capability digest to one anonymous profile."""

        subject = _digest(subject_sha256, "subject_sha256")
        profile_credential = _digest(
            profile_credential_sha256,
            "profile_credential_sha256",
        )
        idem = _idempotency(idempotency_key)
        subject_binding = hashlib.sha256(
            (f"public-subject\0{client.tenant_id}\0{client.property_id}\0{subject}").encode()
        ).hexdigest()
        profile_id = (
            "CP-PUB-"
            + hashlib.sha256(
                (f"{client.tenant_id}\0{client.property_id}\0{profile_credential}").encode()
            ).hexdigest()[:32]
        )
        key_sha = hashlib.sha256(idem.encode("utf-8")).hexdigest()
        request = {
            "operation": "bootstrap_profile",
            "client_credential_sha256": client.credential_sha256,
            "profile_credential_sha256": profile_credential,
            "subject_binding_sha256": subject_binding,
        }
        request_sha = _sha256(request)
        now = _timestamp(self._clock(), "clock")
        assert now is not None
        core_idempotency = (
            "public-bootstrap-"
            + hashlib.sha256(
                f"{client.credential_sha256}\0{profile_credential}".encode()
            ).hexdigest()
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = connection.execute(
                    "SELECT request_sha256, result_json "
                    "FROM public_consent_idempotency WHERE "
                    "client_credential_sha256 = ? AND key_sha256 = ?",
                    (client.credential_sha256, key_sha),
                ).fetchone()
                if replay is not None:
                    if not hmac.compare_digest(
                        str(replay["request_sha256"]),
                        request_sha,
                    ):
                        raise PublicConsentConflict(
                            "idempotency key was rebound to different content"
                        )
                    result = json.loads(str(replay["result_json"]))
                    if not isinstance(result, dict):
                        raise PublicConsentError("stored bootstrap result is invalid")
                    connection.execute("COMMIT")
                    return result
                existing = connection.execute(
                    "SELECT * FROM public_consent_profiles WHERE credential_sha256 = ?",
                    (profile_credential,),
                ).fetchone()
                if existing is not None:
                    binding = self._profile_binding(existing)
                    if (
                        binding.client_credential_sha256 != client.credential_sha256
                        or binding.tenant_id != client.tenant_id
                        or binding.property_id != client.property_id
                        or binding.subject_binding_sha256 != subject_binding
                    ):
                        raise PublicConsentConflict("profile credential is already bound")
                    core_result: Mapping[str, Any] = {
                        "profile_id": binding.profile_id,
                        "revision": 0,
                        "created_at": now,
                    }
                else:
                    core_result = create_profile(
                        profile_id,
                        subject_binding,
                        core_idempotency,
                    )
                    if (
                        core_result.get("profile_id") != profile_id
                        or core_result.get("revision") != 0
                    ):
                        raise PublicConsentError(
                            "anonymous profile authority returned an invalid binding"
                        )
                    binding_body = {
                        "credential_sha256": profile_credential,
                        "client_credential_sha256": client.credential_sha256,
                        "tenant_id": client.tenant_id,
                        "property_id": client.property_id,
                        "profile_id": profile_id,
                        "subject_binding_sha256": subject_binding,
                    }
                    binding_sha = _sha256(binding_body)
                    connection.execute(
                        "INSERT INTO public_consent_profiles(credential_sha256, "
                        "client_credential_sha256, tenant_id, property_id, "
                        "profile_id, subject_binding_sha256, binding_sha256, "
                        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            profile_credential,
                            client.credential_sha256,
                            client.tenant_id,
                            client.property_id,
                            profile_id,
                            subject_binding,
                            binding_sha,
                            now,
                        ),
                    )
                profile_row = connection.execute(
                    "SELECT * FROM public_consent_profiles WHERE credential_sha256 = ?",
                    (profile_credential,),
                ).fetchone()
                if profile_row is None:
                    raise PublicConsentError("profile binding was not persisted")
                binding = self._profile_binding(profile_row)
                result = {
                    "profile_ref": profile_id,
                    "profile_revision": int(core_result["revision"]),
                    "profile_binding_sha256": binding.binding_sha256,
                    "created_at": float(core_result["created_at"]),
                }
                connection.execute(
                    "INSERT INTO public_consent_idempotency("
                    "client_credential_sha256, key_sha256, request_sha256, "
                    "result_json, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        client.credential_sha256,
                        key_sha,
                        request_sha,
                        _canonical(result).decode("ascii"),
                        now,
                    ),
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise


class PublicConsentRateLimiter:
    """Bounded in-process per-credential sliding-window limiter."""

    def __init__(
        self,
        *,
        requests_per_minute: int = 120,
        clock: Callable[[], float] = time.monotonic,
        limit_source: Callable[[], int | None] | None = None,
    ) -> None:
        if not 1 <= requests_per_minute <= 100_000:
            raise ValueError("requests_per_minute is invalid")
        self.requests_per_minute = requests_per_minute
        # The installation's limit when one is set, read on every request.
        self._limit_source = limit_source
        self._clock = clock
        self._buckets: dict[tuple[str, str], deque[float]] = {}
        self._lock = threading.Lock()

    def __call__(self, credential_sha256: str, action: str) -> None:
        limit = self.requests_per_minute
        if self._limit_source is not None:
            limit = self._limit_source() or limit
        now = self._clock()
        key = (credential_sha256, action)
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= _MAX_RATE_BUCKETS:
                for candidate, values in tuple(self._buckets.items()):
                    while values and now - values[0] >= _RATE_WINDOW_SECONDS:
                        values.popleft()
                    if not values:
                        self._buckets.pop(candidate, None)
                if len(self._buckets) >= _MAX_RATE_BUCKETS:
                    raise PublicConsentRateLimitExceeded("rate-limit capacity reached")
            values = self._buckets.setdefault(key, deque())
            while values and now - values[0] >= _RATE_WINDOW_SECONDS:
                values.popleft()
            if len(values) >= limit:
                raise PublicConsentRateLimitExceeded("rate limit reached")
            values.append(now)


@dataclass(frozen=True)
class PublicConsentDependencies:
    credential_store: PublicConsentCredentialStore
    publishing_store_for: Callable[[str], Any]
    preference_store_for: Callable[[str], Any]
    gate: Callable[[], bool]
    rate_limit: Callable[[str, str], None]
    context_resolver: Callable[[Request, PublicClientBinding], PublicRequestContext]
    clock: Callable[[], float] = time.time
    experiment_gate: Callable[[], bool] | None = None
    experiment_authority_for: Callable[[str], Any] | None = None
    experiment_variant_resolver: Callable[..., Mapping[str, Any] | None] | None = None
    profile_data_gate: Callable[[], bool] | None = None
    profile_data_store_for: Callable[[str], Any] | None = None
    profile_assignment_store_for: Callable[[str], Any] | None = None
    profile_data_key_authority: Any | None = None
    trust_center_gate: Callable[[], bool] | None = None
    trust_center_store_for: Callable[..., Any] | None = None
    rights_consumer_delivery_gate: Callable[[], bool] | None = None
    rights_consumer_delivery_store_for: Callable[..., Any] | None = None
    rights_reauthentication_resolver: Callable[..., str] | None = None
    rights_package_delivery_adapter: Callable[..., Any] | None = None
    rights_intake_gate: Callable[[], bool] | None = None
    rights_intake_store_for: Callable[..., Any] | None = None
    # Visitor session lifetime in seconds, or None for no sessions (the
    # default reads [consent_preferences.public_api] token_ttl_seconds).
    session_ttl: Callable[[], int | None] | None = None
    # Publication signing policy (default: maverick.consent_publication_signing).
    publication_signing: Callable[[], Any] | None = None


@dataclass(frozen=True)
class PublicRightsIntakeMaterial:
    """Trusted subject-bound intake authority returned by deployment composition."""

    store: Any
    authority: Any


def default_public_consent_gate() -> bool:
    """Require all three explicit feature gates; errors keep the plane off."""

    try:
        from maverick.config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    consent = config.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    for section_name in ("publishing", "public_api"):
        section = consent.get(section_name)
        if not isinstance(section, Mapping) or section.get("enable") is not True:
            return False
    return True


def default_public_experiment_gate() -> bool:
    """Fail closed unless the core experiment capability is exactly enabled."""

    try:
        from maverick.consent_experiments import experiments_enabled

        return experiments_enabled()
    except Exception:
        return False


def default_public_profile_data_gate() -> bool:
    """Fail closed unless the exact parent and profile-data gates are enabled."""

    try:
        from maverick.consent_profile_data import profile_data_enabled

        return profile_data_enabled()
    except Exception:
        return False


def default_public_request_context(
    request: Request,
    binding: PublicClientBinding,
) -> PublicRequestContext:
    """Use enrolled geo facts and a bounded Accept-Language preference."""

    requested = binding.default_locale
    accept_language = request.headers.get("accept-language", "")
    if len(accept_language.encode("utf-8")) <= 256 and accept_language:
        candidate = accept_language.split(",", 1)[0].split(";", 1)[0].strip()
        try:
            requested = _locale(candidate)
        except PublicConsentValidationError:
            requested = binding.default_locale
    return PublicRequestContext(
        jurisdiction=binding.jurisdiction,
        country_code=binding.country_code,
        region_code=binding.region_code,
        locale=requested,
    )


def _default_public_experiment_authority_for(
    tenant_id: str,
    *,
    key_authority: Any | None = None,
) -> Any:
    """Open the same tenant experiment authority used by the operator API."""

    from maverick.consent_experiments import ConsentExperimentAuthority
    from maverick.paths import data_dir

    from .consent_experiments_api import _config, _LocalExperimentKeyAuthority

    return ConsentExperimentAuthority(
        data_dir(
            "consent_preferences",
            "consent-experiments.sqlite3",
            tenant=tenant_id,
        ),
        key_authority=key_authority or _LocalExperimentKeyAuthority(),
        config_loader=_config,
    )


def _default_public_profile_data_store_for(tenant_id: str) -> Any:
    from maverick.consent_profile_data import ConsentProfileDataStore
    from maverick.paths import data_dir

    return ConsentProfileDataStore(
        data_dir(
            "consent_preferences",
            "consent-profile-data.sqlite3",
            tenant=tenant_id,
        )
    )


def _default_public_profile_assignment_store_for(
    tenant_id: str,
    *,
    key_authority: Any | None = None,
) -> Any:
    from maverick.paths import data_dir

    from .consent_experiments_api import _LocalExperimentKeyAuthority
    from .consent_profile_data_api import PublicPromptAssignmentStore

    return PublicPromptAssignmentStore(
        data_dir(
            "consent_preferences",
            "consent-profile-data-assignments.sqlite3",
            tenant=tenant_id,
        ),
        tenant_id=tenant_id,
        key_authority=key_authority or _LocalExperimentKeyAuthority(),
    )


def default_public_consent_dependencies() -> PublicConsentDependencies:
    """Build production defaults without relying on request-global tenancy."""

    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.consent_publishing import ConsentPublishingStore
    from maverick.paths import data_dir

    registry = PublicConsentCredentialStore(
        data_dir(
            "consent_public_api",
            "public-consent-credentials.sqlite3",
            tenant=None,
        )
    )
    limiter = PublicConsentRateLimiter(limit_source=configured_requests_per_minute)
    return PublicConsentDependencies(
        credential_store=registry,
        publishing_store_for=lambda tenant: ConsentPublishingStore(
            data_dir(
                "consent_preferences",
                "consent-publishing.sqlite3",
                tenant=tenant,
            )
        ),
        preference_store_for=lambda tenant: ConsentPreferenceStore(
            data_dir(
                "consent_preferences",
                "consent-preferences.sqlite3",
                tenant=tenant,
            )
        ),
        gate=default_public_consent_gate,
        rate_limit=limiter,
        context_resolver=default_public_request_context,
        experiment_gate=default_public_experiment_gate,
        profile_data_gate=default_public_profile_data_gate,
    )


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class BootstrapProfileIn(_StrictModel):
    subject_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_credential_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    )


class _ContractEcho(_StrictModel):
    publication_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: int = Field(ge=1)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PublicPreferenceChoiceIn(_StrictModel):
    purpose_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    action: Literal["grant", "deny", "revoke", "withdraw"]
    expires_at: float | None = Field(default=None, gt=0)


class PublicPreferenceUpdateIn(_ContractEcho):
    expected_revision: int = Field(ge=0)
    idempotency_key: str = Field(
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    )
    choices: list[PublicPreferenceChoiceIn] = Field(
        min_length=1,
        max_length=128,
    )


class PublicSignalIn(_ContractEcho):
    signal: Literal["gpc", "dnt"]
    expected_revision: int = Field(ge=0)
    idempotency_key: str = Field(
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    )


class PublicExperimentEventIn(_ContractEcho):
    idempotency_key: str = Field(
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    )


class PublicExperimentOutcomeIn(PublicExperimentEventIn):
    success: bool


_ProfileOption = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
]
_ProfileMultiValue = Annotated[
    list[_ProfileOption],
    Field(min_length=1, max_length=64),
]


class PublicProfileValueIn(_StrictModel):
    value: bool | _ProfileOption | _ProfileMultiValue
    expected_revision: int = Field(ge=0, le=1_000_000)
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$",
    )


class PublicProfileMutationIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$",
    )


class PublicTrustCenterExportIn(_StrictModel):
    idempotency_key: str = Field(
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    )


class PublicRightsDeliveryRedeemIn(_StrictModel):
    capability: str = Field(
        min_length=32,
        max_length=256,
        pattern=r"^lwrcd1\.[A-Za-z0-9_-]{32,192}$",
    )


class PublicRightsRequestIn(_StrictModel):
    rights: list[
        Literal[
            "access",
            "portability",
            "erasure",
            "rectification",
            "restriction",
            "objection",
            "opt_out",
        ]
    ] = Field(min_length=1, max_length=7)
    expected_revision: Literal[0]
    idempotency_key: str = Field(
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    )


class PublicPromptInteractionIn(_StrictModel):
    assignment_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    outcome: Literal["inserted", "completed", "dismissed"]
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$",
    )


@dataclass(frozen=True)
class _Authority:
    binding: PublicClientBinding
    credential_sha256: str


@dataclass(frozen=True)
class _Contract:
    public_configuration: dict[str, Any]
    policy: dict[str, Any]
    context: PublicRequestContext


@dataclass(frozen=True)
class _ReauthenticatedPublicAuthority:
    binding: PublicClientBinding
    profile: PublicProfileBinding
    context: PublicRequestContext
    actor_sha256: str


@dataclass(frozen=True)
class PublicRightsPackageDownload:
    """Bounded encrypted package bytes returned by a governed server adapter."""

    content: bytes
    package_sha256: str


@dataclass(frozen=True)
class _PublicExperimentMaterial:
    response: dict[str, Any]
    authority: Any | None
    subject_identity: str | None
    assignment_context: Any | None


@dataclass(frozen=True)
class _PublicProfileDataMaterial:
    ops: Any
    store: Any
    authority: Any
    catalog: Any
    journey_id: str
    published_definitions: Mapping[str, Mapping[str, Any]]
    binding_sha256: str


async def _cache_limited_body(request: Request) -> None:
    if request.method in {"GET", "HEAD"}:
        return
    declared_value = request.headers.get("content-length")
    if declared_value:
        try:
            declared = int(declared_value)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if declared < 0:
            raise HTTPException(status_code=400, detail="invalid Content-Length")
    limit = _request_byte_limit()
    if declared_value and declared > limit:
        raise HTTPException(status_code=413, detail="request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(status_code=413, detail="request body too large")
    request._body = bytes(body)  # noqa: SLF001 - bounded cache for Pydantic parsing


def _authorization_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, raw = authorization.partition(" ")
    if not separator or scheme.lower() != "consentpublic" or not raw:
        raise PublicConsentCredentialError(_AUTH_DETAIL)
    return _token(raw, "credential")


def public_consent_error_origin(
    request: Request,
    dependencies: PublicConsentDependencies,
) -> str | None:
    """Resolve an exact enrolled browser origin for an error response.

    This deliberately performs only the same closed client/origin admission as
    ``authenticate``.  It exists for failures raised before dependencies run
    (notably the outer streaming body cap), so browser callers can read their
    own 4xx response without granting CORS to an unlisted origin.
    """

    try:
        if dependencies.gate() is not True or request.query_params:
            return None
        if any(
            request.headers.get(name)
            for name in (
                "x-lightwork-property",
                "x-lightwork-tenant",
                "x-maverick-property",
                "x-maverick-tenant",
            )
        ):
            return None
        binding = dependencies.credential_store.resolve_client(
            _authorization_token(request)
        )
        origin = _origin(request.headers.get("origin"))
        if (
            binding.client_kind != "browser"
            or binding.browser_origin != origin
            or request.headers.get("x-lightwork-consent-service-client") is not None
        ):
            return None
        return origin
    except Exception:
        return None


def _set_private_response_headers(
    response: Response,
    *,
    request: Request | None = None,
    binding: PublicClientBinding | None = None,
) -> None:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request is not None and binding is not None and binding.client_kind == "browser":
        origin = request.headers.get("origin")
        if origin is not None and origin == binding.browser_origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"


def _public_api_settings() -> Mapping[str, Any]:
    """``[consent_preferences.public_api]`` (Settings > All settings), or {}."""
    try:
        from maverick.config import load_config

        consent = (load_config() or {}).get("consent_preferences")
    except Exception:  # an unreadable config keeps the built-in limits
        return {}
    section = consent.get("public_api") if isinstance(consent, Mapping) else None
    return section if isinstance(section, Mapping) else {}


def _configured_int(section: Mapping[str, Any], key: str, lower: int, upper: int,
                    default: int) -> int:
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        return default
    return value


def configured_request_byte_limit() -> int | None:
    """The installation's largest public request body, or None when unset."""
    value = _public_api_settings().get("max_request_bytes")
    if isinstance(value, bool) or not isinstance(value, int) or not 1_024 <= value <= 1_048_576:
        return None
    return value


def _request_byte_limit() -> int:
    """Largest public request body: the installation's, else 64 KiB."""
    return configured_request_byte_limit() or _MAX_REQUEST_BYTES


def _response_byte_limit() -> int:
    """Largest public response: the installation's, else 256 KiB."""
    return _configured_int(_public_api_settings(), "max_response_bytes", 1_024, 4_194_304,
                           _MAX_RESPONSE_BYTES)


def configured_requests_per_minute() -> int | None:
    """Requests per minute for each public client, or None for the built-in 120."""
    value = _public_api_settings().get("requests_per_minute")
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10_000:
        return None
    return value


def configured_token_ttl_seconds() -> int | None:
    """How long a visitor session lasts, or None when sessions are not used.

    ``[consent_preferences.public_api] token_ttl_seconds`` (60 to 86400).
    Unset -- or a value outside those bounds, which the configuration check
    reports -- keeps today's behaviour: the site key alone on every request.
    """
    value = _public_api_settings().get("token_ttl_seconds")
    lower, upper = _SESSION_TTL_BOUNDS
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        return None
    return value


def _session_ttl(dependencies: PublicConsentDependencies) -> int | None:
    # A failing source raises, and every caller turns that into a refusal.
    value = (getattr(dependencies, "session_ttl", None) or configured_token_ttl_seconds)()
    lower, upper = _SESSION_TTL_BOUNDS
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        return None
    return value


def _session_audience(binding: PublicClientBinding) -> str:
    """What a session is bound to: the enrolled site origin or service client."""
    if binding.client_kind == "browser" and binding.browser_origin:
        return binding.browser_origin
    return f"service:{binding.service_client_id}"


async def require_public_session(
    request: Request,
    dependencies: PublicConsentDependencies,
    binding: PublicClientBinding,
) -> None:
    """Refuse a request without a live visitor session when sessions are on.

    A no-op while ``token_ttl_seconds`` is unset. The session must belong to
    the same client, enrolled record and site origin (or service client) the
    request was admitted for. Tokens are never logged or echoed.
    """
    if _session_ttl(dependencies) is None:
        return
    raw = request.headers.get(_SESSION_HEADER)
    if not raw:
        raise HTTPException(status_code=401, detail=_SESSION_REQUIRED_DETAIL)
    try:
        await run_in_threadpool(
            dependencies.credential_store.resolve_session,
            raw,
            binding,
            audience=_session_audience(binding),
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail=_SESSION_INVALID_DETAIL) from exc


def signed_configuration(
    dependencies: PublicConsentDependencies,
    binding: PublicClientBinding,
    configuration: Mapping[str, Any],
    policy_record: Mapping[str, Any],
) -> dict[str, Any] | None:
    """The served configuration's Ed25519 signature, or None.

    None while ``require_signed_publications`` is off, when no signing key is
    in custody, or when the publication has no publish-time signature from a
    key this installation trusts -- a website that checks signatures then
    refuses it, while other websites keep today's unsigned behaviour.
    """
    from maverick import consent_publication_signing as signing

    try:
        source = getattr(dependencies, "publication_signing", None)
        policy = (source or signing.configured_policy)()
        if not isinstance(policy, signing.SigningPolicy) or not policy.required:
            return None
        signer = policy.custody.signer_for(binding.tenant_id)
        trusted = policy.custody.trusted_public_keys(binding.tenant_id)
        publication = configuration["publication"]
        record = dependencies.publishing_store_for(binding.tenant_id).publication_signature(
            binding.tenant_id,
            str(publication["publication_id"]),
            trusted_public_keys=trusted,
        )
        if record is None:
            return None
        statement = signing.configuration_statement(
            signer.key_id,
            publication_key_id=str(record["key_id"]),
            property_id=str(configuration["property"]["property_id"]),
            publication_sha256=str(publication["publication_sha256"]),
            configuration_sha256=str(configuration["configuration_sha256"]),
            policy_id=str(policy_record["policy_id"]),
            policy_version=int(policy_record["version"]),
            policy_sha256=str(policy_record["policy_sha256"]),
        )
        return {
            "schema": signing.CONFIGURATION_SIGNATURE_SCHEMA,
            "algorithm": signing.ALGORITHM,
            "key_id": signer.key_id,
            "statement": statement,
            "signature": signer.sign(signing.canonical(statement)),
        }
    except Exception:  # noqa: BLE001 -- unsigned: a site that checks signatures refuses it
        return None


def _sdk_cache_control() -> str:
    """How long the consent script may be cached (``[consent_preferences.edge_cache]``).

    Only the static consent script is ever cached: configuration, preference
    and personal answers stay ``no-store``. Without the edge cache on, the
    historical five-minute browser cache applies.
    """
    try:
        from maverick.config import load_config

        consent = (load_config() or {}).get("consent_preferences")
    except Exception:
        consent = None
    section = consent.get("edge_cache") if isinstance(consent, Mapping) else None
    if not isinstance(section, Mapping) or section.get("enable") is not True:
        return "public, max-age=300"
    max_age = _configured_int(section, "max_age_seconds", 0, 86_400, 300)
    stale = _configured_int(section, "stale_if_error_seconds", 0, 604_800, 0)
    return f"public, max-age={max_age}" + (f", stale-if-error={stale}" if stale else "")


def _bounded_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        _canonical(payload, maximum=_response_byte_limit())
    except PublicConsentValidationError as exc:
        raise HTTPException(
            status_code=503,
            detail="public consent response unavailable",
        ) from exc
    return dict(payload)


def _contract_echo_matches(body: _ContractEcho, contract: _Contract) -> bool:
    configuration = contract.public_configuration
    publication = configuration["publication"]
    return bool(
        hmac.compare_digest(
            body.publication_sha256,
            str(publication["publication_sha256"]),
        )
        and hmac.compare_digest(
            body.bundle_sha256,
            str(publication["bundle_sha256"]),
        )
        and hmac.compare_digest(
            body.configuration_sha256,
            str(configuration["configuration_sha256"]),
        )
        and body.policy_version == contract.policy["version"]
        and hmac.compare_digest(
            body.policy_sha256,
            str(contract.policy["policy_sha256"]),
        )
    )


def _public_experiment_id(binding: PublicClientBinding, contract: _Contract) -> str:
    """Derive the only experiment slot admitted by this exact published contract."""

    configuration = contract.public_configuration
    content = configuration["configuration"]
    template = content["template"]
    digest = _sha256(
        {
            "bundle_sha256": binding.bundle_sha256,
            "configuration_sha256": configuration["configuration_sha256"],
            "policy_sha256": contract.policy["policy_sha256"],
            "property_sha256": binding.property_sha256,
            "surface": template["surface"],
            "tenant": binding.tenant_id,
        }
    )
    return f"public-consent-{digest[:32]}"


def _public_experiment_subject(
    authority: _Authority,
    profile: PublicProfileBinding,
) -> str:
    """Return a stable pseudonym that cannot reveal the raw public subject."""

    return (
        "public-profile-"
        + hashlib.sha256(
            (
                "public-consent-experiment\0"
                f"{authority.credential_sha256}\0{profile.subject_binding_sha256}"
            ).encode()
        ).hexdigest()
    )


def _published_experiment_render(
    contract: _Contract,
    *,
    layout: str = "stacked",
) -> dict[str, Any]:
    content = contract.public_configuration["configuration"]
    template = content["template"]
    actions = template["actions"]
    return {
        "language": contract.public_configuration["rule"]["locale"],
        "layout": layout,
        "template": {
            "actions": {key: actions[key] for key in sorted(_PUBLIC_EXPERIMENT_ACTIONS)},
            "body": template["body"],
            "title": template["title"],
        },
    }


def _validated_experiment_render(
    value: object,
    contract: _Contract,
) -> dict[str, Any] | None:
    """Admit only plain, bounded fields that cannot change legal semantics."""

    if not isinstance(value, Mapping) or set(value) != {"language", "layout", "template"}:
        return None
    language = value.get("language")
    layout = value.get("layout")
    template = value.get("template")
    if (
        not isinstance(language, str)
        or _LOCALE_RE.fullmatch(language) is None
        or language != contract.public_configuration["rule"]["locale"]
        or layout not in _PUBLIC_EXPERIMENT_LAYOUTS
        or not isinstance(template, Mapping)
        or set(template) != {"actions", "body", "title"}
    ):
        return None
    actions = template.get("actions")
    if not isinstance(actions, Mapping) or set(actions) != _PUBLIC_EXPERIMENT_ACTIONS:
        return None
    fields = [template.get("title"), template.get("body"), *actions.values()]
    if any(
        not isinstance(item, str)
        or not 1 <= len(item) <= 2_048
        or any(ord(character) < 32 and character not in "\t\n\r" for character in item)
        for item in fields
    ):
        return None
    if not actions["accept_all"].strip() or not actions["reject_all"].strip():
        return None
    return {
        "language": language,
        "layout": layout,
        "template": {
            "actions": {key: actions[key] for key in sorted(_PUBLIC_EXPERIMENT_ACTIONS)},
            "body": template["body"],
            "title": template["title"],
        },
    }


def _public_experiment_response(
    *,
    experiment_id: str,
    variant_id: str,
    eligible: bool,
    is_control: bool,
    is_holdout: bool,
    reason: str,
    render: Mapping[str, Any],
) -> dict[str, Any]:
    safe_reason = reason if reason in _PUBLIC_EXPERIMENT_REASONS else "experiment_unavailable"
    return {
        "content_sha256": _sha256(render),
        "eligible": eligible,
        "experiment_id": experiment_id,
        "is_control": is_control,
        "is_holdout": is_holdout,
        "reason": safe_reason,
        "render": dict(render),
        "variant_id": variant_id,
    }


def _browser_rate_key(request: Request, identifier: str) -> str:
    from .ip_allowlist import client_ip

    client = client_ip(request)
    return hashlib.sha256(f"{identifier}\0{client or 'unknown'}".encode()).hexdigest()


def create_consent_public_router(  # noqa: C901 - closure wires one isolated router
    dependencies: PublicConsentDependencies | None = None,
) -> APIRouter:
    """Create the isolated public router with injectable trust dependencies."""

    from .consent_global_opt_out_public_adapter import (
        GlobalOptOutPublicRouteDependencies,
        attach_consent_global_opt_out_public_routes,
        global_opt_out_preflight_contracts,
    )

    deps = dependencies or default_public_consent_dependencies()
    router = APIRouter(prefix="/api/v1/public/consent", tags=["public-consent"])

    @router.get("/sdk.js", include_in_schema=True)
    async def browser_sdk() -> FileResponse:
        """Serve the inert first-party SDK only while the public plane is enabled."""

        try:
            if not deps.gate():
                raise HTTPException(status_code=404, detail="not found")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        path = Path(__file__).parent / "static" / "lightwork-consent-sdk.js"
        return FileResponse(
            path,
            media_type="text/javascript; charset=utf-8",
            headers={
                "Cache-Control": _sdk_cache_control(),
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            },
        )

    @router.options("/{resource_path:path}")
    async def browser_preflight(resource_path: str, request: Request) -> Response:
        """Admit CORS preflight only for active exact-origin enrollments."""

        contracts = {
            "configuration": {"GET"},
            "experiments/assignment": {"GET"},
            "experiments/exposure": {"POST"},
            "experiments/outcome": {"POST"},
            "identity/pairings": {"POST"},
            "identity/pairings/authorize": {"POST"},
            "identity/pairings/redeem": {"POST"},
            "identity/pairings/revoke": {"POST"},
            "profiles/bootstrap": {"POST"},
            "preferences": {"GET", "PUT"},
            "profile-data": {"GET"},
            "profile-data/export": {"GET"},
            "profile-data/prompt": {"GET"},
            "profile-data/prompt/interactions": {"POST"},
            "trust-center": {"GET"},
            "trust-center/exports": {"POST"},
            "rights-requests": {"POST"},
            "rights-deliveries/redeem": {"POST"},
            "privacy-signals": {"POST"},
            "sessions": {"POST"},
            "sessions/renew": {"POST"},
        }
        contracts.update(global_opt_out_preflight_contracts())
        if re.fullmatch(
            r"rights-requests/[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
            resource_path,
        ):
            contracts[resource_path] = {"GET"}
        if re.fullmatch(
            r"trust-center/brand-assets/[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}/[0-9a-f]{64}",
            resource_path,
        ):
            contracts[resource_path] = {"GET"}
        if re.fullmatch(
            r"profile-data/preferences/[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
            resource_path,
        ):
            contracts[resource_path] = {"PUT"}
        elif re.fullmatch(
            r"profile-data/preferences/[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}/"
            r"(?:history|unset|revoke)",
            resource_path,
        ):
            contracts[resource_path] = {"GET"} if resource_path.endswith("/history") else {"POST"}
        try:
            if not deps.gate() or resource_path not in contracts:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            origin = request.headers.get("origin", "")
            method = request.headers.get("access-control-request-method", "").upper()
            requested_headers = {
                item.strip().lower()
                for item in request.headers.get(
                    "access-control-request-headers",
                    "",
                ).split(",")
                if item.strip()
            }
            allowed_headers = {
                "authorization",
                "content-type",
                "dnt",
                "sec-gpc",
                _SESSION_HEADER,
                "x-lightwork-profile-credential",
                "x-lightwork-reauthentication-receipt",
            }
            if (
                method not in contracts[resource_path]
                or not requested_headers.issubset(allowed_headers)
                or not await run_in_threadpool(
                    deps.credential_store.browser_origin_allowed,
                    origin,
                )
            ):
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            origin_sha = hashlib.sha256(origin.encode("utf-8")).hexdigest()
            deps.rate_limit(_browser_rate_key(request, origin_sha), "preflight")
        except PublicConsentRateLimitExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail="rate limit reached",
                headers={"Retry-After": "60"},
            ) from exc
        except Exception as exc:
            raise HTTPException(status_code=403, detail=_AUTH_DETAIL) from exc
        response = Response(status_code=204)
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = ", ".join(
            sorted(contracts[resource_path])
        )
        response.headers["Access-Control-Allow-Headers"] = ", ".join(sorted(requested_headers))
        response.headers["Access-Control-Max-Age"] = "600"
        response.headers["Vary"] = (
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        )
        return response

    async def admit(request: Request, *, session_required: bool) -> _Authority:
        try:
            if not deps.gate():
                raise HTTPException(status_code=404, detail="not found")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        if request.query_params or any(
            request.headers.get(name)
            for name in (
                "x-lightwork-property",
                "x-lightwork-tenant",
                "x-maverick-property",
                "x-maverick-tenant",
            )
        ):
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL)
        try:
            raw = _authorization_token(request)
            binding = await run_in_threadpool(deps.credential_store.resolve_client, raw)
            origin = request.headers.get("origin")
            service_client = request.headers.get("x-lightwork-consent-service-client")
            if binding.client_kind == "browser":
                admitted = (
                    origin is not None
                    and _origin(origin) == binding.browser_origin
                    and service_client is None
                )
            else:
                admitted = origin is None and service_client == binding.service_client_id
            if not admitted:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            if binding.client_kind == "browser":
                request.state.public_consent_allowed_origin = binding.browser_origin
            rate_key = (_browser_rate_key(request, binding.credential_sha256)
                        if binding.client_kind == "browser" else binding.credential_sha256)
            # Caller-controlled path identifiers must not create fresh buckets.
            deps.rate_limit(rate_key, "request")
            if session_required:
                await require_public_session(request, deps, binding)
            await _cache_limited_body(request)
            return _Authority(binding, binding.credential_sha256)
        except PublicConsentRateLimitExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail="rate limit reached",
                headers={"Retry-After": "60"},
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL) from exc

    async def authenticate(request: Request) -> _Authority:
        """Admit the site key, plus a live visitor session when sessions are on."""
        return await admit(request, session_required=True)

    async def authenticate_client(request: Request) -> _Authority:
        """Admit the site key alone: only for starting or renewing a session."""
        return await admit(request, session_required=False)

    def session_response(response: Response, request: Request, binding: PublicClientBinding,
                         token: str, expires_at: float, ttl: int) -> dict[str, Any]:
        _set_private_response_headers(response, request=request, binding=binding)
        return {"session_token": token, "expires_at": expires_at, "ttl_seconds": ttl}

    @router.post("/sessions", status_code=201)
    async def start_session(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate_client),  # noqa: B008
    ) -> dict[str, Any]:
        """Exchange the site key for a short-lived visitor session."""
        ttl = _session_ttl(deps)
        if ttl is None:
            raise HTTPException(status_code=404, detail="not found")
        try:
            token, expires_at = await run_in_threadpool(
                deps.credential_store.issue_session,
                authority.binding,
                audience=_session_audience(authority.binding),
                ttl_seconds=ttl,
            )
        except PublicConsentRateLimitExceeded as exc:
            raise HTTPException(status_code=429, detail="rate limit reached",
                                headers={"Retry-After": "60"}) from exc
        except Exception as exc:
            raise HTTPException(status_code=503,
                                detail="consent session authority unavailable") from exc
        return session_response(response, request, authority.binding, token, expires_at, ttl)

    @router.post("/sessions/renew", status_code=201)
    async def renew_session(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate_client),  # noqa: B008
    ) -> dict[str, Any]:
        """Replace a live visitor session before it ends; an ended one is refused."""
        ttl = _session_ttl(deps)
        if ttl is None:
            raise HTTPException(status_code=404, detail="not found")
        raw = request.headers.get(_SESSION_HEADER)
        if not raw:
            raise HTTPException(status_code=401, detail=_SESSION_REQUIRED_DETAIL)
        try:
            token, expires_at = await run_in_threadpool(
                deps.credential_store.renew_session,
                raw,
                authority.binding,
                audience=_session_audience(authority.binding),
                ttl_seconds=ttl,
            )
        except PublicConsentRateLimitExceeded as exc:
            raise HTTPException(status_code=429, detail="rate limit reached",
                                headers={"Retry-After": "60"}) from exc
        except (PublicConsentCredentialError, PublicConsentValidationError) as exc:
            raise HTTPException(status_code=401, detail=_SESSION_INVALID_DETAIL) from exc
        except Exception as exc:
            raise HTTPException(status_code=503,
                                detail="consent session authority unavailable") from exc
        return session_response(response, request, authority.binding, token, expires_at, ttl)

    async def profile_authority(
        request: Request,
        authority: _Authority,
    ) -> PublicProfileBinding:
        raw = request.headers.get("x-lightwork-profile-credential", "")
        try:
            return await run_in_threadpool(
                deps.credential_store.resolve_profile,
                raw,
                authority.binding,
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL) from exc

    async def active_contract(request: Request, authority: _Authority) -> _Contract:
        binding = authority.binding
        try:
            context = deps.context_resolver(request, binding)
            if not isinstance(context, PublicRequestContext):
                raise PublicConsentError("context resolver returned an invalid result")
            publishing = deps.publishing_store_for(binding.tenant_id)
            preview = await run_in_threadpool(
                publishing.preview,
                binding.tenant_id,
                binding.property_id,
                binding.rule_group_id,
                binding.rule_group_version,
            )
            preview_bundle = preview.get("bundle")
            preview_property = (
                preview_bundle.get("property") if isinstance(preview_bundle, dict) else None
            )
            if (
                not isinstance(preview_property, dict)
                or not hmac.compare_digest(
                    str(preview_property.get("record_sha256", "")),
                    binding.property_sha256,
                )
                or not hmac.compare_digest(
                    str(preview.get("bundle_sha256", "")),
                    binding.bundle_sha256,
                )
            ):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            configuration = await run_in_threadpool(
                publishing.resolve_public_configuration,
                binding.tenant_id,
                binding.property_id,
                server_origin=binding.target_origin,
                server_bundle_id=binding.target_bundle_id,
                server_platform=binding.target_platform,
                jurisdiction=context.jurisdiction,
                country_code=context.country_code,
                region_code=context.region_code,
                requested_locale=context.locale,
                evaluated_at=deps.clock(),
            )
            if not isinstance(configuration, dict) or configuration.get("allowed") is not True:
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            publication = configuration.get("publication")
            property_binding = configuration.get("property")
            if not isinstance(publication, dict) or not isinstance(property_binding, dict):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            if (
                property_binding.get("property_id") != binding.property_id
                or property_binding.get("revision") != binding.property_revision
                or publication.get("property_revision") != binding.property_revision
                or not hmac.compare_digest(
                    str(publication.get("publication_sha256", "")),
                    binding.publication_sha256,
                )
                or not hmac.compare_digest(
                    str(publication.get("bundle_sha256", "")),
                    binding.bundle_sha256,
                )
            ):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            preferences = deps.preference_store_for(binding.tenant_id)
            policy = await run_in_threadpool(
                preferences.get_active_policy,
                binding.tenant_id, binding.policy_id, at=deps.clock(),
            )
            if not isinstance(policy, dict):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            if policy.get("version") != binding.policy_version or not hmac.compare_digest(
                str(policy.get("policy_sha256", "")),
                binding.policy_sha256,
            ):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            content = configuration.get("configuration")
            if not isinstance(content, dict):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            purposes = content.get("purposes")
            notice = content.get("notice")
            if not isinstance(purposes, list) or not isinstance(notice, dict):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            published_purposes: dict[str, str] = {}
            for item in purposes:
                if not isinstance(item, dict):
                    raise PublicConsentConflict(_CONTRACT_DETAIL)
                purpose_id = str(item.get("id", ""))
                if purpose_id in published_purposes:
                    raise PublicConsentConflict(_CONTRACT_DETAIL)
                published_purposes[purpose_id] = str(item.get("lawful_basis", ""))
            if published_purposes != policy.get("purposes") or not hmac.compare_digest(
                str(notice.get("document_sha256", "")),
                str(policy.get("notice_sha256", "")),
            ):
                raise PublicConsentConflict(_CONTRACT_DETAIL)
            return _Contract(configuration, policy, context)
        except PublicConsentConflict as exc:
            raise HTTPException(status_code=409, detail=_CONTRACT_DETAIL) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="public consent authority unavailable",
            ) from exc

    def core_context(contract: _Contract, binding: PublicClientBinding):
        from maverick.consent_preferences import ConsentContext

        return ConsentContext(
            jurisdiction=contract.context.jurisdiction,
            country_code=contract.context.country_code,
            region_code=contract.context.region_code,
            collection_point=("web" if binding.client_kind == "browser" else "service"),
            asserted_source="edge" if binding.client_kind == "browser" else "sdk",
        )

    def core_idempotency(
        operation: str,
        authority: _Authority,
        profile: PublicProfileBinding,
        caller_key: str,
    ) -> str:
        return (
            f"public-{operation}-"
            + hashlib.sha256(
                (
                    f"{authority.credential_sha256}\0{profile.credential_sha256}\0{caller_key}"
                ).encode()
            ).hexdigest()
        )

    def actor_sha256(
        authority: _Authority,
        profile: PublicProfileBinding,
    ) -> str:
        return hashlib.sha256(
            (
                f"public-consent-actor\0{authority.credential_sha256}\0{profile.credential_sha256}"
            ).encode()
        ).hexdigest()

    def experiment_enabled() -> bool:
        gate = deps.experiment_gate or default_public_experiment_gate
        try:
            return gate() is True
        except Exception:
            return False

    def experiment_authority(request: Request, tenant_id: str) -> Any | None:
        factory = deps.experiment_authority_for
        if factory is not None:
            return factory(tenant_id)
        state_factory = getattr(
            request.app.state,
            "consent_experiment_authority_factory",
            None,
        )
        if callable(state_factory):
            return state_factory(tenant_id=tenant_id, request=request)
        return _default_public_experiment_authority_for(
            tenant_id,
            key_authority=getattr(
                request.app.state,
                "consent_experiment_key_authority",
                None,
            ),
        )

    async def experiment_render(
        request: Request,
        authority: _Authority,
        contract: _Contract,
        variant: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        content_ref = variant.get("content_ref")
        value: object = None
        if isinstance(content_ref, str) and content_ref.startswith("public-layout:"):
            layout = content_ref.partition(":")[2]
            if layout in _PUBLIC_EXPERIMENT_LAYOUTS:
                value = _published_experiment_render(contract, layout=layout)
        else:
            resolver = deps.experiment_variant_resolver or getattr(
                request.app.state,
                "consent_public_experiment_variant_resolver",
                None,
            )
            if callable(resolver):
                value = await run_in_threadpool(
                    resolver,
                    tenant_id=authority.binding.tenant_id,
                    property_id=authority.binding.property_id,
                    content_ref=content_ref,
                    public_configuration=contract.public_configuration,
                )
        render = _validated_experiment_render(value, contract)
        if render is None or not isinstance(variant.get("content_sha256"), str):
            return None
        if not hmac.compare_digest(_sha256(render), variant["content_sha256"]):
            return None
        return render

    async def public_experiment_material(  # noqa: C901 - closed fail-control pipeline
        request: Request,
        authority: _Authority,
        profile: PublicProfileBinding,
        contract: _Contract,
    ) -> _PublicExperimentMaterial:
        from maverick import consent_experiments as experiment_ops

        experiment_id = _public_experiment_id(authority.binding, contract)
        control = _validated_experiment_render(
            _published_experiment_render(contract),
            contract,
        )
        if control is None:
            raise HTTPException(status_code=409, detail=_CONTRACT_DETAIL)

        def fallback(reason: str) -> _PublicExperimentMaterial:
            return _PublicExperimentMaterial(
                _public_experiment_response(
                    experiment_id=experiment_id,
                    variant_id="published-control",
                    eligible=False,
                    is_control=True,
                    is_holdout=False,
                    reason=reason,
                    render=control,
                ),
                None,
                None,
                None,
            )

        if not experiment_enabled():
            return fallback("experiment_disabled")
        try:
            core = experiment_authority(request, authority.binding.tenant_id)
        except Exception:
            return fallback("experiment_unavailable")
        if core is None:
            return fallback("experiment_unavailable")
        try:
            record = await run_in_threadpool(
                core.get_experiment,
                authority.binding.tenant_id,
                experiment_id,
            )
        except experiment_ops.ConsentExperimentConfigError:
            return fallback("experiment_disabled")
        except experiment_ops.ConsentExperimentNotFound:
            return fallback("experiment_unavailable")
        except experiment_ops.ConsentExperimentIntegrityError:
            return fallback("experiment_integrity_failure")
        except Exception:
            return fallback("experiment_unavailable")
        definition = record.get("definition")
        if (
            not isinstance(definition, Mapping)
            or record.get("approved_by_token") is None
            or not isinstance(record.get("definition_sha256"), str)
            or not isinstance(record.get("approved_definition_sha256"), str)
            or not hmac.compare_digest(
                record["definition_sha256"],
                record["approved_definition_sha256"],
            )
        ):
            return fallback("not_active")
        variants = definition.get("variants")
        if not isinstance(variants, list) or not variants:
            return fallback("unsafe_variant_definition")
        renders: dict[str, dict[str, Any]] = {}
        for variant in variants:
            if not isinstance(variant, Mapping) or not isinstance(variant.get("variant_id"), str):
                return fallback("unsafe_variant_definition")
            render = await experiment_render(request, authority, contract, variant)
            if render is None or variant["variant_id"] in renders:
                return fallback("unsafe_variant_definition")
            renders[variant["variant_id"]] = render
        control_id = definition.get("control_variant_id")
        if not isinstance(control_id, str) or control_id not in renders:
            return fallback("unsafe_variant_definition")
        signals = []
        if request.headers.get("sec-gpc") == "1":
            signals.append("gpc")
        if request.headers.get("dnt") == "1":
            signals.append("dnt")
        purposes = contract.public_configuration["configuration"]["purposes"]
        assignment_context = experiment_ops.AssignmentContext(
            country_code=contract.context.country_code,
            region_code=contract.context.region_code or None,
            channel=("web" if authority.binding.client_kind == "browser" else "service"),
            locale=contract.context.locale,
            privacy_signals=tuple(signals),
            required_purpose=any(item.get("required") is True for item in purposes),
            accessibility_supported=authority.binding.client_kind == "browser",
            equal_choice_prominence=all(
                render["template"]["actions"]["accept_all"].strip()
                and render["template"]["actions"]["reject_all"].strip()
                for render in renders.values()
            ),
        )
        subject_identity = _public_experiment_subject(authority, profile)
        try:
            assignment = await run_in_threadpool(
                core.assign,
                authority.binding.tenant_id,
                experiment_id,
                subject_identity,
                assignment_context,
                at=deps.clock(),
            )
        except experiment_ops.ConsentExperimentConfigError:
            return fallback("experiment_disabled")
        except experiment_ops.ConsentExperimentIntegrityError:
            return fallback("experiment_integrity_failure")
        except Exception:
            return fallback("experiment_unavailable")
        render = renders.get(assignment.variant_id)
        if render is None:
            return fallback("unsafe_variant_definition")
        response = _public_experiment_response(
            experiment_id=experiment_id,
            variant_id=assignment.variant_id,
            eligible=assignment.eligible,
            is_control=assignment.is_control,
            is_holdout=assignment.is_holdout,
            reason=assignment.reason,
            render=render,
        )
        return _PublicExperimentMaterial(
            response,
            core,
            subject_identity,
            assignment_context,
        )

    def profile_data_enabled() -> bool:
        gate = deps.profile_data_gate or default_public_profile_data_gate
        try:
            return gate() is True
        except Exception:
            return False

    def profile_data_store(request: Request, tenant_id: str) -> Any:
        if deps.profile_data_store_for is not None:
            return deps.profile_data_store_for(tenant_id)
        factory = getattr(
            request.app.state,
            "consent_profile_data_store_factory",
            None,
        )
        if callable(factory):
            return factory(tenant_id=tenant_id, request=request)
        return _default_public_profile_data_store_for(tenant_id)

    def profile_assignment_store(request: Request, tenant_id: str) -> Any:
        if deps.profile_assignment_store_for is not None:
            return deps.profile_assignment_store_for(tenant_id)
        factory = getattr(
            request.app.state,
            "consent_profile_assignment_store_factory",
            None,
        )
        if callable(factory):
            return factory(tenant_id=tenant_id, request=request)
        key_authority = deps.profile_data_key_authority or getattr(
            request.app.state,
            "consent_profile_data_key_authority",
            None,
        )
        return _default_public_profile_assignment_store_for(
            tenant_id,
            key_authority=key_authority,
        )

    def _published_profile_definitions(
        contract: _Contract,
        catalog: Any,
    ) -> dict[str, Mapping[str, Any]]:
        raw = contract.public_configuration["configuration"].get("custom_preferences")
        if not isinstance(raw, list) or not raw:
            raise PublicConsentConflict("profile data is not published")
        published: dict[str, Mapping[str, Any]] = {}
        for item in raw:
            if not isinstance(item, Mapping):
                raise PublicConsentConflict("profile data is not published")
            preference_id = _ref(item.get("id"), "published preference id")
            version = _version(item.get("version"), "published preference version")
            value_type = item.get("value_type")
            required = item.get("required")
            option_ids = item.get("option_ids", [])
            if (
                preference_id in published
                or value_type not in {"boolean", "single_select", "multi_select"}
                or not isinstance(required, bool)
                or not isinstance(option_ids, list)
                or len(option_ids) > 64
            ):
                raise PublicConsentConflict("profile data is not published")
            options = [_ref(value, "published option id") for value in option_ids]
            if len(set(options)) != len(options):
                raise PublicConsentConflict("profile data is not published")
            published[preference_id] = {
                "id": preference_id,
                "version": version,
                "value_type": value_type,
                "required": required,
                "option_ids": options,
            }
        definitions = {str(item["preference_id"]): item for item in catalog.definitions}
        if set(definitions) != set(published):
            raise PublicConsentConflict("profile catalog differs from the published configuration")
        for preference_id, expected in published.items():
            definition = definitions[preference_id]
            options = definition.get("options")
            if not isinstance(options, list):
                raise PublicConsentConflict(
                    "profile catalog differs from the published configuration"
                )
            actual_options = []
            for option in options:
                if not isinstance(option, Mapping) or option.get("value_id") != option.get(
                    "label_ref"
                ):
                    raise PublicConsentConflict(
                        "profile catalog differs from the published configuration"
                    )
                actual_options.append(option.get("value_id"))
            if (
                definition.get("definition_version") != expected["version"]
                or definition.get("label_ref") != preference_id
                or definition.get("value_type") != expected["value_type"]
                or definition.get("required") != expected["required"]
                or actual_options != expected["option_ids"]
            ):
                raise PublicConsentConflict(
                    "profile catalog differs from the published configuration"
                )
        return published

    async def public_profile_data_material(
        request: Request,
        authority: _Authority,
        profile: PublicProfileBinding,
        contract: _Contract,
    ) -> _PublicProfileDataMaterial:
        if not profile_data_enabled():
            raise HTTPException(status_code=404, detail="not found")
        from maverick import consent_profile_data as profile_ops

        from .consent_profile_data_api import public_profile_data_ids

        binding = authority.binding
        try:
            catalog_id, journey_id = public_profile_data_ids(
                tenant_id=binding.tenant_id,
                property_id=binding.property_id,
                publication_sha256=contract.public_configuration["publication"][
                    "publication_sha256"
                ],
                bundle_sha256=contract.public_configuration["publication"]["bundle_sha256"],
                configuration_sha256=contract.public_configuration["configuration_sha256"],
                policy_id=contract.policy["policy_id"],
                policy_version=contract.policy["version"],
                policy_sha256=contract.policy["policy_sha256"],
            )
            public_authority = profile_ops.PublicProfileAuthority(
                tenant_id=binding.tenant_id,
                profile_id=profile.profile_id,
                property_id=binding.property_id,
                catalog_id=catalog_id,
                catalog_version=1,
                publication_sha256=contract.public_configuration["publication"][
                    "publication_sha256"
                ],
                bundle_sha256=contract.public_configuration["publication"]["bundle_sha256"],
                configuration_sha256=contract.public_configuration["configuration_sha256"],
                policy_id=contract.policy["policy_id"],
                policy_version=contract.policy["version"],
                policy_sha256=contract.policy["policy_sha256"],
                profile_capability_sha256=profile.credential_sha256,
            )
            store = profile_data_store(request, binding.tenant_id)
            if store is None:
                raise RuntimeError("profile store factory returned no authority")
            catalog = await run_in_threadpool(
                store.get_catalog_version,
                binding.tenant_id,
                catalog_id,
                1,
            )
            published = _published_profile_definitions(contract, catalog)
            binding_sha = _sha256(
                {
                    "tenant_id": public_authority.tenant_id,
                    "profile_id": public_authority.profile_id,
                    "property_id": public_authority.property_id,
                    "catalog_id": public_authority.catalog_id,
                    "catalog_version": public_authority.catalog_version,
                    "publication_sha256": public_authority.publication_sha256,
                    "bundle_sha256": public_authority.bundle_sha256,
                    "configuration_sha256": public_authority.configuration_sha256,
                    "policy_id": public_authority.policy_id,
                    "policy_version": public_authority.policy_version,
                    "policy_sha256": public_authority.policy_sha256,
                    "profile_capability_sha256": (public_authority.profile_capability_sha256),
                }
            )
            return _PublicProfileDataMaterial(
                profile_ops,
                store,
                public_authority,
                catalog,
                journey_id,
                published,
                binding_sha,
            )
        except profile_ops.ConsentProfileDataNotFound as exc:
            raise HTTPException(status_code=404, detail="profile data unavailable") from exc
        except profile_ops.ConsentProfileDataConflict as exc:
            raise HTTPException(status_code=409, detail="profile data changed") from exc
        except profile_ops.ConsentProfileDataPermissionDenied as exc:
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL) from exc
        except profile_ops.ConsentProfileDataValidationError as exc:
            raise HTTPException(status_code=409, detail="profile data unavailable") from exc
        except profile_ops.ConsentProfileDataConfigError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        except HTTPException:
            raise
        except PublicConsentConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="profile data authority unavailable",
            ) from exc

    def _public_value(record: Any) -> dict[str, Any]:
        return {
            "preference_id": record.preference_id,
            "definition_version": record.definition_version,
            "value_type": record.value_type,
            "value": record.value,
            "status": record.status,
            "revision": record.revision,
            "expires_at": record.expires_at,
            "receipt_id": record.receipt_id,
            "updated_at": record.updated_at,
            "evidence_sha256": record.integrity_sha256,
        }

    def _public_receipt(receipt: Any) -> dict[str, Any]:
        return {
            "sequence": receipt.sequence,
            "receipt_id": receipt.receipt_id,
            "preference_id": receipt.preference_id,
            "action": receipt.action,
            "definition_version": receipt.definition_version,
            "value_type": receipt.value_type,
            "value": receipt.value,
            "status": receipt.status,
            "value_revision": receipt.value_revision,
            "expires_at": receipt.expires_at,
            "occurred_at": receipt.occurred_at,
            "evidence_sha256": receipt.integrity_sha256,
            "previous_receipt_sha256": receipt.previous_receipt_sha256,
        }

    async def profile_call(
        material: _PublicProfileDataMaterial, function: Any, *args: Any, **kwargs: Any
    ) -> Any:
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except material.ops.ConsentProfileDataConflict as exc:
            raise HTTPException(status_code=409, detail="profile data changed") from exc
        except material.ops.ConsentProfileDataNotFound as exc:
            raise HTTPException(status_code=404, detail="profile data unavailable") from exc
        except material.ops.ConsentProfileDataPermissionDenied as exc:
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL) from exc
        except material.ops.ConsentProfileDataValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except material.ops.ConsentProfileDataConfigError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        except material.ops.ConsentProfileDataIntegrityError as exc:
            raise HTTPException(
                status_code=503, detail="profile data authority unavailable"
            ) from exc
        except material.ops.ConsentProfileDataError as exc:
            raise HTTPException(
                status_code=503, detail="profile data authority unavailable"
            ) from exc

    async def trusted_prompt_context(
        authority: _Authority,
        profile: PublicProfileBinding,
        contract: _Contract,
        ops: Any,
    ) -> Any:
        preferences = deps.preference_store_for(authority.binding.tenant_id)
        signals: list[tuple[str, str]] = []
        for purpose in contract.public_configuration["configuration"]["purposes"]:
            decision = await run_in_threadpool(
                preferences.decide,
                authority.binding.tenant_id,
                profile.profile_id,
                purpose["id"],
                policy_id=contract.policy["policy_id"],
                policy_version=contract.policy["version"],
                at=deps.clock(),
            )
            signals.append((purpose["id"], "grant" if decision.allowed else "deny"))
        return ops.PromptContext(tuple(signals))

    @router.get("/configuration")
    async def configuration(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        contract = await active_contract(request, authority)
        signature = await run_in_threadpool(
            signed_configuration,
            deps,
            authority.binding,
            contract.public_configuration,
            contract.policy,
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        payload = {
            **contract.public_configuration,
            "policy_id": contract.policy["policy_id"],
            "policy_version": contract.policy["version"],
            "policy_sha256": contract.policy["policy_sha256"],
        }
        if signature is not None:
            # Only while require_signed_publications is on (unset: unchanged).
            payload["signature"] = signature
        return _bounded_response(payload)

    @router.post("/profiles/bootstrap", status_code=201)
    async def bootstrap_profile(
        body: BootstrapProfileIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        contract = await active_contract(request, authority)
        preference_store = deps.preference_store_for(authority.binding.tenant_id)

        def create_profile(
            profile_id: str,
            subject_binding_sha256: str,
            idempotency_key: str,
        ) -> Mapping[str, Any]:
            return preference_store.create_profile(
                authority.binding.tenant_id,
                profile_id,
                "anonymous",
                subject_binding_sha256,
                idempotency_key,
            )

        try:
            result = await run_in_threadpool(
                deps.credential_store.bootstrap_profile,
                authority.binding,
                subject_sha256=body.subject_sha256,
                profile_credential_sha256=body.profile_credential_sha256,
                idempotency_key=body.idempotency_key,
                create_profile=create_profile,
            )
        except PublicConsentConflict as exc:
            raise HTTPException(status_code=409, detail=_PREFERENCE_DETAIL) from exc
        except Exception as exc:
            from maverick import consent_preferences as preference_ops

            if isinstance(
                exc,
                (
                    preference_ops.ConsentConflict,
                    preference_ops.ConsentIdempotencyConflict,
                ),
            ):
                raise HTTPException(status_code=409, detail=_PREFERENCE_DETAIL) from exc
            raise HTTPException(
                status_code=503,
                detail="anonymous profile authority unavailable",
            ) from exc
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(
            {
                **result,
                "publication_sha256": contract.public_configuration["publication"][
                    "publication_sha256"
                ],
                "policy_version": contract.policy["version"],
                "policy_sha256": contract.policy["policy_sha256"],
            }
        )

    @router.get("/preferences")
    async def current_preferences(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        store = deps.preference_store_for(authority.binding.tenant_id)
        purposes = contract.public_configuration["configuration"]["purposes"]
        decisions = []
        for purpose in purposes:
            decision = await run_in_threadpool(
                store.decide,
                authority.binding.tenant_id,
                profile.profile_id,
                purpose["id"],
                policy_id=contract.policy["policy_id"],
                policy_version=contract.policy["version"],
                at=deps.clock(),
            )
            decisions.append(decision.as_dict())
        revisions = {
            decision.get("profile_revision")
            for decision in decisions
            if decision.get("profile_revision") is not None
        }
        if len(revisions) != 1:
            raise HTTPException(
                status_code=503,
                detail="preference state unavailable",
            )
        items = [
            {
                "purpose_id": purpose["id"],
                "granted": bool(decision["allowed"]),
                "reason": decision["reason"],
                "action": decision["action"],
                "receipt_sha256": decision["receipt_sha256"],
            }
            for purpose, decision in zip(purposes, decisions, strict=True)
        ]
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(
            {
                "profile_revision": revisions.pop(),
                "preferences": items,
                "publication_sha256": contract.public_configuration["publication"][
                    "publication_sha256"
                ],
                "bundle_sha256": contract.public_configuration["publication"]["bundle_sha256"],
                "configuration_sha256": contract.public_configuration["configuration_sha256"],
                "policy_version": contract.policy["version"],
                "policy_sha256": contract.policy["policy_sha256"],
            }
        )

    @router.put("/preferences")
    async def update_preferences(
        body: PublicPreferenceUpdateIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        if not _contract_echo_matches(body, contract):
            raise HTTPException(status_code=409, detail=_CONTRACT_DETAIL)
        allowed_purposes = {
            str(item["id"]) for item in contract.public_configuration["configuration"]["purposes"]
        }
        if len({item.purpose_id for item in body.choices}) != len(body.choices) or any(
            item.purpose_id not in allowed_purposes for item in body.choices
        ):
            raise HTTPException(status_code=422, detail="invalid preference request")
        from maverick import consent_preferences as preference_ops

        choices = [
            preference_ops.PreferenceChoice(
                purpose_id=item.purpose_id,
                action=item.action,
                expires_at=item.expires_at,
            )
            for item in body.choices
        ]
        store = deps.preference_store_for(authority.binding.tenant_id)
        try:
            result = await run_in_threadpool(
                store.record_preferences,
                authority.binding.tenant_id,
                profile.profile_id,
                contract.policy["policy_id"],
                contract.policy["version"],
                core_context(contract, authority.binding),
                choices,
                expected_revision=body.expected_revision,
                idempotency_key=core_idempotency(
                    "preferences",
                    authority,
                    profile,
                    body.idempotency_key,
                ),
                actor_sha256=actor_sha256(authority, profile),
            )
        except (
            preference_ops.ConsentConflict,
            preference_ops.ConsentIdempotencyConflict,
            preference_ops.ConsentStalePolicy,
        ) as exc:
            raise HTTPException(status_code=409, detail=_PREFERENCE_DETAIL) from exc
        except preference_ops.ConsentValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid preference request") from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="preference authority unavailable",
            ) from exc
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(
            {
                "receipt_id": result["receipt_id"],
                "receipt_sha256": result["receipt_sha256"],
                "profile_revision": result["profile_revision"],
                "policy_version": result["policy_version"],
                "policy_sha256": result["policy_sha256"],
                "context_sha256": result["context_sha256"],
                "created_at": result["created_at"],
            }
        )

    async def profile_request_material(
        request: Request,
        authority: _Authority,
    ) -> tuple[PublicProfileBinding, _Contract, _PublicProfileDataMaterial]:
        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        material = await public_profile_data_material(
            request,
            authority,
            profile,
            contract,
        )
        return profile, contract, material

    def trust_center_enabled(request: Request) -> bool:
        gate = deps.trust_center_gate or getattr(
            request.app.state,
            "consumer_trust_center_gate",
            None,
        )
        if gate is None:
            try:
                from maverick.consumer_trust_center import trust_center_enabled as gate
            except Exception:
                return False
        try:
            return callable(gate) and gate() is True
        except Exception:
            return False

    def public_authority_reauthenticator(
        request: Request,
        authority: _Authority,
        profile: PublicProfileBinding,
    ) -> Callable[[], _ReauthenticatedPublicAuthority]:
        raw_client = _authorization_token(request)
        raw_profile = request.headers.get("x-lightwork-profile-credential", "")
        initial_client_record = authority.binding.record_sha256
        initial_profile_binding = profile.binding_sha256

        def reauthenticate() -> _ReauthenticatedPublicAuthority:
            current_client = deps.credential_store.resolve_client(raw_client)
            current_profile = deps.credential_store.resolve_profile(
                raw_profile,
                current_client,
            )
            if (
                not hmac.compare_digest(
                    current_client.record_sha256,
                    initial_client_record,
                )
                or not hmac.compare_digest(
                    current_profile.binding_sha256,
                    initial_profile_binding,
                )
                or current_client.tenant_id != authority.binding.tenant_id
                or current_client.property_id != authority.binding.property_id
                or current_profile.profile_id != profile.profile_id
            ):
                raise PublicConsentConflict("public trust authority changed")
            context = deps.context_resolver(request, current_client)
            if not isinstance(context, PublicRequestContext):
                raise PublicConsentConflict("public trust context changed")
            return _ReauthenticatedPublicAuthority(
                binding=current_client,
                profile=current_profile,
                context=context,
                actor_sha256=actor_sha256(
                    _Authority(current_client, current_client.credential_sha256),
                    current_profile,
                ),
            )

        return reauthenticate

    async def trust_center_store(
        request: Request,
        authority: _Authority,
    ) -> tuple[Any, PublicProfileBinding]:
        if not trust_center_enabled(request):
            raise HTTPException(status_code=404, detail="not found")
        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        factory = deps.trust_center_store_for or getattr(
            request.app.state,
            "consumer_trust_center_store_factory",
            None,
        )
        if not callable(factory):
            raise HTTPException(status_code=404, detail="not found")
        try:
            store = await run_in_threadpool(
                factory,
                tenant_id=authority.binding.tenant_id,
                initial_client_binding=authority.binding,
                initial_profile_binding=profile,
                active_public_configuration=contract.public_configuration,
                active_policy=contract.policy,
                public_authority_resolver=public_authority_reauthenticator(
                    request,
                    authority,
                    profile,
                ),
                request=request,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="trust center unavailable",
            ) from exc
        if not callable(getattr(store, "snapshot", None)) or not callable(
            getattr(store, "export_signed", None)
        ):
            raise HTTPException(status_code=503, detail="trust center unavailable")
        return store, profile

    def rights_consumer_delivery_enabled(request: Request) -> bool:
        gate = deps.rights_consumer_delivery_gate or getattr(
            request.app.state,
            "rights_consumer_delivery_gate",
            None,
        )
        if gate is None:
            try:
                from maverick.privacy_rights_consumer_delivery import enabled as gate
            except Exception:
                return False
        try:
            return callable(gate) and gate() is True
        except Exception:
            return False

    async def rights_consumer_delivery_material(
        request: Request,
        authority: _Authority,
    ) -> tuple[Any, Callable[..., Any], str, str]:
        if not rights_consumer_delivery_enabled(request):
            raise HTTPException(status_code=404, detail="not found")
        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        public_resolver = public_authority_reauthenticator(
            request,
            authority,
            profile,
        )
        store_factory = deps.rights_consumer_delivery_store_for or getattr(
            request.app.state,
            "rights_consumer_delivery_store_factory",
            None,
        )
        reauth_resolver = deps.rights_reauthentication_resolver or getattr(
            request.app.state,
            "rights_reauthentication_resolver",
            None,
        )
        package_adapter = deps.rights_package_delivery_adapter or getattr(
            request.app.state,
            "rights_package_delivery_adapter",
            None,
        )
        if not all(callable(item) for item in (store_factory, reauth_resolver, package_adapter)):
            raise HTTPException(status_code=404, detail="not found")
        try:
            raw_reauthentication = _token(
                request.headers.get("x-lightwork-reauthentication-receipt", ""),
                "reauthentication receipt",
            )
            reauthentication_sha256 = _digest(
                await run_in_threadpool(
                    reauth_resolver,
                    raw_receipt=raw_reauthentication,
                    tenant_id=authority.binding.tenant_id,
                    property_id=authority.binding.property_id,
                    profile_binding_sha256=profile.binding_sha256,
                    public_authority_resolver=public_resolver,
                    request=request,
                ),
                "reauthentication receipt digest",
            )
            store = await run_in_threadpool(
                store_factory,
                tenant_id=authority.binding.tenant_id,
                consumer_subject_binding_sha256=profile.subject_binding_sha256,
                public_authority_resolver=public_resolver,
                request=request,
            )
        except PublicConsentValidationError as exc:
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="rights delivery unavailable",
            ) from exc
        if not callable(getattr(store, "redeem", None)) or not callable(
            getattr(store, "claim_server_grant", None)
        ):
            raise HTTPException(status_code=503, detail="rights delivery unavailable")
        request_context_sha256 = _sha256(
            {
                "schema": "lightwork.public-rights-delivery-request.v1",
                "client_record_sha256": authority.binding.record_sha256,
                "profile_binding_sha256": profile.binding_sha256,
                "publication_sha256": contract.public_configuration["publication"][
                    "publication_sha256"
                ],
                "configuration_sha256": contract.public_configuration["configuration_sha256"],
                "policy_sha256": contract.policy["policy_sha256"],
                "reauthentication_receipt_sha256": reauthentication_sha256,
                "method": "POST",
                "resource": "rights-deliveries/redeem",
            }
        )
        return store, package_adapter, reauthentication_sha256, request_context_sha256

    def rights_intake_enabled(request: Request) -> bool:
        gate = deps.rights_intake_gate or getattr(
            request.app.state,
            "privacy_rights_intake_gate",
            None,
        )
        if gate is None:
            try:
                from maverick.privacy_rights_intake import enabled as gate
            except Exception:
                return False
        try:
            return callable(gate) and gate() is True
        except Exception:
            return False

    async def rights_intake_material(
        request: Request,
        authority: _Authority,
    ) -> tuple[PublicRightsIntakeMaterial, PublicProfileBinding]:
        """Resolve one independently verified, subject-bound intake authority."""

        if not rights_intake_enabled(request):
            raise HTTPException(status_code=404, detail="not found")
        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        factory = deps.rights_intake_store_for or getattr(
            request.app.state,
            "privacy_rights_intake_store_factory",
            None,
        )
        if not callable(factory):
            raise HTTPException(status_code=404, detail="not found")
        try:
            material = await run_in_threadpool(
                factory,
                tenant_id=authority.binding.tenant_id,
                initial_client_binding=authority.binding,
                initial_profile_binding=profile,
                active_public_configuration=contract.public_configuration,
                active_policy=contract.policy,
                public_authority_resolver=public_authority_reauthenticator(
                    request,
                    authority,
                    profile,
                ),
                request=request,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            ) from exc
        if not isinstance(material, PublicRightsIntakeMaterial):
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            )
        store = material.store
        if not callable(getattr(store, "create_request", None)) or not callable(
            getattr(store, "get_status", None)
        ):
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            )
        return material, profile

    def rights_intake_response(status: Any) -> dict[str, Any]:
        payload = getattr(status, "payload", None)
        value = {
            "payload": dict(payload) if isinstance(payload, Mapping) else None,
            "signing_key_ref": getattr(status, "signing_key_ref", None),
            "signing_key_revision": getattr(status, "signing_key_revision", None),
            "signing_key_authority_sha256": getattr(
                status,
                "signing_key_authority_sha256",
                None,
            ),
            "signature": getattr(status, "signature", None),
            "evidence_sha256": getattr(status, "evidence_sha256", None),
        }
        if (
            not isinstance(value["payload"], dict)
            or not isinstance(value["signing_key_ref"], str)
            or type(value["signing_key_revision"]) is not int
            or not isinstance(value["signing_key_authority_sha256"], str)
            or not isinstance(value["signature"], str)
            or not isinstance(value["evidence_sha256"], str)
        ):
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            )
        return value

    def profile_view_response(view: Any) -> dict[str, Any]:
        return {
            "current": [_public_value(item) for item in view.current_records],
            "active_values": dict(view.active_values),
            "history": [_public_receipt(item) for item in view.history],
            "prompt_interactions": [
                {
                    "event_type": item["event_type"],
                    "preference_ids": list(item["preference_ids"]),
                    "stage_ids": list(item["stage_ids"]),
                    "occurred_at": item["occurred_at"],
                }
                for item in view.prompt_interactions
            ],
            "generated_at": view.generated_at,
        }

    @router.get("/profile-data")
    async def current_profile_data(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        _, _, material = await profile_request_material(request, authority)
        view = await profile_call(
            material,
            material.store.consumer_view,
            material.authority,
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(profile_view_response(view))

    @router.get("/profile-data/preferences/{preference_id}/history")
    async def profile_value_history(
        preference_id: str,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        _, _, material = await profile_request_material(request, authority)
        if preference_id not in material.published_definitions:
            raise HTTPException(status_code=404, detail="profile data unavailable")
        history = await profile_call(
            material,
            material.store.value_history,
            material.authority,
            preference_id,
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(
            {
                "preference_id": preference_id,
                "history": [_public_receipt(item) for item in history],
            }
        )

    @router.get("/profile-data/export")
    async def export_profile_data(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        _, _, material = await profile_request_material(request, authority)
        exported = await profile_call(
            material,
            material.store.export_profile,
            material.authority,
        )
        view = await profile_call(
            material,
            material.store.consumer_view,
            material.authority,
        )
        body = {
            "schema": "lightwork.public-consent-profile-data-export.v1",
            **profile_view_response(view),
            "authority_export_sha256": exported.export_sha256,
            "product_boundaries": dict(material.ops.product_boundaries()),
        }
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response({**body, "export_sha256": _sha256(body)})

    @router.put("/profile-data/preferences/{preference_id}")
    async def set_profile_value(
        preference_id: str,
        body: PublicProfileValueIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        profile, _, material = await profile_request_material(request, authority)
        if preference_id not in material.published_definitions:
            raise HTTPException(status_code=404, detail="profile data unavailable")
        result = await profile_call(
            material,
            material.store.set_public_value,
            material.authority,
            preference_id,
            body.value,
            expected_revision=body.expected_revision,
            idempotency_key=core_idempotency(
                "profile-value",
                authority,
                profile,
                body.idempotency_key,
            ),
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(_public_value(result))

    async def remove_profile_value(
        action: str,
        preference_id: str,
        body: PublicProfileMutationIn,
        request: Request,
        response: Response,
        authority: _Authority,
    ) -> dict[str, Any]:
        profile, _, material = await profile_request_material(request, authority)
        if preference_id not in material.published_definitions:
            raise HTTPException(status_code=404, detail="profile data unavailable")
        function = getattr(material.store, f"{action}_public_value")
        result = await profile_call(
            material,
            function,
            material.authority,
            preference_id,
            expected_revision=body.expected_revision,
            idempotency_key=core_idempotency(
                f"profile-{action}",
                authority,
                profile,
                body.idempotency_key,
            ),
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(_public_value(result))

    @router.post("/profile-data/preferences/{preference_id}/unset")
    async def unset_profile_value(
        preference_id: str,
        body: PublicProfileMutationIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        return await remove_profile_value(
            "unset", preference_id, body, request, response, authority
        )

    @router.post("/profile-data/preferences/{preference_id}/revoke")
    async def revoke_profile_value(
        preference_id: str,
        body: PublicProfileMutationIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        return await remove_profile_value(
            "revoke", preference_id, body, request, response, authority
        )

    @router.get("/profile-data/prompt")
    async def profile_prompt(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        profile, contract, material = await profile_request_material(request, authority)
        try:
            journey = await run_in_threadpool(
                material.store.get_journey_version,
                authority.binding.tenant_id,
                material.journey_id,
                1,
            )
        except material.ops.ConsentProfileDataNotFound:
            journey = None
        if journey is not None and any(
            isinstance(stage.get("condition"), Mapping)
            and stage["condition"].get("source") != "purpose"
            for stage in journey.stages
        ):
            raise HTTPException(
                status_code=409,
                detail="profile-value targeting is not available on the public plane",
            )
        context = await trusted_prompt_context(
            authority,
            profile,
            contract,
            material.ops,
        )
        current = await profile_call(
            material,
            material.store.consumer_view,
            material.authority,
        )
        value_state_sha = _sha256(
            [
                {
                    "preference_id": item.preference_id,
                    "receipt_id": item.receipt_id,
                    "revision": item.revision,
                    "status": item.status,
                }
                for item in current.current_records
            ]
        )
        prompt_state_sha = _sha256(
            [
                {
                    "event_type": item["event_type"],
                    "preference_ids": item["preference_ids"],
                    "stage_ids": item["stage_ids"],
                    "occurred_at": item["occurred_at"],
                }
                for item in current.prompt_interactions
            ]
        )
        prompt_bucket = int(deps.clock() // 60)
        assignment = await profile_call(
            material,
            material.store.assign_prompt,
            material.authority,
            context,
            material.journey_id,
            idempotency_key=core_idempotency(
                "profile-prompt",
                authority,
                profile,
                f"{contract.public_configuration['configuration_sha256'][:24]}-"
                f"{prompt_bucket}-{journey.integrity_sha256[:12] if journey else 'none'}-"
                f"{value_state_sha[:12]}-{prompt_state_sha[:12]}",
            ),
        )
        if assignment.eligible:
            try:
                retained = profile_assignment_store(
                    request,
                    authority.binding.tenant_id,
                )
                await run_in_threadpool(
                    retained.save,
                    material.binding_sha256,
                    assignment,
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="prompt assignment retention unavailable",
                ) from exc
        prompts = [
            {
                "stage_id": item.stage_id,
                "preference_id": item.preference_id,
                "definition_version": item.definition_version,
                "label_ref": item.label_ref,
                "value_type": item.value_type,
                "required": item.required,
                "options": [dict(option) for option in item.options],
            }
            for item in assignment.prompts
        ]
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(
            {
                "assignment_id": assignment.assignment_id if assignment.eligible else None,
                "eligible": assignment.eligible,
                "reason": assignment.reason,
                "assigned_at": assignment.assigned_at,
                "prompts": prompts,
            }
        )

    @router.post("/profile-data/prompt/interactions")
    async def profile_prompt_interaction(
        body: PublicPromptInteractionIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        profile, _, material = await profile_request_material(request, authority)
        from .consent_profile_data_api import (
            PublicPromptAssignmentConflict,
            PublicPromptAssignmentError,
        )

        try:
            retained = profile_assignment_store(request, authority.binding.tenant_id)
            scoped_key = core_idempotency(
                f"profile-prompt-{body.outcome}",
                authority,
                profile,
                body.idempotency_key,
            )
            if body.outcome == "inserted":
                result = await run_in_threadpool(
                    retained.mark_inserted,
                    body.assignment_id,
                    material.binding_sha256,
                    scoped_key,
                )
            else:
                assignment, replay = await run_in_threadpool(
                    retained.load_for_terminal,
                    body.assignment_id,
                    material.binding_sha256,
                    body.outcome,
                    scoped_key,
                )
                if not replay:
                    await profile_call(
                        material,
                        material.store.record_prompt_interaction,
                        material.authority,
                        assignment,
                        body.outcome,
                        idempotency_key=scoped_key,
                    )
                result = await run_in_threadpool(
                    retained.mark_terminal,
                    body.assignment_id,
                    material.binding_sha256,
                    body.outcome,
                    scoped_key,
                )
        except PublicPromptAssignmentConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PublicPromptAssignmentError as exc:
            raise HTTPException(status_code=404, detail="prompt assignment unavailable") from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="prompt assignment authority unavailable",
            ) from exc
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(dict(result))

    async def trust_center_call(call: Callable[[], Any]) -> dict[str, Any]:
        from maverick import consumer_trust_center as trust_ops

        try:
            result = await run_in_threadpool(call)
        except trust_ops.TrustCenterDisabled as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        except trust_ops.TrustCenterConflict as exc:
            raise HTTPException(status_code=409, detail="trust center state changed") from exc
        except (
            trust_ops.TrustCenterIntegrityError,
            trust_ops.TrustCenterValidationError,
        ) as exc:
            raise HTTPException(status_code=503, detail="trust center unavailable") from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="trust center unavailable") from exc
        if not isinstance(result, Mapping):
            raise HTTPException(status_code=503, detail="trust center unavailable")
        return dict(result)

    def branding_material(
        request: Request,
        authority: _Authority,
        contract: _Contract,
    ) -> tuple[Any, Any]:
        """Resolve branding from credential/publication authority, never Host."""

        from maverick.trust_center_branding import BrandPublicationAuthority

        gate = getattr(request.app.state, "trust_center_branding_gate", None)
        factory = getattr(request.app.state, "trust_center_branding_store_factory", None)
        if not callable(gate) or not callable(factory) or gate() is not True:
            raise HTTPException(status_code=404, detail="not found")
        binding = authority.binding
        publication = contract.public_configuration.get("publication")
        if not isinstance(publication, Mapping) or not isinstance(binding.target_origin, str):
            raise HTTPException(status_code=409, detail=_CONTRACT_DETAIL)
        exact = BrandPublicationAuthority(
            tenant_id=binding.tenant_id,
            property_id=binding.property_id,
            property_revision=binding.property_revision,
            publication_id=str(publication.get("publication_id", "")),
            publication_revision=int(publication.get("publication_revision", 0)),
            publication_sha256=binding.publication_sha256,
            bundle_sha256=binding.bundle_sha256,
            client_credential_id=binding.credential_id,
            client_revision=binding.revision,
            client_record_sha256=binding.record_sha256,
            public_origin=binding.target_origin,
        ).normalized()
        try:
            store = factory(
                tenant_id=binding.tenant_id,
                request=request,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail="trust center branding unavailable") from exc
        return store, exact

    async def brand_projection_response(
        request: Request,
        authority: _Authority,
        contract: _Contract,
    ) -> dict[str, Any] | None:
        from maverick import trust_center_branding as brand_ops

        try:
            store, exact = branding_material(request, authority, contract)
            projection = await run_in_threadpool(store.resolve_projection, exact)
        except HTTPException as exc:
            if exc.status_code == 404:
                return None
            raise
        except brand_ops.BrandingNotFound:
            return None
        except brand_ops.BrandingConflict:
            return {
                "schema": "lightwork.public-trust-center-brand.v1",
                "available": False,
                "reason": "binding_changed",
            }
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="trust center branding unavailable",
            ) from exc
        asset_url = (
            "/api/v1/public/consent/trust-center/brand-assets/"
            f"{projection.projection_id}/{projection.asset_content_sha256}"
        )
        return {
            "schema": "lightwork.public-trust-center-brand.v1",
            "available": True,
            "projection_id": projection.projection_id,
            "projection_revision": projection.projection_revision,
            "publication_sha256": projection.publication_sha256,
            "public_origin": projection.public_origin,
            "public_host": projection.public_host,
            "asset": {
                "kind": projection.asset_kind,
                "media_type": projection.asset_media_type,
                "width": projection.asset_width,
                "height": projection.asset_height,
                "content_sha256": projection.asset_content_sha256,
                "url": asset_url,
            },
            "custom_domain": (
                {
                    "claim_id": projection.domain_claim_id,
                    "claim_version": projection.domain_claim_version,
                    "authority_sha256": projection.domain_authority_sha256,
                    "deployment_sha256": projection.domain_deployment_sha256,
                    "host": projection.public_host,
                }
                if projection.domain_claim_id is not None
                else None
            ),
            "host_header_tenant_inference": False,
        }

    async def rights_intake_call(
        store: Any,
        call: Callable[[], Any],
    ) -> dict[str, Any]:
        from maverick import privacy_rights_intake as intake_ops

        try:
            result = await run_in_threadpool(call)
        except intake_ops.PrivacyRightsIntakeNotFound as exc:
            raise HTTPException(status_code=404, detail="rights request unavailable") from exc
        except intake_ops.PrivacyRightsIntakeConflict as exc:
            raise HTTPException(status_code=409, detail="rights request state changed") from exc
        except intake_ops.PrivacyRightsIntakeValidationError as exc:
            raise HTTPException(status_code=422, detail="rights request is invalid") from exc
        except (
            intake_ops.PrivacyRightsIntakeConfigError,
            intake_ops.PrivacyRightsIntakeIntegrityError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            ) from exc
        verifier = getattr(store, "verify_signed_status", None)
        if type(result) is not intake_ops.SignedConsumerRightsStatus or not callable(verifier):
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            )
        try:
            verified = await run_in_threadpool(verifier, result)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            ) from exc
        if verified is not True:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights intake unavailable",
            )
        return rights_intake_response(result)

    @router.get("/trust-center")
    async def consumer_trust_center(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        store, _ = await trust_center_store(request, authority)
        result = await trust_center_call(store.snapshot)
        contract = await active_contract(request, authority)
        brand = await brand_projection_response(request, authority, contract)
        if brand is not None:
            result["brand"] = brand
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(result)

    @router.get("/trust-center/brand-assets/{projection_id}/{content_sha256}")
    async def consumer_trust_center_brand_asset(
        projection_id: Annotated[
            str,
            ApiPath(
                min_length=1,
                max_length=128,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
            ),
        ],
        content_sha256: Annotated[
            str,
            ApiPath(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
        ],
        request: Request,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> Response:
        from maverick import trust_center_branding as brand_ops

        contract = await active_contract(request, authority)
        try:
            store, exact = branding_material(request, authority, contract)
            asset = await run_in_threadpool(
                store.read_public_asset,
                exact,
                projection_id,
                content_sha256,
            )
        except (brand_ops.BrandingNotFound, brand_ops.BrandingConflict) as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="trust center branding unavailable",
            ) from exc
        response = Response(content=asset.content, media_type=asset.projection.asset_media_type)
        response.headers.update(
            {
                "Cache-Control": "private, max-age=0, must-revalidate",
                "Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
                "ETag": f'"sha256-{asset.projection.asset_content_sha256}"',
                "X-Content-Type-Options": "nosniff",
                "X-Lightwork-Publication-SHA256": asset.projection.publication_sha256,
            }
        )
        return response

    @router.post("/trust-center/exports")
    async def export_consumer_trust_center(
        body: PublicTrustCenterExportIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        store, _ = await trust_center_store(request, authority)
        result = await trust_center_call(
            lambda: store.export_signed(idempotency_key=body.idempotency_key)
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(result)

    @router.post("/rights-requests", status_code=201)
    async def create_rights_request(
        body: PublicRightsRequestIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        material, profile = await rights_intake_material(request, authority)
        result = await rights_intake_call(
            material.store,
            lambda: material.store.create_request(
                material.authority,
                rights=body.rights,
                expected_revision=body.expected_revision,
                idempotency_key=core_idempotency(
                    "rights-intake-create",
                    authority,
                    profile,
                    body.idempotency_key,
                ),
            )
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(result)

    @router.get("/rights-requests/{case_id}")
    async def rights_request_status(
        case_id: Annotated[
            str,
            ApiPath(
                min_length=1,
                max_length=128,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
            ),
        ],
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        material, _profile = await rights_intake_material(request, authority)
        result = await rights_intake_call(
            material.store,
            lambda: material.store.get_status(material.authority, case_id)
        )
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(result)

    @router.post("/rights-deliveries/redeem")
    async def redeem_rights_delivery(
        body: PublicRightsDeliveryRedeemIn,
        request: Request,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> Response:
        from maverick import privacy_rights_consumer_delivery as delivery_ops

        (
            store,
            adapter,
            reauthentication_sha256,
            request_context_sha256,
        ) = await rights_consumer_delivery_material(request, authority)
        try:
            server_grant = await run_in_threadpool(
                store.redeem,
                body.capability,
                reauthentication_receipt_sha256=reauthentication_sha256,
                request_context_sha256=request_context_sha256,
            )
            claimed = await run_in_threadpool(
                store.claim_server_grant,
                server_grant,
            )
            download = await run_in_threadpool(
                adapter,
                claimed_grant=claimed,
                request=request,
            )
        except (
            delivery_ops.RightsConsumerDeliveryDenied,
            delivery_ops.RightsConsumerDeliveryNotFound,
        ) as exc:
            raise HTTPException(status_code=404, detail="delivery unavailable") from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="rights delivery unavailable",
            ) from exc
        if (
            not isinstance(download, PublicRightsPackageDownload)
            or not isinstance(download.content, bytes)
            or not 1 <= len(download.content) <= _MAX_RIGHTS_PACKAGE_BYTES
            or not isinstance(download.package_sha256, str)
            or not _DIGEST_RE.fullmatch(download.package_sha256)
            or not hmac.compare_digest(download.package_sha256, claimed.package_sha256)
            or not hmac.compare_digest(
                hashlib.sha256(download.content).hexdigest(),
                claimed.package_sha256,
            )
        ):
            raise HTTPException(status_code=503, detail="rights delivery unavailable")
        response = Response(
            content=download.content,
            media_type="application/octet-stream",
        )
        response.headers["Content-Disposition"] = (
            'attachment; filename="lightwork-rights-response.bin"'
        )
        response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return response

    @router.get("/experiments/assignment")
    async def experiment_assignment(
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        """Resolve one certified assignment from server-side contract context."""

        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        material = await public_experiment_material(
            request,
            authority,
            profile,
            contract,
        )
        _set_private_response_headers(
            response,
            request=request,
            binding=authority.binding,
        )
        return _bounded_response(material.response)

    @router.post("/experiments/exposure")
    async def experiment_exposure(
        body: PublicExperimentEventIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        """Record a bounded aggregate exposure; profile capability is the subject."""

        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        if not _contract_echo_matches(body, contract):
            raise HTTPException(status_code=409, detail=_CONTRACT_DETAIL)
        material = await public_experiment_material(
            request,
            authority,
            profile,
            contract,
        )
        if (
            material.authority is None
            or material.subject_identity is None
            or material.assignment_context is None
        ):
            result = {
                "assignment": material.response,
                "recorded": False,
                "deduplicated": False,
            }
        else:
            try:
                result = await run_in_threadpool(
                    material.authority.record_exposure,
                    authority.binding.tenant_id,
                    material.response["experiment_id"],
                    material.subject_identity,
                    material.assignment_context,
                    idempotency_key=core_idempotency(
                        "experiment-exposure",
                        authority,
                        profile,
                        body.idempotency_key,
                    ),
                )
            except Exception as exc:
                from maverick import consent_experiments as experiment_ops

                if isinstance(
                    exc,
                    (
                        experiment_ops.ConsentExperimentConflict,
                        experiment_ops.ConsentExperimentIdempotencyConflict,
                        experiment_ops.ConsentExperimentStateError,
                    ),
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="experiment exposure unavailable",
                    ) from exc
                if isinstance(exc, experiment_ops.ConsentExperimentValidationError):
                    raise HTTPException(
                        status_code=422,
                        detail="invalid experiment exposure",
                    ) from exc
                raise HTTPException(
                    status_code=503,
                    detail="experiment exposure unavailable",
                ) from exc
        assignment = result["assignment"]
        reason = str(assignment.get("reason", material.response["reason"]))
        _set_private_response_headers(
            response,
            request=request,
            binding=authority.binding,
        )
        return _bounded_response(
            {
                "deduplicated": bool(result.get("deduplicated", False)),
                "eligible": bool(assignment.get("eligible", False)),
                "experiment_id": material.response["experiment_id"],
                "is_control": bool(assignment.get("is_control", True)),
                "reason": (
                    reason if reason in _PUBLIC_EXPERIMENT_REASONS else "experiment_unavailable"
                ),
                "recorded": bool(result.get("recorded", False)),
                "variant_id": str(assignment.get("variant_id", material.response["variant_id"])),
            }
        )

    @router.post("/experiments/outcome")
    async def experiment_outcome(
        body: PublicExperimentOutcomeIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        """Record one binary outcome only after the core retained an exposure."""

        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        if not _contract_echo_matches(body, contract):
            raise HTTPException(status_code=409, detail=_CONTRACT_DETAIL)
        material = await public_experiment_material(
            request,
            authority,
            profile,
            contract,
        )
        if (
            material.authority is None
            or material.subject_identity is None
            or material.response["reason"] not in {"assigned", "holdout", "max_exposures"}
        ):
            result = {
                "deduplicated": False,
                "recorded": False,
                "variant_id": material.response["variant_id"],
            }
        else:
            try:
                result = await run_in_threadpool(
                    material.authority.record_outcome,
                    authority.binding.tenant_id,
                    material.response["experiment_id"],
                    material.subject_identity,
                    success=body.success,
                    idempotency_key=core_idempotency(
                        "experiment-outcome",
                        authority,
                        profile,
                        body.idempotency_key,
                    ),
                )
            except Exception as exc:
                from maverick import consent_experiments as experiment_ops

                if isinstance(
                    exc,
                    (
                        experiment_ops.ConsentExperimentConflict,
                        experiment_ops.ConsentExperimentIdempotencyConflict,
                        experiment_ops.ConsentExperimentStateError,
                    ),
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="experiment outcome unavailable",
                    ) from exc
                if isinstance(exc, experiment_ops.ConsentExperimentValidationError):
                    raise HTTPException(
                        status_code=422,
                        detail="invalid experiment outcome",
                    ) from exc
                raise HTTPException(
                    status_code=503,
                    detail="experiment outcome unavailable",
                ) from exc
        _set_private_response_headers(
            response,
            request=request,
            binding=authority.binding,
        )
        return _bounded_response(
            {
                "deduplicated": bool(result.get("deduplicated", False)),
                "experiment_id": material.response["experiment_id"],
                "recorded": bool(result.get("recorded", False)),
                "success": body.success,
                "variant_id": str(result["variant_id"]),
            }
        )

    @router.post("/privacy-signals")
    async def privacy_signal(
        body: PublicSignalIn,
        request: Request,
        response: Response,
        authority: _Authority = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        profile = await profile_authority(request, authority)
        contract = await active_contract(request, authority)
        if not _contract_echo_matches(body, contract):
            raise HTTPException(status_code=409, detail=_CONTRACT_DETAIL)
        if (body.signal == "gpc" and request.headers.get("sec-gpc") != "1") or (
            body.signal == "dnt" and request.headers.get("dnt") != "1"
        ):
            raise HTTPException(status_code=422, detail="privacy signal header required")
        # Preference receipts can only deny purposes governed by consent. Other
        # lawful bases are present in the published banner, but recording them
        # here would reject the *entire* browser signal.
        purposes = [
            str(item["id"])
            for item in contract.public_configuration["configuration"]["purposes"]
            if item["lawful_basis"] == "consent"
        ]
        if not purposes:
            raise HTTPException(
                status_code=409,
                detail="no consent purposes are configured for this privacy signal",
            )
        from maverick import consent_preferences as preference_ops

        store = deps.preference_store_for(authority.binding.tenant_id)
        try:
            result = await run_in_threadpool(
                store.ingest_privacy_signal,
                authority.binding.tenant_id,
                profile.profile_id,
                body.signal,
                purposes,
                contract.policy["policy_id"],
                contract.policy["version"],
                core_context(contract, authority.binding),
                expected_revision=body.expected_revision,
                idempotency_key=core_idempotency(
                    f"signal-{body.signal}",
                    authority,
                    profile,
                    body.idempotency_key,
                ),
                actor_sha256=actor_sha256(authority, profile),
            )
        except (
            preference_ops.ConsentConflict,
            preference_ops.ConsentIdempotencyConflict,
            preference_ops.ConsentStalePolicy,
        ) as exc:
            raise HTTPException(status_code=409, detail=_PREFERENCE_DETAIL) from exc
        except preference_ops.ConsentValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid privacy signal") from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="preference authority unavailable",
            ) from exc
        _set_private_response_headers(response, request=request, binding=authority.binding)
        return _bounded_response(
            {
                "signal": body.signal,
                "receipt_id": result["receipt_id"],
                "receipt_sha256": result["receipt_sha256"],
                "profile_revision": result["profile_revision"],
                "policy_version": result["policy_version"],
                "policy_sha256": result["policy_sha256"],
                "context_sha256": result["context_sha256"],
                "created_at": result["created_at"],
            }
        )

    attach_consent_global_opt_out_public_routes(
        router,
        GlobalOptOutPublicRouteDependencies(
            authenticate=authenticate,
            profile_authority=profile_authority,
            active_contract=active_contract,
            rights_intake_material=rights_intake_material,
            public_authority_reauthenticator=public_authority_reauthenticator,
            set_private_headers=lambda response, request, authority: (
                _set_private_response_headers(
                    response,
                    request=request,
                    binding=authority.binding,
                )
            ),
        ),
    )
    return router


__all__ = [
    "BootstrapProfileIn",
    "PublicClientBinding",
    "PublicConsentConflict",
    "PublicConsentCredentialError",
    "PublicConsentCredentialStore",
    "PublicConsentDependencies",
    "PublicConsentRateLimitExceeded",
    "PublicConsentRateLimiter",
    "PublicConsentValidationError",
    "PublicExperimentEventIn",
    "PublicExperimentOutcomeIn",
    "PublicProfileMutationIn",
    "PublicProfileValueIn",
    "PublicPromptInteractionIn",
    "PublicPreferenceChoiceIn",
    "PublicPreferenceUpdateIn",
    "PublicRequestContext",
    "PublicRightsIntakeContextBinding",
    "PublicRightsIntakeMaterial",
    "PublicRightsRequestIn",
    "PublicSignalIn",
    "configured_token_ttl_seconds",
    "create_consent_public_router",
    "default_public_consent_dependencies",
    "default_public_consent_gate",
    "default_public_experiment_gate",
    "default_public_profile_data_gate",
    "default_public_request_context",
    "public_consent_error_origin",
    "require_public_session",
    "signed_configuration",
]
