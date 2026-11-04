"""Tenant-safe evergreen public and private policy links.

This module is a local publication authority, not evidence of live external
publication or customer acceptance.  It stores immutable, versioned plain-text
policy artifacts; exposes one stable opaque link per policy family; and moves an
exact current-version pointer only through CAS-protected operations.  Private
links use high-entropy bearer capabilities whose raw value is returned once and
never persisted.

Scheduled publication uses bounded SQLite leases.  Expiry and revocation are
also enforced from their stored timestamps during retrieval, so a stopped
scheduler fails closed instead of serving past the approved boundary.  Policy
content is rendered as deterministic text or escaped HTML; caller-supplied HTML
is never interpreted.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import html
import json
import math
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
ARTIFACT_SCHEMA = "lightwork.policy-publication-artifact.v1"
AUDIT_SCHEMA = "lightwork.policy-publication-audit.v1"
ACCESS_SCHEMA = "lightwork.policy-publication-access.v1"
CHECKPOINT_SCHEMA = "lightwork.policy-publication-access-checkpoint.v1"
TOMBSTONE_SCHEMA = "lightwork.policy-publication-content-tombstone.v1"

_OPAQUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_CAPABILITY_RE = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ERROR_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")

_MAX_TITLE_BYTES = 1024
_MAX_BODY_BYTES = 256 * 1024
_MAX_JSON_BYTES = 320 * 1024
_MAX_AUDIT_DETAILS_BYTES = 32 * 1024
_MAX_LIST_LIMIT = 500
_MAX_CLAIM_LIMIT = 100
_MAX_LEASE_SECONDS = 3600.0
_MAX_RETRY_SECONDS = 86_400.0
_MAX_PENDING_JOBS = 10_000
_MAX_JOB_ATTEMPTS = 20

_VISIBILITIES = frozenset({"public", "private"})
_APPROVAL_MODES = frozenset({"none", "approval", "four_eyes"})
_DECISIONS = frozenset({"approve", "reject"})
_JOB_ACTIONS = frozenset({"publish", "expire", "revoke"})
_JOB_STATES = frozenset({"pending", "leased", "applied", "failed", "cancelled"})
_FORMATS = frozenset({"text", "html"})


class PolicyPublicationError(RuntimeError):
    """Base error for policy publication links."""


class PolicyPublicationConfigError(PolicyPublicationError):
    """The feature is disabled or its local prerequisites failed."""


class PolicyPublicationValidationError(PolicyPublicationError, ValueError):
    """Input is outside the closed publication contract."""


class PolicyPublicationConflict(PolicyPublicationError):
    """A uniqueness, state, or CAS precondition failed."""


class PolicyPublicationIdempotencyConflict(PolicyPublicationConflict):
    """An idempotency key was rebound to different content."""


class PolicyPublicationNotFound(PolicyPublicationError):
    """A tenant-scoped policy resource does not exist."""


class PolicyPublicationAccessDenied(PolicyPublicationError):
    """A link cannot currently disclose policy content."""


class PolicyPublicationApprovalRequired(PolicyPublicationConflict):
    """The immutable version has not satisfied its approval contract."""


class PolicyPublicationLeaseLost(PolicyPublicationConflict):
    """A scheduler lease expired, was recovered, or failed CAS validation."""


class PolicyPublicationIntegrityError(PolicyPublicationError):
    """Stored publication evidence failed canonical integrity verification."""


@dataclass(frozen=True)
class PublicationClaim:
    """One bounded scheduler claim.

    ``lease_token`` is process-local authority and is stored only as a digest.
    It is excluded from representations to reduce accidental logging.
    """

    tenant_id: str
    job_id: str
    action: str
    link_id: str
    target_version: int | None
    scheduled_for: float
    expires_at: float | None
    expected_revision: int
    attempt: int
    worker_id: str
    lease_token: str = field(repr=False)


def enabled() -> bool:
    """Return true only for both explicit TRC policy-link config gates.

    The TRC product schema is intentionally fail-closed.  It never infers
    publication authority from the broader ``[compliance]`` workspace.
    """

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        loaded = load_config()
    except Exception:
        return False
    if not isinstance(loaded, Mapping):
        return False
    trc = loaded.get("tech_risk_compliance")
    links = trc.get("policy_publication_links") if isinstance(trc, Mapping) else None
    return (
        isinstance(trc, Mapping)
        and trc.get("enable") is True
        and isinstance(links, Mapping)
        and links.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless the TRC authority and policy-link gate are enabled."""

    if not enabled():
        raise PolicyPublicationConfigError(
            "policy publication links are disabled; explicitly enable "
            "tech_risk_compliance and "
            "tech_risk_compliance.policy_publication_links"
        )


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PolicyPublicationValidationError(
            "publication data must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise PolicyPublicationValidationError(
            "publication data exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object, *, maximum: int = _MAX_JSON_BYTES) -> str:
    return hashlib.sha256(_canonical(value, maximum=maximum)).hexdigest()


def _opaque(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _OPAQUE_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PolicyPublicationValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise PolicyPublicationValidationError("tenant_id is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PolicyPublicationValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _positive_int(value: object, label: str, *, maximum: int = 2**31 - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise PolicyPublicationValidationError(
            f"{label} must be an integer between 1 and {maximum}"
        )
    return value


def _revision(value: object, label: str = "expected_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**31:
        raise PolicyPublicationValidationError(
            f"{label} must be a non-negative integer"
        )
    return value


def _finite_time(value: object, label: str, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise PolicyPublicationValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return float(value)


def _bounded_float(value: object, label: str, *, maximum: float) -> float:
    parsed = _finite_time(value, label)
    assert parsed is not None
    if parsed > maximum:
        raise PolicyPublicationValidationError(
            f"{label} must be no greater than {maximum:g}"
        )
    return parsed


def _plain_text(value: object, label: str, *, maximum: int, multiline: bool) -> str:
    if not isinstance(value, str):
        raise PolicyPublicationValidationError(f"{label} must be plain text")
    normalized = unicodedata.normalize(
        "NFC", value.replace("\r\n", "\n").replace("\r", "\n")
    )
    if not normalized.strip():
        raise PolicyPublicationValidationError(f"{label} must not be blank")
    if not multiline and ("\n" in normalized or "\t" in normalized):
        raise PolicyPublicationValidationError(f"{label} must be one line")
    for character in normalized:
        if character in {"\n", "\t"} and multiline:
            continue
        if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            raise PolicyPublicationValidationError(
                f"{label} contains unsafe control characters"
            )
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeError as exc:
        raise PolicyPublicationValidationError(f"{label} is not valid Unicode") from exc
    if len(encoded) > maximum:
        raise PolicyPublicationValidationError(f"{label} exceeds its byte bound")
    return normalized


def _loads(value: object, label: str, *, maximum: int = _MAX_JSON_BYTES) -> Any:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise PolicyPublicationIntegrityError(f"stored {label} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise PolicyPublicationIntegrityError(f"stored {label} is invalid") from exc


def _no_secret_details(value: object) -> None:
    prohibited = {
        "bearer",
        "capability",
        "lease_token",
        "password",
        "raw_capability",
        "secret",
        "token",
    }
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in prohibited:
                raise PolicyPublicationValidationError(
                    "audit details must not contain raw authority material"
                )
            _no_secret_details(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _no_secret_details(item)



def _emit_published(result: dict[str, Any], actor: str) -> None:
    """``policy.published`` for webhook subscribers; never raises."""
    try:
        from .webhook_events import emit, record_link

        emit("policy.published", record_type="policy", record_id=str(result.get("policy_id") or ""),
             title=f"policy {result.get('policy_id')} version {result.get('current_version')}",
             summary={"link_id": result.get("link_id"), "version": result.get("current_version"),
                      "effective_at": result.get("effective_at")},
             link=record_link("/settings#policy-publication"), payload={"actor_id": actor})
    except Exception:  # pragma: no cover - webhooks never block a publication
        pass


class PolicyPublicationStore:
    """SQLite authority for exact-version policy publication links."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        capability_factory: Callable[[], str] | None = None,
        config_gate: Callable[[], bool] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self._id_factory = id_factory or (
            lambda prefix: f"{prefix}-{secrets.token_urlsafe(18)}"
        )
        self._capability_factory = capability_factory or (
            lambda: secrets.token_urlsafe(32)
        )
        self._config_gate = config_gate or enabled
        self._require_enabled()
        self._initialize()

    def _require_enabled(self) -> None:
        try:
            allowed = self._config_gate()
        except Exception as exc:
            raise PolicyPublicationConfigError(
                "policy publication config gate failed"
            ) from exc
        if allowed is not True:
            raise PolicyPublicationConfigError("policy publication links are disabled")

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception as exc:
            raise PolicyPublicationConfigError("policy publication clock failed") from exc
        parsed = _finite_time(value, "current time")
        assert parsed is not None
        return parsed

    def _new_id(self, prefix: str) -> str:
        return _opaque(self._id_factory(prefix), f"{prefix} identifier")

    def _new_capability(self) -> str:
        try:
            value = self._capability_factory()
        except Exception as exc:
            raise PolicyPublicationConfigError("capability generation failed") from exc
        return _opaque(value, "private capability", _CAPABILITY_RE)

    @staticmethod
    def _tenant(value: object) -> str:
        return _tenant_id(value)

    @staticmethod
    def _idempotency(value: object) -> str:
        raw = _opaque(value, "idempotency_key", _IDEMPOTENCY_RE)
        return hashlib.sha256(raw.encode("ascii")).hexdigest()

    @contextlib.contextmanager
    def _connect(self):
        ensure_private_directory(self.path.parent)
        if not self.path.exists():
            try:
                descriptor = os.open(
                    self.path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        ensure_private_file(self.path, 0o600)
        connection = sqlite3.connect(
            str(self.path), timeout=10.0, isolation_level=None
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

    @contextlib.contextmanager
    def _transaction(self):
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS policy_publication_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policy_publication_artifacts (
                    tenant TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    author_id TEXT NOT NULL,
                    approval_mode TEXT NOT NULL CHECK(
                        approval_mode IN ('none','approval','four_eyes')
                    ),
                    content_sha256 TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, policy_id, version)
                );
                CREATE TABLE IF NOT EXISTS policy_publication_content (
                    tenant TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, policy_id, version),
                    FOREIGN KEY (tenant, policy_id, version)
                        REFERENCES policy_publication_artifacts(tenant, policy_id, version)
                );
                CREATE TABLE IF NOT EXISTS policy_publication_approvals (
                    tenant TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision IN ('approve','reject')),
                    rationale_sha256 TEXT,
                    approval_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, policy_id, version, reviewer_id),
                    FOREIGN KEY (tenant, policy_id, version)
                        REFERENCES policy_publication_artifacts(tenant, policy_id, version)
                );
                CREATE TABLE IF NOT EXISTS policy_publication_links (
                    tenant TEXT NOT NULL,
                    link_id TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    visibility TEXT NOT NULL CHECK(visibility IN ('public','private')),
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    capability_sha256 TEXT,
                    capability_generation INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    pointer_revision INTEGER NOT NULL,
                    current_version INTEGER,
                    effective_at REAL,
                    expires_at REAL,
                    scheduled_revoke_at REAL,
                    created_by TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    revoked_at REAL,
                    record_sha256 TEXT NOT NULL,
                    PRIMARY KEY (tenant, link_id)
                );
                CREATE INDEX IF NOT EXISTS policy_publication_links_policy
                    ON policy_publication_links(tenant, policy_id, status);
                CREATE TABLE IF NOT EXISTS policy_publication_jobs (
                    tenant TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('publish','expire','revoke')),
                    link_id TEXT NOT NULL,
                    target_version INTEGER,
                    scheduled_for REAL NOT NULL,
                    expires_at REAL,
                    expected_revision INTEGER NOT NULL,
                    scheduled_by TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(
                        state IN ('pending','leased','applied','failed','cancelled')
                    ),
                    attempts INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    next_attempt_at REAL NOT NULL,
                    lease_owner TEXT,
                    lease_token_sha256 TEXT,
                    lease_until REAL,
                    last_error_code TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    applied_at REAL,
                    record_sha256 TEXT NOT NULL,
                    PRIMARY KEY (tenant, job_id),
                    FOREIGN KEY (tenant, link_id)
                        REFERENCES policy_publication_links(tenant, link_id)
                );
                CREATE INDEX IF NOT EXISTS policy_publication_jobs_due
                    ON policy_publication_jobs(tenant, state, next_attempt_at, job_id);
                CREATE TABLE IF NOT EXISTS policy_publication_idempotency (
                    tenant TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    result_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, namespace, key_sha256)
                );
                CREATE TABLE IF NOT EXISTS policy_publication_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    details_sha256 TEXT NOT NULL,
                    previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE (tenant, event_id)
                );
                CREATE INDEX IF NOT EXISTS policy_publication_audit_tenant
                    ON policy_publication_audit(tenant, sequence);
                CREATE TABLE IF NOT EXISTS policy_publication_access (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    link_id TEXT NOT NULL,
                    output_format TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    credential_present INTEGER NOT NULL,
                    request_context_sha256 TEXT,
                    previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE (tenant, event_id)
                );
                CREATE INDEX IF NOT EXISTS policy_publication_access_tenant
                    ON policy_publication_access(tenant, sequence);
                CREATE TABLE IF NOT EXISTS policy_publication_access_checkpoints (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL,
                    from_sequence INTEGER NOT NULL,
                    through_sequence INTEGER NOT NULL,
                    purged_count INTEGER NOT NULL,
                    last_event_sha256 TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    previous_checkpoint_sha256 TEXT,
                    checkpoint_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE (tenant, checkpoint_id)
                );
                CREATE TABLE IF NOT EXISTS policy_publication_content_tombstones (
                    tenant TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    tombstone_sha256 TEXT NOT NULL,
                    purged_at REAL NOT NULL,
                    PRIMARY KEY (tenant, policy_id, version),
                    FOREIGN KEY (tenant, policy_id, version)
                        REFERENCES policy_publication_artifacts(tenant, policy_id, version)
                );

                CREATE TRIGGER IF NOT EXISTS policy_publication_artifacts_no_update
                    BEFORE UPDATE ON policy_publication_artifacts
                    BEGIN SELECT RAISE(ABORT, 'policy artifact is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_artifacts_no_delete
                    BEFORE DELETE ON policy_publication_artifacts
                    BEGIN SELECT RAISE(ABORT, 'policy artifact is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_content_no_update
                    BEFORE UPDATE ON policy_publication_content
                    BEGIN SELECT RAISE(ABORT, 'policy content is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_approvals_no_update
                    BEFORE UPDATE ON policy_publication_approvals
                    BEGIN SELECT RAISE(ABORT, 'policy approval is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_approvals_no_delete
                    BEFORE DELETE ON policy_publication_approvals
                    BEGIN SELECT RAISE(ABORT, 'policy approval is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_idempotency_no_update
                    BEFORE UPDATE ON policy_publication_idempotency
                    BEGIN SELECT RAISE(ABORT, 'publication idempotency is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_idempotency_no_delete
                    BEFORE DELETE ON policy_publication_idempotency
                    BEGIN SELECT RAISE(ABORT, 'publication idempotency is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_audit_no_update
                    BEFORE UPDATE ON policy_publication_audit
                    BEGIN SELECT RAISE(ABORT, 'publication audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_audit_no_delete
                    BEFORE DELETE ON policy_publication_audit
                    BEGIN SELECT RAISE(ABORT, 'publication audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_access_no_update
                    BEFORE UPDATE ON policy_publication_access
                    BEGIN SELECT RAISE(ABORT, 'publication access is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_checkpoints_no_update
                    BEFORE UPDATE ON policy_publication_access_checkpoints
                    BEGIN SELECT RAISE(ABORT, 'access checkpoint is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_checkpoints_no_delete
                    BEFORE DELETE ON policy_publication_access_checkpoints
                    BEGIN SELECT RAISE(ABORT, 'access checkpoint is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_tombstones_no_update
                    BEFORE UPDATE ON policy_publication_content_tombstones
                    BEGIN SELECT RAISE(ABORT, 'content tombstone is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS policy_publication_tombstones_no_delete
                    BEFORE DELETE ON policy_publication_content_tombstones
                    BEGIN SELECT RAISE(ABORT, 'content tombstone is immutable'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO policy_publication_meta(key,value) "
                "VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM policy_publication_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise PolicyPublicationIntegrityError(
                    "unsupported policy publication schema"
                )

    @staticmethod
    def _artifact_body(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": ARTIFACT_SCHEMA,
            "tenant_id": str(row["tenant"]),
            "policy_id": str(row["policy_id"]),
            "version": int(row["version"]),
            "title": str(row["title"]),
            "author_id": str(row["author_id"]),
            "approval_mode": str(row["approval_mode"]),
            "content_sha256": str(row["content_sha256"]),
            "created_at": float(row["created_at"]),
        }

    @staticmethod
    def _link_body(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "tenant_id": str(row["tenant"]),
            "link_id": str(row["link_id"]),
            "policy_id": str(row["policy_id"]),
            "visibility": str(row["visibility"]),
            "status": str(row["status"]),
            "capability_sha256": row["capability_sha256"],
            "capability_generation": int(row["capability_generation"]),
            "revision": int(row["revision"]),
            "pointer_revision": int(row["pointer_revision"]),
            "current_version": row["current_version"],
            "effective_at": row["effective_at"],
            "expires_at": row["expires_at"],
            "scheduled_revoke_at": row["scheduled_revoke_at"],
            "created_by": str(row["created_by"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "revoked_at": row["revoked_at"],
        }

    @staticmethod
    def _job_body(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "tenant_id": str(row["tenant"]),
            "job_id": str(row["job_id"]),
            "action": str(row["action"]),
            "link_id": str(row["link_id"]),
            "target_version": row["target_version"],
            "scheduled_for": float(row["scheduled_for"]),
            "expires_at": row["expires_at"],
            "expected_revision": int(row["expected_revision"]),
            "scheduled_by": str(row["scheduled_by"]),
            "state": str(row["state"]),
            "attempts": int(row["attempts"]),
            "max_attempts": int(row["max_attempts"]),
            "next_attempt_at": float(row["next_attempt_at"]),
            "lease_owner": row["lease_owner"],
            "lease_token_sha256": row["lease_token_sha256"],
            "lease_until": row["lease_until"],
            "last_error_code": row["last_error_code"],
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "applied_at": row["applied_at"],
        }

    @staticmethod
    def _verify_link_row(row: Mapping[str, Any]) -> None:
        if not hmac.compare_digest(
            str(row["record_sha256"]),
            _sha256(PolicyPublicationStore._link_body(row)),
        ):
            raise PolicyPublicationIntegrityError("policy link digest changed")

    @staticmethod
    def _verify_job_row(row: Mapping[str, Any]) -> None:
        if not hmac.compare_digest(
            str(row["record_sha256"]),
            _sha256(PolicyPublicationStore._job_body(row)),
        ):
            raise PolicyPublicationIntegrityError("publication job digest changed")

    @staticmethod
    def _safe_link(row: Mapping[str, Any], *, now: float) -> dict[str, Any]:
        scheduled_revoke_at = row["scheduled_revoke_at"]
        expires_at = row["expires_at"]
        status = str(row["status"])
        effective_status = status
        if status == "active" and scheduled_revoke_at is not None:
            if now >= float(scheduled_revoke_at):
                effective_status = "revoked"
        if status == "active" and expires_at is not None and now >= float(expires_at):
            effective_status = "expired"
        return {
            "link_id": str(row["link_id"]),
            "policy_id": str(row["policy_id"]),
            "visibility": str(row["visibility"]),
            "status": status,
            "effective_status": effective_status,
            "capability_generation": int(row["capability_generation"]),
            "revision": int(row["revision"]),
            "pointer_revision": int(row["pointer_revision"]),
            "current_version": row["current_version"],
            "effective_at": row["effective_at"],
            "expires_at": expires_at,
            "scheduled_revoke_at": scheduled_revoke_at,
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "revoked_at": row["revoked_at"],
        }

    @staticmethod
    def _refresh_link_digest(
        connection: sqlite3.Connection, tenant: str, link_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
            (tenant, link_id),
        ).fetchone()
        if row is None:
            raise PolicyPublicationNotFound("policy link was not found")
        digest = _sha256(PolicyPublicationStore._link_body(row))
        connection.execute(
            "UPDATE policy_publication_links SET record_sha256=? "
            "WHERE tenant=? AND link_id=?",
            (digest, tenant, link_id),
        )
        return connection.execute(
            "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
            (tenant, link_id),
        ).fetchone()

    @staticmethod
    def _refresh_job_digest(
        connection: sqlite3.Connection, tenant: str, job_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM policy_publication_jobs WHERE tenant=? AND job_id=?",
            (tenant, job_id),
        ).fetchone()
        if row is None:
            raise PolicyPublicationNotFound("publication job was not found")
        digest = _sha256(PolicyPublicationStore._job_body(row))
        connection.execute(
            "UPDATE policy_publication_jobs SET record_sha256=? "
            "WHERE tenant=? AND job_id=?",
            (digest, tenant, job_id),
        )
        return connection.execute(
            "SELECT * FROM policy_publication_jobs WHERE tenant=? AND job_id=?",
            (tenant, job_id),
        ).fetchone()

    @staticmethod
    def _idempotent_result(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT * FROM policy_publication_idempotency "
            "WHERE tenant=? AND namespace=? AND key_sha256=?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(str(row["request_sha256"]), request_sha256):
            raise PolicyPublicationIdempotencyConflict(
                "idempotency key was already used for different publication content"
            )
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise PolicyPublicationIntegrityError(
                "stored idempotency result is invalid"
            )
        return result

    @staticmethod
    def _save_idempotency(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
        result: Mapping[str, Any],
        now: float,
    ) -> None:
        result_value = dict(result)
        _no_secret_details(result_value)
        result_json = _canonical(result_value).decode("ascii")
        result_sha256 = hashlib.sha256(result_json.encode("ascii")).hexdigest()
        record = {
            "tenant_id": tenant,
            "namespace": namespace,
            "key_sha256": key_sha256,
            "request_sha256": request_sha256,
            "result_sha256": result_sha256,
            "created_at": now,
        }
        connection.execute(
            "INSERT INTO policy_publication_idempotency(tenant,namespace,key_sha256,"
            "request_sha256,result_json,result_sha256,record_sha256,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                tenant,
                namespace,
                key_sha256,
                request_sha256,
                result_json,
                result_sha256,
                _sha256(record),
                now,
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        event_type: str,
        subject_id: str,
        details: Mapping[str, Any],
        now: float,
    ) -> str:
        event = _opaque(event_type, "audit event_type")
        subject = _opaque(subject_id, "audit subject_id")
        detail_value = dict(details)
        _no_secret_details(detail_value)
        details_json = _canonical(
            detail_value, maximum=_MAX_AUDIT_DETAILS_BYTES
        ).decode("ascii")
        details_sha256 = hashlib.sha256(details_json.encode("ascii")).hexdigest()
        previous = connection.execute(
            "SELECT event_sha256 FROM policy_publication_audit WHERE tenant=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        previous_sha256 = None if previous is None else str(previous["event_sha256"])
        event_id = self._new_id("PPA")
        body = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant,
            "event_id": event_id,
            "event_type": event,
            "subject_id": subject,
            "details_sha256": details_sha256,
            "previous_event_sha256": previous_sha256,
            "created_at": now,
        }
        event_sha256 = _sha256(body)
        connection.execute(
            "INSERT INTO policy_publication_audit(tenant,event_id,event_type,"
            "subject_id,details_json,details_sha256,previous_event_sha256,"
            "event_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                event_id,
                event,
                subject,
                details_json,
                details_sha256,
                previous_sha256,
                event_sha256,
                now,
            ),
        )
        return event_sha256

    def _access(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        link_id: str,
        output_format: str,
        outcome: str,
        credential_present: bool,
        request_context_sha256: str | None,
        now: float,
    ) -> None:
        context_digest = (
            None
            if request_context_sha256 is None
            else _digest(request_context_sha256, "request_context_sha256")
        )
        previous = connection.execute(
            "SELECT event_sha256 FROM policy_publication_access WHERE tenant=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        if previous is None:
            checkpoint = connection.execute(
                "SELECT last_event_sha256 FROM "
                "policy_publication_access_checkpoints WHERE tenant=? "
                "ORDER BY sequence DESC LIMIT 1",
                (tenant,),
            ).fetchone()
            previous_sha256 = (
                None if checkpoint is None else str(checkpoint["last_event_sha256"])
            )
        else:
            previous_sha256 = str(previous["event_sha256"])
        event_id = self._new_id("PAX")
        body = {
            "schema": ACCESS_SCHEMA,
            "tenant_id": tenant,
            "event_id": event_id,
            "link_id": link_id,
            "output_format": output_format,
            "outcome": outcome,
            "credential_present": credential_present,
            "request_context_sha256": context_digest,
            "previous_event_sha256": previous_sha256,
            "created_at": now,
        }
        event_sha256 = _sha256(body)
        connection.execute(
            "INSERT INTO policy_publication_access(tenant,event_id,link_id,"
            "output_format,outcome,credential_present,request_context_sha256,"
            "previous_event_sha256,event_sha256,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                event_id,
                link_id,
                output_format,
                outcome,
                int(credential_present),
                context_digest,
                previous_sha256,
                event_sha256,
                now,
            ),
        )

    @staticmethod
    def _artifact_row(
        connection: sqlite3.Connection, tenant: str, policy_id: str, version: int
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM policy_publication_artifacts "
            "WHERE tenant=? AND policy_id=? AND version=?",
            (tenant, policy_id, version),
        ).fetchone()
        if row is None:
            raise PolicyPublicationNotFound("policy version was not found")
        if not hmac.compare_digest(
            str(row["artifact_sha256"]),
            _sha256(PolicyPublicationStore._artifact_body(row)),
        ):
            raise PolicyPublicationIntegrityError("policy artifact digest changed")
        return row

    @staticmethod
    def _approval_summary(
        connection: sqlite3.Connection, artifact: Mapping[str, Any]
    ) -> dict[str, Any]:
        rows = connection.execute(
            "SELECT decision,reviewer_id FROM policy_publication_approvals "
            "WHERE tenant=? AND policy_id=? AND version=? ORDER BY reviewer_id",
            (artifact["tenant"], artifact["policy_id"], artifact["version"]),
        ).fetchall()
        approvals = sum(row["decision"] == "approve" for row in rows)
        rejections = sum(row["decision"] == "reject" for row in rows)
        mode = str(artifact["approval_mode"])
        required = {"none": 0, "approval": 1, "four_eyes": 2}[mode]
        ready = rejections == 0 and approvals >= required
        return {
            "approval_mode": mode,
            "required_approvals": required,
            "approval_count": approvals,
            "rejection_count": rejections,
            "ready_to_publish": ready,
        }

    @staticmethod
    def _require_publishable(
        connection: sqlite3.Connection, artifact: Mapping[str, Any]
    ) -> None:
        summary = PolicyPublicationStore._approval_summary(connection, artifact)
        if not summary["ready_to_publish"]:
            raise PolicyPublicationApprovalRequired(
                "policy version has not satisfied its independent approval gate"
            )
        content = connection.execute(
            "SELECT 1 FROM policy_publication_content "
            "WHERE tenant=? AND policy_id=? AND version=?",
            (artifact["tenant"], artifact["policy_id"], artifact["version"]),
        ).fetchone()
        if content is None:
            raise PolicyPublicationConflict(
                "policy content was retired and cannot be republished"
            )

    def publish_artifact(
        self,
        tenant_id: str,
        *,
        policy_id: str,
        version: int,
        title: str,
        body_text: str,
        author_id: str,
        approval_mode: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create one immutable plain-text policy version."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        policy = _opaque(policy_id, "policy_id")
        parsed_version = _positive_int(version, "version")
        normalized_title = _plain_text(
            title, "title", maximum=_MAX_TITLE_BYTES, multiline=False
        )
        normalized_body = _plain_text(
            body_text, "body_text", maximum=_MAX_BODY_BYTES, multiline=True
        )
        author = _opaque(author_id, "author_id")
        if approval_mode not in _APPROVAL_MODES:
            raise PolicyPublicationValidationError("approval_mode is not supported")
        key_sha256 = self._idempotency(idempotency_key)
        content = {"title": normalized_title, "body_text": normalized_body}
        content_sha256 = _sha256(content)
        request_sha256 = _sha256(
            {
                "policy_id": policy,
                "version": parsed_version,
                "content_sha256": content_sha256,
                "author_id": author,
                "approval_mode": approval_mode,
            }
        )
        now = self._now()
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace="publish_artifact",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if prior is not None:
                return {**prior, "idempotent_replay": True}
            existing = connection.execute(
                "SELECT 1 FROM policy_publication_artifacts "
                "WHERE tenant=? AND policy_id=? AND version=?",
                (tenant, policy, parsed_version),
            ).fetchone()
            if existing is not None:
                raise PolicyPublicationConflict("policy version already exists")
            artifact_values: dict[str, Any] = {
                "tenant": tenant,
                "policy_id": policy,
                "version": parsed_version,
                "title": normalized_title,
                "author_id": author,
                "approval_mode": approval_mode,
                "content_sha256": content_sha256,
                "created_at": now,
            }
            artifact_sha256 = _sha256(self._artifact_body(artifact_values))
            connection.execute(
                "INSERT INTO policy_publication_artifacts(tenant,policy_id,version,"
                "title,author_id,approval_mode,content_sha256,artifact_sha256,"
                "created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    policy,
                    parsed_version,
                    normalized_title,
                    author,
                    approval_mode,
                    content_sha256,
                    artifact_sha256,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO policy_publication_content(tenant,policy_id,version,"
                "content_json,content_sha256,created_at) VALUES(?,?,?,?,?,?)",
                (
                    tenant,
                    policy,
                    parsed_version,
                    _canonical(content).decode("ascii"),
                    content_sha256,
                    now,
                ),
            )
            result = {
                "policy_id": policy,
                "version": parsed_version,
                "title": normalized_title,
                "approval_mode": approval_mode,
                "artifact_sha256": artifact_sha256,
                "content_sha256": content_sha256,
                "created_at": now,
                "idempotent_replay": False,
            }
            self._audit(
                connection,
                tenant=tenant,
                event_type="artifact_created",
                subject_id=policy,
                details={
                    "version": parsed_version,
                    "artifact_sha256": artifact_sha256,
                    "approval_mode": approval_mode,
                    "author_id": author,
                },
                now=now,
            )
            saved = {**result}
            saved.pop("idempotent_replay")
            self._save_idempotency(
                connection,
                tenant=tenant,
                namespace="publish_artifact",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=saved,
                now=now,
            )
            return result

    def approve_artifact(
        self,
        tenant_id: str,
        *,
        policy_id: str,
        version: int,
        reviewer_id: str,
        decision: str,
        idempotency_key: str,
        rationale_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Record one immutable independent reviewer decision."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        policy = _opaque(policy_id, "policy_id")
        parsed_version = _positive_int(version, "version")
        reviewer = _opaque(reviewer_id, "reviewer_id")
        if decision not in _DECISIONS:
            raise PolicyPublicationValidationError("decision is not supported")
        rationale = (
            None
            if rationale_sha256 is None
            else _digest(rationale_sha256, "rationale_sha256")
        )
        key_sha256 = self._idempotency(idempotency_key)
        request_sha256 = _sha256(
            {
                "policy_id": policy,
                "version": parsed_version,
                "reviewer_id": reviewer,
                "decision": decision,
                "rationale_sha256": rationale,
            }
        )
        now = self._now()
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace="approve_artifact",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if prior is not None:
                return {**prior, "idempotent_replay": True}
            artifact = self._artifact_row(connection, tenant, policy, parsed_version)
            if artifact["approval_mode"] == "none":
                raise PolicyPublicationConflict(
                    "this policy version has no approval workflow"
                )
            if hmac.compare_digest(str(artifact["author_id"]), reviewer):
                raise PolicyPublicationConflict(
                    "the policy author cannot satisfy an independent approval gate"
                )
            body = {
                "tenant_id": tenant,
                "policy_id": policy,
                "version": parsed_version,
                "reviewer_id": reviewer,
                "decision": decision,
                "rationale_sha256": rationale,
                "created_at": now,
            }
            approval_sha256 = _sha256(body)
            try:
                connection.execute(
                    "INSERT INTO policy_publication_approvals(tenant,policy_id,"
                    "version,reviewer_id,decision,rationale_sha256,approval_sha256,"
                    "created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        policy,
                        parsed_version,
                        reviewer,
                        decision,
                        rationale,
                        approval_sha256,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise PolicyPublicationConflict(
                    "reviewer already decided this immutable version"
                ) from exc
            summary = self._approval_summary(connection, artifact)
            result = {
                "policy_id": policy,
                "version": parsed_version,
                "reviewer_id": reviewer,
                "decision": decision,
                "approval_sha256": approval_sha256,
                **summary,
                "idempotent_replay": False,
            }
            self._audit(
                connection,
                tenant=tenant,
                event_type="artifact_reviewed",
                subject_id=policy,
                details={
                    "version": parsed_version,
                    "reviewer_id": reviewer,
                    "decision": decision,
                    "approval_sha256": approval_sha256,
                },
                now=now,
            )
            saved = {**result}
            saved.pop("idempotent_replay")
            self._save_idempotency(
                connection,
                tenant=tenant,
                namespace="approve_artifact",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=saved,
                now=now,
            )
            return result

    def artifact_status(
        self, tenant_id: str, *, policy_id: str, version: int
    ) -> dict[str, Any]:
        """Return immutable version metadata and its approval readiness."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        policy = _opaque(policy_id, "policy_id")
        parsed_version = _positive_int(version, "version")
        with self._connect() as connection:
            artifact = self._artifact_row(connection, tenant, policy, parsed_version)
            content = connection.execute(
                "SELECT 1 FROM policy_publication_content "
                "WHERE tenant=? AND policy_id=? AND version=?",
                (tenant, policy, parsed_version),
            ).fetchone()
            return {
                "policy_id": policy,
                "version": parsed_version,
                "title": str(artifact["title"]),
                "author_id": str(artifact["author_id"]),
                "artifact_sha256": str(artifact["artifact_sha256"]),
                "content_sha256": str(artifact["content_sha256"]),
                "content_available": content is not None,
                "created_at": float(artifact["created_at"]),
                **self._approval_summary(connection, artifact),
            }

    def create_link(
        self,
        tenant_id: str,
        *,
        policy_id: str,
        visibility: str,
        created_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create one stable public or private policy-family link.

        A private capability is present only on the first successful return.
        Idempotent retries return the stable link metadata but never replay the
        raw capability.
        """

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        policy = _opaque(policy_id, "policy_id")
        if visibility not in _VISIBILITIES:
            raise PolicyPublicationValidationError("visibility is not supported")
        creator = _opaque(created_by, "created_by")
        key_sha256 = self._idempotency(idempotency_key)
        request_sha256 = _sha256(
            {"policy_id": policy, "visibility": visibility, "created_by": creator}
        )
        now = self._now()
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace="create_link",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if prior is not None:
                return {
                    **prior,
                    "private_capability": None,
                    "capability_returned": False,
                    "idempotent_replay": True,
                }
            exists = connection.execute(
                "SELECT 1 FROM policy_publication_artifacts "
                "WHERE tenant=? AND policy_id=? LIMIT 1",
                (tenant, policy),
            ).fetchone()
            if exists is None:
                raise PolicyPublicationNotFound("policy family was not found")
            link_id = self._new_id("PPL")
            raw_capability = self._new_capability() if visibility == "private" else None
            capability_sha256 = (
                None
                if raw_capability is None
                else hashlib.sha256(raw_capability.encode("ascii")).hexdigest()
            )
            values: dict[str, Any] = {
                "tenant": tenant,
                "link_id": link_id,
                "policy_id": policy,
                "visibility": visibility,
                "status": "active",
                "capability_sha256": capability_sha256,
                "capability_generation": 1 if raw_capability is not None else 0,
                "revision": 0,
                "pointer_revision": 0,
                "current_version": None,
                "effective_at": None,
                "expires_at": None,
                "scheduled_revoke_at": None,
                "created_by": creator,
                "created_at": now,
                "updated_at": now,
                "revoked_at": None,
            }
            record_sha256 = _sha256(self._link_body(values))
            connection.execute(
                "INSERT INTO policy_publication_links(tenant,link_id,policy_id,"
                "visibility,status,capability_sha256,capability_generation,revision,"
                "pointer_revision,current_version,effective_at,expires_at,"
                "scheduled_revoke_at,created_by,created_at,updated_at,revoked_at,"
                "record_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    link_id,
                    policy,
                    visibility,
                    "active",
                    capability_sha256,
                    values["capability_generation"],
                    0,
                    0,
                    None,
                    None,
                    None,
                    None,
                    creator,
                    now,
                    now,
                    None,
                    record_sha256,
                ),
            )
            safe_result = {
                "link_id": link_id,
                "policy_id": policy,
                "visibility": visibility,
                "status": "active",
                "capability_generation": values["capability_generation"],
                "revision": 0,
                "pointer_revision": 0,
                "created_at": now,
            }
            self._audit(
                connection,
                tenant=tenant,
                event_type="link_created",
                subject_id=link_id,
                details={
                    "policy_id": policy,
                    "visibility": visibility,
                    "created_by": creator,
                    "capability_generation": values["capability_generation"],
                },
                now=now,
            )
            self._save_idempotency(
                connection,
                tenant=tenant,
                namespace="create_link",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=safe_result,
                now=now,
            )
            return {
                **safe_result,
                "private_capability": raw_capability,
                "capability_returned": raw_capability is not None,
                "idempotent_replay": False,
            }

    def list_artifacts(self, tenant_id: str, *, limit: int = 200) -> dict[str, Any]:
        """Newest-first policy versions with their approval readiness (read-only)."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        bound = _positive_int(limit, "limit", maximum=_MAX_LIST_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_publication_artifacts WHERE tenant=? "
                "ORDER BY created_at DESC, policy_id, version DESC LIMIT ?",
                (tenant, bound + 1),
            ).fetchall()
            items = []
            for row in rows[:bound]:
                artifact = self._artifact_row(
                    connection, tenant, str(row["policy_id"]), int(row["version"])
                )
                items.append(
                    {
                        "policy_id": str(artifact["policy_id"]),
                        "version": int(artifact["version"]),
                        "title": str(artifact["title"]),
                        "author_id": str(artifact["author_id"]),
                        "created_at": float(artifact["created_at"]),
                        **self._approval_summary(connection, artifact),
                    }
                )
        return {"items": items, "truncated": len(rows) > bound}

    def list_links(self, tenant_id: str, *, limit: int = 200) -> dict[str, Any]:
        """Safe metadata of every link, newest first; no credential digest."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        bound = _positive_int(limit, "limit", maximum=_MAX_LIST_LIMIT)
        now = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=? "
                "ORDER BY created_at DESC, link_id LIMIT ?",
                (tenant, bound + 1),
            ).fetchall()
        items = []
        for row in rows[:bound]:
            self._verify_link_row(row)
            items.append(self._safe_link(row, now=now))
        return {"items": items, "truncated": len(rows) > bound}

    def list_jobs(self, tenant_id: str, *, limit: int = 200) -> dict[str, Any]:
        """Scheduled publication work, newest first; never lease material."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        bound = _positive_int(limit, "limit", maximum=_MAX_LIST_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_publication_jobs WHERE tenant=? "
                "ORDER BY scheduled_for DESC, job_id LIMIT ?",
                (tenant, bound + 1),
            ).fetchall()
        items = []
        for row in rows[:bound]:
            self._verify_job_row(row)
            items.append(
                {
                    "job_id": str(row["job_id"]),
                    "action": str(row["action"]),
                    "link_id": str(row["link_id"]),
                    "target_version": row["target_version"],
                    "scheduled_for": float(row["scheduled_for"]),
                    "expires_at": row["expires_at"],
                    "state": str(row["state"]),
                    "attempts": int(row["attempts"]),
                    "max_attempts": int(row["max_attempts"]),
                    "last_error_code": row["last_error_code"],
                    "applied_at": row["applied_at"],
                }
            )
        return {"items": items, "truncated": len(rows) > bound}

    def get_link(self, tenant_id: str, *, link_id: str) -> dict[str, Any]:
        """Return safe link metadata without any credential digest."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        link = _opaque(link_id, "link_id")
        now = self._now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
                (tenant, link),
            ).fetchone()
            if row is None:
                raise PolicyPublicationNotFound("policy link was not found")
            self._verify_link_row(row)
            return self._safe_link(row, now=now)

    def _set_pointer(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        link_id: str,
        version: int,
        expected_pointer_revision: int,
        effective_at: float,
        expires_at: float | None,
        actor_id: str,
        now: float,
    ) -> tuple[sqlite3.Row, bool]:
        link = connection.execute(
            "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
            (tenant, link_id),
        ).fetchone()
        if link is None:
            raise PolicyPublicationNotFound("policy link was not found")
        self._verify_link_row(link)
        if int(link["pointer_revision"]) != expected_pointer_revision:
            raise PolicyPublicationConflict("policy pointer revision changed")
        if link["status"] != "active":
            raise PolicyPublicationConflict("policy link is revoked")
        scheduled_revoke_at = link["scheduled_revoke_at"]
        if scheduled_revoke_at is not None and now >= float(scheduled_revoke_at):
            raise PolicyPublicationConflict("scheduled link revocation is effective")
        artifact = self._artifact_row(
            connection, tenant, str(link["policy_id"]), version
        )
        self._require_publishable(connection, artifact)
        if expires_at is not None and expires_at <= effective_at:
            raise PolicyPublicationValidationError(
                "expires_at must be later than the publication effective time"
            )
        if link["current_version"] == version and link["expires_at"] == expires_at:
            return link, True
        changed = connection.execute(
            "UPDATE policy_publication_links SET current_version=?,effective_at=?,"
            "expires_at=?,pointer_revision=pointer_revision+1,updated_at=? "
            "WHERE tenant=? AND link_id=? AND pointer_revision=? AND status='active'",
            (
                version,
                effective_at,
                expires_at,
                now,
                tenant,
                link_id,
                expected_pointer_revision,
            ),
        ).rowcount
        if changed != 1:
            raise PolicyPublicationConflict("policy pointer CAS failed")
        row = self._refresh_link_digest(connection, tenant, link_id)
        self._audit(
            connection,
            tenant=tenant,
            event_type="pointer_published",
            subject_id=link_id,
            details={
                "policy_id": str(link["policy_id"]),
                "version": version,
                "pointer_revision": int(row["pointer_revision"]),
                "effective_at": effective_at,
                "expires_at": expires_at,
                "actor_id": actor_id,
            },
            now=now,
        )
        return row, False

    def publish_version(
        self,
        tenant_id: str,
        *,
        link_id: str,
        version: int,
        expected_pointer_revision: int,
        actor_id: str,
        idempotency_key: str,
        expires_at: float | None = None,
    ) -> dict[str, Any]:
        """Immediately move the exact current-version pointer with CAS."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        link = _opaque(link_id, "link_id")
        parsed_version = _positive_int(version, "version")
        expected = _revision(expected_pointer_revision, "expected_pointer_revision")
        actor = _opaque(actor_id, "actor_id")
        expiry = _finite_time(expires_at, "expires_at", allow_none=True)
        key_sha256 = self._idempotency(idempotency_key)
        request_sha256 = _sha256(
            {
                "link_id": link,
                "version": parsed_version,
                "expected_pointer_revision": expected,
                "actor_id": actor,
                "expires_at": expiry,
            }
        )
        now = self._now()
        if expiry is not None and expiry <= now:
            raise PolicyPublicationValidationError("expires_at must be in the future")
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace="publish_version",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if prior is not None:
                return {**prior, "idempotent_replay": True}
            row, no_change = self._set_pointer(
                connection,
                tenant=tenant,
                link_id=link,
                version=parsed_version,
                expected_pointer_revision=expected,
                effective_at=now,
                expires_at=expiry,
                actor_id=actor,
                now=now,
            )
            if no_change:
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="pointer_no_change",
                    subject_id=link,
                    details={
                        "version": parsed_version,
                        "pointer_revision": expected,
                        "actor_id": actor,
                    },
                    now=now,
                )
            result = {
                "link_id": link,
                "policy_id": str(row["policy_id"]),
                "current_version": int(row["current_version"]),
                "pointer_revision": int(row["pointer_revision"]),
                "effective_at": float(row["effective_at"]),
                "expires_at": row["expires_at"],
                "no_change": no_change,
            }
            self._save_idempotency(
                connection,
                tenant=tenant,
                namespace="publish_version",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=result,
                now=now,
            )
        if not no_change:
            _emit_published(result, actor)
        return {**result, "idempotent_replay": False}

    def rotate_private_capability(
        self,
        tenant_id: str,
        *,
        link_id: str,
        expected_revision: int,
        actor_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Rotate a private bearer capability and reveal the new value once."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        link = _opaque(link_id, "link_id")
        expected = _revision(expected_revision)
        actor = _opaque(actor_id, "actor_id")
        key_sha256 = self._idempotency(idempotency_key)
        request_sha256 = _sha256(
            {"link_id": link, "expected_revision": expected, "actor_id": actor}
        )
        now = self._now()
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace="rotate_private_capability",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if prior is not None:
                return {
                    **prior,
                    "private_capability": None,
                    "capability_returned": False,
                    "idempotent_replay": True,
                }
            row = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
                (tenant, link),
            ).fetchone()
            if row is None:
                raise PolicyPublicationNotFound("policy link was not found")
            self._verify_link_row(row)
            if row["visibility"] != "private" or row["status"] != "active":
                raise PolicyPublicationConflict("only active private links can rotate")
            if row["scheduled_revoke_at"] is not None:
                raise PolicyPublicationConflict(
                    "a link scheduled for revocation cannot rotate authority"
                )
            if int(row["revision"]) != expected:
                raise PolicyPublicationConflict("policy link revision changed")
            raw_capability = self._new_capability()
            capability_sha256 = hashlib.sha256(
                raw_capability.encode("ascii")
            ).hexdigest()
            changed = connection.execute(
                "UPDATE policy_publication_links SET capability_sha256=?,"
                "capability_generation=capability_generation+1,revision=revision+1,"
                "updated_at=? WHERE tenant=? AND link_id=? AND revision=? "
                "AND status='active' AND scheduled_revoke_at IS NULL",
                (capability_sha256, now, tenant, link, expected),
            ).rowcount
            if changed != 1:
                raise PolicyPublicationConflict("private capability rotation CAS failed")
            updated = self._refresh_link_digest(connection, tenant, link)
            safe = {
                "link_id": link,
                "revision": int(updated["revision"]),
                "capability_generation": int(updated["capability_generation"]),
            }
            self._audit(
                connection,
                tenant=tenant,
                event_type="capability_rotated",
                subject_id=link,
                details={
                    "actor_id": actor,
                    "revision": safe["revision"],
                    "capability_generation": safe["capability_generation"],
                },
                now=now,
            )
            self._save_idempotency(
                connection,
                tenant=tenant,
                namespace="rotate_private_capability",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=safe,
                now=now,
            )
            return {
                **safe,
                "private_capability": raw_capability,
                "capability_returned": True,
                "idempotent_replay": False,
            }

    def revoke_link(
        self,
        tenant_id: str,
        *,
        link_id: str,
        expected_revision: int,
        actor_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Immediately and irreversibly revoke one stable link."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        link = _opaque(link_id, "link_id")
        expected = _revision(expected_revision)
        actor = _opaque(actor_id, "actor_id")
        key_sha256 = self._idempotency(idempotency_key)
        request_sha256 = _sha256(
            {"link_id": link, "expected_revision": expected, "actor_id": actor}
        )
        now = self._now()
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace="revoke_link",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if prior is not None:
                return {**prior, "idempotent_replay": True}
            current = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
                (tenant, link),
            ).fetchone()
            if current is None:
                raise PolicyPublicationNotFound("policy link was not found")
            self._verify_link_row(current)
            if int(current["revision"]) != expected or current["status"] != "active":
                raise PolicyPublicationConflict("policy link revocation CAS failed")
            changed = connection.execute(
                "UPDATE policy_publication_links SET status='revoked',"
                "capability_sha256=NULL,current_version=NULL,effective_at=NULL,"
                "expires_at=NULL,scheduled_revoke_at=NULL,revision=revision+1,"
                "pointer_revision=pointer_revision+1,updated_at=?,revoked_at=? "
                "WHERE tenant=? AND link_id=? AND revision=? AND status='active'",
                (now, now, tenant, link, expected),
            ).rowcount
            if changed != 1:
                raise PolicyPublicationConflict("policy link revocation CAS failed")
            row = self._refresh_link_digest(connection, tenant, link)
            result = {
                "link_id": link,
                "status": "revoked",
                "revision": int(row["revision"]),
                "pointer_revision": int(row["pointer_revision"]),
                "revoked_at": now,
            }
            self._audit(
                connection,
                tenant=tenant,
                event_type="link_revoked",
                subject_id=link,
                details={"actor_id": actor, "revision": int(row["revision"])},
                now=now,
            )
            self._save_idempotency(
                connection,
                tenant=tenant,
                namespace="revoke_link",
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=result,
                now=now,
            )
            return {**result, "idempotent_replay": False}

    def _insert_job(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        action: str,
        link_id: str,
        target_version: int | None,
        scheduled_for: float,
        expires_at: float | None,
        expected_revision: int,
        scheduled_by: str,
        max_attempts: int,
        now: float,
    ) -> sqlite3.Row:
        count = connection.execute(
            "SELECT COUNT(*) AS n FROM policy_publication_jobs "
            "WHERE tenant=? AND state IN ('pending','leased')",
            (tenant,),
        ).fetchone()
        if count is not None and int(count["n"]) >= _MAX_PENDING_JOBS:
            raise PolicyPublicationConflict("tenant publication job bound reached")
        job_id = self._new_id("PPJ")
        values: dict[str, Any] = {
            "tenant": tenant,
            "job_id": job_id,
            "action": action,
            "link_id": link_id,
            "target_version": target_version,
            "scheduled_for": scheduled_for,
            "expires_at": expires_at,
            "expected_revision": expected_revision,
            "scheduled_by": scheduled_by,
            "state": "pending",
            "attempts": 0,
            "max_attempts": max_attempts,
            "next_attempt_at": scheduled_for,
            "lease_owner": None,
            "lease_token_sha256": None,
            "lease_until": None,
            "last_error_code": None,
            "created_at": now,
            "updated_at": now,
            "applied_at": None,
        }
        connection.execute(
            "INSERT INTO policy_publication_jobs(tenant,job_id,action,link_id,"
            "target_version,scheduled_for,expires_at,expected_revision,scheduled_by,"
            "state,attempts,max_attempts,next_attempt_at,lease_owner,"
            "lease_token_sha256,lease_until,last_error_code,created_at,updated_at,"
            "applied_at,record_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                job_id,
                action,
                link_id,
                target_version,
                scheduled_for,
                expires_at,
                expected_revision,
                scheduled_by,
                "pending",
                0,
                max_attempts,
                scheduled_for,
                None,
                None,
                None,
                None,
                now,
                now,
                None,
                _sha256(self._job_body(values)),
            ),
        )
        return connection.execute(
            "SELECT * FROM policy_publication_jobs WHERE tenant=? AND job_id=?",
            (tenant, job_id),
        ).fetchone()

    def schedule_publication(
        self,
        tenant_id: str,
        *,
        link_id: str,
        version: int,
        scheduled_for: float,
        expected_pointer_revision: int,
        scheduled_by: str,
        idempotency_key: str,
        expires_at: float | None = None,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        """Schedule an exact artifact version for CAS publication."""

        return self._schedule(
            tenant_id,
            action="publish",
            link_id=link_id,
            target_version=version,
            scheduled_for=scheduled_for,
            expires_at=expires_at,
            expected_revision=expected_pointer_revision,
            scheduled_by=scheduled_by,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )

    def schedule_expiry(
        self,
        tenant_id: str,
        *,
        link_id: str,
        version: int,
        scheduled_for: float,
        expected_pointer_revision: int,
        scheduled_by: str,
        idempotency_key: str,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        """Set fail-closed expiry now and schedule pointer cleanup."""

        return self._schedule(
            tenant_id,
            action="expire",
            link_id=link_id,
            target_version=version,
            scheduled_for=scheduled_for,
            expires_at=None,
            expected_revision=expected_pointer_revision,
            scheduled_by=scheduled_by,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )

    def schedule_revocation(
        self,
        tenant_id: str,
        *,
        link_id: str,
        scheduled_for: float,
        expected_revision: int,
        scheduled_by: str,
        idempotency_key: str,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        """Set fail-closed revocation time now and schedule final cleanup."""

        return self._schedule(
            tenant_id,
            action="revoke",
            link_id=link_id,
            target_version=None,
            scheduled_for=scheduled_for,
            expires_at=None,
            expected_revision=expected_revision,
            scheduled_by=scheduled_by,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )

    def _schedule(
        self,
        tenant_id: str,
        *,
        action: str,
        link_id: str,
        target_version: int | None,
        scheduled_for: float,
        expires_at: float | None,
        expected_revision: int,
        scheduled_by: str,
        idempotency_key: str,
        max_attempts: int,
    ) -> dict[str, Any]:
        self._require_enabled()
        tenant = self._tenant(tenant_id)
        if action not in _JOB_ACTIONS:
            raise PolicyPublicationValidationError("job action is not supported")
        link = _opaque(link_id, "link_id")
        version = (
            None
            if target_version is None
            else _positive_int(target_version, "target_version")
        )
        if action in {"publish", "expire"} and version is None:
            raise PolicyPublicationValidationError("job action requires a version")
        if action == "revoke" and version is not None:
            raise PolicyPublicationValidationError("revocation cannot target a version")
        due = _finite_time(scheduled_for, "scheduled_for")
        assert due is not None
        expiry = _finite_time(expires_at, "expires_at", allow_none=True)
        expected = _revision(expected_revision)
        actor = _opaque(scheduled_by, "scheduled_by")
        attempts = _positive_int(
            max_attempts, "max_attempts", maximum=_MAX_JOB_ATTEMPTS
        )
        key_sha256 = self._idempotency(idempotency_key)
        request_sha256 = _sha256(
            {
                "action": action,
                "link_id": link,
                "target_version": version,
                "scheduled_for": due,
                "expires_at": expiry,
                "expected_revision": expected,
                "scheduled_by": actor,
                "max_attempts": attempts,
            }
        )
        now = self._now()
        if due <= now:
            raise PolicyPublicationValidationError(
                "scheduled_for must be in the future; use an immediate operation"
            )
        if expiry is not None and expiry <= due:
            raise PolicyPublicationValidationError(
                "expires_at must be later than scheduled_for"
            )
        namespace = f"schedule_{action}"
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace=namespace,
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if prior is not None:
                return {**prior, "idempotent_replay": True}
            link_row = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
                (tenant, link),
            ).fetchone()
            if link_row is None:
                raise PolicyPublicationNotFound("policy link was not found")
            self._verify_link_row(link_row)
            if link_row["status"] != "active":
                raise PolicyPublicationConflict("policy link is revoked")
            job_expected = expected
            if action == "publish":
                if int(link_row["pointer_revision"]) != expected:
                    raise PolicyPublicationConflict("policy pointer revision changed")
                assert version is not None
                self._artifact_row(
                    connection, tenant, str(link_row["policy_id"]), version
                )
            elif action == "expire":
                if (
                    int(link_row["pointer_revision"]) != expected
                    or link_row["current_version"] != version
                ):
                    raise PolicyPublicationConflict("policy expiry pointer CAS failed")
                connection.execute(
                    "UPDATE policy_publication_links SET expires_at=?,"
                    "pointer_revision=pointer_revision+1,updated_at=? "
                    "WHERE tenant=? AND link_id=? AND pointer_revision=?",
                    (due, now, tenant, link, expected),
                )
                link_row = self._refresh_link_digest(connection, tenant, link)
                job_expected = int(link_row["pointer_revision"])
            else:
                if int(link_row["revision"]) != expected:
                    raise PolicyPublicationConflict("policy link revision changed")
                if link_row["scheduled_revoke_at"] is not None:
                    raise PolicyPublicationConflict("link revocation is already scheduled")
                connection.execute(
                    "UPDATE policy_publication_links SET scheduled_revoke_at=?,"
                    "revision=revision+1,updated_at=? WHERE tenant=? AND link_id=? "
                    "AND revision=? AND scheduled_revoke_at IS NULL",
                    (due, now, tenant, link, expected),
                )
                link_row = self._refresh_link_digest(connection, tenant, link)
                job_expected = int(link_row["revision"])
            job = self._insert_job(
                connection,
                tenant=tenant,
                action=action,
                link_id=link,
                target_version=version,
                scheduled_for=due,
                expires_at=expiry,
                expected_revision=job_expected,
                scheduled_by=actor,
                max_attempts=attempts,
                now=now,
            )
            result = {
                "job_id": str(job["job_id"]),
                "action": action,
                "link_id": link,
                "target_version": version,
                "scheduled_for": due,
                "expires_at": expiry,
                "expected_revision": job_expected,
                "state": "pending",
            }
            self._audit(
                connection,
                tenant=tenant,
                event_type=f"{action}_scheduled",
                subject_id=link,
                details={
                    "job_id": str(job["job_id"]),
                    "target_version": version,
                    "scheduled_for": due,
                    "expires_at": expiry,
                    "expected_revision": job_expected,
                    "scheduled_by": actor,
                },
                now=now,
            )
            self._save_idempotency(
                connection,
                tenant=tenant,
                namespace=namespace,
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=result,
                now=now,
            )
            return {**result, "idempotent_replay": False}

    def _recover_expired_leases(
        self, connection: sqlite3.Connection, *, tenant: str, now: float
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM policy_publication_jobs WHERE tenant=? AND state='leased' "
            "AND lease_until<=? ORDER BY job_id LIMIT ?",
            (tenant, now, _MAX_CLAIM_LIMIT),
        ).fetchall()
        for row in rows:
            self._verify_job_row(row)
            terminal = int(row["attempts"]) >= int(row["max_attempts"])
            state = "failed" if terminal else "pending"
            error = "lease_exhausted" if terminal else "lease_recovered"
            connection.execute(
                "UPDATE policy_publication_jobs SET state=?,next_attempt_at=?,"
                "lease_owner=NULL,lease_token_sha256=NULL,lease_until=NULL,"
                "last_error_code=?,updated_at=? WHERE tenant=? AND job_id=? "
                "AND state='leased' AND lease_until<=?",
                (
                    state,
                    now,
                    error,
                    now,
                    tenant,
                    row["job_id"],
                    now,
                ),
            )
            updated = self._refresh_job_digest(connection, tenant, str(row["job_id"]))
            self._audit(
                connection,
                tenant=tenant,
                event_type="job_lease_recovered",
                subject_id=str(row["job_id"]),
                details={
                    "state": str(updated["state"]),
                    "attempts": int(updated["attempts"]),
                },
                now=now,
            )

    def claim_due_jobs(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 20,
        lease_seconds: float = 60.0,
    ) -> tuple[PublicationClaim, ...]:
        """Lease a bounded due-job batch with expired-lease recovery."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        worker = _opaque(worker_id, "worker_id")
        parsed_limit = _positive_int(limit, "limit", maximum=_MAX_CLAIM_LIMIT)
        lease = _bounded_float(
            lease_seconds, "lease_seconds", maximum=_MAX_LEASE_SECONDS
        )
        now = self._now()
        with self._transaction() as connection:
            self._recover_expired_leases(connection, tenant=tenant, now=now)
            rows = connection.execute(
                "SELECT * FROM policy_publication_jobs WHERE tenant=? "
                "AND state='pending' AND next_attempt_at<=? "
                "ORDER BY next_attempt_at,job_id LIMIT ?",
                (tenant, now, parsed_limit),
            ).fetchall()
            claims: list[PublicationClaim] = []
            for row in rows:
                self._verify_job_row(row)
                raw_token = self._new_capability()
                token_sha256 = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
                changed = connection.execute(
                    "UPDATE policy_publication_jobs SET state='leased',"
                    "attempts=attempts+1,lease_owner=?,lease_token_sha256=?,"
                    "lease_until=?,last_error_code=NULL,updated_at=? "
                    "WHERE tenant=? AND job_id=? AND state='pending'",
                    (
                        worker,
                        token_sha256,
                        now + lease,
                        now,
                        tenant,
                        row["job_id"],
                    ),
                ).rowcount
                if changed != 1:
                    continue
                updated = self._refresh_job_digest(
                    connection, tenant, str(row["job_id"])
                )
                claim = PublicationClaim(
                    tenant_id=tenant,
                    job_id=str(updated["job_id"]),
                    action=str(updated["action"]),
                    link_id=str(updated["link_id"]),
                    target_version=updated["target_version"],
                    scheduled_for=float(updated["scheduled_for"]),
                    expires_at=updated["expires_at"],
                    expected_revision=int(updated["expected_revision"]),
                    attempt=int(updated["attempts"]),
                    worker_id=worker,
                    lease_token=raw_token,
                )
                claims.append(claim)
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="job_claimed",
                    subject_id=claim.job_id,
                    details={
                        "action": claim.action,
                        "attempt": claim.attempt,
                        "worker_id": worker,
                        "lease_until": now + lease,
                    },
                    now=now,
                )
            return tuple(claims)

    @staticmethod
    def _claim_row(
        connection: sqlite3.Connection, claim: PublicationClaim, *, now: float
    ) -> sqlite3.Row:
        if not isinstance(claim, PublicationClaim):
            raise PolicyPublicationValidationError("claim must be a PublicationClaim")
        row = connection.execute(
            "SELECT * FROM policy_publication_jobs WHERE tenant=? AND job_id=?",
            (claim.tenant_id, claim.job_id),
        ).fetchone()
        if row is None:
            raise PolicyPublicationLeaseLost("publication claim no longer exists")
        try:
            token_sha256 = hashlib.sha256(
                _opaque(
                    claim.lease_token, "lease token", _CAPABILITY_RE
                ).encode("ascii")
            ).hexdigest()
        except PolicyPublicationValidationError as exc:
            raise PolicyPublicationLeaseLost("publication claim is invalid") from exc
        if (
            row["state"] != "leased"
            or row["lease_owner"] != claim.worker_id
            or row["lease_until"] is None
            or float(row["lease_until"]) <= now
            or row["lease_token_sha256"] is None
            or not hmac.compare_digest(str(row["lease_token_sha256"]), token_sha256)
            or int(row["attempts"]) != claim.attempt
            or row["action"] != claim.action
            or row["link_id"] != claim.link_id
            or row["target_version"] != claim.target_version
            or int(row["expected_revision"]) != claim.expected_revision
        ):
            raise PolicyPublicationLeaseLost("publication claim lost its lease")
        PolicyPublicationStore._verify_job_row(row)
        return row

    def apply_claim(self, claim: PublicationClaim) -> dict[str, Any]:
        """Apply one claimed scheduled action from stored authority."""

        self._require_enabled()
        now = self._now()
        with self._transaction() as connection:
            job = self._claim_row(connection, claim, now=now)
            link = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
                (claim.tenant_id, claim.link_id),
            ).fetchone()
            if link is None:
                raise PolicyPublicationNotFound("scheduled policy link was not found")
            self._verify_link_row(link)
            action = str(job["action"])
            if action == "publish":
                assert job["target_version"] is not None
                updated, _ = self._set_pointer(
                    connection,
                    tenant=claim.tenant_id,
                    link_id=claim.link_id,
                    version=int(job["target_version"]),
                    expected_pointer_revision=int(job["expected_revision"]),
                    effective_at=float(job["scheduled_for"]),
                    expires_at=job["expires_at"],
                    actor_id=str(job["scheduled_by"]),
                    now=now,
                )
                applied_revision = int(updated["pointer_revision"])
            elif action == "expire":
                if (
                    int(link["pointer_revision"]) != int(job["expected_revision"])
                    or link["current_version"] != job["target_version"]
                    or link["expires_at"] != job["scheduled_for"]
                    or now < float(job["scheduled_for"])
                ):
                    raise PolicyPublicationConflict("scheduled expiry CAS failed")
                connection.execute(
                    "UPDATE policy_publication_links SET current_version=NULL,"
                    "effective_at=NULL,expires_at=NULL,"
                    "pointer_revision=pointer_revision+1,updated_at=? "
                    "WHERE tenant=? AND link_id=? AND pointer_revision=?",
                    (
                        now,
                        claim.tenant_id,
                        claim.link_id,
                        job["expected_revision"],
                    ),
                )
                updated = self._refresh_link_digest(
                    connection, claim.tenant_id, claim.link_id
                )
                applied_revision = int(updated["pointer_revision"])
                self._audit(
                    connection,
                    tenant=claim.tenant_id,
                    event_type="pointer_expired",
                    subject_id=claim.link_id,
                    details={
                        "version": job["target_version"],
                        "pointer_revision": applied_revision,
                    },
                    now=now,
                )
            else:
                if (
                    int(link["revision"]) != int(job["expected_revision"])
                    or link["scheduled_revoke_at"] != job["scheduled_for"]
                    or now < float(job["scheduled_for"])
                    or link["status"] != "active"
                ):
                    raise PolicyPublicationConflict("scheduled revocation CAS failed")
                connection.execute(
                    "UPDATE policy_publication_links SET status='revoked',"
                    "capability_sha256=NULL,current_version=NULL,effective_at=NULL,"
                    "expires_at=NULL,scheduled_revoke_at=NULL,revision=revision+1,"
                    "pointer_revision=pointer_revision+1,updated_at=?,revoked_at=? "
                    "WHERE tenant=? AND link_id=? AND revision=? AND status='active'",
                    (
                        now,
                        now,
                        claim.tenant_id,
                        claim.link_id,
                        job["expected_revision"],
                    ),
                )
                updated = self._refresh_link_digest(
                    connection, claim.tenant_id, claim.link_id
                )
                applied_revision = int(updated["revision"])
                self._audit(
                    connection,
                    tenant=claim.tenant_id,
                    event_type="link_revoked",
                    subject_id=claim.link_id,
                    details={
                        "scheduled": True,
                        "revision": applied_revision,
                        "scheduled_by": str(job["scheduled_by"]),
                    },
                    now=now,
                )
            connection.execute(
                "UPDATE policy_publication_jobs SET state='applied',"
                "lease_owner=NULL,lease_token_sha256=NULL,lease_until=NULL,"
                "last_error_code=NULL,updated_at=?,applied_at=? "
                "WHERE tenant=? AND job_id=? AND state='leased'",
                (now, now, claim.tenant_id, claim.job_id),
            )
            self._refresh_job_digest(connection, claim.tenant_id, claim.job_id)
            self._audit(
                connection,
                tenant=claim.tenant_id,
                event_type="job_applied",
                subject_id=claim.job_id,
                details={
                    "action": action,
                    "link_id": claim.link_id,
                    "applied_revision": applied_revision,
                    "attempt": claim.attempt,
                    "worker_id": claim.worker_id,
                },
                now=now,
            )
            return {
                "job_id": claim.job_id,
                "state": "applied",
                "action": action,
                "link_id": claim.link_id,
                "applied_revision": applied_revision,
                "applied_at": now,
            }

    def fail_claim(
        self,
        claim: PublicationClaim,
        *,
        error_code: str,
        retryable: bool,
        retry_after_seconds: float = 60.0,
    ) -> dict[str, Any]:
        """Release a claim to bounded retry or a terminal failed state."""

        self._require_enabled()
        error = _opaque(error_code, "error_code", _ERROR_CODE_RE)
        retry_after = _bounded_float(
            retry_after_seconds,
            "retry_after_seconds",
            maximum=_MAX_RETRY_SECONDS,
        )
        now = self._now()
        with self._transaction() as connection:
            row = self._claim_row(connection, claim, now=now)
            can_retry = retryable is True and int(row["attempts"]) < int(
                row["max_attempts"]
            )
            state = "pending" if can_retry else "failed"
            next_attempt = now + retry_after if can_retry else float(row["next_attempt_at"])
            connection.execute(
                "UPDATE policy_publication_jobs SET state=?,next_attempt_at=?,"
                "lease_owner=NULL,lease_token_sha256=NULL,lease_until=NULL,"
                "last_error_code=?,updated_at=? WHERE tenant=? AND job_id=? "
                "AND state='leased'",
                (
                    state,
                    next_attempt,
                    error,
                    now,
                    claim.tenant_id,
                    claim.job_id,
                ),
            )
            updated = self._refresh_job_digest(
                connection, claim.tenant_id, claim.job_id
            )
            self._audit(
                connection,
                tenant=claim.tenant_id,
                event_type="job_failed" if state == "failed" else "job_retried",
                subject_id=claim.job_id,
                details={
                    "error_code": error,
                    "state": state,
                    "attempts": int(updated["attempts"]),
                    "next_attempt_at": next_attempt if can_retry else None,
                },
                now=now,
            )
            return {
                "job_id": claim.job_id,
                "state": state,
                "attempts": int(updated["attempts"]),
                "next_attempt_at": next_attempt if can_retry else None,
                "last_error_code": error,
            }

    def run_due_jobs(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 20,
        lease_seconds: float = 60.0,
        approval_retry_seconds: float = 60.0,
    ) -> tuple[dict[str, Any], ...]:
        """Claim and apply one bounded batch with safe classified failures."""

        claims = self.claim_due_jobs(
            tenant_id,
            worker_id=worker_id,
            limit=limit,
            lease_seconds=lease_seconds,
        )
        outcomes: list[dict[str, Any]] = []
        for claim in claims:
            try:
                outcomes.append(self.apply_claim(claim))
            except PolicyPublicationApprovalRequired:
                outcomes.append(
                    self.fail_claim(
                        claim,
                        error_code="approval_pending",
                        retryable=True,
                        retry_after_seconds=approval_retry_seconds,
                    )
                )
            except PolicyPublicationConflict:
                outcomes.append(
                    self.fail_claim(
                        claim,
                        error_code="state_conflict",
                        retryable=False,
                    )
                )
            except PolicyPublicationError:
                outcomes.append(
                    self.fail_claim(
                        claim,
                        error_code="application_error",
                        retryable=False,
                    )
                )
        return tuple(outcomes)

    def retrieve(
        self,
        tenant_id: str,
        *,
        link_id: str,
        output_format: str = "html",
        bearer_capability: str | None = None,
        request_context_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve deterministic current policy content and audit the access.

        All authorization failures use the same exception type.  The access log
        records only whether a credential was presented, never its raw value or
        a digest derived from it.
        """

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        link = _opaque(link_id, "link_id")
        if output_format not in _FORMATS:
            raise PolicyPublicationValidationError("output_format is not supported")
        capability: str | None = None
        if bearer_capability is not None:
            capability = _opaque(
                bearer_capability, "bearer_capability", _CAPABILITY_RE
            )
        now = self._now()
        response: dict[str, Any] | None = None
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=? AND link_id=?",
                (tenant, link),
            ).fetchone()
            outcome = "not_found"
            content_row: sqlite3.Row | None = None
            artifact: sqlite3.Row | None = None
            if row is not None:
                self._verify_link_row(row)
                outcome = "denied"
                scheduled_revoke = row["scheduled_revoke_at"]
                expiry = row["expires_at"]
                effective = row["effective_at"]
                active_time = (
                    effective is not None
                    and now >= float(effective)
                    and (expiry is None or now < float(expiry))
                    and (scheduled_revoke is None or now < float(scheduled_revoke))
                )
                credential_ok = row["visibility"] == "public"
                if row["visibility"] == "private" and capability is not None:
                    stored = row["capability_sha256"]
                    presented = hashlib.sha256(capability.encode("ascii")).hexdigest()
                    credential_ok = stored is not None and hmac.compare_digest(
                        str(stored), presented
                    )
                if row["status"] == "revoked" or (
                    scheduled_revoke is not None and now >= float(scheduled_revoke)
                ):
                    outcome = "revoked"
                elif expiry is not None and now >= float(expiry):
                    outcome = "expired"
                elif (
                    active_time
                    and credential_ok
                    and row["current_version"] is not None
                ):
                    artifact = self._artifact_row(
                        connection,
                        tenant,
                        str(row["policy_id"]),
                        int(row["current_version"]),
                    )
                    content_row = connection.execute(
                        "SELECT * FROM policy_publication_content WHERE tenant=? "
                        "AND policy_id=? AND version=?",
                        (tenant, row["policy_id"], row["current_version"]),
                    ).fetchone()
                    if content_row is None:
                        raise PolicyPublicationIntegrityError(
                            "current policy content is unavailable"
                        )
                    outcome = "granted"
            self._access(
                connection,
                tenant=tenant,
                link_id=link,
                output_format=output_format,
                outcome=outcome,
                credential_present=capability is not None,
                request_context_sha256=request_context_sha256,
                now=now,
            )
            if outcome == "granted" and row is not None and artifact is not None:
                assert content_row is not None
                content = _loads(content_row["content_json"], "policy content")
                if not isinstance(content, dict) or set(content) != {
                    "title",
                    "body_text",
                }:
                    raise PolicyPublicationIntegrityError(
                        "stored policy content changed"
                    )
                content_sha256 = _sha256(content)
                if not hmac.compare_digest(
                    content_sha256, str(content_row["content_sha256"])
                ) or not hmac.compare_digest(
                    content_sha256, str(artifact["content_sha256"])
                ):
                    raise PolicyPublicationIntegrityError(
                        "stored policy content changed"
                    )
                title = str(content["title"])
                body_text = str(content["body_text"])
                if output_format == "text":
                    rendered = f"{title}\n\n{body_text}\n"
                    content_type = "text/plain; charset=utf-8"
                else:
                    rendered = (
                        '<article data-lightwork-policy="v1" '
                        f'data-artifact-sha256="{artifact["artifact_sha256"]}">'
                        f"<h1>{html.escape(title, quote=True)}</h1>"
                        f"<pre>{html.escape(body_text, quote=True)}</pre>"
                        "</article>"
                    )
                    content_type = "text/html; charset=utf-8"
                response_body = {
                    "schema": "lightwork.policy-publication-retrieval.v1",
                    "link_id": link,
                    "policy_id": str(row["policy_id"]),
                    "version": int(row["current_version"]),
                    "title": title,
                    "format": output_format,
                    "content_type": content_type,
                    "content": rendered,
                    "artifact_sha256": str(artifact["artifact_sha256"]),
                    "effective_at": float(row["effective_at"]),
                    "expires_at": row["expires_at"],
                }
                response = {**response_body, "etag": _sha256(response_body)}
        if response is None:
            raise PolicyPublicationAccessDenied(
                "policy link is unavailable or access was denied"
            )
        return response

    def list_audit(
        self,
        tenant_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        """Return bounded control-audit events with canonical details."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        after = _revision(after_sequence, "after_sequence")
        parsed_limit = _positive_int(limit, "limit", maximum=_MAX_LIST_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_publication_audit WHERE tenant=? "
                "AND sequence>? ORDER BY sequence LIMIT ?",
                (tenant, after, parsed_limit),
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            details = _loads(
                row["details_json"],
                "audit details",
                maximum=_MAX_AUDIT_DETAILS_BYTES,
            )
            output.append(
                {
                    "sequence": int(row["sequence"]),
                    "event_id": str(row["event_id"]),
                    "event_type": str(row["event_type"]),
                    "subject_id": str(row["subject_id"]),
                    "details": details,
                    "previous_event_sha256": row["previous_event_sha256"],
                    "event_sha256": str(row["event_sha256"]),
                    "created_at": float(row["created_at"]),
                }
            )
        return tuple(output)

    def list_access_events(
        self,
        tenant_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        """Return bounded safe access evidence without credential material."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        after = _revision(after_sequence, "after_sequence")
        parsed_limit = _positive_int(limit, "limit", maximum=_MAX_LIST_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence,event_id,link_id,output_format,outcome,"
                "credential_present,request_context_sha256,previous_event_sha256,"
                "event_sha256,created_at FROM policy_publication_access "
                "WHERE tenant=? AND sequence>? ORDER BY sequence LIMIT ?",
                (tenant, after, parsed_limit),
            ).fetchall()
        return tuple(
            {
                "sequence": int(row["sequence"]),
                "event_id": str(row["event_id"]),
                "link_id": str(row["link_id"]),
                "output_format": str(row["output_format"]),
                "outcome": str(row["outcome"]),
                "credential_present": bool(row["credential_present"]),
                "request_context_sha256": row["request_context_sha256"],
                "previous_event_sha256": row["previous_event_sha256"],
                "event_sha256": str(row["event_sha256"]),
                "created_at": float(row["created_at"]),
            }
            for row in rows
        )

    def purge_access_events(
        self,
        tenant_id: str,
        *,
        before: float,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Purge one bounded oldest access prefix and retain a chain checkpoint."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        cutoff = _finite_time(before, "before")
        assert cutoff is not None
        parsed_limit = _positive_int(limit, "limit", maximum=_MAX_LIST_LIMIT)
        now = self._now()
        with self._transaction() as connection:
            candidates = connection.execute(
                "SELECT * FROM policy_publication_access WHERE tenant=? "
                "ORDER BY sequence LIMIT ?",
                (tenant, parsed_limit),
            ).fetchall()
            rows: list[sqlite3.Row] = []
            for row in candidates:
                if float(row["created_at"]) >= cutoff:
                    break
                rows.append(row)
            if not rows:
                return {"purged": 0, "before": cutoff, "checkpoint_id": None}
            first_sequence = int(rows[0]["sequence"])
            through_sequence = int(rows[-1]["sequence"])
            last_sha256 = str(rows[-1]["event_sha256"])
            manifest_sha256 = _sha256(
                [
                    {"sequence": int(row["sequence"]), "sha256": row["event_sha256"]}
                    for row in rows
                ]
            )
            previous = connection.execute(
                "SELECT checkpoint_sha256 FROM policy_publication_access_checkpoints "
                "WHERE tenant=? ORDER BY sequence DESC LIMIT 1",
                (tenant,),
            ).fetchone()
            previous_checkpoint = (
                None if previous is None else str(previous["checkpoint_sha256"])
            )
            checkpoint_id = self._new_id("PAC")
            checkpoint_body = {
                "schema": CHECKPOINT_SCHEMA,
                "tenant_id": tenant,
                "checkpoint_id": checkpoint_id,
                "from_sequence": first_sequence,
                "through_sequence": through_sequence,
                "purged_count": len(rows),
                "last_event_sha256": last_sha256,
                "manifest_sha256": manifest_sha256,
                "previous_checkpoint_sha256": previous_checkpoint,
                "created_at": now,
            }
            checkpoint_sha256 = _sha256(checkpoint_body)
            connection.execute(
                "INSERT INTO policy_publication_access_checkpoints(tenant,"
                "checkpoint_id,from_sequence,through_sequence,purged_count,"
                "last_event_sha256,manifest_sha256,previous_checkpoint_sha256,"
                "checkpoint_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    checkpoint_id,
                    first_sequence,
                    through_sequence,
                    len(rows),
                    last_sha256,
                    manifest_sha256,
                    previous_checkpoint,
                    checkpoint_sha256,
                    now,
                ),
            )
            placeholders = ",".join("?" for _ in rows)
            connection.execute(
                "DELETE FROM policy_publication_access WHERE tenant=? "
                f"AND sequence IN ({placeholders})",
                (tenant, *(int(row["sequence"]) for row in rows)),
            )
            self._audit(
                connection,
                tenant=tenant,
                event_type="access_retention_purged",
                subject_id=checkpoint_id,
                details={
                    "purged_count": len(rows),
                    "through_sequence": through_sequence,
                    "manifest_sha256": manifest_sha256,
                },
                now=now,
            )
            return {
                "purged": len(rows),
                "before": cutoff,
                "checkpoint_id": checkpoint_id,
                "through_sequence": through_sequence,
                "manifest_sha256": manifest_sha256,
            }

    def purge_unreferenced_content(
        self,
        tenant_id: str,
        *,
        before: float,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Retire bounded unreferenced policy bodies while retaining tombstones."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        cutoff = _finite_time(before, "before")
        assert cutoff is not None
        parsed_limit = _positive_int(limit, "limit", maximum=_MAX_LIST_LIMIT)
        now = self._now()
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT a.tenant,a.policy_id,a.version,a.content_sha256 "
                "FROM policy_publication_artifacts a "
                "JOIN policy_publication_content c ON c.tenant=a.tenant "
                "AND c.policy_id=a.policy_id AND c.version=a.version "
                "WHERE a.tenant=? AND a.created_at<? "
                "AND NOT EXISTS (SELECT 1 FROM policy_publication_links l "
                "WHERE l.tenant=a.tenant AND l.policy_id=a.policy_id "
                "AND l.current_version=a.version) "
                "AND NOT EXISTS (SELECT 1 FROM policy_publication_jobs j "
                "WHERE j.tenant=a.tenant AND j.link_id IN "
                "(SELECT link_id FROM policy_publication_links l2 "
                "WHERE l2.tenant=a.tenant AND l2.policy_id=a.policy_id) "
                "AND j.target_version=a.version AND j.state IN ('pending','leased')) "
                "ORDER BY a.policy_id,a.version LIMIT ?",
                (tenant, cutoff, parsed_limit),
            ).fetchall()
            manifest: list[dict[str, Any]] = []
            for row in rows:
                body = {
                    "schema": TOMBSTONE_SCHEMA,
                    "tenant_id": tenant,
                    "policy_id": str(row["policy_id"]),
                    "version": int(row["version"]),
                    "content_sha256": str(row["content_sha256"]),
                    "purged_at": now,
                }
                tombstone_sha256 = _sha256(body)
                connection.execute(
                    "INSERT INTO policy_publication_content_tombstones(tenant,"
                    "policy_id,version,content_sha256,tombstone_sha256,purged_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        tenant,
                        row["policy_id"],
                        row["version"],
                        row["content_sha256"],
                        tombstone_sha256,
                        now,
                    ),
                )
                connection.execute(
                    "DELETE FROM policy_publication_content WHERE tenant=? "
                    "AND policy_id=? AND version=?",
                    (tenant, row["policy_id"], row["version"]),
                )
                manifest.append(
                    {
                        "policy_id": str(row["policy_id"]),
                        "version": int(row["version"]),
                        "content_sha256": str(row["content_sha256"]),
                        "tombstone_sha256": tombstone_sha256,
                    }
                )
            manifest_sha256 = _sha256(manifest)
            if manifest:
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="content_retention_purged",
                    subject_id=self._new_id("PRM"),
                    details={
                        "purged_count": len(manifest),
                        "manifest_sha256": manifest_sha256,
                    },
                    now=now,
                )
            return {
                "purged": len(manifest),
                "before": cutoff,
                "manifest_sha256": manifest_sha256,
            }

    def verify_integrity(  # noqa: C901 - one linear forensic verification walk
        self, tenant_id: str
    ) -> dict[str, Any]:
        """Verify immutable artifacts, mutable digests, and both audit chains."""

        self._require_enabled()
        tenant = self._tenant(tenant_id)
        with self._connect() as connection:
            artifacts = connection.execute(
                "SELECT * FROM policy_publication_artifacts WHERE tenant=? "
                "ORDER BY policy_id,version",
                (tenant,),
            ).fetchall()
            for artifact in artifacts:
                if not hmac.compare_digest(
                    str(artifact["artifact_sha256"]),
                    _sha256(self._artifact_body(artifact)),
                ):
                    raise PolicyPublicationIntegrityError(
                        "policy artifact digest changed"
                    )
                content = connection.execute(
                    "SELECT * FROM policy_publication_content WHERE tenant=? "
                    "AND policy_id=? AND version=?",
                    (tenant, artifact["policy_id"], artifact["version"]),
                ).fetchone()
                tombstone = connection.execute(
                    "SELECT * FROM policy_publication_content_tombstones "
                    "WHERE tenant=? AND policy_id=? AND version=?",
                    (tenant, artifact["policy_id"], artifact["version"]),
                ).fetchone()
                if (content is None) == (tombstone is None):
                    raise PolicyPublicationIntegrityError(
                        "policy content retention state is ambiguous"
                    )
                if content is not None:
                    value = _loads(content["content_json"], "policy content")
                    actual = _sha256(value)
                    if not hmac.compare_digest(
                        actual, str(content["content_sha256"])
                    ) or not hmac.compare_digest(
                        actual, str(artifact["content_sha256"])
                    ):
                        raise PolicyPublicationIntegrityError(
                            "policy content digest changed"
                        )
                else:
                    tombstone_body = {
                        "schema": TOMBSTONE_SCHEMA,
                        "tenant_id": tenant,
                        "policy_id": str(tombstone["policy_id"]),
                        "version": int(tombstone["version"]),
                        "content_sha256": str(tombstone["content_sha256"]),
                        "purged_at": float(tombstone["purged_at"]),
                    }
                    if not hmac.compare_digest(
                        str(tombstone["tombstone_sha256"]),
                        _sha256(tombstone_body),
                    ) or not hmac.compare_digest(
                        str(tombstone["content_sha256"]),
                        str(artifact["content_sha256"]),
                    ):
                        raise PolicyPublicationIntegrityError(
                            "policy content tombstone changed"
                        )

            approvals = connection.execute(
                "SELECT * FROM policy_publication_approvals WHERE tenant=?",
                (tenant,),
            ).fetchall()
            for row in approvals:
                body = {
                    "tenant_id": tenant,
                    "policy_id": str(row["policy_id"]),
                    "version": int(row["version"]),
                    "reviewer_id": str(row["reviewer_id"]),
                    "decision": str(row["decision"]),
                    "rationale_sha256": row["rationale_sha256"],
                    "created_at": float(row["created_at"]),
                }
                if not hmac.compare_digest(
                    str(row["approval_sha256"]), _sha256(body)
                ):
                    raise PolicyPublicationIntegrityError(
                        "policy approval digest changed"
                    )

            links = connection.execute(
                "SELECT * FROM policy_publication_links WHERE tenant=?",
                (tenant,),
            ).fetchall()
            for row in links:
                if not hmac.compare_digest(
                    str(row["record_sha256"]), _sha256(self._link_body(row))
                ):
                    raise PolicyPublicationIntegrityError("policy link digest changed")

            jobs = connection.execute(
                "SELECT * FROM policy_publication_jobs WHERE tenant=?",
                (tenant,),
            ).fetchall()
            for row in jobs:
                if row["state"] not in _JOB_STATES or not hmac.compare_digest(
                    str(row["record_sha256"]), _sha256(self._job_body(row))
                ):
                    raise PolicyPublicationIntegrityError(
                        "publication job digest changed"
                    )

            idempotency_rows = connection.execute(
                "SELECT * FROM policy_publication_idempotency WHERE tenant=?",
                (tenant,),
            ).fetchall()
            for row in idempotency_rows:
                result_sha256 = hashlib.sha256(
                    str(row["result_json"]).encode("ascii")
                ).hexdigest()
                record = {
                    "tenant_id": tenant,
                    "namespace": str(row["namespace"]),
                    "key_sha256": str(row["key_sha256"]),
                    "request_sha256": str(row["request_sha256"]),
                    "result_sha256": str(row["result_sha256"]),
                    "created_at": float(row["created_at"]),
                }
                if not hmac.compare_digest(
                    result_sha256, str(row["result_sha256"])
                ) or not hmac.compare_digest(
                    _sha256(record), str(row["record_sha256"])
                ):
                    raise PolicyPublicationIntegrityError(
                        "publication idempotency record changed"
                    )

            previous_audit: str | None = None
            audit_rows = connection.execute(
                "SELECT * FROM policy_publication_audit WHERE tenant=? "
                "ORDER BY sequence",
                (tenant,),
            ).fetchall()
            for row in audit_rows:
                details = _loads(
                    row["details_json"],
                    "audit details",
                    maximum=_MAX_AUDIT_DETAILS_BYTES,
                )
                details_sha256 = _sha256(
                    details, maximum=_MAX_AUDIT_DETAILS_BYTES
                )
                body = {
                    "schema": AUDIT_SCHEMA,
                    "tenant_id": tenant,
                    "event_id": str(row["event_id"]),
                    "event_type": str(row["event_type"]),
                    "subject_id": str(row["subject_id"]),
                    "details_sha256": details_sha256,
                    "previous_event_sha256": previous_audit,
                    "created_at": float(row["created_at"]),
                }
                if row["previous_event_sha256"] != previous_audit:
                    raise PolicyPublicationIntegrityError(
                        "publication audit chain is broken"
                    )
                if not hmac.compare_digest(
                    details_sha256, str(row["details_sha256"])
                ) or not hmac.compare_digest(
                    _sha256(body), str(row["event_sha256"])
                ):
                    raise PolicyPublicationIntegrityError(
                        "publication audit event changed"
                    )
                previous_audit = str(row["event_sha256"])

            checkpoints = connection.execute(
                "SELECT * FROM policy_publication_access_checkpoints "
                "WHERE tenant=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous_checkpoint: str | None = None
            access_previous: str | None = None
            through_sequence = 0
            for row in checkpoints:
                checkpoint_body = {
                    "schema": CHECKPOINT_SCHEMA,
                    "tenant_id": tenant,
                    "checkpoint_id": str(row["checkpoint_id"]),
                    "from_sequence": int(row["from_sequence"]),
                    "through_sequence": int(row["through_sequence"]),
                    "purged_count": int(row["purged_count"]),
                    "last_event_sha256": str(row["last_event_sha256"]),
                    "manifest_sha256": str(row["manifest_sha256"]),
                    "previous_checkpoint_sha256": previous_checkpoint,
                    "created_at": float(row["created_at"]),
                }
                if row["previous_checkpoint_sha256"] != previous_checkpoint or not (
                    hmac.compare_digest(
                        _sha256(checkpoint_body), str(row["checkpoint_sha256"])
                    )
                ):
                    raise PolicyPublicationIntegrityError(
                        "access retention checkpoint chain is broken"
                    )
                previous_checkpoint = str(row["checkpoint_sha256"])
                access_previous = str(row["last_event_sha256"])
                through_sequence = int(row["through_sequence"])

            access_rows = connection.execute(
                "SELECT * FROM policy_publication_access WHERE tenant=? "
                "ORDER BY sequence",
                (tenant,),
            ).fetchall()
            for row in access_rows:
                if int(row["sequence"]) <= through_sequence:
                    raise PolicyPublicationIntegrityError(
                        "retained access event overlaps a retention checkpoint"
                    )
                body = {
                    "schema": ACCESS_SCHEMA,
                    "tenant_id": tenant,
                    "event_id": str(row["event_id"]),
                    "link_id": str(row["link_id"]),
                    "output_format": str(row["output_format"]),
                    "outcome": str(row["outcome"]),
                    "credential_present": bool(row["credential_present"]),
                    "request_context_sha256": row["request_context_sha256"],
                    "previous_event_sha256": access_previous,
                    "created_at": float(row["created_at"]),
                }
                if row["previous_event_sha256"] != access_previous or not (
                    hmac.compare_digest(_sha256(body), str(row["event_sha256"]))
                ):
                    raise PolicyPublicationIntegrityError(
                        "publication access chain is broken"
                    )
                access_previous = str(row["event_sha256"])

            return {
                "tenant_id": tenant,
                "schema_version": SCHEMA_VERSION,
                "artifact_count": len(artifacts),
                "approval_count": len(approvals),
                "link_count": len(links),
                "job_count": len(jobs),
                "audit_event_count": len(audit_rows),
                "retained_access_event_count": len(access_rows),
                "access_checkpoint_count": len(checkpoints),
                "access_purged_through_sequence": through_sequence,
                "status": "verified",
            }
