"""Private, tenant/owner/device-bound persistence for Ekko work discovery."""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .work_discovery import (
    MAX_RETENTION_DAYS,
    CapturePolicy,
    Enrollment,
    SessionState,
    WorkEvent,
    WorkSession,
    discover_candidates,
)


class WorkDiscoveryStoreError(RuntimeError):
    """Base exception for durable Ekko state errors."""


class EnrollmentRequired(WorkDiscoveryStoreError):
    """Capture was attempted without a matching active client enrollment."""


class SessionStateError(WorkDiscoveryStoreError):
    """The requested session transition or append is not permitted."""


class EventConflictError(WorkDiscoveryStoreError):
    """An event id was reused with different content."""


class EventSequenceError(WorkDiscoveryStoreError):
    """An event sequence was replayed or arrived with a gap."""


class CollectorLeaseError(WorkDiscoveryStoreError):
    """A collector could not acquire or prove its exclusive live lease."""


@dataclass(frozen=True)
class CollectorLease:
    """Opaque, scope-bound proof that one collector owns a device session."""

    # One-way digest of the process-held capability. The raw random token is
    # never written to SQLite or to a recoverable sealed payload.
    collector_key: str
    session_id: str
    state: str
    claimed_at: float
    heartbeat_at: float
    expires_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_TERMINAL_STATES = frozenset({SessionState.STOPPED, SessionState.HALTED})
_TRANSITIONS = {
    SessionState.CREATED: frozenset({SessionState.RUNNING, SessionState.STOPPED, SessionState.HALTED}),
    SessionState.RUNNING: frozenset({SessionState.PAUSED, SessionState.STOPPED, SessionState.HALTED}),
    SessionState.PAUSED: frozenset({SessionState.RUNNING, SessionState.STOPPED, SessionState.HALTED}),
    SessionState.STOPPED: frozenset(),
    SessionState.HALTED: frozenset(),
}
_MAX_LIST_EVENTS = 50_000
DEFAULT_ENROLLMENT_DAYS = 30
MAX_ENROLLMENT_DAYS = 90
_MAX_EVENT_BLOB_BYTES = 8_192
MAX_EVENTS_PER_SESSION = 10_000
MAX_EVENTS_PER_DEVICE = 100_000
MAX_DATABASE_BYTES = 512 * 1024 * 1024
MAX_SESSIONS_PER_DEVICE = 1_000
MAX_AUDIT_OUTBOX = 2_000
_DATABASE_GROWTH_RESERVE = 64 * 1024
DEFAULT_COLLECTOR_LEASE_SECONDS = 30.0
MIN_COLLECTOR_LEASE_SECONDS = 5.0
MAX_COLLECTOR_LEASE_SECONDS = 1200.0
_MAX_CONTROL_REVISION = 2**63 - 1
_SESSION_AUTHORITY_REVOKED = b"EKKO-SESSION-REVOKED-V1\n"


def _scope_key(kind: str, value: str) -> str:
    value = str(value)
    if not value or len(value) > 256 or any(ord(char) < 32 for char in value):
        raise ValueError(f"invalid {kind}")
    return hashlib.sha256(f"ekko:{kind}:v1:{value}".encode()).hexdigest()


def _digest_ok(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _grant_id_ok(value: str) -> bool:
    return (
        len(value) == 38
        and value.startswith("grant-")
        and all(char in "0123456789abcdef" for char in value[6:])
    )


def _timestamp(value: float | None) -> float:
    result = time.time() if value is None else float(value)
    if not math.isfinite(result) or not 946_684_800.0 <= result <= 4_102_444_800.0:
        raise ValueError("timestamp is outside the allowed range")
    return result


def _collector_token(value: str) -> str:
    result = str(value or "")
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-"
    if not result or len(result) > 64 or any(char not in allowed for char in result):
        raise ValueError("invalid collector_id")
    return result


def _collector_key(value: str) -> str:
    token = _collector_token(value)
    return hashlib.sha256(f"ekko:collector:v1:{token}".encode()).hexdigest()


def _session_authority_key(session_id: str) -> str:
    """Return a filename/payload-safe binding without exposing a session id."""
    return hashlib.sha256(
        f"ekko:session-authority:v1:{session_id}".encode()
    ).hexdigest()


def _lease_ttl(value: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError("collector lease TTL must be numeric") from None
    if not math.isfinite(result) or not (
        MIN_COLLECTOR_LEASE_SECONDS <= result <= MAX_COLLECTOR_LEASE_SECONDS
    ):
        raise ValueError(
            "collector lease TTL must be between "
            f"{MIN_COLLECTOR_LEASE_SECONDS:g} and {MAX_COLLECTOR_LEASE_SECONDS:g} seconds"
        )
    return result


def _default_authority_check(policy: CapturePolicy) -> None:
    """Revalidate deployment authority at the durable write boundary."""
    from .config import validate_ekko_policy_ceiling
    from .killswitch import check

    check(force_refresh=True, fail_closed=True)
    validate_ekko_policy_ceiling(policy)


class WorkDiscoveryStore:
    """SQLite ledger scoped to one tenant, owner, and enrolled device.

    Scope identifiers are retained only as fixed digests.  Every statement is
    constrained by all three keys, so even an explicitly injected shared test
    database cannot cross an owner/device boundary.
    """

    def __init__(
        self, owner: str, device_id: str, *, tenant: str | None = None,
        path: str | Path | None = None,
        clock: Callable[[], float] = time.time,
        authority_check: Callable[[CapturePolicy], None] = _default_authority_check,
    ):
        from .paths import current_tenant_id

        active_tenant = tenant if tenant is not None else (current_tenant_id() or "__local__")
        self._tenant_key = _scope_key("tenant", active_tenant)
        self._owner_key = _scope_key("owner", owner)
        self._device_key = _scope_key("device", device_id)
        self.owner = str(owner)
        self.device_id = str(device_id)
        self.tenant = active_tenant
        self._clock = clock
        self._authority_check = authority_check
        if path is not None:
            self.path = Path(path).expanduser()
        else:
            from .paths import data_dir

            self.path = (
                data_dir("ekko", "work-discovery.sqlite3", tenant=tenant)
                if tenant is not None
                else data_dir("ekko", "work-discovery.sqlite3")
            )

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        from .file_lock import ensure_private_directory, ensure_private_file

        ensure_private_directory(self.path.parent)
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            ensure_private_file(self.path, 0o600)
        else:
            os.close(fd)
            ensure_private_file(self.path, 0o600)

        conn = sqlite3.connect(str(self.path), timeout=10.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA secure_delete=ON")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS ekko_enrollments (
                    tenant_key TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK (active IN (0, 1)),
                    grant_id TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    policy_blob BLOB NOT NULL,
                    enrolled_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (tenant_key, owner_key, device_key)
                );
                CREATE TABLE IF NOT EXISTS ekko_sessions (
                    tenant_key TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('created', 'running', 'paused', 'stopped', 'halted')
                    ),
                    policy_digest TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    ended_at REAL,
                    last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
                    session_blob BLOB NOT NULL,
                    PRIMARY KEY (tenant_key, owner_key, device_key, session_id)
                );
                CREATE INDEX IF NOT EXISTS ekko_sessions_scope_time
                    ON ekko_sessions(tenant_key, owner_key, device_key, updated_at DESC);
                CREATE TABLE IF NOT EXISTS ekko_events (
                    tenant_key TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    payload BLOB NOT NULL,
                    event_digest TEXT NOT NULL,
                    ingested_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (tenant_key, owner_key, device_key, event_id),
                    UNIQUE (tenant_key, owner_key, device_key, session_id, sequence),
                    FOREIGN KEY (tenant_key, owner_key, device_key, session_id)
                        REFERENCES ekko_sessions(tenant_key, owner_key, device_key, session_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS ekko_events_scope_time
                    ON ekko_events(tenant_key, owner_key, device_key, ingested_at);
                CREATE INDEX IF NOT EXISTS ekko_events_expiry
                    ON ekko_events(tenant_key, owner_key, device_key, expires_at);
                CREATE TABLE IF NOT EXISTS ekko_audit_outbox (
                    tenant_key TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    outbox_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    payload BLOB NOT NULL,
                    PRIMARY KEY (tenant_key, owner_key, device_key, outbox_id)
                );
                CREATE TABLE IF NOT EXISTS ekko_collector_leases (
                    tenant_key TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    collector_key TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('active', 'paused', 'released')),
                    claimed_at REAL NOT NULL,
                    heartbeat_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    lease_blob BLOB NOT NULL,
                    PRIMARY KEY (tenant_key, owner_key, device_key),
                    FOREIGN KEY (tenant_key, owner_key, device_key, session_id)
                        REFERENCES ekko_sessions(tenant_key, owner_key, device_key, session_id)
                        ON DELETE CASCADE
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ekko_collector_lease_session
                    ON ekko_collector_leases(
                        tenant_key, owner_key, device_key, session_id
                    );
                CREATE TABLE IF NOT EXISTS ekko_plans (
                    tenant_key TEXT NOT NULL, owner_key TEXT NOT NULL, device_key TEXT NOT NULL,
                    opportunity_id TEXT NOT NULL, revision TEXT NOT NULL, payload BLOB NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (tenant_key, owner_key, device_key, opportunity_id)
                );
                CREATE TABLE IF NOT EXISTS ekko_plan_sources (
                    tenant_key TEXT NOT NULL, owner_key TEXT NOT NULL, device_key TEXT NOT NULL,
                    opportunity_id TEXT NOT NULL, session_id TEXT NOT NULL,
                    PRIMARY KEY (tenant_key, owner_key, device_key, opportunity_id, session_id),
                    FOREIGN KEY (tenant_key, owner_key, device_key, opportunity_id)
                        REFERENCES ekko_plans(tenant_key, owner_key, device_key, opportunity_id) ON DELETE CASCADE
                );
            """)
            yield conn
        finally:
            conn.close()

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.rollback()
                raise
            else:
                conn.commit()

    @property
    def _scope(self) -> tuple[str, str, str]:
        return self._tenant_key, self._owner_key, self._device_key

    def _now(self) -> float:
        return _timestamp(self._clock())

    def _seal(self, value: dict[str, Any], *, purpose: str) -> bytes:
        from .tenant.kms import seal_for_tenant

        if purpose not in {
            "authority", "enrollment", "session", "session_authority",
            "event", "audit", "lease", "plan",
        }:
            raise ValueError("invalid Ekko sealed-payload purpose")
        envelope = {
            "version": 1,
            "purpose": purpose,
            "scope": list(self._scope),
            "payload": value,
        }
        plaintext = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        blob = seal_for_tenant(self.tenant, plaintext)
        if len(blob) > (65_536 if purpose == "plan" else _MAX_EVENT_BLOB_BYTES):
            raise ValueError("sealed Ekko payload exceeds its byte limit")
        return blob

    def _unseal(self, blob: bytes, *, purpose: str) -> dict[str, Any]:
        from .tenant.kms import unseal_for_tenant

        limit = 65_536 if purpose == "plan" else _MAX_EVENT_BLOB_BYTES
        if not isinstance(blob, bytes) or len(blob) > limit:
            raise WorkDiscoveryStoreError("invalid sealed Ekko payload")
        try:
            plaintext = unseal_for_tenant(self.tenant, blob)
        except Exception as exc:
            # Collapse KMS/decryption/authentication failures to a stable,
            # content-free domain error. Callers must fail closed without
            # exposing key-provider or ciphertext details to a user surface.
            raise WorkDiscoveryStoreError(
                "sealed Ekko payload could not be authenticated"
            ) from exc
        if len(plaintext) > limit:
            raise WorkDiscoveryStoreError("unsealed Ekko payload exceeds its byte limit")
        try:
            envelope = json.loads(plaintext)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise WorkDiscoveryStoreError("invalid sealed Ekko payload") from exc
        if not isinstance(envelope, dict):
            raise WorkDiscoveryStoreError("invalid sealed Ekko payload")
        if (
            set(envelope) != {"version", "purpose", "scope", "payload"}
            or envelope.get("version") != 1
            or envelope.get("purpose") != purpose
            or envelope.get("scope") != list(self._scope)
            or not isinstance(envelope.get("payload"), dict)
        ):
            raise WorkDiscoveryStoreError(
                "sealed Ekko payload is not bound to this scope"
            )
        return envelope["payload"]

    @staticmethod
    def _enrollment_payload(
        policy: CapturePolicy,
        *,
        grant_id: str,
        active: bool,
        enrolled_at: float,
        updated_at: float,
        expires_at: float,
    ) -> dict[str, Any]:
        return {
            "grant_id": grant_id,
            "active": bool(active),
            "policy": policy.to_dict(),
            "policy_digest": policy.fingerprint(),
            "enrolled_at": float(enrolled_at),
            "updated_at": float(updated_at),
            "expires_at": float(expires_at),
        }

    def _decode_enrollment_row(
        self, row: sqlite3.Row, *, now: float,
    ) -> tuple[Enrollment, CapturePolicy]:
        data = self._unseal(bytes(row["policy_blob"]), purpose="enrollment")
        if set(data) != {
            "grant_id", "active", "policy", "policy_digest", "enrolled_at",
            "updated_at", "expires_at",
        } or not isinstance(data.get("policy"), dict):
            raise WorkDiscoveryStoreError("invalid sealed enrollment state")
        policy = CapturePolicy.from_dict(data["policy"])
        policy.require_valid(require_enabled=True)
        expected = {
            "grant_id": str(row["grant_id"]),
            "active": bool(row["active"]),
            "policy_digest": str(row["policy_digest"]),
            "enrolled_at": float(row["enrolled_at"]),
            "updated_at": float(row["updated_at"]),
            "expires_at": float(row["expires_at"]),
        }
        if any(data.get(key) != value for key, value in expected.items()):
            raise WorkDiscoveryStoreError("enrollment authority integrity check failed")
        if (
            not _grant_id_ok(expected["grant_id"])
            or not hmac.compare_digest(
                policy.fingerprint(), expected["policy_digest"],
            )
        ):
            raise WorkDiscoveryStoreError("enrolled policy integrity check failed")
        self._assert_consent_authority(data)
        enrollment = Enrollment(
            bool(data["active"]) and float(data["expires_at"]) > now,
            expected["policy_digest"],
            float(data["enrolled_at"]),
            float(data["updated_at"]),
            float(data["expires_at"]),
        )
        return enrollment, policy

    @property
    def _consent_authority_path(self) -> Path:
        name = "-".join(key[:24] for key in self._scope) + ".bin"
        return self.path.parent / "consent-authority" / name

    @contextlib.contextmanager
    def _consent_barrier(self) -> Iterator[None]:
        """Serialize the database grant and its external authority marker."""
        from .file_lock import cross_process_lock

        with cross_process_lock(self._consent_authority_path, strict=True):
            yield

    @contextlib.contextmanager
    def _deployment_control_barrier(self) -> Iterator[None]:
        from .ekko_control import control_barrier

        with control_barrier():
            yield

    def _write_consent_authority(self, payload: dict[str, Any]) -> None:
        from .file_lock import atomic_write_bytes, ensure_private_directory

        ensure_private_directory(self._consent_authority_path.parent)
        atomic_write_bytes(
            self._consent_authority_path,
            self._seal(payload, purpose="authority"),
            mode=0o600,
        )

    def _write_revoked_sentinel(self, *, revoked_at: float) -> None:
        from .file_lock import atomic_write_bytes, ensure_private_directory

        ensure_private_directory(self._consent_authority_path.parent)
        body = f"EKKO-REVOKED-V1\n{revoked_at:.6f}\n".encode("ascii")
        atomic_write_bytes(self._consent_authority_path, body, mode=0o600)

    def _read_consent_authority(self) -> dict[str, Any] | None:
        path = self._consent_authority_path
        if not path.exists():
            return None
        from .file_lock import ensure_private_file

        ensure_private_file(path, 0o600)
        raw = path.read_bytes()
        if len(raw) > _MAX_EVENT_BLOB_BYTES:
            raise WorkDiscoveryStoreError("invalid Ekko consent authority")
        if raw.startswith(b"EKKO-REVOKED-V1\n"):
            return {"state": "revoked"}
        value = self._unseal(raw, purpose="authority")
        if set(value) != {"state", "grant_id", "policy_digest", "expires_at"}:
            raise WorkDiscoveryStoreError("invalid Ekko consent authority")
        return value

    def _assert_consent_authority(self, enrollment: dict[str, Any]) -> None:
        expected = {
            "state": "active",
            "grant_id": enrollment["grant_id"],
            "policy_digest": enrollment["policy_digest"],
            "expires_at": enrollment["expires_at"],
        }
        if self._read_consent_authority() != expected:
            raise EnrollmentRequired(
                "Ekko consent authority is revoked, missing, or stale"
            )

    @property
    def _session_authority_directory(self) -> Path:
        scope_key = hashlib.sha256(
            ("ekko:session-authority-scope:v1:" + ":".join(self._scope)).encode()
        ).hexdigest()[:32]
        return self.path.parent / "session-authority" / scope_key

    def _session_authority_path(self, session_id: str) -> Path:
        return self._session_authority_directory / (
            f"{_session_authority_key(session_id)[:32]}.bin"
        )

    @contextlib.contextmanager
    def _session_authority_barrier(self, session_id: str) -> Iterator[None]:
        """Serialize a session's SQLite controls with its rollback authority."""
        from .file_lock import cross_process_lock

        with cross_process_lock(
            self._session_authority_path(session_id), strict=True,
        ):
            yield

    def _scoped_session_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT session_id FROM ekko_sessions WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? ORDER BY session_id",
                self._scope,
            ).fetchall()
        return [str(row["session_id"]) for row in rows]

    @contextlib.contextmanager
    def _session_authority_barriers(
        self, session_ids: list[str],
    ) -> Iterator[None]:
        """Acquire multiple session locks in a stable deadlock-free order."""
        paths = [self._session_authority_path(value) for value in session_ids]
        with self._session_authority_path_barriers(paths):
            yield

    @contextlib.contextmanager
    def _session_authority_path_barriers(
        self, paths: list[Path],
    ) -> Iterator[None]:
        from .file_lock import cross_process_lock

        with contextlib.ExitStack() as stack:
            for path in sorted(set(paths), key=lambda value: str(value)):
                stack.enter_context(cross_process_lock(path, strict=True))
            yield

    def _scoped_session_authority_paths(self) -> list[Path]:
        directory = self._session_authority_directory
        if not directory.exists():
            return []
        from .file_lock import ensure_private_directory

        ensure_private_directory(directory)
        return sorted(
            (
                path for path in directory.iterdir()
                if path.suffix == ".bin"
                and len(path.stem) == 32
                and all(char in "0123456789abcdef" for char in path.stem)
            ),
            key=lambda value: value.name,
        )

    def _read_session_authority(
        self, session_id: str, *, required: bool = True,
    ) -> dict[str, Any] | None:
        path = self._session_authority_path(session_id)
        if not path.exists():
            if required:
                raise WorkDiscoveryStoreError(
                    "Ekko session control authority is missing or stale"
                )
            return None
        from .file_lock import ensure_private_file

        ensure_private_file(path, 0o600)
        raw = path.read_bytes()
        if len(raw) > _MAX_EVENT_BLOB_BYTES:
            raise WorkDiscoveryStoreError("invalid Ekko session control authority")
        if raw.startswith(_SESSION_AUTHORITY_REVOKED):
            expected = _SESSION_AUTHORITY_REVOKED + path.stem.encode("ascii") + b"\n"
            if raw != expected:
                raise WorkDiscoveryStoreError(
                    "invalid Ekko session control authority tombstone"
                )
            raise WorkDiscoveryStoreError(
                "Ekko session control authority is revoked or stale"
            )
        value = self._unseal(raw, purpose="session_authority")
        if set(value) != {"session_id", "revision"}:
            raise WorkDiscoveryStoreError("invalid Ekko session control authority")
        revision = value.get("revision")
        if (
            value.get("session_id") != session_id
            or not isinstance(revision, int)
            or isinstance(revision, bool)
            or not 1 <= revision <= _MAX_CONTROL_REVISION
        ):
            raise WorkDiscoveryStoreError("invalid Ekko session control authority")
        return value

    def _write_session_authority(
        self, session_id: str, *, revision: int,
    ) -> None:
        from .file_lock import atomic_write_bytes, ensure_private_directory

        if not 1 <= revision <= _MAX_CONTROL_REVISION:
            raise WorkDiscoveryStoreError("Ekko session control revision is exhausted")
        path = self._session_authority_path(session_id)
        ensure_private_directory(path.parent.parent)
        ensure_private_directory(path.parent)
        atomic_write_bytes(
            path,
            self._seal(
                {
                    "session_id": session_id,
                    "revision": revision,
                },
                purpose="session_authority",
            ),
            mode=0o600,
        )

    def _fresh_session_revision(self, session_id: str) -> int:
        if self._session_authority_path(session_id).exists():
            raise SessionStateError(
                "session_id has prior Ekko control authority and cannot be reused"
            )
        self._write_session_authority(session_id, revision=1)
        return 1

    def _rotate_session_revision(
        self,
        session_id: str,
        *,
        expected_revision: int,
    ) -> int:
        current = self._read_session_authority(session_id)
        assert current is not None
        if current["revision"] != expected_revision:
            raise WorkDiscoveryStoreError(
                "Ekko session control authority is erased or stale"
            )
        revision = expected_revision + 1
        self._write_session_authority(session_id, revision=revision)
        return revision

    def _write_session_authority_tombstone(self, path: Path) -> None:
        from .file_lock import atomic_write_bytes, ensure_private_directory

        if (
            path.parent != self._session_authority_directory
            or path.suffix != ".bin"
            or len(path.stem) != 32
            or any(char not in "0123456789abcdef" for char in path.stem)
        ):
            raise WorkDiscoveryStoreError("invalid Ekko session authority path")
        ensure_private_directory(path.parent.parent)
        ensure_private_directory(path.parent)
        atomic_write_bytes(
            path,
            _SESSION_AUTHORITY_REVOKED + path.stem.encode("ascii") + b"\n",
            mode=0o600,
        )

    def _tombstone_session_authority(self, session_id: str) -> None:
        # This is deliberately non-KMS: privacy deletion must still fail closed
        # when the encrypted authority is corrupt or the key service is down.
        self._write_session_authority_tombstone(
            self._session_authority_path(session_id),
        )

    def _assert_session_revision(self, session_id: str, revision: int) -> None:
        current = self._read_session_authority(session_id)
        assert current is not None
        if current["revision"] != revision:
            raise WorkDiscoveryStoreError(
                "Ekko session control authority is erased or stale"
            )

    @staticmethod
    def _session_payload(
        session: WorkSession, *, revision: int, enrollment_grant_id: str,
    ) -> dict[str, Any]:
        if not _grant_id_ok(enrollment_grant_id):
            raise WorkDiscoveryStoreError("invalid Ekko enrollment grant binding")
        return {
            **session.to_dict(),
            "control_revision": revision,
            "enrollment_grant_id": enrollment_grant_id,
        }

    def _session_from_blob(
        self, row: sqlite3.Row,
    ) -> tuple[WorkSession, int, str]:
        data = self._unseal(bytes(row["session_blob"]), purpose="session")
        if set(data) != {
            "session_id", "state", "policy_digest", "started_at", "updated_at",
            "ended_at", "last_sequence", "control_revision",
            "enrollment_grant_id",
        }:
            raise WorkDiscoveryStoreError("invalid sealed session state")
        try:
            session = WorkSession(
                session_id=str(data["session_id"]),
                state=SessionState(str(data["state"])),
                policy_digest=str(data["policy_digest"]),
                started_at=float(data["started_at"]),
                updated_at=float(data["updated_at"]),
                ended_at=(
                    float(data["ended_at"])
                    if data["ended_at"] is not None else None
                ),
                last_sequence=int(data["last_sequence"]),
            )
            raw_revision = data["control_revision"]
            if not isinstance(raw_revision, int) or isinstance(raw_revision, bool):
                raise ValueError("invalid control revision")
            revision = raw_revision
            enrollment_grant_id = str(data["enrollment_grant_id"])
        except (TypeError, ValueError, KeyError) as exc:
            raise WorkDiscoveryStoreError("invalid sealed session state") from exc
        if (
            not _digest_ok(session.policy_digest)
            or not _grant_id_ok(enrollment_grant_id)
            or not 1 <= revision <= _MAX_CONTROL_REVISION
        ):
            raise WorkDiscoveryStoreError("invalid sealed session state")
        return session, revision, enrollment_grant_id

    def _decode_session_row_state(
        self, row: sqlite3.Row,
    ) -> tuple[WorkSession, int, str]:
        session, revision, enrollment_grant_id = self._session_from_blob(row)
        expected = {
            "session_id": str(row["session_id"]),
            "state": str(row["state"]),
            "policy_digest": str(row["policy_digest"]),
            "started_at": float(row["started_at"]),
            "updated_at": float(row["updated_at"]),
            "ended_at": (
                float(row["ended_at"]) if row["ended_at"] is not None else None
            ),
            "last_sequence": int(row["last_sequence"]),
        }
        if session.to_dict() != expected:
            raise WorkDiscoveryStoreError("session authority integrity check failed")
        return session, revision, enrollment_grant_id

    def _decode_session_row(self, row: sqlite3.Row) -> WorkSession:
        # Read surfaces expose authenticated SQLite history even when a
        # restrictive control crashed after advancing its external marker.
        # Every mutating/capture path separately proves that marker is current.
        session, _revision, _grant_id = self._decode_session_row_state(row)
        return session

    @staticmethod
    def _lease_payload(
        lease: CollectorLease, *, revision: int,
    ) -> dict[str, Any]:
        return {**lease.to_dict(), "control_revision": revision}

    def _decode_lease_row_state(
        self, row: sqlite3.Row,
    ) -> tuple[CollectorLease, int]:
        data = self._unseal(bytes(row["lease_blob"]), purpose="lease")
        if set(data) != {
            "collector_key", "session_id", "state", "claimed_at",
            "heartbeat_at", "expires_at", "control_revision",
        }:
            raise WorkDiscoveryStoreError("invalid sealed collector lease")
        try:
            lease = CollectorLease(
                collector_key=str(data["collector_key"]),
                session_id=str(data["session_id"]),
                state=str(data["state"]),
                claimed_at=_timestamp(float(data["claimed_at"])),
                heartbeat_at=_timestamp(float(data["heartbeat_at"])),
                expires_at=_timestamp(float(data["expires_at"])),
            )
            raw_revision = data["control_revision"]
            if not isinstance(raw_revision, int) or isinstance(raw_revision, bool):
                raise ValueError("invalid control revision")
            revision = raw_revision
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkDiscoveryStoreError("invalid sealed collector lease") from exc
        if lease.state not in {"active", "paused", "released"}:
            raise WorkDiscoveryStoreError("invalid sealed collector lease")
        if (
            not _digest_ok(lease.collector_key)
            or not 1 <= revision <= _MAX_CONTROL_REVISION
        ):
            raise WorkDiscoveryStoreError("invalid sealed collector lease")
        expected = {
            "collector_key": str(row["collector_key"]),
            "session_id": str(row["session_id"]),
            "state": str(row["state"]),
            "claimed_at": float(row["claimed_at"]),
            "heartbeat_at": float(row["heartbeat_at"]),
            "expires_at": float(row["expires_at"]),
        }
        if lease.to_dict() != expected:
            raise WorkDiscoveryStoreError("collector lease authority integrity check failed")
        return lease, revision

    def _decode_lease_row(self, row: sqlite3.Row) -> CollectorLease:
        lease, revision = self._decode_lease_row_state(row)
        self._assert_session_revision(lease.session_id, revision)
        return lease

    def _lease_row(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT collector_key,session_id,state,claimed_at,heartbeat_at,"
            "expires_at,lease_blob FROM ekko_collector_leases "
            "WHERE tenant_key=? AND owner_key=? AND device_key=?",
            self._scope,
        ).fetchone()

    def _bind_session_revision(
        self,
        conn: sqlite3.Connection,
        session: WorkSession,
        *,
        revision: int,
        enrollment_grant_id: str,
    ) -> None:
        conn.execute(
            "UPDATE ekko_sessions SET session_blob=? WHERE tenant_key=? "
            "AND owner_key=? AND device_key=? AND session_id=?",
            (
                self._seal(
                    self._session_payload(
                        session,
                        revision=revision,
                        enrollment_grant_id=enrollment_grant_id,
                    ),
                    purpose="session",
                ),
                *self._scope,
                session.session_id,
            ),
        )
        if conn.execute("SELECT changes()").fetchone()[0] != 1:
            raise SessionStateError("session state changed concurrently")

    def _sync_lease_session_state(
        self,
        conn: sqlite3.Connection,
        *,
        session_id: str,
        state: SessionState,
        now: float,
        expected_revision: int,
        revision: int,
    ) -> None:
        """Bind a live collector capability to the authenticated session state."""
        row = self._lease_row(conn)
        if row is None:
            return
        lease, lease_revision = self._decode_lease_row_state(row)
        if lease.session_id != session_id:
            return
        if lease_revision != expected_revision:
            raise WorkDiscoveryStoreError(
                "Ekko collector lease control revision is stale"
            )
        desired = lease.state
        expires_at = lease.expires_at
        if lease.state != "released" and state in _TERMINAL_STATES:
            desired = "released"
            expires_at = now
        elif lease.state != "released" and state == SessionState.PAUSED:
            desired = "paused"
        elif (
            lease.state != "released"
            and state == SessionState.RUNNING
            and lease.expires_at > now
        ):
            desired = "active"
        updated = CollectorLease(
            collector_key=lease.collector_key,
            session_id=lease.session_id,
            state=desired,
            claimed_at=lease.claimed_at,
            heartbeat_at=lease.heartbeat_at,
            expires_at=expires_at,
        )
        conn.execute(
            "UPDATE ekko_collector_leases SET state=?,expires_at=?,lease_blob=? "
            "WHERE tenant_key=? AND owner_key=? AND device_key=? AND "
            "collector_key=? AND session_id=?",
            (
                desired,
                expires_at,
                self._seal(
                    self._lease_payload(updated, revision=revision), purpose="lease",
                ),
                *self._scope,
                lease.collector_key,
                lease.session_id,
            ),
        )
        if conn.execute("SELECT changes()").fetchone()[0] != 1:
            raise CollectorLeaseError("collector lease changed concurrently")

    def _queue_audit(
        self, conn: sqlite3.Connection, kind: str, payload: dict[str, Any], *, at: float,
    ) -> None:
        pending = int(conn.execute(
            "SELECT COUNT(*) FROM ekko_audit_outbox WHERE tenant_key=? "
            "AND owner_key=? AND device_key=?",
            self._scope,
        ).fetchone()[0])
        if pending >= MAX_AUDIT_OUTBOX:
            raise WorkDiscoveryStoreError("Ekko lifecycle audit outbox is full")
        outbox_id = f"audit-{secrets.token_hex(12)}"
        sealed = self._seal(
            {"kind": str(kind), "payload": payload, "created_at": float(at)},
            purpose="audit",
        )
        conn.execute(
            "INSERT INTO ekko_audit_outbox(tenant_key,owner_key,device_key,"
            "outbox_id,created_at,payload) VALUES(?,?,?,?,?,?)",
            (*self._scope, outbox_id, at, sealed),
        )

    def pending_audit_count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute(
                "SELECT COUNT(*) FROM ekko_audit_outbox WHERE tenant_key=? "
                "AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchone()[0])

    def flush_audit_outbox(
        self,
        *,
        limit: int = 100,
        recorder: Callable[..., bool] | None = None,
    ) -> dict[str, int]:
        """Deliver bounded lifecycle events with at-least-once semantics."""
        if not 1 <= int(limit) <= 500:
            raise ValueError("audit flush limit must be between 1 and 500")
        if recorder is None:
            from .audit import record as recorder

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT outbox_id,created_at,payload FROM ekko_audit_outbox "
                "WHERE tenant_key=? AND owner_key=? AND device_key=? "
                "ORDER BY created_at,outbox_id LIMIT ?",
                (*self._scope, int(limit)),
            ).fetchall()
        delivered = 0
        for row in rows:
            sealed_blob = bytes(row["payload"])
            data = self._unseal(sealed_blob, purpose="audit")
            if (
                set(data) != {"kind", "payload", "created_at"}
                or not isinstance(data.get("kind"), str)
                or not data["kind"].startswith("ekko_")
                or not isinstance(data.get("payload"), dict)
                or data.get("created_at") != float(row["created_at"])
            ):
                raise WorkDiscoveryStoreError("invalid sealed Ekko audit outbox row")
            outbox_id = str(row["outbox_id"])
            try:
                accepted = bool(recorder(
                    data["kind"],
                    agent="ekko-store-outbox",
                    ekko_outbox_id=outbox_id,
                    occurred_at=float(data["created_at"]),
                    lifecycle=data["payload"],
                ))
            except Exception:
                accepted = False
            if not accepted:
                break
            with self._transaction() as conn:
                conn.execute(
                    "DELETE FROM ekko_audit_outbox WHERE tenant_key=? AND "
                    "owner_key=? AND device_key=? AND outbox_id=? AND payload=?",
                    (*self._scope, outbox_id, sealed_blob),
                )
                if conn.execute("SELECT changes()").fetchone()[0] != 1:
                    # Another drainer won the acknowledgement race. Delivery is
                    # still at-least-once and the stable outbox id enables sink
                    # deduplication.
                    continue
            delivered += 1
        return {"delivered": delivered, "pending": self.pending_audit_count()}

    def _assert_database_capacity(self) -> None:
        try:
            database_bytes = self.path.stat().st_size
        except OSError:
            database_bytes = 0
        if database_bytes > MAX_DATABASE_BYTES - _DATABASE_GROWTH_RESERVE:
            raise WorkDiscoveryStoreError("Ekko storage quota is exhausted")

    def enroll(
        self, policy: CapturePolicy, *, expires_at: float | None = None,
        at: float | None = None,
    ) -> Enrollment:
        if not isinstance(policy, CapturePolicy):
            raise TypeError("policy must be a CapturePolicy")
        # Rehydrate through the persistence parser so the built-in sensitive
        # application block floor is present in the exact enrolled fingerprint.
        policy = CapturePolicy.from_dict(policy.to_dict())
        policy.require_valid(require_enabled=True)
        digest = policy.fingerprint()
        now = self._now() if at is None else _timestamp(at)
        expiry = (
            now + DEFAULT_ENROLLMENT_DAYS * 86_400.0
            if expires_at is None else _timestamp(expires_at)
        )
        if not now < expiry <= now + MAX_ENROLLMENT_DAYS * 86_400.0:
            raise ValueError(f"enrollment expiry must be within {MAX_ENROLLMENT_DAYS} days")
        enrolled_at = now
        grant_id = f"grant-{secrets.token_hex(16)}"
        policy_blob = self._seal(
            self._enrollment_payload(
                policy,
                grant_id=grant_id,
                active=True,
                enrolled_at=enrolled_at,
                updated_at=now,
                expires_at=expiry,
            ),
            purpose="enrollment",
        )
        with self._deployment_control_barrier(), self._consent_barrier():
            session_ids = self._scoped_session_ids()
            with self._session_authority_barriers(session_ids), self._transaction() as conn:
                self._authority_check(policy)
                self._assert_database_capacity()
                session_rows = conn.execute(
                    "SELECT session_id,state,policy_digest,started_at,updated_at,"
                    "ended_at,last_sequence,session_blob FROM ekko_sessions "
                    "WHERE tenant_key=? AND owner_key=? AND device_key=?",
                    self._scope,
                ).fetchall()
                for session_row in session_rows:
                    session, revision, _session_grant_id = (
                        self._decode_session_row_state(session_row)
                    )
                    self._assert_session_revision(session.session_id, revision)
                    if session.state not in _TERMINAL_STATES:
                        raise SessionStateError(
                            "stop all active Ekko sessions before changing enrollment"
                        )
                conn.execute(
                    "INSERT INTO ekko_enrollments(tenant_key,owner_key,device_key,active,"
                    "grant_id,policy_digest,policy_blob,enrolled_at,updated_at,expires_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(tenant_key,owner_key,device_key) DO UPDATE SET "
                    "active=excluded.active, grant_id=excluded.grant_id, "
                    "policy_digest=excluded.policy_digest, policy_blob=excluded.policy_blob, "
                    "enrolled_at=excluded.enrolled_at, updated_at=excluded.updated_at, "
                    "expires_at=excluded.expires_at",
                    (
                        *self._scope, 1, grant_id, digest, policy_blob,
                        enrolled_at, now, expiry,
                    ),
                )
                self._queue_audit(
                    conn,
                    "ekko_consent_changed",
                    {"state": "enrolled", "policy_digest": digest},
                    at=now,
                )
            # The database row is intentionally committed first: a crash before
            # this marker update leaves a stale generation and capture fails
            # closed. The barrier prevents a delayed enroll from overwriting a
            # concurrent revocation marker.
            self._write_consent_authority({
                "state": "active",
                "grant_id": grant_id,
                "policy_digest": digest,
                "expires_at": expiry,
            })
        return Enrollment(True, digest, enrolled_at, now, expiry)

    def get_enrollment(self) -> Enrollment | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT active,grant_id,policy_digest,policy_blob,enrolled_at,"
                "updated_at,expires_at "
                "FROM ekko_enrollments "
                "WHERE tenant_key=? AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchone()
        return self._decode_enrollment_row(row, now=self._now())[0] if row else None

    def get_policy(self) -> CapturePolicy | None:
        now = self._now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT active,grant_id,policy_digest,policy_blob,enrolled_at,"
                "updated_at,expires_at "
                "FROM ekko_enrollments "
                "WHERE tenant_key=? AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchone()
        if row is None:
            return None
        enrollment, policy = self._decode_enrollment_row(row, now=now)
        return policy if enrollment.active else None

    def revoke_enrollment(self, *, at: float | None = None) -> Enrollment | None:
        now = self._now() if at is None else _timestamp(at)
        with self._deployment_control_barrier(), self._consent_barrier():
            return self._revoke_enrollment_locked(now)

    def _revoke_enrollment_locked(self, now: float) -> Enrollment | None:
        # This authority lives outside the database so replaying a backed-up
        # active row cannot resurrect consent. Write it before touching SQLite;
        # a crash can only fail closed.
        try:
            self._write_consent_authority({
                "state": "revoked",
                "grant_id": "",
                "policy_digest": "",
                "expires_at": now,
            })
        except Exception:
            self._write_revoked_sentinel(revoked_at=now)
        session_ids = self._scoped_session_ids()
        with self._session_authority_barriers(session_ids), self._transaction() as conn:
            row = conn.execute(
                "SELECT active,grant_id,policy_digest,policy_blob,enrolled_at,"
                "updated_at,expires_at "
                "FROM ekko_enrollments "
                "WHERE tenant_key=? AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchone()
            if row is None:
                return None
            try:
                enrollment, _policy = self._decode_enrollment_row(row, now=now)
            except WorkDiscoveryStoreError:
                digest = str(row["policy_digest"])
                enrollment = Enrollment(
                    False,
                    digest if _digest_ok(digest) else "0" * 64,
                    now,
                    now,
                    now,
                )
            # Safety control is deletion-based: even corrupted consent state or
            # an unavailable KMS cannot make revocation depend on re-sealing a
            # value. A later enrollment is a fresh, separately audited grant.
            conn.execute(
                "DELETE FROM ekko_enrollments WHERE tenant_key=? AND owner_key=? "
                "AND device_key=?",
                self._scope,
            )
            # Revocation and capture state change share one write lock, closing
            # the race where an event lands after a client turns discovery off.
            sessions = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob FROM ekko_sessions "
                "WHERE tenant_key=? AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchall()
            for session_row in sessions:
                session_id = str(session_row["session_id"])
                try:
                    session, revision, session_grant_id = (
                        self._decode_session_row_state(session_row)
                    )
                    self._assert_session_revision(session.session_id, revision)
                except WorkDiscoveryStoreError:
                    # Unreadable state cannot safely survive a revoke. Cascading
                    # deletion removes its events and prevents later revival.
                    try:
                        self._tombstone_session_authority(session_id)
                    except WorkDiscoveryStoreError:
                        # A missing or corrupt marker already fails closed.
                        pass
                    conn.execute(
                        "DELETE FROM ekko_sessions WHERE tenant_key=? AND owner_key=? "
                        "AND device_key=? AND session_id=?",
                        (*self._scope, session_id),
                    )
                    continue
                if session.state in _TERMINAL_STATES:
                    continue
                stopped = (
                    WorkSession(
                        session.session_id,
                        SessionState.STOPPED,
                        session.policy_digest,
                        session.started_at,
                        now,
                        now,
                        session.last_sequence,
                    )
                    if session.state not in _TERMINAL_STATES else session
                )
                next_revision = self._rotate_session_revision(
                    session.session_id, expected_revision=revision,
                )
                conn.execute(
                    "UPDATE ekko_sessions SET state=?,policy_digest=?,started_at=?,"
                    "updated_at=?,ended_at=?,last_sequence=?,session_blob=? "
                    "WHERE tenant_key=? AND owner_key=? AND device_key=? "
                    "AND session_id=?",
                    (
                        stopped.state.value, stopped.policy_digest,
                        stopped.started_at, stopped.updated_at,
                        stopped.ended_at, stopped.last_sequence,
                        self._seal(
                            self._session_payload(
                                stopped,
                                revision=next_revision,
                                enrollment_grant_id=session_grant_id,
                            ),
                            purpose="session",
                        ),
                        *self._scope, session.session_id,
                    ),
                )
                self._sync_lease_session_state(
                    conn,
                    session_id=session.session_id,
                    state=SessionState.STOPPED,
                    now=now,
                    expected_revision=revision,
                    revision=next_revision,
                )
            try:
                self._queue_audit(
                    conn, "ekko_consent_changed", {"state": "revoked"}, at=now,
                )
            except Exception:
                # Revocation/stop must win even when the audit outbox is down.
                # This is not true of a KMS outage: re-sealing the stopped
                # sessions above needs the KMS, so its failure rolls back this
                # SQLite transaction. Capture still fails closed, because the
                # revoked consent authority was written before it began.
                pass
        return Enrollment(
            False, enrollment.policy_digest, enrollment.enrolled_at, now,
            enrollment.expires_at,
        )

    def _active_enrollment(
        self, conn: sqlite3.Connection, policy: CapturePolicy,
    ) -> tuple[str, str]:
        row = conn.execute(
            "SELECT active,grant_id,policy_digest,policy_blob,enrolled_at,"
            "updated_at,expires_at "
            "FROM ekko_enrollments "
            "WHERE tenant_key=? "
            "AND owner_key=? AND device_key=?",
            self._scope,
        ).fetchone()
        if row is None:
            raise EnrollmentRequired("this owner and device are not enrolled")
        enrollment, _stored = self._decode_enrollment_row(row, now=self._now())
        if not enrollment.active:
            raise EnrollmentRequired("this owner and device enrollment expired")
        digest = policy.fingerprint()
        if not hmac.compare_digest(enrollment.policy_digest, digest):
            raise EnrollmentRequired("capture policy changed; re-enrollment is required")
        return digest, str(row["grant_id"])

    def create_session(
        self, *, policy: CapturePolicy | None = None,
        policy_digest: str | None = None, session_id: str | None = None,
        started_at: float | None = None,
    ) -> WorkSession:
        policy = policy or self.get_policy()
        if policy is None:
            raise EnrollmentRequired("no active, unexpired enrollment policy")
        policy.require_valid(require_enabled=True)
        digest = policy.fingerprint()
        if policy_digest is not None and not hmac.compare_digest(
            digest, str(policy_digest).strip().lower(),
        ):
            raise EnrollmentRequired("capture policy changed; re-enrollment is required")
        session_id = session_id or f"ekko-{secrets.token_hex(12)}"
        # WorkEvent owns the canonical id grammar; validate without inventing a
        # dummy persisted event.
        if len(session_id) > 64 or not session_id or any(
            char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-"
            for char in session_id
        ):
            raise ValueError("invalid session_id")
        now = self._now() if started_at is None else _timestamp(started_at)
        session = WorkSession(
            session_id, SessionState.RUNNING, digest, now, now, None, 0,
        )
        with (
            self._deployment_control_barrier(),
            self._consent_barrier(),
            self._session_authority_barrier(session_id),
            self._transaction() as conn,
        ):
            self._authority_check(policy)
            _active_digest, enrollment_grant_id = self._active_enrollment(
                conn, policy,
            )
            self._assert_database_capacity()
            session_count = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_sessions WHERE tenant_key=? "
                "AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchone()[0])
            if session_count >= MAX_SESSIONS_PER_DEVICE:
                raise WorkDiscoveryStoreError("Ekko session quota is exhausted")
            if conn.execute(
                "SELECT 1 FROM ekko_sessions WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND state IN ('created','running','paused') LIMIT 1",
                self._scope,
            ).fetchone() is not None:
                raise SessionStateError(
                    "this device already has an active Ekko session"
                )
            if conn.execute(
                "SELECT 1 FROM ekko_sessions WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND session_id=?",
                (*self._scope, session_id),
            ).fetchone() is not None:
                raise SessionStateError(
                    "session_id already exists in this device scope"
                )
            # The authenticated marker is advanced before SQLite. A crash can
            # leave an unusable marker without a row, but can never make an old
            # row authoritative again. Prior/orphaned ids are never reused.
            revision = self._fresh_session_revision(session_id)
            session_blob = self._seal(
                self._session_payload(
                    session,
                    revision=revision,
                    enrollment_grant_id=enrollment_grant_id,
                ),
                purpose="session",
            )
            try:
                conn.execute(
                    "INSERT INTO ekko_sessions(tenant_key,owner_key,device_key,session_id,"
                    "state,policy_digest,started_at,updated_at,ended_at,last_sequence,"
                    "session_blob) VALUES(?,?,?,?,?,?,?,?,NULL,0,?)",
                    (
                        *self._scope, session_id, SessionState.RUNNING.value,
                        digest, now, now, session_blob,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SessionStateError("session_id already exists in this device scope") from exc
            self._queue_audit(
                conn,
                "ekko_session",
                {"session_id": session_id, "state": "running"},
                at=now,
            )
        return session

    def get_session(self, session_id: str) -> WorkSession | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob "
                "FROM ekko_sessions WHERE tenant_key=? AND owner_key=? AND device_key=? "
                "AND session_id=?",
                (*self._scope, session_id),
            ).fetchone()
        return self._decode_session_row(row) if row else None

    def latest_session(self) -> WorkSession | None:
        rows = self.list_sessions(limit=1)
        return rows[0] if rows else None

    def list_sessions(self, *, limit: int = 100) -> list[WorkSession]:
        if not 1 <= int(limit) <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob "
                "FROM ekko_sessions WHERE tenant_key=? AND owner_key=? AND device_key=? "
                "ORDER BY updated_at DESC LIMIT ?",
                (*self._scope, int(limit)),
            ).fetchall()
        return [self._decode_session_row(row) for row in rows]

    def transition_session(
        self, session_id: str, state: SessionState | str, *, at: float | None = None,
    ) -> WorkSession:
        try:
            target = state if isinstance(state, SessionState) else SessionState(str(state))
        except ValueError as exc:
            raise ValueError("invalid session state") from exc
        resume_policy = self.get_policy() if target == SessionState.RUNNING else None
        if target == SessionState.RUNNING and resume_policy is None:
            raise EnrollmentRequired("no active, unexpired enrollment policy")
        now = self._now() if at is None else _timestamp(at)
        with (
            self._deployment_control_barrier(),
            self._consent_barrier(),
            self._session_authority_barrier(session_id),
            self._transaction() as conn,
        ):
            row = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob "
                "FROM ekko_sessions WHERE tenant_key=? AND owner_key=? AND device_key=? "
                "AND session_id=?",
                (*self._scope, session_id),
            ).fetchone()
            if row is None:
                raise SessionStateError("session does not exist in this device scope")
            session, revision, session_grant_id = (
                self._decode_session_row_state(row)
            )
            authority = self._read_session_authority(session.session_id)
            assert authority is not None
            marker_ahead = authority["revision"] == revision + 1
            if authority["revision"] != revision and not (
                marker_ahead and target != SessionState.RUNNING
            ):
                raise WorkDiscoveryStoreError(
                    "Ekko session control authority is stale"
                )
            current = session.state
            if target == SessionState.RUNNING:
                assert resume_policy is not None
                self._authority_check(resume_policy)
                digest, active_grant_id = self._active_enrollment(
                    conn, resume_policy,
                )
                if (
                    not hmac.compare_digest(digest, session.policy_digest)
                    or not hmac.compare_digest(
                        active_grant_id, session_grant_id,
                    )
                ):
                    raise EnrollmentRequired(
                        "session enrollment changed; start a new enrolled session"
                    )
            if current == target:
                if authority["revision"] != revision:
                    raise WorkDiscoveryStoreError(
                        "Ekko session control authority is stale"
                    )
                return session
            if target not in _TRANSITIONS[current]:
                raise SessionStateError(f"cannot transition session from {current.value} to {target.value}")
            ended = now if target in _TERMINAL_STATES else None
            result = WorkSession(
                session_id=session_id,
                state=target,
                policy_digest=session.policy_digest,
                started_at=session.started_at,
                updated_at=now,
                ended_at=ended,
                last_sequence=session.last_sequence,
            )
            # Restrictive controls advance the external rollback authority
            # before SQLite. Resume proves the current revision but does not
            # advance it: replaying a paused row can only fail closed.
            next_revision = (
                revision
                if target == SessionState.RUNNING
                else authority["revision"]
                if marker_ahead
                else self._rotate_session_revision(
                    session_id, expected_revision=revision,
                )
            )
            conn.execute(
                "UPDATE ekko_sessions SET state=?,updated_at=?,ended_at=?,session_blob=? "
                "WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? AND session_id=? AND state=?",
                (
                    target.value, now, ended,
                    self._seal(
                        self._session_payload(
                            result,
                            revision=next_revision,
                            enrollment_grant_id=session_grant_id,
                        ),
                        purpose="session",
                    ),
                    *self._scope, session_id, current.value,
                ),
            )
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise SessionStateError("session state changed concurrently")
            self._sync_lease_session_state(
                conn,
                session_id=session_id,
                state=target,
                now=now,
                expected_revision=revision,
                revision=next_revision,
            )
            try:
                self._queue_audit(
                    conn,
                    "ekko_session",
                    {"session_id": session_id, "state": target.value},
                    at=now,
                )
            except Exception:
                if target == SessionState.RUNNING:
                    # Resuming observation is expansive and fails closed when
                    # its durable lifecycle outbox cannot accept the event.
                    raise
                # Pause/stop/halt are safety controls. Their authenticated
                # session and lease transitions must commit even during an
                # audit/outbox outage.
        return result

    def claim_collector(
        self,
        session_id: str,
        collector_id: str,
        *,
        policy: CapturePolicy,
        ttl_seconds: float = DEFAULT_COLLECTOR_LEASE_SECONDS,
        at: float | None = None,
    ) -> CollectorLease:
        """Claim the sole live collector lease for this owner/device/session."""
        collector = _collector_key(collector_id)
        ttl = _lease_ttl(ttl_seconds)
        if not isinstance(policy, CapturePolicy):
            raise TypeError("policy must be a CapturePolicy")
        policy.require_valid(require_enabled=True)
        now = self._now() if at is None else _timestamp(at)
        with (
            self._deployment_control_barrier(),
            self._consent_barrier(),
            self._session_authority_barrier(session_id),
            self._transaction() as conn,
        ):
            self._authority_check(policy)
            digest, active_grant_id = self._active_enrollment(conn, policy)
            self._assert_database_capacity()
            session_row = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob FROM ekko_sessions WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? AND session_id=?",
                (*self._scope, session_id),
            ).fetchone()
            if session_row is None:
                raise SessionStateError("session does not exist in this device scope")
            session, revision, session_grant_id = (
                self._decode_session_row_state(session_row)
            )
            self._assert_session_revision(session.session_id, revision)
            if session.state not in {SessionState.RUNNING, SessionState.PAUSED}:
                raise SessionStateError("collector lease requires an active session")
            if (
                not hmac.compare_digest(digest, session.policy_digest)
                or not hmac.compare_digest(active_grant_id, session_grant_id)
            ):
                raise EnrollmentRequired(
                    "session enrollment changed; start a new session"
                )

            existing_row = self._lease_row(conn)
            claimed_at = now
            if existing_row is not None:
                existing = self._decode_lease_row(existing_row)
                same_owner = (
                    existing.collector_key == collector
                    and existing.session_id == session_id
                )
                existing_session_live = False
                if existing.state in {"active", "paused"} and existing.expires_at > now:
                    old_row = conn.execute(
                        "SELECT session_id,state,policy_digest,started_at,updated_at,"
                        "ended_at,last_sequence,session_blob FROM ekko_sessions "
                        "WHERE tenant_key=? AND owner_key=? AND device_key=? "
                        "AND session_id=?",
                        (*self._scope, existing.session_id),
                    ).fetchone()
                    if old_row is not None:
                        old_session = self._decode_session_row(old_row)
                        existing_session_live = old_session.state in {
                            SessionState.RUNNING, SessionState.PAUSED,
                        }
                if existing.state in {"active", "paused"} and existing.expires_at > now:
                    if not same_owner and existing_session_live:
                        raise CollectorLeaseError(
                            "this device already has a live collector"
                        )
                    if same_owner:
                        claimed_at = existing.claimed_at

            lease = CollectorLease(
                collector_key=collector,
                session_id=session_id,
                state=(
                    "active" if session.state == SessionState.RUNNING else "paused"
                ),
                claimed_at=claimed_at,
                heartbeat_at=now,
                expires_at=now + ttl,
            )
            next_revision = self._rotate_session_revision(
                session_id, expected_revision=revision,
            )
            self._bind_session_revision(
                conn,
                session,
                revision=next_revision,
                enrollment_grant_id=session_grant_id,
            )
            conn.execute(
                "INSERT INTO ekko_collector_leases(tenant_key,owner_key,device_key,"
                "collector_key,session_id,state,claimed_at,heartbeat_at,expires_at,"
                "lease_blob) VALUES(?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_key,owner_key,device_key) DO UPDATE SET "
                "collector_key=excluded.collector_key,session_id=excluded.session_id,"
                "state=excluded.state,claimed_at=excluded.claimed_at,"
                "heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at,"
                "lease_blob=excluded.lease_blob",
                (
                    *self._scope, lease.collector_key, lease.session_id, lease.state,
                    lease.claimed_at, lease.heartbeat_at, lease.expires_at,
                    self._seal(
                        self._lease_payload(lease, revision=next_revision),
                        purpose="lease",
                    ),
                ),
            )
            self._queue_audit(
                conn,
                "ekko_session",
                {"session_id": session_id, "state": "collector_claimed"},
                at=now,
            )
        return lease

    def heartbeat_collector(
        self,
        session_id: str,
        collector_id: str,
        *,
        policy: CapturePolicy,
        ttl_seconds: float = DEFAULT_COLLECTOR_LEASE_SECONDS,
        at: float | None = None,
    ) -> CollectorLease:
        """Extend a matching unexpired lease; an expired lease cannot revive."""
        collector = _collector_key(collector_id)
        ttl = _lease_ttl(ttl_seconds)
        if not isinstance(policy, CapturePolicy):
            raise TypeError("policy must be a CapturePolicy")
        policy.require_valid(require_enabled=True)
        now = self._now() if at is None else _timestamp(at)
        with (
            self._deployment_control_barrier(),
            self._consent_barrier(),
            self._session_authority_barrier(session_id),
            self._transaction() as conn,
        ):
            self._authority_check(policy)
            digest, active_grant_id = self._active_enrollment(conn, policy)
            row = self._lease_row(conn)
            if row is None:
                raise CollectorLeaseError("collector lease is missing")
            current, lease_revision = self._decode_lease_row_state(row)
            self._assert_session_revision(current.session_id, lease_revision)
            if (
                current.state not in {"active", "paused"}
                or current.collector_key != collector
                or current.session_id != session_id
            ):
                raise CollectorLeaseError("collector does not own this lease")
            if current.expires_at <= now:
                raise CollectorLeaseError("collector lease expired")
            session_row = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob FROM ekko_sessions WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? AND session_id=?",
                (*self._scope, session_id),
            ).fetchone()
            if session_row is None:
                raise SessionStateError("session does not exist in this device scope")
            session, revision, session_grant_id = (
                self._decode_session_row_state(session_row)
            )
            self._assert_session_revision(session.session_id, revision)
            if (
                not hmac.compare_digest(digest, session.policy_digest)
                or not hmac.compare_digest(active_grant_id, session_grant_id)
            ):
                raise EnrollmentRequired(
                    "session enrollment changed; start a new session"
                )
            if lease_revision != revision:
                raise WorkDiscoveryStoreError(
                    "Ekko collector lease control revision is stale"
                )
            if session.state not in {SessionState.RUNNING, SessionState.PAUSED}:
                raise SessionStateError("collector lease requires an active session")
            lease = CollectorLease(
                collector_key=collector,
                session_id=session_id,
                state=(
                    "active" if session.state == SessionState.RUNNING else "paused"
                ),
                claimed_at=current.claimed_at,
                heartbeat_at=now,
                expires_at=now + ttl,
            )
            conn.execute(
                "UPDATE ekko_collector_leases SET heartbeat_at=?,expires_at=?,"
                "lease_blob=? WHERE tenant_key=? AND owner_key=? AND device_key=? "
                "AND collector_key=? AND session_id=? AND state IN ('active','paused')",
                (
                    lease.heartbeat_at, lease.expires_at,
                    self._seal(
                        self._lease_payload(lease, revision=revision),
                        purpose="lease",
                    ),
                    *self._scope, collector, session_id,
                ),
            )
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise CollectorLeaseError("collector lease changed concurrently")
        return lease

    def release_collector(
        self, session_id: str, collector_id: str, *, at: float | None = None,
    ) -> bool:
        """Release a matching lease. Safety shutdown never needs policy authority."""
        collector = _collector_key(collector_id)
        now = self._now() if at is None else _timestamp(at)
        with (
            self._deployment_control_barrier(),
            self._consent_barrier(),
            self._session_authority_barrier(session_id),
            self._transaction() as conn,
        ):
            row = self._lease_row(conn)
            if row is None:
                return False
            current, lease_revision = self._decode_lease_row_state(row)
            if current.collector_key != collector or current.session_id != session_id:
                raise CollectorLeaseError("collector does not own this lease")
            session_row = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob FROM ekko_sessions WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? AND session_id=?",
                (*self._scope, session_id),
            ).fetchone()
            if session_row is None:
                raise SessionStateError("session does not exist in this device scope")
            session, revision, session_grant_id = (
                self._decode_session_row_state(session_row)
            )
            if lease_revision != revision:
                raise WorkDiscoveryStoreError(
                    "Ekko collector lease control revision is stale"
                )
            authority = self._read_session_authority(session_id)
            assert authority is not None
            marker_revision = int(authority["revision"])
            marker_ahead = marker_revision == revision + 1
            if marker_revision == revision:
                if current.state == "released":
                    return False
                next_revision = self._rotate_session_revision(
                    session_id, expected_revision=revision,
                )
            elif marker_ahead:
                # Release is restrictive. If a prior attempt advanced the
                # external marker and SQLite rolled back, catch both sealed
                # rows up to that exact revision without advancing it again.
                next_revision = marker_revision
            else:
                raise WorkDiscoveryStoreError(
                    "Ekko session control authority is stale"
                )
            released = CollectorLease(
                collector_key=collector,
                session_id=session_id,
                state="released",
                claimed_at=current.claimed_at,
                heartbeat_at=now,
                expires_at=now,
            )
            self._bind_session_revision(
                conn,
                session,
                revision=next_revision,
                enrollment_grant_id=session_grant_id,
            )
            conn.execute(
                "UPDATE ekko_collector_leases SET state='released',heartbeat_at=?,"
                "expires_at=?,lease_blob=? WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND collector_key=? AND session_id=?",
                (
                    now, now,
                    self._seal(
                        self._lease_payload(released, revision=next_revision),
                        purpose="lease",
                    ),
                    *self._scope, collector, session_id,
                ),
            )
            changed = conn.execute("SELECT changes()").fetchone()[0] == 1
            if changed:
                try:
                    self._queue_audit(
                        conn,
                        "ekko_session",
                        {"session_id": session_id, "state": "collector_released"},
                        at=now,
                    )
                except Exception:
                    # Release is a safety action and must not depend on audit.
                    pass
        return changed

    def collector_status(
        self, session_id: str | None = None, *, now: float | None = None,
    ) -> dict[str, Any]:
        """Return a content-free liveness view: ``live``, ``waiting``, or ``stale``."""
        trusted_now = self._now() if now is None else _timestamp(now)
        session = self.get_session(session_id) if session_id else self.latest_session()
        if session is None:
            return {"state": "waiting", "session_id": None}
        with self._session_authority_barrier(session.session_id), self._connect() as conn:
            session_row = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob FROM ekko_sessions WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? AND session_id=?",
                (*self._scope, session.session_id),
            ).fetchone()
            if session_row is None:
                return {"state": "waiting", "session_id": None}
            session, revision, session_grant_id = (
                self._decode_session_row_state(session_row)
            )
            self._assert_session_revision(session.session_id, revision)
            row = self._lease_row(conn)
            enrollment_row = conn.execute(
                "SELECT active,grant_id,policy_digest,policy_blob,enrolled_at,"
                "updated_at,expires_at FROM ekko_enrollments WHERE tenant_key=? "
                "AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchone()
            grant_is_current = False
            if enrollment_row is not None:
                try:
                    enrollment, _policy = self._decode_enrollment_row(
                        enrollment_row, now=trusted_now,
                    )
                    grant_is_current = (
                        enrollment.active
                        and hmac.compare_digest(
                            str(enrollment_row["grant_id"]), session_grant_id,
                        )
                        and hmac.compare_digest(
                            enrollment.policy_digest, session.policy_digest,
                        )
                    )
                except WorkDiscoveryStoreError:
                    grant_is_current = False
        if session.state in _TERMINAL_STATES:
            return {"state": "waiting", "session_id": session.session_id}
        if not grant_is_current:
            return {"state": "stale", "session_id": session.session_id}
        if row is None:
            return {"state": "waiting", "session_id": session.session_id}
        lease = self._decode_lease_row(row)
        if lease.session_id != session.session_id or lease.state == "released":
            state = "waiting"
        elif lease.expires_at <= trusted_now:
            state = "stale"
        else:
            state = "live"
        return {
            "state": state,
            "session_id": session.session_id,
            "heartbeat_at": lease.heartbeat_at,
            "expires_at": lease.expires_at,
        }

    def _assert_live_collector(
        self,
        conn: sqlite3.Connection,
        *,
        session_id: str,
        collector_id: str,
        now: float,
    ) -> None:
        row = self._lease_row(conn)
        if row is None:
            raise CollectorLeaseError("collector lease is missing")
        lease = self._decode_lease_row(row)
        if (
            lease.state != "active"
            or lease.session_id != session_id
            or not hmac.compare_digest(lease.collector_key, _collector_key(collector_id))
        ):
            raise CollectorLeaseError("collector does not own this lease")
        if lease.expires_at <= now:
            raise CollectorLeaseError("collector lease expired")

    @staticmethod
    def _event_digest(event: WorkEvent) -> str:
        body = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def _purge_expired_events(self, *, now: float | None = None, audit: bool = False) -> int:
        """Physically delete expired ciphertext on every active store touch.

        ``audit`` also queues an ``ekko_retention_purge`` record in the same
        transaction, so a deletion is never committed without its record.
        """
        trusted_now = self._now() if now is None else _timestamp(now)
        with self._transaction() as conn:
            conn.execute("DELETE FROM ekko_plans WHERE tenant_key=? AND owner_key=? AND device_key=? AND expires_at<=?",
                         (*self._scope, trusted_now))
            count = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND expires_at<=?",
                (*self._scope, trusted_now),
            ).fetchone()[0])
            if count:
                conn.execute(
                    "DELETE FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                    "AND device_key=? AND expires_at<=?",
                    (*self._scope, trusted_now),
                )
                if audit:
                    self._queue_audit(
                        conn, "ekko_retention_purge",
                        {"state": "expired_removed", "removed": count}, at=trusted_now,
                    )
        return count

    def purge_expired(self) -> int:
        """Delete this scope's expired ciphertext now. Explicit write actions call this.

        The deletion and its retention record commit together. A full audit outbox
        raises and deletes nothing, so the rows wait for the next explicit write.
        """
        with self._deployment_control_barrier(), self._consent_barrier():
            return self._purge_expired_events(audit=True)

    def append_collector_event(
        self,
        event: WorkEvent,
        *,
        policy: CapturePolicy,
        collector_id: str,
    ) -> bool:
        """Append from a daemon only after proving its matching live lease."""
        return self.append_event(
            event, policy=policy, collector_id=collector_id,
        )

    def append_event(
        self,
        event: WorkEvent,
        *,
        policy: CapturePolicy,
        collector_id: str,
    ) -> bool:
        """Append exactly the next event; return ``False`` for an exact retry.

        The running-state check and insert share a ``BEGIN IMMEDIATE`` lock, so
        a concurrent stop/revocation wins either before or after the append but
        can never leave an event committed after its terminal transition.

        Every ingest path proves an unexpired exclusive lease inside this same
        transaction. Reviewed integrations use the same lease protocol as the
        bundled observer; there is no production-callable unleased bypass.
        """
        if not isinstance(event, WorkEvent):
            raise TypeError("event must be a WorkEvent")
        if not isinstance(policy, CapturePolicy):
            raise TypeError("policy must be a CapturePolicy")
        policy.require_valid(require_enabled=True)
        if not policy.allows(event):
            raise EnrollmentRequired("event is outside the enrolled capture policy")
        event_digest = self._event_digest(event)
        now = self._now()
        if event.occurred_at > now + 300.0:
            raise ValueError("event timestamp is more than five minutes in the future")
        if event.occurred_at < now - policy.retention_days * 86_400.0:
            raise ValueError("event timestamp is older than the retention window")
        # Retention is measured from when the work occurred, not when a guided
        # integration delivered it. Otherwise a nearly-expired backfilled event
        # could remain readable for almost twice the client-approved window.
        expires_at = event.occurred_at + policy.retention_days * 86_400.0
        payload = self._seal(
            {
                "event": event.to_dict(),
                "ingested_at": now,
                "expires_at": expires_at,
            },
            purpose="event",
        )
        # The deployment-wide dashboard OFF mutation holds the same strict
        # cross-process barrier. It cannot return until every append authorized
        # under the previous policy has either committed or failed.
        with (
            self._deployment_control_barrier(),
            self._consent_barrier(),
            self._session_authority_barrier(event.session_id),
            self._transaction() as conn,
        ):
            self._authority_check(policy)
            self._assert_database_capacity()
            conn.execute(
                "DELETE FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND expires_at<=?",
                (*self._scope, now),
            )
            row = conn.execute(
                "SELECT session_id,state,policy_digest,started_at,updated_at,ended_at,"
                "last_sequence,session_blob FROM ekko_sessions WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? AND session_id=?",
                (*self._scope, event.session_id),
            ).fetchone()
            if row is None:
                raise SessionStateError("session does not exist in this device scope")
            session, revision, session_grant_id = (
                self._decode_session_row_state(row)
            )
            self._assert_session_revision(session.session_id, revision)
            digest, active_grant_id = self._active_enrollment(conn, policy)
            if (
                not hmac.compare_digest(digest, session.policy_digest)
                or not hmac.compare_digest(active_grant_id, session_grant_id)
            ):
                raise EnrollmentRequired(
                    "session enrollment changed; start a new session"
                )
            if event.occurred_at < session.started_at - 300.0:
                raise ValueError("event timestamp materially predates the session")
            if session.state != SessionState.RUNNING:
                raise SessionStateError("events are accepted only while the session is running")
            self._assert_live_collector(
                conn,
                session_id=event.session_id,
                collector_id=collector_id,
                now=now,
            )
            duplicate = conn.execute(
                "SELECT event_digest FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND event_id=?",
                (*self._scope, event.event_id),
            ).fetchone()
            if duplicate is not None:
                if hmac.compare_digest(str(duplicate["event_digest"]), event_digest):
                    return False
                raise EventConflictError("event_id was already used for different content")
            expected = session.last_sequence + 1
            if event.sequence != expected:
                detail = "replayed" if event.sequence < expected else "has a gap"
                raise EventSequenceError(f"event sequence {detail}; expected {expected}")
            if session.last_sequence >= MAX_EVENTS_PER_SESSION:
                raise WorkDiscoveryStoreError("Ekko session event quota is exhausted")
            device_count = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                "AND device_key=?",
                self._scope,
            ).fetchone()[0])
            if device_count >= MAX_EVENTS_PER_DEVICE:
                raise WorkDiscoveryStoreError("Ekko device event quota is exhausted")
            conn.execute(
                "INSERT INTO ekko_events(tenant_key,owner_key,device_key,session_id,event_id,"
                "sequence,payload,event_digest,ingested_at,expires_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (*self._scope, event.session_id, event.event_id, event.sequence,
                 payload, event_digest, now, expires_at),
            )
            updated_session = WorkSession(
                session.session_id,
                session.state,
                session.policy_digest,
                session.started_at,
                now,
                session.ended_at,
                event.sequence,
            )
            conn.execute(
                "UPDATE ekko_sessions SET last_sequence=?,updated_at=?,session_blob=? "
                "WHERE tenant_key=? "
                "AND owner_key=? AND device_key=? AND session_id=? AND state='running'",
                (
                    event.sequence, now,
                    self._seal(
                        self._session_payload(
                            updated_session,
                            revision=revision,
                            enrollment_grant_id=session_grant_id,
                        ),
                        purpose="session",
                    ),
                    *self._scope, event.session_id,
                ),
            )
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise SessionStateError("session stopped while the event was appended")
        return True

    def list_events(
        self, *, session_id: str | None = None, since: float | None = None,
        limit: int = 10_000,
    ) -> list[WorkEvent]:
        if not 1 <= int(limit) <= _MAX_LIST_EVENTS:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST_EVENTS}")
        with self._deployment_control_barrier(), self._consent_barrier():
            session_ids = (
                [session_id]
                if session_id is not None
                else self._scoped_session_ids()
            )
            with self._session_authority_barriers(session_ids):
                self._purge_expired_events()
                return self._list_events_locked(
                    session_id=session_id,
                    since=since,
                    limit=int(limit),
                    trusted_now=self._now(),
                )

    def _list_events_locked(
        self,
        *,
        session_id: str | None,
        since: float | None,
        limit: int,
        trusted_now: float,
    ) -> list[WorkEvent]:
        """Read/decrypt while the caller holds every relevant erase barrier."""
        where = ["tenant_key=?", "owner_key=?", "device_key=?", "expires_at>?"]
        params: list[Any] = list(self._scope)
        params.append(trusted_now)
        if session_id is not None:
            where.append("session_id=?")
            params.append(session_id)
        since_value = _timestamp(since) if since is not None else None
        # Read one bounded page, then filter the authenticated timestamp after
        # decryption. Occurrence time is deliberately not a plaintext index.
        # The page holds the NEWEST events (the device quota exceeds the page
        # cap), returned oldest first.
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_id,session_id,sequence,payload,event_digest,"
                "ingested_at,expires_at "
                "FROM ekko_events WHERE " + " AND ".join(where)
                + " ORDER BY ingested_at DESC,session_id DESC,sequence DESC"
                " LIMIT ?",
                params,
            ).fetchall()
            rows.reverse()
            session_rows = {
                str(row["session_id"]): row
                for row in conn.execute(
                    "SELECT session_id,state,policy_digest,started_at,updated_at,"
                    "ended_at,last_sequence,session_blob FROM ekko_sessions "
                    "WHERE tenant_key=? AND owner_key=? AND device_key=?",
                    self._scope,
                ).fetchall()
            }
            enrollment_row = conn.execute(
                "SELECT active,grant_id,policy_digest,policy_blob,enrolled_at,"
                "updated_at,expires_at FROM ekko_enrollments WHERE tenant_key=? "
                "AND owner_key=? AND device_key=?",
                self._scope,
            ).fetchone()
        active_grant_id: str | None = None
        active_policy_digest: str | None = None
        if enrollment_row is not None:
            try:
                enrollment, _policy = self._decode_enrollment_row(
                    enrollment_row, now=trusted_now,
                )
                if enrollment.active:
                    active_grant_id = str(enrollment_row["grant_id"])
                    active_policy_digest = enrollment.policy_digest
            except WorkDiscoveryStoreError:
                pass
        # An erase marker must prevent a restored SQLite backup from becoming
        # a decryption oracle for deleted observations. Session history itself
        # remains inspectable for restrictive crash recovery, but event content
        # is returned only under the current external control revision.
        for event_session_id in {str(row["session_id"]) for row in rows}:
            session_row = session_rows.get(event_session_id)
            if session_row is None:
                raise WorkDiscoveryStoreError(
                    "event session authority is missing or stale"
                )
            session, revision, session_grant_id = (
                self._decode_session_row_state(session_row)
            )
            self._assert_session_revision(event_session_id, revision)
            if session.state not in _TERMINAL_STATES and (
                active_grant_id is None
                or active_policy_digest is None
                or not hmac.compare_digest(active_grant_id, session_grant_id)
                or not hmac.compare_digest(
                    active_policy_digest, session.policy_digest,
                )
            ):
                raise EnrollmentRequired(
                    "event session enrollment is missing or stale"
                )
        events: list[WorkEvent] = []
        for row in rows:
            sealed = self._unseal(bytes(row["payload"]), purpose="event")
            if (
                set(sealed) != {"event", "ingested_at", "expires_at"}
                or not isinstance(sealed.get("event"), dict)
                or sealed.get("ingested_at") != float(row["ingested_at"])
                or sealed.get("expires_at") != float(row["expires_at"])
            ):
                raise WorkDiscoveryStoreError("event authority integrity check failed")
            event = WorkEvent.from_dict(sealed["event"])
            if (
                event.event_id != str(row["event_id"])
                or event.session_id != str(row["session_id"])
                or event.sequence != int(row["sequence"])
                or not hmac.compare_digest(self._event_digest(event), str(row["event_digest"]))
            ):
                raise WorkDiscoveryStoreError("sealed event integrity check failed")
            if since_value is None or event.occurred_at >= since_value:
                events.append(event)
        return events

    def discover(self, **kwargs):
        return discover_candidates(self.list_events(limit=_MAX_LIST_EVENTS), **kwargs)

    def governed_candidate_projection(self) -> dict[str, Any]:
        """Return exact work-discovery candidates under live owner consent.

        This is the only projection intended for the governed knowledge plane.
        It keeps deployment, consent, and every session rollback authority
        locked from the first enrollment read through final assembly. Raw event
        content never leaves the method; the result carries a commitment to
        the exact content-free events that support the candidate evidence.
        """
        with self._deployment_control_barrier(), self._consent_barrier():
            trusted_now = self._now()
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT active,grant_id,policy_digest,policy_blob,enrolled_at,"
                    "updated_at,expires_at FROM ekko_enrollments WHERE tenant_key=? "
                    "AND owner_key=? AND device_key=?",
                    self._scope,
                ).fetchone()
                if row is None:
                    raise EnrollmentRequired("this owner and device are not enrolled")
                enrollment, policy = self._decode_enrollment_row(row, now=trusted_now)
                if not enrollment.active:
                    raise EnrollmentRequired("this owner and device enrollment expired")
                policy.require_valid(require_enabled=True)
                self._authority_check(policy)
                policy_digest, grant_id = self._active_enrollment(conn, policy)
                session_ids = [
                    str(item["session_id"])
                    for item in conn.execute(
                        "SELECT session_id FROM ekko_sessions WHERE tenant_key=? "
                        "AND owner_key=? AND device_key=? ORDER BY session_id",
                        self._scope,
                    ).fetchall()
                ]
            with self._session_authority_barriers(session_ids):
                # A projection is a read: the listing below already excludes
                # expired rows, and their physical deletion stays with the
                # store's write and maintenance paths.
                events = self._list_events_locked(
                    session_id=None,
                    since=None,
                    limit=_MAX_LIST_EVENTS,
                    trusted_now=trusted_now,
                )
                opportunities = discover_candidates(
                    events,
                    min_occurrences=policy.min_occurrences,
                    min_distinct_days=policy.min_distinct_days,
                )
                final_now = self._now()
                with self._connect() as conn:
                    final_digest, final_grant_id = self._active_enrollment(conn, policy)
                if (
                    final_now >= enrollment.expires_at
                    or not hmac.compare_digest(policy_digest, final_digest)
                    or not hmac.compare_digest(grant_id, final_grant_id)
                ):
                    raise EnrollmentRequired(
                        "work-discovery consent changed during projection"
                    )
                event_material = [event.to_dict() for event in events]
                event_sha256 = hashlib.sha256(
                    json.dumps(
                        {
                            "scope": list(self._scope),
                            "events": event_material,
                        },
                        allow_nan=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest()
                return {
                    "schema": "lightwork.ekko-knowledge-projection.v1",
                    "owner_sha256": _scope_key(
                        "knowledge-owner",
                        f"{self._tenant_key}:{self._owner_key}",
                    ),
                    "device_sha256": _scope_key(
                        "knowledge-device",
                        ":".join(self._scope),
                    ),
                    "consent": {
                        "policy_sha256": policy_digest,
                        "enrolled_at": enrollment.enrolled_at,
                        "valid_until": enrollment.expires_at,
                    },
                    "lineage": {
                        "event_count": len(events),
                        "event_sha256": event_sha256,
                    },
                    "candidates": [item.to_dict() for item in opportunities],
                }

    def prune(self, retention_days: int, *, now: float | None = None) -> dict[str, int]:
        if not isinstance(retention_days, int) or not 1 <= retention_days <= MAX_RETENTION_DAYS:
            raise ValueError(f"retention_days must be between 1 and {MAX_RETENTION_DAYS}")
        trusted_now = self._now() if now is None else _timestamp(now)
        cutoff = trusted_now - retention_days * 86_400.0
        with self._deployment_control_barrier(), self._consent_barrier():
            with self._connect() as conn:
                session_ids = [
                    str(row["session_id"])
                    for row in conn.execute(
                        "SELECT session_id FROM ekko_sessions WHERE tenant_key=? "
                        "AND owner_key=? AND device_key=? AND state IN "
                        "('stopped','halted') AND updated_at<? ORDER BY session_id",
                        (*self._scope, cutoff),
                    ).fetchall()
                ]
            with self._session_authority_barriers(session_ids):
                for session_id in session_ids:
                    self._tombstone_session_authority(session_id)
                return self._prune_locked(
                    trusted_now=trusted_now, cutoff=cutoff,
                )

    def _prune_locked(self, *, trusted_now: float, cutoff: float) -> dict[str, int]:
        with self._transaction() as conn:
            conn.execute("DELETE FROM ekko_plans WHERE tenant_key=? AND owner_key=? AND device_key=? AND expires_at<=?",
                         (*self._scope, trusted_now))
            old_events = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND (expires_at<=? OR ingested_at<?)",
                (*self._scope, trusted_now, cutoff),
            ).fetchone()[0])
            conn.execute(
                "DELETE FROM ekko_events WHERE tenant_key=? AND owner_key=? AND device_key=? "
                "AND (expires_at<=? OR ingested_at<?)",
                (*self._scope, trusted_now, cutoff),
            )
            old_sessions = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_sessions WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND state IN ('stopped','halted') AND updated_at<?",
                (*self._scope, cutoff),
            ).fetchone()[0])
            conn.execute(
                "DELETE FROM ekko_sessions WHERE tenant_key=? AND owner_key=? AND device_key=? "
                "AND state IN ('stopped','halted') AND updated_at<?",
                (*self._scope, cutoff),
            )
        return {"events": old_events, "sessions": old_sessions}

    def erase(self, *, session_id: str | None = None) -> dict[str, int]:
        with self._deployment_control_barrier(), self._consent_barrier():
            return self._erase_authorities_locked(session_id=session_id)

    def _erase_authorities_locked(
        self, *, session_id: str | None,
    ) -> dict[str, int]:
        """Invalidate authorities and SQLite under held control/consent locks."""
        if session_id is not None:
            # Explicit erasure invalidates the requested authority even if an
            # attacker removed its SQLite row before this call.
            authority_paths = [self._session_authority_path(session_id)]
        else:
            database_paths = [
                self._session_authority_path(value)
                for value in self._scoped_session_ids()
            ]
            # The scope-specific directory is the external manifest. It catches
            # valid, hidden, and corrupt markers not enumerable from SQLite
            # without risking another tenant/device's files.
            authority_paths = list({
                *database_paths,
                *self._scoped_session_authority_paths(),
            })
        with self._session_authority_path_barriers(authority_paths):
            for authority_path in authority_paths:
                self._write_session_authority_tombstone(authority_path)
            return self._erase_locked(session_id=session_id)

    def _erase_locked(self, *, session_id: str | None) -> dict[str, int]:
        with self._transaction() as conn:
            extra = " AND session_id=?" if session_id is not None else ""
            params: tuple[Any, ...] = (*self._scope, *((session_id,) if session_id is not None else ()))
            plan_filter = (
                " AND opportunity_id IN (SELECT opportunity_id FROM ekko_plan_sources WHERE "
                "tenant_key=? AND owner_key=? AND device_key=? AND session_id=?)"
                if session_id is not None else ""
            )
            conn.execute("DELETE FROM ekko_plans WHERE tenant_key=? AND owner_key=? AND device_key=?" + plan_filter,
                         (*self._scope, *params) if session_id is not None else self._scope)
            events = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                "AND device_key=?" + extra,
                params,
            ).fetchone()[0])
            sessions = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_sessions WHERE tenant_key=? AND owner_key=? "
                "AND device_key=?" + extra,
                params,
            ).fetchone()[0])
            conn.execute(
                "DELETE FROM ekko_sessions WHERE tenant_key=? AND owner_key=? AND device_key=?" + extra,
                params,
            )
            try:
                self._queue_audit(
                    conn,
                    "ekko_erase",
                    {
                        "scope": "session" if session_id else "device",
                        "events": events,
                        "sessions": sessions,
                    },
                    at=self._now(),
                )
            except Exception:
                # Erasure is a safety/privacy action and never depends on audit.
                pass
        # PRAGMA secure_delete overwrites deleted cells. File compaction is
        # intentionally deferred to maintenance; request-path VACUUM would take
        # an exclusive database lock and turn erase into a denial-of-service.
        return {"events": events, "sessions": sessions}

    def forget_device(self) -> dict[str, int]:
        """Revoke consent and delete this device's sessions/observations."""
        with self._deployment_control_barrier(), self._consent_barrier():
            enrollment = self._revoke_enrollment_locked(self._now())
            erased = self._erase_authorities_locked(session_id=None)
        return {**erased, "enrollments": 1 if enrollment is not None else 0}

    def status(self) -> dict[str, Any]:
        self._purge_expired_events()
        enrollment = self.get_enrollment()
        latest = self.latest_session()
        if latest is not None and latest.state in {
            SessionState.CREATED, SessionState.RUNNING, SessionState.PAUSED,
        }:
            authorized = bool(enrollment and enrollment.active)
            if authorized:
                policy = self.get_policy()
                try:
                    assert policy is not None
                    self._authority_check(policy)
                except Exception:
                    authorized = False
            if not authorized:
                latest = self.transition_session(
                    latest.session_id, SessionState.HALTED,
                )
        now = self._now()
        with self._connect() as conn:
            event_count = int(conn.execute(
                "SELECT COUNT(*) FROM ekko_events WHERE tenant_key=? AND owner_key=? "
                "AND device_key=? AND expires_at>?",
                (*self._scope, now),
            ).fetchone()[0])
        collector = self.collector_status(
            latest.session_id if latest is not None else None,
            now=now,
        )
        try:
            audit_state = self.flush_audit_outbox(limit=100)
        except Exception:
            # Status and safety controls remain available during an audit sink
            # outage. The bounded encrypted outbox is retried on a later touch.
            audit_state = {"delivered": 0, "pending": self.pending_audit_count()}
        return {
            "enrollment": enrollment.to_dict() if enrollment else None,
            "session": latest.to_dict() if latest else None,
            "event_count": event_count,
            "collector": collector,
            "collector_state": collector["state"],
            "audit_pending": audit_state["pending"],
        }


__all__ = [
    "CollectorLease", "CollectorLeaseError", "DEFAULT_COLLECTOR_LEASE_SECONDS",
    "EnrollmentRequired", "EventConflictError", "EventSequenceError",
    "MAX_COLLECTOR_LEASE_SECONDS", "MIN_COLLECTOR_LEASE_SECONDS",
    "SessionStateError", "WorkDiscoveryStore", "WorkDiscoveryStoreError",
]
