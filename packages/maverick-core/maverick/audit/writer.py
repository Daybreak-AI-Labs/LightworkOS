"""Audit log writer. Append-only NDJSON with daily rotation.

The writer is fail-safe by default: ordinary write errors are logged to the
regular Python logger and swallowed, because the agent kernel must never crash
because of an audit-path bug.

The one deliberate exception is :class:`~maverick.audit.errors.AuditRefused` and
its two subclasses: :class:`AuditWriteRefused` (an active compliance profile
mandates signed, tamper-evident logs and the signer will not start) and
:class:`~maverick.audit.signing.OffHostSigningRequiredError` (custody policy
forbids signing with a co-located key). In both the writer refuses rather than
silently downgrading, and that refusal is meant to reach the caller: swallowing
it converts "we could not record this action" into "we recorded nothing and did
it anyway", which is the failure the profile exists to prevent.

**Prefer :func:`audit_event` over calling :func:`record` inside your own try.**
It applies the contract for you. Catching ``Exception`` around a raw ``record()``
is the documented mistake -- and note you must catch the BASE class, because a
handler written against ``AuditWriteRefused`` alone misses the off-host refusal,
which is the one that fires under the strictest posture the product supports.
"""

from __future__ import annotations

import contextlib
import contextvars
import io
import json
import logging
import os
import threading
import time
import weakref
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..file_lock import (
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from ..paths import data_dir
from .errors import AuditRefused
from .events import AuditEvent, EventKind, is_valid_day

log = logging.getLogger(__name__)


# Goal-id binding for events logged deep in the stack. The agent kernel records
# tool/shield events with an explicit goal_id, but events emitted further down --
# notably the consent gate (safety/consent.py) and the per-action approval gate
# -- don't carry one. The run loop binds this ContextVar for the duration of a
# goal (see orchestrator.run_goal_sync), so a goal-less record() still attributes
# to the run. A ContextVar (not a global) so concurrent async runs each keep
# their own goal id; asyncio.run copies the current context into the root task,
# so a binding set just before it propagates to every nested tool/consent call.
_current_goal: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "maverick_audit_goal", default=None,
)


def set_goal_context(goal_id: int | None) -> contextvars.Token:
    """Bind the goal id that goal-less :func:`record` calls attribute to.

    Returns a token for :func:`reset_goal_context`. Prefer the
    :func:`goal_context` context manager unless you need manual control.
    """
    return _current_goal.set(goal_id)


def reset_goal_context(token: contextvars.Token) -> None:
    """Undo a :func:`set_goal_context` binding (fail-soft on a stale token)."""
    try:
        _current_goal.reset(token)
    except (ValueError, LookupError):  # token from another context -- ignore
        pass


@contextlib.contextmanager
def goal_context(goal_id: int | None):
    """Bind ``goal_id`` for goal-less audit records within the ``with`` block."""
    token = set_goal_context(goal_id)
    try:
        yield
    finally:
        reset_goal_context(token)


DEFAULT_AUDIT_DIR = data_dir("audit")

# Every live AuditLog registers here so an erase can drop the stale in-memory
# chain head on *any* writer pointed at the erased dir -- not just the default
# singleton. A WeakSet so GC'd logs fall out on their own.
_live_logs: weakref.WeakSet[AuditLog] = weakref.WeakSet()
_live_logs_lock = threading.Lock()

# Serialize distinct AuditLog/AuditSigner instances that target the same file
# even on platforms without a usable OS advisory lock. A fixed stripe table is
# bounded (unlike one immortal Lock per tenant/day path); collisions only make
# unrelated local audit writes briefly serialize, which is safe.
_APPEND_LOCK_STRIPES = tuple(threading.Lock() for _ in range(64))


class AuditWriteRefused(AuditRefused):
    """A compliance floor mandates signed logs and the signer would not start.

    Distinct from an incidental audit failure, and callers must treat it
    differently. An audit write is otherwise best-effort -- a broken log must
    not take down a running agent -- but when a profile like HIPAA asserts
    "every action is recorded on a tamper-evident chain", proceeding with the
    action while the record cannot be written breaks the control the profile
    exists to provide. The unrecorded action is the failure, not the log.

    Subclasses :class:`~maverick.audit.errors.AuditRefused` (itself a
    RuntimeError, which is what this path raised before it had a name, so
    existing handlers keep working). Catch the BASE, not this class: the sibling
    refusal ``OffHostSigningRequiredError`` fires under the strictest posture we
    sell, and a handler written against this name alone missed exactly that one.
    """


class _file_append_lock:
    """Advisory cross-process exclusive lock for the duration of an append.

    Two processes appending to the same day-file can interleave torn records
    once a line exceeds ``PIPE_BUF`` (single-``write`` atomicity no longer
    holds), corrupting NDJSON and -- when signing -- the hash chain. An
    advisory OS lock on the open file handle serializes concurrent writers.
    POSIX uses ``flock`` and Windows uses ``msvcrt.locking``. A bounded striped
    process lock additionally covers distinct writer instances in this process.

    Failure to acquire the OS lock is fatal for the append. Continuing with only
    the process-local stripe would let two service processes interleave unsigned
    rows or fork a signed hash chain while still reporting a successful write.
    """

    def __init__(self, fileobj: Any):
        self._fileobj = fileobj
        self._locked = False
        self._backend: str | None = None
        name = os.path.abspath(os.fspath(getattr(fileobj, "name", "")))
        self._thread_lock = _APPEND_LOCK_STRIPES[hash(name) % len(_APPEND_LOCK_STRIPES)]

    def __enter__(self) -> _file_append_lock:
        self._thread_lock.acquire()
        try:
            try:
                import fcntl
            except ImportError:
                # Windows byte-range locking. Every Lightwork audit writer
                # locks the first byte (locking past EOF is supported for a new
                # empty file), so tail-read + append is one cross-process
                # transaction.
                try:
                    import msvcrt
                except ImportError as exc:  # pragma: no cover - supported OSes
                    raise OSError(
                        "audit append has no cross-process lock backend"
                    ) from exc
                original_pos = self._fileobj.tell()
                self._fileobj.seek(0)
                try:
                    msvcrt.locking(self._fileobj.fileno(), msvcrt.LK_LOCK, 1)
                finally:
                    self._fileobj.seek(original_pos)
                self._locked = True
                self._backend = "msvcrt"
            else:
                fcntl.flock(self._fileobj.fileno(), fcntl.LOCK_EX)
                self._locked = True
                self._backend = "fcntl"
            return self
        # failure-policy: fail_closed
        except BaseException:
            # __exit__ is not called when __enter__ raises. Never strand the
            # in-process stripe after a filesystem/backend failure.
            self._thread_lock.release()
            raise

    def __exit__(self, *exc: Any) -> None:
        try:
            if self._locked and self._backend == "fcntl":
                try:
                    import fcntl

                    fcntl.flock(self._fileobj.fileno(), fcntl.LOCK_UN)
                except (ImportError, OSError):  # pragma: no cover - best-effort
                    pass
            elif self._locked and self._backend == "msvcrt":
                try:
                    import msvcrt

                    original_pos = self._fileobj.tell()
                    self._fileobj.seek(0)
                    msvcrt.locking(self._fileobj.fileno(), msvcrt.LK_UNLCK, 1)
                    self._fileobj.seek(original_pos)
                except (ImportError, OSError, ValueError):  # pragma: no cover
                    pass
        finally:
            self._locked = False
            self._thread_lock.release()


def _audit_idempotency_identity(
    payload: dict[str, Any],
) -> tuple[str, str] | None:
    """Return the governed sink identity for events that require append-once."""
    field_by_kind = {
        EventKind.APPROVAL_DECISION: "approval_event_id",
        EventKind.ACCESS_GRANT_CHANGED: "scim_group_event_id",
        EventKind.LEARNING_UPDATE: "event_id",
        EventKind.PRIVACY_RECORD_CHANGED: "event_id",
        EventKind.SECURITY_RECORD_CHANGED: "event_id",
        EventKind.PLATFORM_HUNT_CUSTODY_INITIALIZED: "event_id",
        EventKind.THREAT_HUNT_RECORD_CHANGED: "event_id",
        EventKind.ENV_HUNT_RECORD_CHANGED: "event_id",
        EventKind.UNIFIED_AUDIT_PROJECTION: "projection_event_id",
        EventKind.FEDERATION_DELEGATE: "event_id",
    }
    field = field_by_kind.get(payload.get("kind"))
    if field is None:
        return None
    value = payload.get(field)
    if payload.get("kind") == EventKind.UNIFIED_AUDIT_PROJECTION:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ValueError(
                "unified audit projection_event_id must be a lowercase SHA-256 digest"
            )
        return field, value
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    return field, value


def _locked_event_identity_exists(
    fileobj: Any,
    payload: dict[str, Any],
    identity: tuple[str, str],
    *,
    require_signed: bool = False,
) -> bool:
    """Check one locked NDJSON stream and reject identity/content collisions."""
    field, value = identity
    kind = payload.get("kind")
    fileobj.seek(0)
    for line_number, raw in enumerate(fileobj, start=1):
        if not raw.strip():
            continue
        try:
            existing = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError(
                "audit idempotency scan found malformed NDJSON at "
                f"line {line_number}"
            ) from error
        if (
            not isinstance(existing, dict)
            or existing.get("kind") != kind
            or existing.get(field) != value
        ):
            continue
        if require_signed and not (
            isinstance(existing.get("prev_hash"), str)
            and isinstance(existing.get("hash"), str)
            and bool(existing["hash"])
            and isinstance(existing.get("sig"), str)
            and bool(existing["sig"])
            and isinstance(existing.get("key_id"), str)
            and bool(existing["key_id"])
        ):
            raise ValueError(
                "audit idempotency identity is bound to an unsigned prior row"
            )
        # Retries get a fresh transport timestamp, while ``occurred_at`` is the
        # transactional business time. Every other logical field must match;
        # accepting the same identity for different content would hide a
        # conflicting decision instead of deduplicating a retry.
        for key, expected in payload.items():
            if key == "ts":
                continue
            if existing.get(key) != expected:
                raise ValueError(
                    "audit idempotency identity is bound to conflicting content"
                )
        return True
    return False


def _prior_day_identity_exists(
    audit_dir: Path,
    current_path: Path,
    payload: dict[str, Any],
    identity: tuple[str, str],
    *,
    require_signed: bool = False,
) -> bool:
    """Search closed segments while the deployment-wide identity lock is held."""
    from .sealing import segment_text

    for path in sorted(audit_dir.glob("*.ndjson")):
        if path == current_path:
            continue
        # A retention/erase rewriter uses this same sidecar lock. Take a stable
        # snapshot before parsing so a replace cannot turn a duplicate into a
        # missed identity at the rollover boundary.
        with cross_process_lock(path):
            text = segment_text(path, fail_soft=False)
        with io.StringIO(text) as stream:
            if _locked_event_identity_exists(
                stream,
                payload,
                identity,
                require_signed=require_signed,
            ):
                return True
    return False


def _strict_signed_identity_exists(
    audit_dir: Path,
    payload: dict[str, Any],
    identity: tuple[str, str],
) -> bool:
    """Acknowledge an identity only when its complete day chain verifies.

    The governed identity lock is held by the caller. Take each segment's
    rewrite lock across both the identity scan and cryptographic verification,
    so an erase/re-anchor cannot swap the file between those two decisions.
    """
    from .sealing import segment_text
    from .signing import verify_chain

    for path in sorted(audit_dir.glob("*.ndjson")):
        if not is_valid_day(path.stem):
            continue
        with cross_process_lock(path, strict=True):
            text = segment_text(path, fail_soft=False)
            with io.StringIO(text) as stream:
                exists = _locked_event_identity_exists(
                    stream,
                    payload,
                    identity,
                    require_signed=True,
                )
            if not exists:
                continue
            breaks = verify_chain(path)
            if breaks:
                first = breaks[0]
                raise ValueError(
                    "audit idempotency identity is bound to an unverifiable "
                    f"signed chain ({first.reason})"
                )
            return True
    return False


def _resolve_signing(explicit: bool | None) -> bool:
    """Whether to sign + hash-chain audit rows.

    Compliance floors are mandatory and strictest-wins: HIPAA-mode audit logging
    requires signed/tamper-evident audit rows even if the standalone signing knob
    is absent or false. Otherwise, precedence is explicit arg >
    MAVERICK_AUDIT_SIGN env > [audit] sign in config.toml > secure-by-default
    (ON unless explicitly disabled, via ``MAVERICK_SECURE_DEFAULT=0`` /
    ``[security] secure_defaults = false``). Resolved once at construction so the
    hot record() path never re-reads config.
    """
    try:
        from ..compliance_profiles import FLOOR_AUDIT_LOG, requires_floor
        if requires_floor(FLOOR_AUDIT_LOG):
            return True
    # failure-policy: best_effort
    except Exception:
        pass
    if explicit is not None:
        return bool(explicit)
    if "MAVERICK_AUDIT_SIGN" in os.environ:
        from .._envparse import env_bool

        return env_bool("MAVERICK_AUDIT_SIGN", False)
    try:
        from ..config import load_config
        from ..security_defaults import secure_by_default

        # Secure-by-default: sign + hash-chain the audit log unless explicitly
        # disabled. An explicit [audit] sign still wins when present.
        sign = ((load_config() or {}).get("audit") or {}).get("sign")
        if sign is not None:
            return bool(sign)
        return secure_by_default()
    # failure-policy: best_effort
    except Exception:
        return False


def _prepare_private_audit_file(path: Path) -> None:
    """Create one empty audit file privately, or tighten an existing file.

    The stable sidecar lock closes the first-writer race: two dashboard workers
    may both observe a new UTC day, but only one may publish the initial empty
    file. The second rechecks under the lock and must never replace a file after
    the first worker has already appended evidence to it.
    """
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        try:
            ensure_private_file(path, 0o600)
        except FileNotFoundError:
            atomic_write_bytes(path, b"", mode=0o600)


class AuditLog:
    """Append-only NDJSON sink with per-day rotation.

    Single writer instance per process. Thread-safe.

    When signing is enabled (**on by default** via secure-by-default; also
    forced by ``sign=True`` / ``MAVERICK_AUDIT_SIGN`` / ``[audit] sign``, and
    turned off by ``[audit] sign = false`` / ``MAVERICK_AUDIT_SIGN=0`` / the
    ``secure_defaults`` master switch), each row is routed
    through :class:`maverick.audit.signing.AuditSigner`, adding an
    Ed25519 ``prev_hash``/``hash``/``sig`` chain so tampering is
    detectable by ``maverick audit verify``. For third-party
    tamper-evidence the verifier must be given an externally-held
    pubkey: a co-located key only detects accidental/non-privileged
    edits, not an attacker who can also write the key dir.
    """

    def __init__(self, audit_dir: Path | None = None, *, sign: bool | None = None):
        # Resolve the dir at construction (not as a default arg, which would
        # freeze the path at import time). With no explicit dir, route through
        # the tenant-aware helper: the no-tenant default is the legacy
        # ``~/.maverick/audit`` and an active tenant gets its own audit chain
        # under ``~/.maverick/tenants/<t>/audit``.
        if audit_dir is None:
            from ..paths import data_dir

            audit_dir = data_dir("audit")
        self.audit_dir = audit_dir
        self._lock = threading.Lock()
        self._current_path: Path | None = None
        self._current_day: str | None = None
        self._signing_enabled = _resolve_signing(sign)
        self._signer: Any = None
        self._signer_path: Path | None = None
        with _live_logs_lock:
            _live_logs.add(self)

    def _path_for(self, day_str: str) -> Path:
        # ``day_str`` becomes a path component; refuse anything that isn't a
        # bare YYYY-MM-DD so a crafted ``day`` (e.g. ``../../etc/passwd``)
        # can't escape the audit dir. ``_rotate_if_needed`` only ever passes a
        # strftime value, so the write path is unaffected.
        if not is_valid_day(day_str):
            raise ValueError(f"invalid audit day {day_str!r}: expected YYYY-MM-DD")
        return self.audit_dir / f"{day_str}.ndjson"

    @property
    def signing_enabled(self) -> bool:
        """Whether this writer's resolved runtime policy selects signing.

        This exposes the writer's actual resolved state instead of asking a
        caller to re-read configuration with subtly different precedence.
        It is deliberately read-only. If the optional signing dependency is
        unavailable outside a mandatory compliance floor, the existing legacy
        fallback changes this value to ``False`` when the first write attempts
        signer initialization.
        """
        return self._signing_enabled

    def _ensure_dir(self) -> bool:
        try:
            ensure_private_directory(self.audit_dir)
            return True
        except OSError as e:
            log.warning("audit: cannot create dir %s: %s", self.audit_dir, e)
            return False

    def _rotate_if_needed(self) -> Path | None:
        day_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._current_day == day_str and self._current_path is not None:
            try:
                # Do not silently recreate a deleted live log: that would
                # restart a signed chain at genesis after evidence vanished.
                ensure_private_file(self._current_path, 0o600)
            except OSError as e:
                log.warning("audit: live file is unavailable: %s", e)
                return None
            return self._current_path
        if not self._ensure_dir():
            return None
        path = self._path_for(day_str)
        try:
            _prepare_private_audit_file(path)
        except OSError as e:
            log.warning("audit: cannot create or protect %s: %s", path, e)
            return None
        self._current_path = path
        self._current_day = day_str
        if self._signing_enabled:
            # Rollover (or first write this process): any now-complete prior
            # day-files get a signed tip-ledger anchor so deleting a whole
            # day-file is detectable. Best-effort -- anchoring must never block
            # an audit write.
            try:
                from .signing import ensure_anchors
                ensure_anchors(self.audit_dir)
            # failure-policy: fail_soft_with_audit
            except Exception as e:  # pragma: no cover - defensive
                log.debug("audit: ensure_anchors failed: %s", e)
        return path

    def record(self, event: AuditEvent) -> bool:
        """Write one event. Returns True on success.

        String fields in the event payload are run through
        ``secret_detector.redact`` so API keys, OAuth tokens, JWTs, and
        ``.env`` fragments that leak via tool output never land on disk
        in plaintext. When anonymous mode is enabled, the already-secret-
        redacted payload is additionally passed through Lightwork's privacy
        anonymizer before it is serialized or signed. Redaction failure is
        non-fatal: the event still writes, but a warning logs.
        """
        with self._lock:
            path = self._rotate_if_needed()
            if path is None:
                return False
            try:
                payload = _redact_event(event.to_dict())
                identity = _audit_idempotency_identity(payload)
                guard = (
                    cross_process_lock(
                        self.audit_dir / ".governed-audit-idempotency"
                    )
                    if identity is not None
                    else contextlib.nullcontext()
                )
                with guard:
                    if identity is not None and _prior_day_identity_exists(
                        self.audit_dir,
                        path,
                        payload,
                        identity,
                    ):
                        return True
                    return self._append_payload(path, payload, identity)
            except (OSError, TypeError, ValueError) as e:
                log.warning("audit: write failed: %s", e)
                return False

    def record_strict_signed(self, event: AuditEvent) -> bool:
        """Append ``event`` only through an initialized signed writer.

        Unlike :meth:`record`, this path never uses the legacy optional-crypto
        unsigned fallback. It preflights signer construction before checking or
        appending the governed identity, refuses an unsigned prior duplicate,
        and raises :class:`AuditWriteRefused` when signing is unavailable.
        ``True`` therefore means this logical event is present as a signed row;
        ``False`` means the signed append was not confirmed. A failure after
        bytes were written does not prove that the row is absent.
        """
        with self._lock:
            path = self._rotate_if_needed()
            if path is None:
                raise AuditWriteRefused(
                    "audit: strict signed writer could not open its audit segment"
                )
            try:
                payload = _redact_event(event.to_dict())
                identity = _audit_idempotency_identity(payload)
            except (TypeError, ValueError) as error:
                log.warning("audit: strict signed write validation failed: %s", error)
                return False

            if not self._signing_enabled:
                raise AuditWriteRefused(
                    "audit: strict signed write requested while signing is disabled"
                )
            try:
                signer = self._signer_for(path)
            except AuditRefused:
                raise
            # failure-policy: fail_closed
            except Exception as error:
                raise AuditWriteRefused(
                    "audit: strict signed writer could not initialize"
                ) from error
            if signer is None:
                raise AuditWriteRefused(
                    "audit: strict signed writer refused an unsigned fallback"
                )

            guard = (
                cross_process_lock(self.audit_dir / ".governed-audit-idempotency")
                if identity is not None
                else contextlib.nullcontext()
            )
            try:
                with guard:
                    if identity is not None and _strict_signed_identity_exists(
                        self.audit_dir,
                        payload,
                        identity,
                    ):
                        return True
                    # Verify the destination chain and append while holding the
                    # SAME strict rewrite lock. ``AuditSigner.write`` re-enters
                    # this path lock safely, then takes its append-handle lock;
                    # an erase/re-anchor/other cooperative whole-file rewriter
                    # therefore cannot replace the segment between verification
                    # and append. Identity handling was completed above; passing
                    # it into AuditSigner would re-enter its legacy presence-only
                    # acknowledgement path without cryptographic verification.
                    from .signing import verify_chain

                    with cross_process_lock(path, strict=True):
                        breaks = verify_chain(path)
                        if breaks:
                            first = breaks[0]
                            raise ValueError(
                                "audit destination chain is not verifiable "
                                f"({first.reason})"
                            )
                        return signer.write(payload, idempotency_identity=None) is True
            except AuditRefused:
                raise
            except (OSError, TypeError, ValueError) as error:
                log.warning("audit: strict signed write failed: %s", error)
                return False

    def _append_payload(
        self,
        path: Path,
        payload: dict[str, Any],
        identity: tuple[str, str] | None,
    ) -> bool:
        """Append under the optional cross-day identity guard held by caller."""
        signer = self._signer_for(path)
        if signer is not None:
            # Sign the already-redacted payload so secrets never enter the
            # signed bytes either.
            return bool(
                signer.write(payload, idempotency_identity=identity)
            )
        line = json.dumps(payload, default=str) + "\n"
        # Sidecar lock FIRST, exactly as AuditSigner.write does. Whole-file
        # rewriters publish a new inode via os.replace, so an advisory lock on
        # an already-open handle alone cannot serialize against them.
        with cross_process_lock(path), open(
            path,
            "a+",
            encoding="utf-8",
        ) as fileobj:
            with _file_append_lock(fileobj):
                if identity is not None and _locked_event_identity_exists(
                    fileobj,
                    payload,
                    identity,
                ):
                    return True
                fileobj.seek(0, os.SEEK_END)
                fileobj.write(line)
                fileobj.flush()
                os.fsync(fileobj.fileno())
        return True

    def _signer_for(self, path: Path) -> Any:
        """Lazily build (and rotate with the day file) the AuditSigner.

        Falls back to unsigned only when the optional crypto dependency is
        missing and no compliance floor mandates signing. Corrupt keys,
        malformed tails, and custody/locking failures always fail closed.
        """
        if not self._signing_enabled:
            return None
        if self._signer is None or self._signer_path != path:
            try:
                from .signing import AuditSigner

                self._signer = AuditSigner(path)
                self._signer_path = path
            # failure-policy: fail_soft_with_audit
            except Exception as e:
                from .signing import OffHostSigningRequiredError

                # An explicit off-host custody requirement is already a strict
                # policy error with a precise operator-facing message. Preserve
                # it rather than hiding it inside the generic compliance error.
                if isinstance(e, OffHostSigningRequiredError):
                    raise

                # A compliance floor (e.g. HIPAA) mandates a functioning signed,
                # tamper-evident writer -- not merely an installed cryptography
                # package. A corrupt/unreadable key, invalid key material, or any
                # other signer-initialization failure is just as unsafe as a
                # missing dependency. Refuse every such downgrade instead of
                # disabling signing and appending plaintext.
                try:
                    from ..compliance_profiles import FLOOR_AUDIT_LOG, requires_floor
                    floored = requires_floor(FLOOR_AUDIT_LOG)
                # failure-policy: best_effort
                except Exception:  # pragma: no cover - floor lookup never blocks
                    floored = False
                if floored:
                    if isinstance(e, ImportError):
                        detail = (
                            "the 'cryptography' extra is not installed. Run: "
                            "python -m pip install -e "
                            "'./packages/maverick-core[audit-signing]'"
                        )
                    else:
                        detail = f"the audit signer could not initialize ({type(e).__name__})"
                    raise AuditWriteRefused(
                        "audit: an active compliance profile requires signed, "
                        f"tamper-evident audit logs, but {detail} -- refusing to "
                        "write UNSIGNED."
                    ) from e

                # Outside a mandatory floor, retain only the documented
                # optional-dependency fallback. Integrity/custody failures are
                # not availability choices and must never downgrade the stream.
                if isinstance(e, ImportError):
                    log.error(
                        "audit: signing enabled but 'cryptography' not installed; "
                        "writing UNSIGNED. Run: python -m pip install -e "
                        "'./packages/maverick-core[audit-signing]'"
                    )
                    self._signing_enabled = False
                    return None
                raise OSError(
                    "audit signer could not initialize; refusing unsigned downgrade"
                ) from e
        return self._signer

    def reset_signer_for_dir(self, audit_dir: Path) -> None:
        """Drop the cached signer if it targets ``audit_dir``.

        An erase re-anchors the day file on disk, but the live signer still
        holds the pre-erase ``_last_hash`` in memory, so the next in-process
        ``record()`` would chain onto a hash no longer in the file ->
        immediate ``chain_mismatch``. Clearing the cached signer forces the
        next write to rebuild it and re-read the new chain tail via
        ``_resume_last_hash``. No-op if this log writes elsewhere.
        """
        try:
            same = self.audit_dir.resolve() == audit_dir.resolve()
        except OSError:
            same = self.audit_dir == audit_dir
        if not same:
            return
        with self._lock:
            self._signer = None
            self._signer_path = None

    def reanchor_after_erase(self) -> int:
        """Refresh signed audit files after a GDPR erase.

        Erase helpers verify each signed file before mutating it and re-anchor
        only those modified files. This compatibility hook therefore only
        attempts safe/idempotent re-anchors: ``reanchor_file`` refuses to
        rewrite a chain that is not already clean unless the caller explicitly
        supplies proof that the pre-erase file was verified.

        No-op (returns 0) when signing is disabled -- an unsigned log has no
        chain to repair. Never raises: a re-anchor failure must not undo a
        completed erasure.
        """
        with self._lock:
            # Re-anchoring rewrites the day file, so the in-memory chain head
            # is now stale -- force a rebuild on the next write.
            self._signer = None
            self._signer_path = None
            if not self._signing_enabled:
                return 0
            try:
                from .signing import reanchor_file
            # failure-policy: best_effort
            except Exception:  # pragma: no cover - crypto missing
                return 0
            total = 0
            if not self.audit_dir.exists():
                return 0
            for path in sorted(self.audit_dir.glob("*.ndjson")):
                try:
                    n = reanchor_file(path)
                # failure-policy: fail_soft_with_audit
                except Exception as e:  # pragma: no cover - defensive
                    log.warning("audit: reanchor failed for %s: %s", path, e)
                    continue
                if n > 0:
                    total += n
            return total

    def tail(self, n: int = 50, day: str | None = None, *, report=None) -> list[dict[str, Any]]:
        """Return the last ``n`` events from ``day`` (default today)."""
        if day is None:
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = self._path_for(day)
        from .reader import tail_events
        return tail_events(path, n, report=report)

    def grep(self, pattern: str, day: str | None = None) -> list[dict[str, Any]]:
        """Crude regex grep over the day's events."""
        import re

        try:
            rx = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"invalid regex pattern {pattern!r}: {e}") from e
        if day is None:
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = self._path_for(day)
        if not path.exists():
            return []
        from .segments import ReadReport, SegmentSnapshot
        out: list[dict[str, Any]] = []
        try:
            with SegmentSnapshot(path, ReadReport()) as snapshot:
                for line in snapshot.lines():
                    if rx.search(line):
                        try:
                            event = json.loads(line)
                            if isinstance(event, dict):
                                out.append(event)
                        except (json.JSONDecodeError, RecursionError):
                            continue
        except (OSError, ValueError, RuntimeError) as error:
            log.warning("audit grep incomplete: %s (%s)", path.name, type(error).__name__)
        return out


def _redact_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Walk an audit event dict and redact secrets plus anonymous-mode PII.

    Lazy-imports the detectors so the audit module stays usable in
    environments where optional safety/privacy modules were stripped or
    vendored. Returns a new dict; never mutates the input.
    """
    try:
        from ..safety.secret_detector import redact
    # failure-policy: best_effort
    except Exception:
        redact = None

    def _walk(v: Any, depth: int = 0) -> Any:
        # Depth cap: the payload carries arbitrary **kwargs (tool args/results)
        # that can be model/tool-controlled and deeply nested; without a guard a
        # deep value raises RecursionError inside the audit-write path.
        if depth > 64:
            # Past the recursion guard, do NOT str() the value: str(dict)/str(list)
            # dumps nested secrets in cleartext, and returning a bare string would
            # skip redaction (secrets would leak at depth > 64).
            # Scalars are safe as-is; a leaf string is still redacted; any deeper
            # container collapses to an opaque marker.
            if isinstance(v, (int, float, bool, type(None))):
                return v
            if isinstance(v, str):
                return v if redact is None else redact(v)[0]
            return "[truncated: nesting depth > 64]"
        if isinstance(v, str):
            if redact is None:
                return v
            redacted, _ = redact(v)
            return redacted
        if isinstance(v, dict):
            return {k: _walk(vv, depth + 1) for k, vv in v.items()}
        if isinstance(v, list):
            return [_walk(vv, depth + 1) for vv in v]
        return v

    redacted_payload = _walk(payload)
    try:
        from ..privacy import anon_enabled, anonymize_dict
        if anon_enabled():
            return anonymize_dict(redacted_payload)
    # failure-policy: best_effort
    except Exception:
        pass
    return redacted_payload


_default: AuditLog | None = None
_defaults: dict[Path, AuditLog] = {}
_default_lock = threading.Lock()


def default_audit_log() -> AuditLog:
    """Return the default audit log for the active tenant context.

    ``AuditLog`` resolves its output directory at construction time, so the
    module-level shortcut must not share one tenant-dependent instance across
    all callers in a long-lived process. Cache one default writer per resolved
    audit directory instead: the no-tenant path keeps the legacy singleton
    semantics, while tenant-scoped calls get an independent writer and chain.
    """
    global _default
    from ..paths import data_dir

    audit_dir = data_dir("audit")
    shared_audit_dir = data_dir("audit", tenant=None)
    with _default_lock:
        if audit_dir == shared_audit_dir:
            # No active tenant: keep the legacy singleton semantics so callers
            # that ASSIGN ``writer._default`` (the dashboard grep endpoint, the
            # audit tests) keep overriding the writer that ``record()`` uses.
            # Reading the new per-dir cache here would ignore that override and
            # silently build a fresh empty writer at the real home dir.
            if _default is None:
                _default = AuditLog(audit_dir)
            _defaults[audit_dir] = _default
            return _default
        log_obj = _defaults.get(audit_dir)
        if log_obj is None:
            log_obj = AuditLog(audit_dir)
            _defaults[audit_dir] = log_obj
        return log_obj


def global_audit_log() -> AuditLog:
    """Return the deployment-global writer regardless of tenant context.

    Repo-wide control-plane changes must not land in a tenant-scoped chain that
    can later be erased with that tenant. This intentionally shares the legacy
    no-tenant singleton so signing, tests and verification use one chain.
    """
    global _default
    from ..paths import data_dir

    audit_dir = data_dir("audit", tenant=None)
    with _default_lock:
        if _default is None:
            _default = AuditLog(audit_dir)
        _defaults[audit_dir] = _default
        return _default


def record(
    kind: str,
    *,
    agent: str = "system",
    goal_id: int | None = None,
    _require_signed: bool = False,
    **payload: Any,
) -> bool:
    """Module-level shortcut for the default audit log.

    When ``goal_id`` is not given, falls back to the goal bound by the run loop
    (:func:`set_goal_context`) so consent/approval and other deep events still
    attribute to the active run. An explicit ``goal_id`` always wins.

    ``_require_signed=True`` requires the same tenant-selected writer to use
    its strict signed path. It does not enable disabled signing or change the
    policy for ordinary callers. This reserved boolean option is not payload.
    """
    if type(_require_signed) is not bool:
        raise TypeError("_require_signed must be a bool")
    if goal_id is None:
        goal_id = _current_goal.get()
    event = AuditEvent(
        ts=time.time(),
        kind=kind,
        agent=agent,
        goal_id=goal_id,
        payload=payload,
    )
    sink = default_audit_log()
    return sink.record_strict_signed(event) if _require_signed else sink.record(event)


def record_global(
    kind: str,
    *,
    agent: str = "system",
    goal_id: int | None = None,
    **payload: Any,
) -> bool:
    """Record a deployment-global control event outside tenant routing."""
    event = AuditEvent(
        ts=time.time(),
        kind=kind,
        agent=agent,
        goal_id=goal_id,
        payload=payload,
    )
    return global_audit_log().record(event)


def audit_event(kind: str, *, agent: str = "system", goal_id: int | None = None,
                _global: bool = False, **payload: Any) -> bool:
    """Record an event with the refusal contract applied for you.

    Prefer this over calling :func:`record` inside your own ``try``. A census of
    this repo found ~93 non-test ``record()`` call sites, 42 of them wrapped in
    a bare ``except Exception: pass``, and exactly ONE that re-raised a refusal.
    A contract honoured at one site in ninety-three is not a contract, it is a
    coincidence -- so the safe behaviour belongs in one function rather than in
    ninety-three reviewers' memories.

    Semantics:

    * :class:`~maverick.audit.errors.AuditRefused` propagates. The audit
      subsystem declined to write because writing would have broken a guarantee
      the deployment asserts; the caller must not proceed with the action.
    * Any other failure is swallowed and logged **with a traceback**, because a
      broken log must not crash a running agent -- but a permanently broken
      audit path must not look identical to a healthy one either. That is what
      a bare ``pass`` did, and it is why nobody noticed.

    Returns True when the row was written, False when the write failed and was
    swallowed. A caller that wants the old fire-and-forget behaviour should say
    so explicitly rather than by omission.
    """
    # Resolve through the package namespace at call time, not this module's
    # globals. `maverick.audit.record` is the documented entry point and is what
    # the repo's tests monkeypatch; binding writer.record here would silently
    # bypass every one of those patches while still looking correct.
    from . import record as _record
    from . import record_global as _record_global

    fn = _record_global if _global else _record
    try:
        return bool(fn(kind, agent=agent, goal_id=goal_id, **payload))
    except AuditRefused:
        raise
    # A broken audit path must not crash a run, but it must not be invisible
    # either; the refusal above is the case that stops the caller.
    # failure-policy: fail_soft_with_audit
    except Exception:
        log.warning("audit: write failed for kind=%r (agent=%r)", kind, agent,
                    exc_info=True)
        return False


def reanchor_after_erase() -> int:
    """Re-anchor the default audit log's signed chain after a GDPR erase.

    Module-level shortcut for the singleton. Safe to call unconditionally:
    a no-op when signing is off.
    """
    return default_audit_log().reanchor_after_erase()


def reset_signer_after_erase(audit_dir: Path) -> None:
    """Reset every live AuditLog whose cached signer targets ``audit_dir``.

    Called by the erase helpers right after they re-anchor a file so a
    same-process erase-then-``record()`` chains onto the rewritten tail
    instead of a stale in-memory ``_last_hash``. Covers the default singleton
    and any directly-constructed log via the live registry; never forces a
    singleton into being.
    """
    with _live_logs_lock:
        logs = list(_live_logs)
    for log_obj in logs:
        log_obj.reset_signer_for_dir(audit_dir)


__all__ = [
    "AuditLog",
    "AuditRefused",
    "AuditWriteRefused",
    "audit_event",
    "DEFAULT_AUDIT_DIR",
    "default_audit_log",
    "record",
    "reanchor_after_erase",
    "EventKind",
    "set_goal_context",
    "reset_goal_context",
    "goal_context",
]
