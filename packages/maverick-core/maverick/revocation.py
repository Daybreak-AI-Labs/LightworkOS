"""Capability revocation list.

A :class:`maverick.capability.Capability` is valid until it *expires*. But a
grant sometimes has to be killed **now** — a leaked key, an agent gone rogue,
a contractor offboarded mid-run — without waiting for the TTL. This is the
revocation list: a small, persisted set of revoked principals that the tool
chokepoint consults, so a revoked principal's *next* tool call is denied even
though its signed capability is otherwise still valid.

"Propagation" is two things:

* **to running agents** — the registry is re-read whenever its file changes
  (mtime check), so an operator running ``maverick capability revoke`` in
  another process reaches agents already mid-run, not just new spawns;
* **down the delegation tree** — :meth:`revoke_subtree` walks the
  parent→child principal graph (the same delegation graph the capability
  layer already tracks) and revokes a principal *and every descendant it
  spawned*, so attenuated children can't outlive a revoked parent.

Fail closed at the authorization boundary: a present-but-unreadable or corrupt
registry cannot prove that a principal remains authorized, so the tool
chokepoint denies the call. Direct registry/operator APIs surface
``RevocationStoreError`` instead of silently replacing damaged state. A
genuinely absent registry still means that no revocations have been recorded.
Only consulted when capability enforcement is on (otherwise there is no
principal to revoke against).
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

log = logging.getLogger(__name__)

_MAX_STORE_BYTES = 2 * 1024 * 1024
_MAX_ENTRIES = 10_000
_MAX_PRINCIPAL_LENGTH = 1024
_MAX_REASON_LENGTH = 4096
_MAX_GENERATION_LENGTH = 128

_T = TypeVar("_T")


def _bounded_read_text(path: Path) -> str:
    """Read at most the configured registry budget, including on races."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        remaining = _MAX_STORE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    payload = b"".join(chunks)
    if len(payload) > _MAX_STORE_BYTES:
        raise RevocationStoreError(
            f"revocation store exceeds {_MAX_STORE_BYTES} bytes"
        )
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RevocationStoreError(
            f"revocation store corrupt: invalid UTF-8: {exc}"
        ) from exc


@dataclass(frozen=True)
class Revocation:
    principal: str
    revoked_at: float
    reason: str = ""
    # Security containment is stronger than an ordinary operator suspension.
    # Older registries omit this field and therefore remain ordinary,
    # backwards-compatible revocations.
    protected: bool = False
    # Every new protected containment receives an opaque generation. Release
    # binds to this value so an operator who started releasing incident A
    # cannot delete a concurrently-published incident B. Legacy records omit
    # the field and use the empty generation until they are re-contained.
    generation: str = ""


class RevocationStoreError(RuntimeError):
    """The configured revocation state exists but cannot be trusted."""


class ProtectedRevocationError(RuntimeError):
    """An ordinary unrevoke attempted to clear security containment."""


class RevocationGenerationMismatch(ProtectedRevocationError):
    """A protected release was superseded by a newer containment."""


def _valid_principal(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= _MAX_PRINCIPAL_LENGTH
    )


def _valid_reason(value: object) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_REASON_LENGTH


def _valid_generation(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= _MAX_GENERATION_LENGTH
        and (not value or (value.isascii() and value.isalnum()))
    )


def _new_generation() -> str:
    return secrets.token_hex(16)


def _parse_revocation_record(principal: object, record: object) -> Revocation:
    if not _valid_principal(principal):
        raise RevocationStoreError("revocation store corrupt: invalid principal")
    principal = str(principal)
    if not isinstance(record, dict):
        raise RevocationStoreError(
            f"revocation store corrupt: record for {principal!r} must be an object"
        )
    revoked_at = record.get("revoked_at")
    reason = record.get("reason", "")
    protected = record.get("protected", False)
    generation = record.get("generation", "")
    if isinstance(revoked_at, bool) or not isinstance(revoked_at, (int, float)):
        raise RevocationStoreError(
            f"revocation store corrupt: timestamp for {principal!r} must be numeric"
        )
    timestamp = float(revoked_at)
    if not math.isfinite(timestamp) or timestamp <= 0:
        raise RevocationStoreError(
            f"revocation store corrupt: timestamp for {principal!r} "
            "must be finite and positive"
        )
    if not isinstance(reason, str):
        raise RevocationStoreError(
            f"revocation store corrupt: reason for {principal!r} must be a string"
        )
    if not _valid_reason(reason):
        raise RevocationStoreError(
            f"revocation store corrupt: reason for {principal!r} is too long"
        )
    if not isinstance(protected, bool):
        raise RevocationStoreError(
            f"revocation store corrupt: protected flag for {principal!r} "
            "must be a boolean"
        )
    if not _valid_generation(generation) or (generation and not protected):
        raise RevocationStoreError(
            f"revocation store corrupt: generation for {principal!r} "
            "must be a bounded protected-containment token"
        )
    return Revocation(
        principal, timestamp, reason, protected=protected, generation=generation,
    )


class RevocationRegistry:
    """A persisted ``principal -> Revocation`` set, re-read on file change."""

    def __init__(self, path: Path | None = None):
        self._explicit_path = Path(path) if path is not None else None
        self._cache: dict[str, Revocation] = {}
        self._version: tuple[int, int, int, int] | None = None
        self._loaded = False
        # Containment callbacks can re-enter registry reads on the same thread.
        # The strict cross-process lock is already re-entrant; mirror that
        # property here so a nested enforcement check cannot self-deadlock.
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        if self._explicit_path is not None:
            return self._explicit_path
        from .paths import data_dir
        return data_dir("capability_revocations.json")

    def _containment_authority_path(self, principal: str) -> Path:
        digest = hashlib.sha256(principal.encode("utf-8")).hexdigest()
        return self.path.parent / f".{self.path.name}.containment-{digest}"

    @contextmanager
    def containment_authority(self, principal: str) -> Iterator[None]:
        """Hold the stable strict authority for one principal's projections."""
        if not _valid_principal(principal):
            raise ValueError("invalid revocation principal")
        from .file_lock import cross_process_lock, ensure_private_directory

        ensure_private_directory(self.path.parent)
        with cross_process_lock(
            self._containment_authority_path(principal), strict=True,
        ):
            yield

    # -- read path (hot) --------------------------------------------------

    def _current_version(self) -> tuple[int, int, int, int] | None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RevocationStoreError(
                f"revocation store metadata unreadable: {exc}"
            ) from exc
        if info.st_size > _MAX_STORE_BYTES:
            raise RevocationStoreError(
                f"revocation store exceeds {_MAX_STORE_BYTES} bytes"
            )
        return (
            info.st_mtime_ns,
            info.st_ctime_ns,
            info.st_size,
            info.st_ino,
        )

    def _load_if_changed(self) -> None:
        version = self._current_version()
        if self._loaded and version == self._version:
            return
        self._cache = self._read()
        self._version = version
        self._loaded = True

    def _read(self) -> dict[str, Revocation]:
        from .file_lock import ensure_private_file, private_path_is_restricted

        try:
            info = self.path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise PermissionError(
                    f"revocation store is not a regular file: {self.path}"
                )
            if not private_path_is_restricted(self.path, 0o600):
                ensure_private_file(self.path)
            text = _bounded_read_text(self.path)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise RevocationStoreError(
                f"revocation store unreadable: {exc}"
            ) from exc

        def _reject_constant(value: str) -> None:
            raise ValueError(f"non-finite number {value!r}")

        def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            data: dict[str, object] = {}
            for key, value in pairs:
                if key in data:
                    raise ValueError(f"duplicate principal {key!r}")
                data[key] = value
            return data

        try:
            raw = json.loads(
                text,
                parse_constant=_reject_constant,
                object_pairs_hook=_object,
            )
        except (TypeError, ValueError) as exc:
            raise RevocationStoreError(
                f"revocation store corrupt: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise RevocationStoreError(
                "revocation store corrupt: top-level value must be an object"
            )
        if len(raw) > _MAX_ENTRIES:
            raise RevocationStoreError(
                f"revocation store exceeds {_MAX_ENTRIES} entries"
            )

        out: dict[str, Revocation] = {}
        for principal, record in raw.items():
            out[str(principal)] = _parse_revocation_record(principal, record)
        return out

    def is_revoked(self, principal: str) -> bool:
        if not principal:
            return False
        if not _valid_principal(principal):
            raise ValueError("invalid revocation principal")
        with self._lock:
            self._load_if_changed()
            return principal in self._cache

    def revoked(self) -> dict[str, Revocation]:
        with self._lock:
            self._load_if_changed()
            return dict(self._cache)

    # -- write path (operator actions) ------------------------------------

    def _write(self, data: dict[str, Revocation]) -> None:
        from .file_lock import atomic_write_text, ensure_private_directory

        p = self.path
        ensure_private_directory(p.parent)
        if len(data) > _MAX_ENTRIES:
            raise ValueError(f"revocation registry exceeds {_MAX_ENTRIES} entries")
        for principal, revocation in data.items():
            if not _valid_principal(principal):
                raise ValueError("invalid revocation principal")
            if not _valid_reason(revocation.reason):
                raise ValueError("revocation reason is too long or not a string")
            if not isinstance(revocation.protected, bool):
                raise ValueError("revocation protected flag must be a boolean")
            if (
                not _valid_generation(revocation.generation)
                or (revocation.generation and not revocation.protected)
            ):
                raise ValueError("revocation generation is invalid")
        payload = {}
        for principal, revocation in data.items():
            record = {
                "revoked_at": revocation.revoked_at,
                "reason": revocation.reason,
                "protected": revocation.protected,
            }
            if revocation.generation:
                record["generation"] = revocation.generation
            payload[principal] = record
        encoded = json.dumps(payload, allow_nan=False, sort_keys=True)
        if len(encoded.encode("utf-8")) > _MAX_STORE_BYTES:
            raise ValueError(
                f"revocation registry exceeds {_MAX_STORE_BYTES} bytes"
            )
        atomic_write_text(p, encoded, mode=0o600)
        self._cache = dict(data)
        self._version = self._current_version()
        self._loaded = True

    def revoke(
        self,
        principal: str,
        *,
        reason: str = "",
        now: float | None = None,
        protected: bool = False,
        durable_apply: Callable[[], None] | None = None,
    ) -> Revocation:
        if not _valid_principal(principal):
            raise ValueError("invalid revocation principal")
        if not _valid_reason(reason):
            raise ValueError("revocation reason is too long or not a string")
        ts = float(now if now is not None else time.time())
        if not math.isfinite(ts) or ts <= 0:
            raise ValueError("revocation timestamp must be finite and positive")
        from .file_lock import cross_process_lock, ensure_private_directory

        ensure_private_directory(self.path.parent)
        with self.containment_authority(principal):
            with self._lock:
                with cross_process_lock(self.path, strict=True):
                    # Re-read while holding the process lock. Atomic publication
                    # alone cannot prevent concurrent read-modify-write updates
                    # from overwriting another revocation.
                    self._loaded = False
                    self._load_if_changed()
                    data = dict(self._cache)
                    previous = data.get(principal)
                    if previous is not None and previous.protected and not protected:
                        # A lower-authority suspension must not repaint containment
                        # with a new timestamp/reason. Preserve the exact incident
                        # provenance and avoid an unnecessary write.
                        return previous
                    # An ordinary revoke must never downgrade a durable security
                    # containment that landed first in another thread/process.
                    keep_protected = bool(protected or (
                        previous is not None and previous.protected
                    ))
                    rev = Revocation(
                        principal, ts, reason, protected=keep_protected,
                        generation=_new_generation() if protected else "",
                    )
                    data[principal] = rev
                    self._write(data)
                    if durable_apply is not None:
                        durable_apply()
                    return rev

    def unrevoke(
        self,
        principal: str,
        *,
        allow_protected: bool = False,
        expected_generation: str | None = None,
        durable_clear: Callable[[], None] | None = None,
    ) -> bool:
        """Remove an ordinary revocation.

        Security containment is durable provenance, not merely a reason string.
        It can only be cleared by an explicit security/admin release passing
        ``allow_protected=True`` *and* the exact generation observed before the
        release began. The optional ``durable_clear`` callback runs while the
        same process and strict cross-process locks still exclude a concurrent
        containment writer; if it fails, the protected row is retained.
        """
        if not _valid_principal(principal):
            raise ValueError("invalid revocation principal")
        from .file_lock import cross_process_lock, ensure_private_directory

        ensure_private_directory(self.path.parent)
        with self.containment_authority(principal):
            with self._lock:
                with cross_process_lock(self.path, strict=True):
                    self._loaded = False
                    self._load_if_changed()
                    if principal not in self._cache:
                        return False
                    current = self._cache[principal]
                    if current.protected and not allow_protected:
                        raise ProtectedRevocationError(
                            "principal is security-contained; use an explicit "
                            "security/admin release"
                        )
                    if current.protected and expected_generation is None:
                        raise ProtectedRevocationError(
                            "protected release requires the observed containment generation"
                        )
                    if (
                        expected_generation is not None
                        and current.generation != expected_generation
                    ):
                        raise RevocationGenerationMismatch(
                            "a newer security containment superseded this release"
                        )
                    if durable_clear is not None:
                        durable_clear()
                    data = dict(self._cache)
                    data.pop(principal, None)
                    self._write(data)
                    return True

    def run_if_unprotected(
        self,
        principal: str,
        action: Callable[[], _T],
    ) -> _T:
        """Run a dependent-store restore only while no protected row exists.

        This closes check-then-clear races in trust/gateway operator surfaces:
        a concurrent containment either lands first and refuses ``action``, or
        waits for ``action`` and then re-applies the restrictive dependent
        state after this lock is released.
        """
        if not _valid_principal(principal):
            raise ValueError("invalid revocation principal")
        from .file_lock import cross_process_lock, ensure_private_directory

        ensure_private_directory(self.path.parent)
        with self.containment_authority(principal):
            with self._lock:
                with cross_process_lock(self.path, strict=True):
                    self._loaded = False
                    self._load_if_changed()
                    current = self._cache.get(principal)
                    if current is not None and current.protected:
                        raise ProtectedRevocationError(
                            "principal is security-contained; use an explicit "
                            "security/admin release"
                        )
                    return action()

    def revoke_subtree(
        self,
        principal: str,
        edges: dict[str, object],
        *,
        reason: str = "",
        now: float | None = None,
        protected: bool = False,
        durable_apply: Callable[[], None] | None = None,
    ) -> list[str]:
        """Revoke ``principal`` and every descendant reachable via ``edges``
        (``parent -> iterable[child]``). Cycle-safe; one atomic write."""
        if not _valid_reason(reason):
            raise ValueError("revocation reason is too long or not a string")
        order = _bfs(principal, edges)
        ts = float(now if now is not None else time.time())
        if not math.isfinite(ts) or ts <= 0:
            raise ValueError("revocation timestamp must be finite and positive")
        from .file_lock import cross_process_lock, ensure_private_directory

        ensure_private_directory(self.path.parent)
        with self.containment_authority(principal):
            with self._lock:
                with cross_process_lock(self.path, strict=True):
                    self._loaded = False
                    self._load_if_changed()
                    data = dict(self._cache)
                    changed = False
                    for pr in order:
                        previous = data.get(pr)
                        if previous is not None and previous.protected and not protected:
                            continue
                        keep_protected = bool(protected or (
                            previous is not None and previous.protected
                        ))
                        data[pr] = Revocation(
                            pr, ts, reason, protected=keep_protected,
                            generation=_new_generation() if protected else "",
                        )
                        changed = True
                    if changed:
                        self._write(data)
                    if durable_apply is not None:
                        durable_apply()
        return order


def _bfs(root: str, edges: dict[str, object]) -> list[str]:
    seen: set[str] = set()
    order: list[str] = []
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        if not _valid_principal(cur):
            raise ValueError("invalid revocation principal")
        if len(seen) >= _MAX_ENTRIES:
            raise ValueError(
                f"revocation subtree exceeds {_MAX_ENTRIES} entries"
            )
        seen.add(cur)
        order.append(cur)
        for child in (edges.get(cur) or []):
            if child not in seen:
                stack.append(child)
    return order


# Key the shared registries by resolved data-dir path so each tenant gets its
# own _cache/_mtime (a single instance's mtime cache could otherwise serve one
# tenant's revocation set to another — mirrors trajectory_store.shared).
_shared: dict[Path, RevocationRegistry] = {}
_shared_lock = threading.Lock()


def shared() -> RevocationRegistry:
    from .paths import data_dir
    path = data_dir("capability_revocations.json")
    with _shared_lock:
        reg = _shared.get(path)
        if reg is None:
            reg = RevocationRegistry(path=path)
            _shared[path] = reg
        return reg


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def is_revoked(principal: str) -> bool:
    """Fail-closed convenience over the process-shared registry."""
    if not principal:
        return False
    try:
        return shared().is_revoked(principal)
    except Exception:
        log.exception("revocation check failed for %r; denying", principal)
        return True


def revoked_principal(principals: Iterable[str] | str) -> str | None:
    """Return the first revoked principal in ``principals``, fail-closed.

    Authorization callers pass the effective capability principal plus its
    ancestor lineage. This makes a parent revocation kill already-spawned
    descendants without depending on an in-memory delegation graph.
    """
    if isinstance(principals, str):
        principals = (principals,)
    candidates = tuple(principal for principal in principals if principal)
    if not candidates:
        return None
    try:
        reg = shared()
        for principal in candidates:
            if reg.is_revoked(principal):
                return principal
    except Exception:
        log.exception("revocation lineage check failed; denying")
        return candidates[0]
    return None


__all__ = ["ProtectedRevocationError", "Revocation", "RevocationGenerationMismatch",
           "RevocationRegistry", "RevocationStoreError",
           "shared", "reset_shared", "is_revoked", "revoked_principal"]
