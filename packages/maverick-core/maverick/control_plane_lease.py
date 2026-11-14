"""One control plane per data root, enforced at runtime.

The single-replica invariant is asserted in eleven places -- the chart, two raw
manifests, six docs, a runbook -- and enforced in exactly one: a
``helm template`` time guard in ``_helpers.tpl`` that fails on
``replicaCount > 1``. That guard is real, but it is build-time and it is the
only thing standing between a deployment and silent corruption. ``kubectl
apply`` with a hand-edited manifest, ``docker compose up --scale``, a systemd
unit, or simply two ``maverick dashboard`` processes on one host all walk past
it, and nothing downstream notices.

What is at stake is not a crash. The data root holds four hash-chained ledgers
-- the signed audit chain plus its cross-file anchor ledger, budget receipts,
fleet memory, and the learning/promotion NDJSONs -- and roughly 133 named
file-backed state roots besides. Individual writes are serialized by
``file_lock.cross_process_lock``, so two writers do not tear a single record.
They interleave *valid* records into an append-only chain that assumes one
author, which is worse: the corruption is well-formed, it verifies, and it is
discovered when someone tries to reconstruct history from it.

This module supplies the missing runtime check. One process holds an exclusive
advisory lock on a sentinel in the data root for its entire lifetime; a second
refuses to start and says who holds it.

**What this is, precisely.** The authority is an OS advisory lock (``flock``
on POSIX, ``msvcrt`` byte-range on Windows) held on an open descriptor for the
process lifetime. It is not a timed lease and does not need renewing: the
kernel drops the lock when the holder dies, so there is no stale-lock problem
and no expiry to tune. The JSON body of the sentinel -- pid, host, start time,
fencing token -- is *observability*, not the mechanism. It is written by the
holder after it wins, and a second process reads it only to name the winner in
its refusal message. Saying "lease" and shipping a lock would be exactly the
claim-vs-code gap this work exists to close, so: it is a lock.

**The holder record and fencing token.** The OS-lock file contains no mutable
state. A separate atomically replaced ``control-plane-holder.json`` records the
diagnostic holder and the counter incremented under the authority lock on each
successful acquisition. The separation matters on Windows, where a mandatory
byte-range lock prevents another process from reading the locked byte. The
token answers "is the component about to write still the one that holds the
root?" for anything that caches an ownership decision -- a stale holder's token
is lower than the current one and its write can be rejected. Nothing consumes
it for admission yet; it is recorded, exposed on ``/readyz``, and honest about
that.

**Where exclusion does not reach.** Advisory locks bind a kernel, so this
covers processes sharing a host and a data root -- which is the deployment
shape the invariant is about, since the state lives on a ReadWriteOnce volume
attached to one node. Two pods on different nodes with genuinely separate
volumes are separate deployments and share no state to corrupt. The dangerous
in-between is a network filesystem where ``flock`` is silently a no-op: there
the lock would appear to succeed while providing no exclusion at all. Explicit
unsupported-lock errors fail closed. This local acquisition cannot detect a
filesystem falsely reporting success and does not qualify cross-host exclusion;
use the supported local volume and retain the deployment singleton guard.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import socket
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger(__name__)

#: Sentinel filename in the data root. Named for what holding it means.
LOCK_FILENAME = "control-plane.lock"

#: Readable diagnostic/fencing record. Windows byte-range locks are mandatory:
#: another process cannot read the byte range that carries the lock. Keeping
#: observability in a separate atomically replaced file lets every platform
#: name the current holder without weakening the authority lock.
HOLDER_FILENAME = "control-plane-holder.json"

#: Opt out of single-writer enforcement. Set only when you have independently
#: guaranteed that no other process writes this data root -- the override is
#: reported on /readyz rather than being silently honoured, because an
#: unenforced invariant that still *claims* to hold is the worse failure.
OVERRIDE_ENV = "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES"


class ControlPlaneBusy(RuntimeError):
    """Another process already owns this data root."""


class LeaseUnavailable(RuntimeError):
    """Exclusivity could not be established, so it must not be assumed."""


@dataclass(frozen=True)
class Holder:
    """Who owns the data root. Diagnostic; the lock is the authority."""

    pid: int
    hostname: str
    started_at: float
    fencing_token: int
    role: str = "control-plane"

    def describe(self) -> str:
        age = max(0.0, time.time() - self.started_at)
        return (f"pid {self.pid} on {self.hostname} (role {self.role}, "
                f"token {self.fencing_token}, up {age:.0f}s)")


def lock_path(root: Path | None = None) -> Path:
    """The authoritative advisory-lock path for a data root."""
    if root is None:
        from .paths import maverick_home
        root = maverick_home()
    return Path(root) / LOCK_FILENAME


def holder_path(root: Path | None = None) -> Path:
    """The readable diagnostic/fencing record for a data root."""
    if root is None:
        from .paths import maverick_home
        root = maverick_home()
    return Path(root) / HOLDER_FILENAME


def override_enabled() -> bool:
    """Whether single-writer enforcement has been deliberately disabled."""
    raw = os.environ.get(OVERRIDE_ENV)
    if raw is not None:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    try:
        from .config import load_config
        section = (load_config() or {}).get("deployment") or {}
        return bool(section.get("allow_multiple_control_planes", False))
    # failure-policy: fail_closed
    except Exception as e:
        # An unreadable config must not silently grant the override: the safe
        # reading of "we cannot tell" is "enforcement stays on".
        log.debug("control-plane lease: cannot read config override: %s", e)
        return False


def _holder_record_unavailable(path: Path, detail: str) -> LeaseUnavailable:
    """Refusal for an unreadable or malformed holder record. A missing record,
    or one without ``fencing_token``, is not refused: the token restarts at 1."""
    return LeaseUnavailable(
        f"control-plane holder record {path} is {detail}; the prior fencing "
        "token cannot be proven, so single-writer startup is refusing to "
        "reset it. Restore the record from a trusted backup before retrying."
    )


def _read_holder(path: Path, *, strict: bool = False) -> Holder | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        if strict:
            raise _holder_record_unavailable(path, "unreadable") from exc
        return None
    try:
        data = json.loads(raw)
    except ValueError as exc:
        if strict:
            raise _holder_record_unavailable(path, "malformed") from exc
        return None
    if not isinstance(data, dict) or "pid" not in data:
        if strict:
            raise _holder_record_unavailable(path, "malformed")
        return None
    try:
        return Holder(
            pid=int(data["pid"]),
            hostname=str(data.get("hostname", "?")),
            started_at=float(data.get("started_at", 0.0)),
            fencing_token=int(data.get("fencing_token", 0)),
            role=str(data.get("role", "control-plane")),
        )
    except (TypeError, ValueError) as exc:
        if strict:
            raise _holder_record_unavailable(path, "malformed") from exc
        return None


def _try_lock(fd: int) -> bool:
    """Take an exclusive non-blocking lock. False = someone else holds it.

    Blocking would be the wrong primitive here even though the repo's
    ``cross_process_lock`` uses it: a second replica must refuse and exit, not
    queue behind the first one forever while its readiness probe times out.
    """
    try:
        import fcntl
    except ImportError:
        try:
            import msvcrt
        except ImportError as exc:  # pragma: no cover - supported OSes
            raise LeaseUnavailable(
                "no advisory-lock backend on this platform, so single-writer "
                "ownership of the data root cannot be established"
            ) from exc
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EDEADLOCK):
                return False
            raise LeaseUnavailable(
                f"the data root's filesystem cannot provide advisory locking "
                f"({e}); single-writer safety cannot be established, so the "
                f"control plane will not start. Move the state volume to a "
                f"filesystem with working locks, or set {OVERRIDE_ENV}=1 if "
                f"you have guaranteed exclusivity another way"
            ) from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as e:
        if e.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
            return False
        # ENOLCK / EOPNOTSUPP: a filesystem that cannot lock (some NFS, some
        # overlay mounts). Proceeding would mean believing we are exclusive
        # while providing no exclusion whatsoever -- the one outcome worse
        # than refusing to start.
        raise LeaseUnavailable(
            f"the data root's filesystem cannot provide advisory locking "
            f"({e}); single-writer safety cannot be established, so the "
            f"control plane will not start. Move the state volume to a "
            f"filesystem with working locks, or set {OVERRIDE_ENV}=1 if you "
            f"have guaranteed exclusivity another way"
        ) from e


class Lease:
    """An acquired ownership record. Held for the process lifetime."""

    def __init__(self, path: Path, fd: int, holder: Holder) -> None:
        self._path = path
        self._fd = fd
        self._holder = holder
        self._released = False

    @property
    def holder(self) -> Holder:
        return self._holder

    @property
    def path(self) -> Path:
        return self._path

    @property
    def fencing_token(self) -> int:
        return self._holder.fencing_token

    def assert_owned(self) -> None:
        """Refuse a released or replaced local lock, without claiming DB fencing."""
        if os.getpid() != self._holder.pid:
            raise LeaseUnavailable("control-plane root ownership belongs to another process; inherited leases cannot authorize work")
        if self._released:
            raise LeaseUnavailable("control-plane root ownership was released")
        try:
            opened, visible = os.fstat(self._fd), self._path.stat()
        except OSError as exc:
            raise LeaseUnavailable("control-plane root ownership cannot be verified") from exc
        if ((opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
                or opened.st_nlink != 1 or visible.st_nlink != 1
                or self._path.is_symlink()):
            raise LeaseUnavailable("control-plane root lock identity changed")

    def release(self) -> None:
        """Drop ownership. The kernel does this anyway if the process dies."""
        if self._released:
            return
        self._released = True
        try:
            os.close(self._fd)
        except OSError:  # pragma: no cover - closing a dead fd is not an error
            pass


#: The lease this process holds, if any. One control plane per process.
_held: Lease | None = None
_admission_lock = threading.RLock()


def _require_single_replica() -> None:
    raw = os.environ.get("MAVERICK_REPLICA_COUNT", "1").strip()
    if raw != "1":
        raise LeaseUnavailable(
            "MAVERICK_REPLICA_COUNT must remain 1: shared records and A2A claims "
            "do not yet qualify the remaining control-plane authorities for "
            "multiple replicas. Keep the single-owner deployment guard."
        )


def acquire(
    root: Path | None = None, *, role: str = "control-plane",
) -> Lease | None:
    """Take exclusive ownership of a data root, or explain who has it.

    Returns the lease, or ``None`` when enforcement is overridden. Raises
    :class:`ControlPlaneBusy` if another process owns the root and
    :class:`LeaseUnavailable` if exclusivity cannot be established at all.
    """
    with _admission_lock:
        return _acquire(root, role=role)


def _acquire(root: Path | None, *, role: str) -> Lease | None:
    global _held
    _require_single_replica()

    path = lock_path(root)
    if _held is not None:
        if _held._released:
            _held = None
        else:
            _held.assert_owned()
            if _held.path.resolve() != path.resolve():
                raise LeaseUnavailable("this process already owns a different control-plane data root")
            return _held
    if override_enabled():
        log.warning(
            "control-plane lease: single-writer enforcement is DISABLED via "
            "%s. Two processes writing %s will interleave records into "
            "append-only ledgers that assume one author; the result verifies "
            "cleanly and is unreconstructable. /readyz reports this posture.",
            OVERRIDE_ENV, path.parent,
        )
        return None

    from .file_lock import ensure_private_directory, ensure_private_file
    ensure_private_directory(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        ensure_private_file(path, 0o600)
        opened, visible = os.fstat(fd), path.stat()
        if ((opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
                or opened.st_nlink != 1 or visible.st_nlink != 1 or path.is_symlink()):
            raise LeaseUnavailable("control-plane root lock identity cannot be verified")
        if not _try_lock(fd):
            other = _read_holder(holder_path(path.parent))
            who = other.describe() if other else "an unidentified process"
            raise ControlPlaneBusy(
                f"another Lightwork control plane already owns {path.parent}: "
                f"{who}. Exactly one may write this data root -- flows, A2A "
                f"claims, and the audit, budget-receipt, fleet-memory and "
                f"learning ledgers are hash-chained and assume a single "
                f"author. Scale remote workers instead of the control plane, "
                f"or point this process at its own data root via "
                f"MAVERICK_HOME."
            )
        # Won the lock. Bump the fencing token under it, so the value is
        # monotonic across restarts and a stale holder is detectable (as long
        # as the holder record survives: a deleted record restarts it at 1).
        record_path = holder_path(path.parent)
        previous = _read_holder(record_path, strict=True)
        holder = Holder(
            pid=os.getpid(),
            hostname=socket.gethostname(),
            started_at=time.time(),
            fencing_token=(previous.fencing_token + 1) if previous else 1,
            role=role,
        )
        from .file_lock import atomic_write_text

        atomic_write_text(
            record_path,
            json.dumps(asdict(holder), sort_keys=True) + "\n",
            mode=0o600,
        )
    except BaseException:
        os.close(fd)
        raise

    _held = Lease(path, fd, holder)
    log.info("control-plane lease: acquired %s as %s", path, holder.describe())
    return _held


def current() -> Lease | None:
    """The lease this process holds, or None."""
    return _held if _held is not None and not _held._released else None


def release() -> None:
    """Drop this process's lease. Primarily for tests and clean shutdown."""
    global _held
    with _admission_lock:
        if _held is not None:
            _held.release()
            _held = None


def posture(root: Path | None = None) -> dict:
    """Replica-safety posture, for /readyz.

    Three states, deliberately distinguished: ``owned`` (this process holds the
    root), ``unenforced`` (the operator disabled the check), and ``unknown``
    (nothing acquired -- which for the dashboard means startup did not run the
    guard, not that the root is free).
    """
    try:
        _require_single_replica()
        owned = current()
        if owned is not None:
            owned.assert_owned()
            if owned.path.resolve() != lock_path(root).resolve():
                raise LeaseUnavailable("this process owns a different data root")
    except LeaseUnavailable as exc:
        return {"state": "unavailable", "single_writer_enforced": False, "detail": str(exc)}
    if owned is not None:
        return {
            "state": "owned",
            "single_writer_enforced": True,
            "fencing_token": owned.fencing_token,
            "holder": owned.holder.describe(),
        }
    if override_enabled():
        return {
            "state": "unenforced",
            "single_writer_enforced": False,
            "detail": (f"{OVERRIDE_ENV} is set; concurrent writers to this "
                       "data root are not prevented"),
        }
    other = _read_holder(holder_path(root))
    return {
        "state": "unknown",
        "single_writer_enforced": False,
        "detail": ("this process holds no control-plane lease"
                   + (f"; last recorded holder was {other.describe()}"
                      if other else "")),
    }


__all__ = [
    "ControlPlaneBusy",
    "HOLDER_FILENAME",
    "Holder",
    "Lease",
    "LeaseUnavailable",
    "OVERRIDE_ENV",
    "acquire",
    "current",
    "holder_path",
    "lock_path",
    "override_enabled",
    "posture",
    "release",
]
