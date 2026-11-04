"""Global killswitch for running agents.

Two ways to halt:
  1. **File trigger**: ``touch ~/.maverick/HALT``  (default path; override
     via ``MAVERICK_HALT_FILE``). Polled cheaply at tool-call boundaries.
  2. **In-process trigger**: any thread calls ``halt(reason)`` and every
     ``check()`` call afterward raises ``Halted``.

Agent kernels call ``check()`` at tool-call boundaries and at each
turn. If a halt is active, ``Halted`` is raised, the goal is recorded
as halted in the audit log, and the orchestrator stops cleanly.

The file trigger lets a user (or operator) abort a swarm from outside
the process — handy when you realize the agent is about to do
something expensive or wrong.
"""
from __future__ import annotations

import logging
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .paths import data_dir

log = logging.getLogger(__name__)
_local_checks: ContextVar[tuple[Callable[[], None], ...]] = ContextVar("execution_local_stop_checks", default=())


@contextmanager
def bind_local_check(checker: Callable[[], None]):
    """Add an owned execution stop without arming the process-wide halt.

    Async children and explicit context copies inherit the check; unrelated
    threads/requests do not. Nested scopes retain their parent's stop checks.
    """
    token = _local_checks.set((*_local_checks.get(), checker))
    try:
        yield
    finally:
        _local_checks.reset(token)


def _default_halt_file() -> Path:
    """Default HALT path, resolved fresh each call.

    Must NOT be cached at import time: a process that re-homes after import
    (a daemon, an embedder, or the test home-isolation fixture) would
    otherwise keep watching the *old* home's HALT file. Honoring the current
    ``Path.home()`` per call keeps the killswitch trustworthy — the one
    place we can least afford a stale path.
    """
    # One local operator stop must cover every tenant/fleet in the process.
    # Tenant-scoping this path lets a tenant silently watch a different file.
    return data_dir("HALT", tenant=None)


class Halted(Exception):
    """Raised by ``check()`` when a halt is active."""

    def __init__(self, reason: str, source: str):
        super().__init__(f"halted: {reason} (source={source})")
        self.reason = reason
        self.source = source


_state_lock = threading.Lock()
_in_process_halt: tuple[str, str] | None = None  # (reason, source)
_in_process_generation: str | None = None
# Exact-owner transition holds keep the serving process stopped while a shared
# HALT transaction removes the local file.  They are separate from ordinary
# in-process halts so concurrent clears cannot release each other's hold and a
# concurrent ``halt()`` remains independently armed.
_clear_transition_holds: dict[str, tuple[str, str]] = {}
_last_file_check_ts: float = 0.0
_last_file_present: bool = False
_last_file_authority: tuple[str, bool, bool] | None = None
# Independent of the in-process/control-plane lock: filesystem observation
# never acquires a control barrier or changes an in-process halt generation.
_file_check_lock = threading.Lock()
# Cluster-wide halt (v22): consulted from the shared world store so an emergency
# stop armed on one replica halts the whole fleet. Throttled like the file check;
# only engaged on a shared backend (Postgres).
_last_shared_check_ts: float = 0.0
_last_shared_halt: tuple[str, str] | None = None
_shared_world = None  # cached world handle for the shared-halt consult

_HALT_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HALT_GENERATION_ATTEMPTS = 3
_CLEAR_ANY_GENERATION = object()


class HaltGenerationChanged(RuntimeError):
    """A newer in-process halt superseded an exact-generation clear."""


def _halt_file_path() -> Path:
    override = os.environ.get("MAVERICK_HALT_FILE")
    return Path(override) if override else _default_halt_file()


def _halt_authority_lock_path(path: Path | None = None) -> Path:
    """One stable lock path shared by every built-in local HALT writer.

    The HALT file itself is atomically replaced and removed, so it cannot be
    used as the lock inode.  A sibling sidecar survives those publications and
    lets an arm that overlaps a clear serialize after it instead of being
    unlinked by the older clear request.
    """

    target = Path(path) if path is not None else _halt_file_path()
    return target.with_name(f".{target.name}.authority.lock")


def _halt_path_is_alias(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _HALT_REPARSE_ATTRIBUTE
    )


def _halt_generation(info: os.stat_result) -> tuple[int, ...]:
    """Identity plus mutation metadata for one exact local HALT generation."""

    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _validate_halt_file(info: os.stat_result) -> None:
    if (
        _halt_path_is_alias(info)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_ino == 0
    ):
        raise PermissionError("HALT authority is not a single-link regular file")


def _halt_file_generation(path: Path | None = None) -> tuple[int, ...] | None:
    """Bind the visible HALT pathname to one verified file generation.

    The descriptor/path comparison closes the lstat/open substitution window.
    Callers compare the returned token again while holding
    :func:`_halt_authority_lock_path` before deleting.  ``None`` is a stable
    absent observation; aliases, hard links, zero-inode results, and repeated
    identity churn are authority failures rather than a healthy clear state.
    """

    target = Path(path) if path is not None else _halt_file_path()
    last_error: BaseException | None = None
    for _attempt in range(_HALT_GENERATION_ATTEMPTS):
        try:
            before = target.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            last_error = exc
            continue
        _validate_halt_file(before)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(os.fspath(target), flags)
            try:
                opened = os.fstat(fd)
            finally:
                os.close(fd)
            after = target.lstat()
        except OSError as exc:
            last_error = exc
            continue
        _validate_halt_file(opened)
        _validate_halt_file(after)
        before_generation = _halt_generation(before)
        if (
            before_generation == _halt_generation(opened)
            and before_generation == _halt_generation(after)
        ):
            return before_generation
    raise PermissionError("HALT authority identity could not be verified") from last_error


def halt(reason: str, source: str = "manual") -> None:
    """Trigger an in-process halt. All subsequent check() calls raise."""
    global _in_process_generation, _in_process_halt
    with _state_lock:
        _in_process_halt = (reason, source)
        _in_process_generation = secrets.token_urlsafe(24)
    # Set the safety state first, then wait for any Ekko commit that sampled the
    # prior state. A lock outage can never undo the halt; it only weakens the
    # return-time barrier and is logged for operators.
    try:
        from .ekko_control import control_barrier

        with control_barrier():
            pass
    except Exception:
        log.exception("killswitch: Ekko commit barrier unavailable during halt")
    log.warning("killswitch: halt set (%s, source=%s)", reason, source)
    from .audit import EventKind, audit_event

    # Page the operator even when the configured audit guarantee refuses its
    # row. The halt remains armed either way, then the refusal propagates so the
    # caller cannot mistake an unrecorded stop for a fully recorded one.
    try:
        audit_event(EventKind.HALT, source=source, detail=reason)
    finally:
        # A halt stops all work, so this is the canonical event an SRE must hear
        # about. No-op unless [alerts] is enabled; paging never blocks the halt.
        try:
            from .ops_alert import alert
            alert(
                "killswitch_tripped",
                f"{reason} (source={source})",
                severity="critical",
            )
        except Exception:  # pragma: no cover -- alerting never blocks the halt
            pass


def _in_process_halt_generation() -> str | None:
    """Return the exact current in-process HALT token under the state lock."""

    with _state_lock:
        return _in_process_generation


def _begin_clear_transition_hold(
    reason: str = "HALT clear transaction in progress",
    source: str = "control-plane-clear",
) -> str:
    """Arm and return one exact-owner temporary process stop.

    The hold is visible to :func:`check` before waiting for the strict control
    barrier.  If that barrier is unavailable the hold deliberately remains:
    an authority-expanding clear must fail stopped rather than continue with an
    uncoordinated transition.
    """

    token = secrets.token_urlsafe(24)
    with _state_lock:
        _clear_transition_holds[token] = (reason, source)
    from .ekko_control import control_barrier

    with control_barrier():
        pass
    return token


def _end_clear_transition_hold(token: str) -> None:
    """Release only the transition hold owned by ``token``."""

    from .ekko_control import control_barrier

    with control_barrier(), _state_lock:
        if token not in _clear_transition_holds:
            raise HaltGenerationChanged("clear transition hold changed")
        del _clear_transition_holds[token]


def clear(
    *,
    durable_clear: Callable[[], None] | None = None,
    expected_in_process_generation: str | None | object = _CLEAR_ANY_GENERATION,
) -> None:
    """Reset the in-process halt after an optional durable-clear callback.

    ``durable_clear`` runs inside the same strict control barrier and state lock
    as the in-process transition.  A caller that removes a HALT file can
    therefore fail before *either* authority is cleared; the old ordering could
    clear the process flag, discover a replaced/unreadable file, and still
    report that the stop remained armed.  When an expected process generation
    is supplied, a concurrent :func:`halt` wins.  Exact-owner shared-clear
    transition holds are intentionally unaffected by this general primitive.
    """
    global _in_process_generation, _in_process_halt
    from .ekko_control import control_barrier

    # Clearing is expansive, so unlike halt it fails closed if the strict
    # cross-process authority barrier is unavailable.
    with control_barrier(), _state_lock:
        if (
            expected_in_process_generation is not _CLEAR_ANY_GENERATION
            and _in_process_generation != expected_in_process_generation
        ):
            raise HaltGenerationChanged("newer in-process HALT generation observed")
        if durable_clear is not None:
            durable_clear()
        _in_process_halt = None
        _in_process_generation = None


def _file_halt_active(
    min_interval: float = 1.0, *, fail_closed: bool = False,
) -> bool:
    """Check the HALT file at most once per ``min_interval`` seconds.

    Avoids stat-ing the filesystem on every tool call. The 1s cache is
    invisible to humans triggering halts but cheap enough to not matter.
    """
    global _last_file_check_ts, _last_file_present, _last_file_authority
    with _file_check_lock:
        try:
            path = _halt_file_path().absolute()
            explicit = bool(os.environ.get("MAVERICK_HALT_FILE"))
            # Path.absolute captures CWD without resolving symlinks or collapsing
            # '..': observe exactly this spelling, even if another thread chdirs.
            authority = (
                os.fspath(path), explicit, fail_closed,
            )
        except (OSError, ValueError) as exc:
            _last_file_check_ts = 0.0
            _last_file_authority = None
            if fail_closed:
                raise Halted("HALT file authority unavailable", "file-error") from exc
            return False
        now = time.monotonic()
        elapsed = now - _last_file_check_ts
        # Re-homing or a stricter observation cannot reuse another authority's
        # positive OR negative result. Zero remains the explicit reset sentinel;
        # a backwards clock and force_refresh also bypass the cache.
        if (
            authority == _last_file_authority
            and _last_file_check_ts > 0.0
            and 0.0 <= elapsed < min_interval
        ):
            return _last_file_present
        # A failed refresh must not leave a formerly healthy cached negative
        # available to the next fail-closed call with this same metadata.
        _last_file_check_ts = 0.0
        _last_file_authority = None
        try:
            path.stat()
            present = True
        except FileNotFoundError:
            # An explicitly configured authority whose parent/mount is absent
            # is not equivalent to an absent HALT file for privileged callers.
            if fail_closed and explicit:
                try:
                    path.parent.stat()
                except OSError as parent_exc:
                    raise Halted(
                        "HALT file authority unavailable", "file-error",
                    ) from parent_exc
            present = False
        except (OSError, ValueError) as exc:
            if fail_closed:
                raise Halted("HALT file authority unavailable", "file-error") from exc
            present = False
        _last_file_present = present
        _last_file_authority = authority
        _last_file_check_ts = now
        return present


def _shared_halt_active(
    min_interval: float = 2.0, *, fail_closed: bool = False,
) -> tuple[str, str] | None:
    """Read the cluster-wide halt with caller-selected outage posture.

    Only engaged on a shared backend (Postgres): the SQLite single-host path is
    already covered by the local HALT file, and querying a per-host SQLite world
    on every tool call would add hot-path cost for no cluster benefit. Returns
    ``(reason, source)`` when armed, else ``None``. Any error -> keep the last
    known state and drop the cached handle so the next check reconnects -- the
    killswitch must never wedge a run on a shared-store hiccup, but a transient
    read error must not silently drop a real halt either. Privileged callers
    set ``fail_closed`` and receive ``Halted(source="shared-error")`` instead.
    """
    global _last_shared_check_ts, _last_shared_halt, _shared_world
    now = time.monotonic()
    elapsed = now - _last_shared_check_ts
    if _last_shared_check_ts > 0.0 and 0.0 <= elapsed < min_interval:
        return _last_shared_halt
    _last_shared_check_ts = now
    try:
        if fail_closed:
            # ``is_postgres_configured`` deliberately fails soft when config is
            # unreadable. That is appropriate for ordinary availability-first
            # callers, but privileged learning transitions must not interpret
            # a malformed backend policy as "SQLite, so no shared HALT exists".
            # Force all active sources to be read, then inspect the config
            # health seam before deciding whether the cluster authority applies.
            from .config import config_source_errors, load_config

            load_config()
            if config_source_errors():
                raise RuntimeError("shared HALT backend configuration unreadable")
        from .world_model_backends import is_postgres_configured
        if not is_postgres_configured():
            _last_shared_halt = None
            return None
        if _shared_world is None:
            from .world_model import open_world
            _shared_world = open_world()
        state = _shared_world.active_halt()
        _last_shared_halt = (
            (state.get("reason") or "cluster halt", state.get("source") or "shared")
            if state else None
        )
    except Exception as exc:  # reconnect next time; posture is caller-selected
        _shared_world = None
        if fail_closed:
            raise Halted(
                "cluster HALT authority unavailable", "shared-error",
            ) from exc
    return _last_shared_halt


def check(*, force_refresh: bool = False, fail_closed: bool = False) -> None:
    """Raise ``Halted`` if any halt source is active.

    Hot agent boundaries use the normal one/two-second file/shared caches.
    Privileged, comparatively infrequent transitions such as learning
    promotions pass ``force_refresh=True`` so a HALT that lands during an
    evaluation cannot hide behind a stale negative cache entry.  Learning and
    other privileged mutations additionally pass ``fail_closed=True``: an
    unreadable configured HALT authority then refuses work rather than being
    mistaken for an inactive stop.  The ordinary agent hot path keeps its
    historical availability-first behavior by leaving this flag false.
    """
    with _state_lock:
        ip = _in_process_halt
        transition = next(iter(_clear_transition_holds.values()), None)
    if ip is not None:
        raise Halted(ip[0], ip[1])
    if transition is not None:
        raise Halted(transition[0], transition[1])
    file_interval = 0.0 if force_refresh else 1.0
    shared_interval = 0.0 if force_refresh else 2.0
    if _file_halt_active(
        min_interval=file_interval, fail_closed=fail_closed,
    ):
        raise Halted(f"HALT file present at {_halt_file_path()}", "file")
    shared = _shared_halt_active(
        min_interval=shared_interval, fail_closed=fail_closed,
    )
    if shared is not None:
        raise Halted(shared[0], shared[1])
    for checker in _local_checks.get():
        checker()


def is_active() -> bool:
    """Non-raising query. Useful for UI."""
    try:
        check()
    except Halted:
        return True
    return False
