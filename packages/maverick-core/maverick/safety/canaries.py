"""Sandbox-escape canaries.

Plants files inside the sandbox at known paths. If the agent reaches a
canary path (read, write, or move), we fire a critical event AND raise
a SandboxCanaryFired exception that aborts the current tool call.

Use case: prove the sandbox boundary is intact under adversarial
attack. If a goal somehow accesses ``/canary-1`` or ``~/.maverick/
canary-deadbeef``, the boundary leaked.

The canary check is a cheap stat() per access. No-op when no canaries
have been registered.
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
from pathlib import Path

log = logging.getLogger(__name__)


_canaries: set[str] = set()
_lock = threading.Lock()


class SandboxCanaryFired(Exception):
    """Raised when a registered canary is read or written."""

    def __init__(self, path: str, action: str = "access"):
        super().__init__(
            f"sandbox canary fired: {action} on {path!r} "
            "(this indicates a sandbox boundary leak)"
        )
        self.path = path
        self.action = action


def register(path: str | os.PathLike) -> str:
    """Register ``path`` as a canary; returns its resolved string form."""
    p = str(Path(path).resolve())
    with _lock:
        _canaries.add(p)
    return p


def unregister(path: str | os.PathLike) -> bool:
    """Remove a canary. Returns True if removed."""
    p = str(Path(path).resolve())
    with _lock:
        if p in _canaries:
            _canaries.remove(p)
            return True
    return False


def list_canaries() -> list[str]:
    with _lock:
        return sorted(_canaries)


def is_canary(path: str | os.PathLike) -> bool:
    p = str(Path(path).resolve())
    with _lock:
        return p in _canaries


def check(path: str | os.PathLike, *, action: str = "access") -> None:
    """Raise SandboxCanaryFired if ``path`` is a registered canary.

    Tools call this before reading / writing user-supplied paths. The
    agent kernel also calls it at goal start to plant a fresh canary,
    and at goal end to verify the canary wasn't touched.
    """
    if not _canaries:
        return  # fast path
    p = str(Path(path).resolve())
    with _lock:
        hit = p in _canaries
    if hit:
        # Audit-log before raising. Fail-safe (audit failures don't block).
        try:
            from ..audit import record
            record("sandbox_canary_fired", path=p, action=action)
        except Exception:  # pragma: no cover
            pass
        raise SandboxCanaryFired(p, action)


def plant_session_canaries(workdir: str | os.PathLike) -> list[str]:
    """Plant ~3 canaries in the sandbox for the current session.

    Returns the list of registered canary paths. Paths use random hex
    names so the agent can't predict them (or have learned them from
    training data).

    Typical usage at agent kernel startup:
        from maverick.safety import canaries
        planted = canaries.plant_session_canaries(sandbox.workdir)
        ... run agent ...
        violations = canaries.verify_canaries(planted)
        if violations:
            log.critical("canary verification failed: %s", violations)
    """
    base = Path(workdir).resolve()
    planted: list[str] = []
    for _ in range(3):
        name = f".maverick-canary-{secrets.token_hex(4)}"
        path = base / name
        try:
            content = f"DO_NOT_TOUCH-{secrets.token_hex(8)}\n"
            path.write_text(content)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            planted.append(register(path))
        except OSError as e:
            log.warning("canaries: cannot plant %s: %s", path, e)
    return planted


def verify_canaries(planted: list[str]) -> list[str]:
    """Verify that each planted canary is still pristine.

    Returns the list of canary paths that were tampered with (deleted,
    modified, or missing).
    """
    violations: list[str] = []
    for p in planted:
        path = Path(p)
        if not path.exists():
            violations.append(p)
            continue
        try:
            content = path.read_text()
        except OSError:
            violations.append(p)
            continue
        if not content.startswith("DO_NOT_TOUCH-"):
            violations.append(p)
    return violations


def clear() -> None:
    """Drop every registered canary. Useful in tests."""
    with _lock:
        _canaries.clear()


__all__ = [
    "register",
    "unregister",
    "list_canaries",
    "is_canary",
    "check",
    "plant_session_canaries",
    "verify_canaries",
    "clear",
    "SandboxCanaryFired",
]
