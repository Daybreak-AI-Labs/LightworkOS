"""Remember the private SQLite files this process has already initialized.

A tenant-scoped authority (third-party lifecycle and collaboration, privacy
rights) runs its whole schema script, a write transaction, when it is
constructed, and the dashboard constructs one per request. On a network file
system that script is dozens of round trips before the request reads a row.

Once a file has been initialized in this process, a later construction checks
with one ``lstat`` that the very same file is still there, unchanged since, as
a private single-link regular file, and only then skips the script. A
replaced, rewritten, re-linked, aliased or loosened file runs it again, and so
does every construction on Windows, where privacy is an ACL rather than a
mode.
"""
from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

#: Distinct files remembered at once; a fuller memo starts again.
_MAX_FILES = 4_096


def _identity(path: Path) -> tuple[int, int, int] | None:
    """The file's identity when it is a private single-link regular file."""
    if os.name == "nt":
        return None
    try:
        info = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        return None
    return info.st_dev, info.st_ino, info.st_ctime_ns


class InitializedFiles:
    """The files one authority initialized in this process, by identity."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._files: dict[str, tuple[int, int, int]] = {}

    def current(self, path: str | Path) -> bool:
        """Whether ``path`` is the same unchanged file initialized here."""
        key = os.fspath(path)
        with self._lock:
            known = self._files.get(key)
        if known is None:
            return False
        if _identity(Path(key)) == known:
            return True
        self.forget(key)
        return False

    def remember(self, path: str | Path) -> None:
        """Record ``path`` right after its schema script succeeded."""
        key = os.fspath(path)
        identity = _identity(Path(key))
        with self._lock:
            if identity is None:
                self._files.pop(key, None)
                return
            if len(self._files) >= _MAX_FILES and key not in self._files:
                self._files.clear()
            self._files[key] = identity

    def forget(self, path: str | Path) -> None:
        with self._lock:
            self._files.pop(os.fspath(path), None)


__all__ = ["InitializedFiles"]
