"""Cross-process locking for self-contained standalone demo stores.

Edit this source and run scripts/sync_standalone_support.py to refresh the
copies included in independently distributable demo directories.
"""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def cross_process_lock(path: Path, *, private: bool = False):
    """Serialize a store's read/compare/write transaction across processes."""
    lock_path = path.with_name(f"{path.name}.lock")
    if private:
        lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if lock_path.is_symlink():
            raise ValueError("local store lock must not be a symbolic link")
        try:
            os.chmod(lock_path.parent, 0o700)
        except OSError:
            pass
    else:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        if private:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            import msvcrt

            while True:
                try:
                    if lock_path.stat().st_size == 0:
                        handle.seek(0)
                        handle.write(b"\0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.01)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:  # pragma: no cover - exercised on POSIX
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
