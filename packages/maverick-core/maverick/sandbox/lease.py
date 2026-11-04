"""Local operation ownership for explicit sandbox policy handoff."""
from __future__ import annotations

import threading
from contextlib import contextmanager, nullcontext


class BackendLease:
    """Retirement is permanent; an old handle can never become a new run's handle."""

    __slots__ = ("_lock", "_active", "_retired")

    def __init__(self):
        self._lock = threading.Lock()
        self._active = 0
        self._retired = False

    @contextmanager
    def operation(self, *, cleanup: bool = False):
        with self._lock:
            if self._retired and not cleanup:
                raise RuntimeError("sandbox lease was transferred; build a new sandbox")
            self._active += 1
        try:
            yield
        finally:
            with self._lock:
                self._active -= 1

    def inspect_idle(self, inspect):
        with self._lock:
            if self._active or self._retired:
                return None
            return inspect()

    def retire_if_idle(self, check) -> bool:
        with self._lock:
            if self._active or self._retired or not check():
                return False
            self._retired = True
            return True


def operation_lease(backend, *, cleanup: bool = False):
    """Legacy/unpickled backends still execute, but cannot enter the pool."""
    lease = getattr(backend, "_pool_lease", None)
    if type(lease) is BackendLease:
        return lease.operation(cleanup=cleanup)
    return nullcontext()
