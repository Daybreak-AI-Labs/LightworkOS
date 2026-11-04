"""Bound the memory held by sealed-attachment downloads at one time.

A sealed attachment is authenticated as one whole blob before any byte is
released, so a download holds the ciphertext and the plaintext in memory
together. Each file is size-capped, but many large downloads at once could
still exhaust the server. Downloads reserve twice their file size from one
shared budget; others wait their turn briefly, then get a plain busy message.
"""
from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager

_DEFAULT_BUDGET_BYTES = 512 * 1024 * 1024


class DecryptBusy(RuntimeError):
    """Too many large downloads are being prepared right now."""


class ByteBudget:
    def __init__(self, total: int) -> None:
        self.total = max(1, int(total))
        self.in_use = 0
        self._cond = threading.Condition()

    @contextmanager
    def reserve(self, amount: int, *, timeout: float = 30.0):
        # A single file larger than the whole budget may still run, alone.
        need = max(0, min(int(amount), self.total))
        deadline = time.monotonic() + timeout
        with self._cond:
            while self.in_use + need > self.total:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DecryptBusy
                self._cond.wait(remaining)
            self.in_use += need
        try:
            yield
        finally:
            with self._cond:
                self.in_use -= need
                self._cond.notify_all()


def _configured_total() -> int:
    raw = os.environ.get("MAVERICK_ATTACH_DECRYPT_BUDGET_BYTES", "").strip()
    try:
        value = int(raw) if raw else _DEFAULT_BUDGET_BYTES
    except ValueError:
        value = _DEFAULT_BUDGET_BYTES
    return value if value > 0 else _DEFAULT_BUDGET_BYTES


BUDGET = ByteBudget(_configured_total())
