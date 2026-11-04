"""SQLite connections that close when their ``with`` block exits.

``with connection:`` in sqlite3 only commits or rolls back; it never closes. On CPython 3.12
a connection used only that way stays open until a cyclic garbage-collection pass (CPython
3.10 closes it at once), and on Windows an open file cannot be deleted or replaced, so a store
whose connections stay open blocks erase, purge, restore and tenant deletion with WinError 32.
Pass ``factory=ClosingConnection`` to ``sqlite3.connect`` so each per-call connection is closed
as its block exits.
"""

from __future__ import annotations

import sqlite3
from types import TracebackType


class ClosingConnection(sqlite3.Connection):
    """A ``sqlite3.Connection`` whose ``with`` block commits or rolls back, then closes."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()
