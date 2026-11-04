"""Private SQLite connection and transaction policy for data-use authorities."""

from __future__ import annotations

import contextlib
import os
import sqlite3

from .sqlite_authority import configure_authority_connection


@contextlib.contextmanager
def private_connection(path, *, ensure_directory, ensure_file, foreign_keys: bool = True):
    """Open a private, durable authority database and always close it."""
    ensure_directory(path.parent)
    if not path.exists():
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    ensure_file(path, 0o600)
    conn = sqlite3.connect(str(path), timeout=10.0, isolation_level=None)
    try:
        configure_authority_connection(conn, foreign_keys=foreign_keys)
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def immediate_transaction(connect):
    """Serialize writes, committing on success and rolling back on any failure."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
