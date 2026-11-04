"""Connection policy shared by private SQLite-backed authorities.

Some authorities use the shared consent PostgreSQL adapter, which accepts
the same connection configuration calls. Creating and closing the connection
remains the responsibility of each authority.
"""
from __future__ import annotations

import sqlite3


def configure_authority_connection(connection, *, foreign_keys: bool = True) -> None:
    """Apply the durable, private policy in its established order."""
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    if foreign_keys:
        connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA secure_delete=ON")
