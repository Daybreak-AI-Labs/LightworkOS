"""Storage for the public website chat widget (see ``public_chat_api``).

Two kinds of SQLite file, both private to the installation:

* a shared index (no tenant) that maps a publishable-key digest and a
  visitor-session digest to exactly one tenant and site, so a public request
  learns its tenant from the key and reads nothing tenant-scoped before that;
* one file per tenant with the sites, the daily spend and the transcripts.

Raw publishable keys and session tokens are never written; only their SHA-256
digests are. Transcript text is sealed with the at-rest helper, bound to the
tenant, site, conversation and row, so a copied row does not decrypt elsewhere.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from maverick.crypto_at_rest import seal_bound, unseal_bound
from maverick.file_lock import ensure_private_directory, ensure_private_file
from maverick.paths import data_dir, tenant_scope

logger = logging.getLogger(__name__)

KEY_PREFIX = "lwpk_"
SESSION_PREFIX = "lwps_"
# A visitor session lasts at most one hour; the widget asks for a fresh one.
SESSION_TTL_SECONDS = 1_800
MAX_ORIGINS = 20
MAX_SITES_PER_TENANT = 50
MAX_LIVE_SESSIONS_PER_SITE = 5_000
MAX_DAILY_CAP_DOLLARS = 1_000.0
# Each answer reserves this much of the daily cap before its provider call.
ANSWER_RESERVE_DOLLARS = 0.05
_DAY_SECONDS = 86_400
_MINUTE_SECONDS = 60.0
# Retention sweeps across every tenant run at most this often, on visits.
_SWEEP_SECONDS = 3_600.0
_sweep_lock = threading.Lock()
_last_sweep: float | None = None
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")

_INDEX_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS chat_keys (key_sha256 TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
    "site_id TEXT NOT NULL, created_at REAL NOT NULL, revoked_at REAL)",
    "CREATE INDEX IF NOT EXISTS chat_keys_site ON chat_keys (site_id)",
    "CREATE TABLE IF NOT EXISTS chat_origins (origin TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
    "site_id TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS chat_origins_site ON chat_origins (site_id)",
    "CREATE TABLE IF NOT EXISTS chat_sessions (token_sha256 TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
    "site_id TEXT NOT NULL, origin TEXT NOT NULL, conversation_id TEXT NOT NULL, issued_at REAL NOT NULL, "
    "expires_at REAL NOT NULL, message_count INTEGER NOT NULL DEFAULT 0, "
    "recent_json TEXT NOT NULL DEFAULT '[]')",
    "CREATE INDEX IF NOT EXISTS chat_sessions_site ON chat_sessions (site_id)",
)
_TENANT_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS chat_sites (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
    "origins_json TEXT NOT NULL, specialist TEXT NOT NULL, greeting TEXT NOT NULL, "
    "daily_cap_dollars REAL NOT NULL, messages_per_session INTEGER NOT NULL, "
    "messages_per_minute INTEGER NOT NULL, retention_days INTEGER NOT NULL, state TEXT NOT NULL, "
    "messages_per_client_per_day INTEGER NOT NULL DEFAULT 200, "
    "created_at REAL NOT NULL, updated_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS chat_spend (site_id TEXT NOT NULL, day TEXT NOT NULL, "
    "dollars REAL NOT NULL DEFAULT 0, PRIMARY KEY (site_id, day))",
    "CREATE TABLE IF NOT EXISTS chat_transcripts (seq INTEGER PRIMARY KEY AUTOINCREMENT, "
    "id TEXT NOT NULL UNIQUE, site_id TEXT NOT NULL, conversation_id TEXT NOT NULL, "
    "role TEXT NOT NULL, sealed TEXT NOT NULL, created_at REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS chat_transcripts_site ON chat_transcripts (site_id, created_at)",
)


# Columns a later release added: (table, column, definition). A file an earlier release
# made gets each missing one added, once, under a write lock.
_ADDED_COLUMNS = (("chat_sites", "messages_per_client_per_day", "INTEGER NOT NULL DEFAULT 200"),)


class ChatStoreError(Exception):
    """A refusal; ``reason`` is a short code the API maps to a generic message."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def index_path() -> Path:
    return data_dir("public_chat", "index.sqlite3", tenant=None)


def sites_path(tenant: str | None) -> Path:
    return data_dir("public_chat", "sites.sqlite3", tenant=tenant)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def new_session_token() -> str:
    return SESSION_PREFIX + secrets.token_urlsafe(32)


def normalize_origin(value: object, *, allow_localhost: bool) -> str:
    """The exact browser origin: https DNS names, or http://localhost with the dev flag."""
    if not isinstance(value, str) or not 1 <= len(value) <= 300 or value != value.strip():
        raise ValueError("origin")
    parts = urlsplit(value)
    if (parts.username or parts.password or parts.query or parts.fragment
            or parts.path not in {"", "/"}):
        raise ValueError("origin")
    scheme, host = parts.scheme, parts.hostname or ""
    if ":" in host or not host:
        raise ValueError("origin")
    if scheme == "https" and host != "localhost":
        pass
    elif scheme == "http" and host == "localhost" and allow_localhost:
        pass
    else:
        raise ValueError("origin")
    if not _HOST_RE.match(host) or host.rsplit(".", 1)[-1].isdigit():
        raise ValueError("origin")
    port = parts.port
    if port is None or (scheme, port) in {("https", 443), ("http", 80)}:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


@contextmanager
def _connect(path: Path, schema: tuple[str, ...]) -> Iterator[sqlite3.Connection]:
    ensure_private_directory(path.parent)
    connection = sqlite3.connect(str(path), isolation_level=None, timeout=10.0)
    try:
        ensure_private_file(path, 0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA secure_delete=ON")
        for statement in schema:
            connection.execute(statement)
        _add_missing_columns(connection)
        yield connection
    finally:
        connection.close()


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _add_missing_columns(connection: sqlite3.Connection) -> None:
    """Add each column in ``_ADDED_COLUMNS`` that the file lacks."""
    for table, column, definition in _ADDED_COLUMNS:
        # A file without this table (the shared index) has nothing to add to.
        if not _columns(connection, table) or column in _columns(connection, table):
            continue
        connection.execute("BEGIN IMMEDIATE")
        try:
            # Checked again under the lock: another connection may have added it first.
            if column not in _columns(connection, table):
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")


@contextmanager
def _write(path: Path, schema: tuple[str, ...]) -> Iterator[sqlite3.Connection]:
    with _connect(path, schema) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")


def _tenant_key(tenant: str | None) -> str:
    return tenant or ""


def _site(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"], "display_name": row["display_name"],
        "origins": json.loads(row["origins_json"]), "specialist": row["specialist"],
        "greeting": row["greeting"], "daily_cap_dollars": row["daily_cap_dollars"],
        "messages_per_session": row["messages_per_session"],
        "messages_per_minute": row["messages_per_minute"],
        "messages_per_client_per_day": row["messages_per_client_per_day"],
        "retention_days": row["retention_days"], "state": row["state"],
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }


def _context(site_id: str, conversation_id: str, role: str, row_id: str) -> str:
    return f"public-chat:{site_id}:{conversation_id}:{role}:{row_id}"


def _purge(db: sqlite3.Connection, site_id: str, now: float, retention_days: int) -> None:
    db.execute("DELETE FROM chat_transcripts WHERE site_id = ? AND created_at < ?",
               (site_id, now - retention_days * _DAY_SECONDS))


def create_site(tenant: str | None, *, site_id: str, fields: dict[str, Any],
                origins: list[str], now: float) -> tuple[dict[str, Any], str]:
    """Store the site, then its key and origins in the index. Returns the key once."""
    with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
        live = db.execute("SELECT COUNT(*) FROM chat_sites WHERE state = 'active'").fetchone()[0]
        if int(live) >= MAX_SITES_PER_TENANT:
            raise ChatStoreError("site_limit")
        db.execute(
            "INSERT INTO chat_sites (id, display_name, origins_json, specialist, greeting, "
            "daily_cap_dollars, messages_per_session, messages_per_minute, messages_per_client_per_day, "
            "retention_days, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
            (site_id, fields["display_name"], json.dumps(origins), fields["specialist"],
             fields["greeting"], fields["daily_cap_dollars"], fields["messages_per_session"],
             fields["messages_per_minute"], fields["messages_per_client_per_day"],
             fields["retention_days"], now, now),
        )
    key = new_key()
    try:
        with _write(index_path(), _INDEX_SCHEMA) as index:
            for origin in origins:
                index.execute("INSERT INTO chat_origins (origin, tenant_id, site_id) VALUES (?, ?, ?)",
                              (origin, _tenant_key(tenant), site_id))
            index.execute("INSERT INTO chat_keys (key_sha256, tenant_id, site_id, created_at) "
                          "VALUES (?, ?, ?, ?)", (digest(key), _tenant_key(tenant), site_id, now))
    except Exception as exc:
        # Any failed index write removes the site row again, so no site is left without its key.
        with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
            db.execute("DELETE FROM chat_sites WHERE id = ?", (site_id,))
        if isinstance(exc, sqlite3.IntegrityError):
            raise ChatStoreError("origin_in_use") from exc
        raise
    return get_site(tenant, site_id) or {}, key


def get_site(tenant: str | None, site_id: str) -> dict[str, Any] | None:
    with _connect(sites_path(tenant), _TENANT_SCHEMA) as db:
        row = db.execute("SELECT * FROM chat_sites WHERE id = ?", (site_id,)).fetchone()
    return _site(row) if row is not None else None


def active_site(tenant: str | None, site_id: str) -> dict[str, Any] | None:
    site = get_site(tenant, site_id)
    return site if site is not None and site["state"] == "active" else None


def list_sites(tenant: str | None) -> list[dict[str, Any]]:
    with _connect(sites_path(tenant), _TENANT_SCHEMA) as db:
        rows = db.execute("SELECT * FROM chat_sites ORDER BY created_at DESC, id LIMIT 200").fetchall()
    return [_site(row) for row in rows]


def rotate_key(tenant: str | None, site_id: str, *, now: float) -> str:
    """Issue a new key, revoke the old ones and end the site's visitor sessions."""
    key = new_key()
    with _write(index_path(), _INDEX_SCHEMA) as index:
        index.execute("UPDATE chat_keys SET revoked_at = ? WHERE site_id = ? AND revoked_at IS NULL",
                      (now, site_id))
        index.execute("INSERT INTO chat_keys (key_sha256, tenant_id, site_id, created_at) "
                      "VALUES (?, ?, ?, ?)", (digest(key), _tenant_key(tenant), site_id, now))
        index.execute("DELETE FROM chat_sessions WHERE site_id = ?", (site_id,))
    return key


def revoke_site(tenant: str | None, site_id: str, *, now: float) -> None:
    """Stop the site: its keys, origins and visitor sessions end at once."""
    with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
        changed = db.execute(
            "UPDATE chat_sites SET state = 'revoked', updated_at = ? WHERE id = ? AND state = 'active'",
            (now, site_id)).rowcount
    if changed != 1:
        raise ChatStoreError("not_found")
    with _write(index_path(), _INDEX_SCHEMA) as index:
        index.execute("UPDATE chat_keys SET revoked_at = ? WHERE site_id = ? AND revoked_at IS NULL",
                      (now, site_id))
        index.execute("DELETE FROM chat_origins WHERE site_id = ?", (site_id,))
        index.execute("DELETE FROM chat_sessions WHERE site_id = ?", (site_id,))
    # A stopped chat keeps no visitor text: its transcripts go with it, not at retention.
    with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
        db.execute("DELETE FROM chat_transcripts WHERE site_id = ?", (site_id,))


def site_for_key(key: str) -> tuple[str | None, str] | None:
    """The (tenant, site) a live publishable key belongs to, or None."""
    with _connect(index_path(), _INDEX_SCHEMA) as index:
        row = index.execute("SELECT tenant_id, site_id, revoked_at FROM chat_keys WHERE key_sha256 = ?",
                            (digest(key),)).fetchone()
    if row is None or row["revoked_at"] is not None:
        return None
    return (row["tenant_id"] or None), row["site_id"]


def site_for_origin(origin: str) -> tuple[str | None, str] | None:
    with _connect(index_path(), _INDEX_SCHEMA) as index:
        row = index.execute("SELECT tenant_id, site_id FROM chat_origins WHERE origin = ?",
                            (origin,)).fetchone()
    return None if row is None else ((row["tenant_id"] or None), row["site_id"])


def issue_session(tenant: str | None, site_id: str, origin: str, *, now: float) -> tuple[str, float, str]:
    """A visitor session bound to one site origin. Only its digest is stored."""
    token = new_session_token()
    conversation_id = secrets.token_hex(16)
    expires_at = now + SESSION_TTL_SECONDS
    with _write(index_path(), _INDEX_SCHEMA) as index:
        index.execute("DELETE FROM chat_sessions WHERE expires_at <= ?", (now,))
        live = index.execute("SELECT COUNT(*) FROM chat_sessions WHERE site_id = ?",
                             (site_id,)).fetchone()[0]
        if int(live) >= MAX_LIVE_SESSIONS_PER_SITE:
            raise ChatStoreError("capacity")
        index.execute(
            "INSERT INTO chat_sessions (token_sha256, tenant_id, site_id, origin, conversation_id, "
            "issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (digest(token), _tenant_key(tenant), site_id, origin, conversation_id, now, expires_at),
        )
    return token, expires_at, conversation_id


def session_row(token: str, *, now: float) -> dict[str, Any] | None:
    with _connect(index_path(), _INDEX_SCHEMA) as index:
        row = index.execute("SELECT * FROM chat_sessions WHERE token_sha256 = ?",
                            (digest(token),)).fetchone()
    if row is None or row["expires_at"] <= now:
        return None
    return dict(row)


def reserve_message(token: str, *, now: float, per_session: int, per_minute: int) -> int:
    """Count one visitor message against its session, or refuse without counting it.

    The per-minute limit is a sliding window: at most ``per_minute`` messages in
    any 60 seconds, from the times of the session's recent messages.
    """
    with _write(index_path(), _INDEX_SCHEMA) as index:
        row = index.execute("SELECT * FROM chat_sessions WHERE token_sha256 = ?",
                            (digest(token),)).fetchone()
        if row is None or row["expires_at"] <= now:
            raise ChatStoreError("session")
        recent = [float(at) for at in json.loads(row["recent_json"])
                  if now - float(at) < _MINUTE_SECONDS]
        if int(row["message_count"]) >= per_session:
            raise ChatStoreError("session_limit")
        if len(recent) >= per_minute:
            raise ChatStoreError("minute_limit")
        recent.append(now)
        index.execute(
            "UPDATE chat_sessions SET message_count = message_count + 1, recent_json = ? "
            "WHERE token_sha256 = ?",
            (json.dumps(recent), digest(token)),
        )
        return per_session - int(row["message_count"]) - 1


def _day(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")


def spent_today(tenant: str | None, site_id: str, *, now: float) -> float:
    with _connect(sites_path(tenant), _TENANT_SCHEMA) as db:
        row = db.execute("SELECT dollars FROM chat_spend WHERE site_id = ? AND day = ?",
                         (site_id, _day(now))).fetchone()
    return float(row[0]) if row is not None else 0.0


def reserve_spend(tenant: str | None, site_id: str, *, cap: float, amount: float, now: float) -> str | None:
    """Hold ``amount`` of today's cap before a call. Returns the day, or None if it does not fit."""
    day = _day(now)
    with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
        row = db.execute("SELECT dollars FROM chat_spend WHERE site_id = ? AND day = ?",
                         (site_id, day)).fetchone()
        spent = float(row[0]) if row is not None else 0.0
        if spent + amount > cap + 1e-9:
            return None
        db.execute(
            "INSERT INTO chat_spend (site_id, day, dollars) VALUES (?, ?, ?) "
            "ON CONFLICT (site_id, day) DO UPDATE SET dollars = chat_spend.dollars + excluded.dollars",
            (site_id, day, amount),
        )
    return day


def settle_spend(tenant: str | None, site_id: str, day: str, *, reserved: float, actual: float) -> None:
    """Replace the hold with what the call really cost (the full hold when unknown)."""
    delta = max(0.0, actual) - reserved
    with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
        db.execute("UPDATE chat_spend SET dollars = MAX(0, dollars + ?) WHERE site_id = ? AND day = ?",
                   (delta, site_id, day))


def append_transcript(tenant: str | None, site: dict[str, Any], conversation_id: str, role: str,
                      text: str, *, now: float) -> None:
    row_id = uuid.uuid4().hex
    with tenant_scope(tenant=tenant):
        sealed = base64.b64encode(seal_bound(
            text.encode("utf-8"), _context(site["id"], conversation_id, role, row_id))).decode("ascii")
    with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
        _purge(db, site["id"], now, site["retention_days"])
        db.execute(
            "INSERT INTO chat_transcripts (id, site_id, conversation_id, role, sealed, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (row_id, site["id"], conversation_id, role, sealed, now),
        )


def purge_expired(*, now: float) -> list[str]:
    """Remove transcripts past their site's retention in every tenant that ever listed a site.

    Rows whose site no longer exists are removed too. Each tenant is handled on
    its own: a tenant whose file cannot be read or written is logged and skipped,
    and the others are still swept. Returns the tenants that failed, so the next
    sweep, which covers every tenant again, tries them again. No site state or key
    material is read. An installation that never used the chat has no index, so
    nothing is created for it here.
    """
    if not index_path().exists():
        return []
    with _connect(index_path(), _INDEX_SCHEMA) as index:
        tenants = [row[0] or None for row in index.execute(
            "SELECT DISTINCT tenant_id FROM chat_keys").fetchall()]
    failed: list[str] = []
    for tenant in tenants:
        try:
            with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
                db.execute("DELETE FROM chat_transcripts WHERE site_id NOT IN (SELECT id FROM chat_sites)")
                db.execute(
                    "DELETE FROM chat_transcripts WHERE created_at < ? - ? * "
                    "(SELECT retention_days FROM chat_sites WHERE chat_sites.id = chat_transcripts.site_id)",
                    (now, float(_DAY_SECONDS)),
                )
        except Exception as exc:  # one workspace's broken file must not stop the others
            logger.warning("public chat retention sweep failed for workspace %s (%s)",
                           tenant or "<shared>", type(exc).__name__)
            failed.append(_tenant_key(tenant))
    return failed


def purge_expired_if_due(*, now: float) -> list[str]:
    """Run ``purge_expired`` at most once per ``_SWEEP_SECONDS`` of the injected clock.

    Returns the workspaces that failed in that run, or none when the sweep was not due.
    """
    global _last_sweep
    with _sweep_lock:
        if _last_sweep is not None and 0 <= now - _last_sweep < _SWEEP_SECONDS:
            return []
        _last_sweep = now
    return purge_expired(now=now)


def read_transcripts(tenant: str | None, site: dict[str, Any], *, now: float, limit: int) -> list[dict[str, Any]]:
    """Decrypted transcript rows, oldest first, after removing anything past retention."""
    with _write(sites_path(tenant), _TENANT_SCHEMA) as db:
        _purge(db, site["id"], now, site["retention_days"])
        rows = db.execute(
            "SELECT * FROM chat_transcripts WHERE site_id = ? ORDER BY seq DESC LIMIT ?",
            (site["id"], limit),
        ).fetchall()
    out: list[dict[str, Any]] = []
    with tenant_scope(tenant=tenant):
        for row in reversed(rows):
            text = unseal_bound(base64.b64decode(row["sealed"], validate=True),
                                _context(site["id"], row["conversation_id"], row["role"], row["id"]))
            out.append({"conversation_id": row["conversation_id"], "role": row["role"],
                        "text": text.decode("utf-8"), "created_at": row["created_at"]})
    return out
