"""Server-side record of browser sign-in sessions.

The ``mvk_session`` cookie is a signed, self-contained token (sub, iat, exp).
That is enough to authenticate, but not to *list* a person's sessions or end
one device without ending them all (the revocation epoch in
:mod:`session_revocation` is per person). Every cookie minted by the OIDC
callback, the SAML ACS, the invitation flow and the owner sign-in now also
carries an opaque session id (``sid``) and is recorded here with who signed
in, how, whether a second factor was proved, when it was issued, when it was
last seen, the client address and a short user-agent summary.

Store: ``<maverick_home>/dashboard-sessions.sqlite3`` (0600), stdlib sqlite3.
Rows are kept ``[auth.sessions] retention_days`` (default 30) past their
expiry, then pruned.

Fail closed: a cookie whose ``sid`` is unknown, revoked, or unreadable here is
not a session. A cookie without a ``sid`` was minted before this record
existed; it is accepted until it expires (at most the sign-in lifetime),
shows on no list, and still ends with "Sign out everywhere".
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from maverick.paths import maverick_home

_LOCK = threading.Lock()
_TOUCH_INTERVAL_SECONDS = 60
_TOUCHED: dict[str, float] = {}  # sid -> last refresh this process wrote
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    via TEXT NOT NULL,
    mfa INTEGER NOT NULL DEFAULT 0,
    mfa_at REAL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    revoked_at REAL,
    revoked_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_principal ON sessions (principal);
"""


class SessionStoreError(RuntimeError):
    """The session record cannot be read or written; callers fail closed."""


@dataclass(frozen=True)
class SessionRecord:
    sid: str
    principal: str
    via: str
    mfa: bool
    mfa_at: float | None
    issued_at: float
    expires_at: float
    last_seen: float
    ip: str
    user_agent: str
    revoked_at: float | None
    revoked_by: str

    @property
    def active(self) -> bool:
        return self.revoked_at is None and self.effective_end > time.time()

    @property
    def effective_end(self) -> float:
        from .session_policy import effective_end

        try:
            return effective_end(expires_at=self.expires_at, issued_at=self.issued_at,
                                 last_seen=self.last_seen, via=self.via)
        except (TypeError, ValueError, OSError) as exc:
            raise SessionStoreError("Sign-in limits cannot be read.") from exc

    def as_dict(self) -> dict:
        data = asdict(self)
        data["original_expires_at"] = self.expires_at
        data["expires_at"] = self.effective_end
        data["active"] = self.active
        return data


def new_sid() -> str:
    return secrets.token_urlsafe(24)


def _path() -> Path:
    return maverick_home() / "dashboard-sessions.sqlite3"


# The store connection is kept open between calls, under _LOCK, and reopened
# whenever the file it was opened on is no longer there (replaced, removed, or
# this is a forked child). Every read still goes to the database.
#
# On Windows a file open in one process cannot be removed or replaced by
# another: Python and SQLite do not request FILE_SHARE_DELETE (see file_lock).
# There the connection is closed after each call, as it always was, so an
# operator can still remove or swap the store file between requests.
_KEEP_OPEN = os.name != "nt"
_SHARED: dict = {"key": None, "conn": None}


def _file_key(path: Path) -> tuple | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (str(path), info.st_dev, info.st_ino, os.getpid())


def _drop_shared() -> None:
    conn, _SHARED["conn"], _SHARED["key"] = _SHARED["conn"], None, None
    if conn is not None:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def _open_store(path: Path) -> sqlite3.Connection:
    key = _file_key(path)
    if _SHARED["conn"] is not None and key is not None and key == _SHARED["key"]:
        return _SHARED["conn"]
    _drop_shared()
    # Shared across request threads; every use happens under _LOCK.
    conn = sqlite3.connect(str(path), timeout=5.0, check_same_thread=False)
    try:
        conn.executescript(_SCHEMA)
    except BaseException:
        conn.close()
        raise
    _SHARED["conn"], _SHARED["key"] = conn, _file_key(path)
    return conn


@contextmanager
def _connect():
    from maverick.file_lock import ensure_private_directory, ensure_private_file

    path = _path()
    try:
        ensure_private_directory(path.parent)
        with _LOCK:
            conn = _open_store(path)
            ensure_private_file(path)
            try:
                yield conn
            except BaseException:
                conn.rollback()
                raise
            else:
                conn.commit()
            finally:
                if not _KEEP_OPEN:
                    _drop_shared()
    except (OSError, sqlite3.Error) as exc:
        if isinstance(exc, sqlite3.Error):
            _drop_shared()
        raise SessionStoreError(f"session record unavailable: {exc}") from exc


def user_agent_summary(user_agent: str | None) -> str:
    """A short, plain description of the browser and system, never the raw
    header (it is long and can carry tracking detail)."""
    ua = str(user_agent or "")
    browser = "Browser"
    for needle, name in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                         ("Chrome/", "Chrome"), ("Safari/", "Safari"), ("curl/", "curl"),
                         ("python-httpx", "Program"), ("python-requests", "Program"),
                         ("testclient", "Test client")):
        if needle in ua:
            browser = name
            break
    system = ""
    for needle, name in (("Windows", "Windows"), ("Android", "Android"),
                         ("iPhone", "iPhone"), ("iPad", "iPad"), ("Mac OS", "Mac"),
                         ("CrOS", "ChromeOS"), ("Linux", "Linux")):
        if needle in ua:
            system = name
            break
    if not ua:
        return "Unknown device"
    return f"{browser} on {system}" if system else browser


def register(*, sid: str, principal: str, via: str, mfa: bool, mfa_at: float | None,
             issued_at: float, expires_at: float, ip: str, user_agent: str) -> None:
    """Record a freshly minted session (raises :class:`SessionStoreError`)."""
    if not sid or not principal:
        raise ValueError("session id and principal are required")
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (sid, principal, via, mfa, mfa_at, issued_at, "
            "expires_at, last_seen, ip, user_agent) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sid, principal, via, 1 if mfa else 0, mfa_at, float(issued_at),
             float(expires_at), float(issued_at), str(ip or ""),
             user_agent_summary(user_agent)),
        )
        _prune(conn)


def status(sid: str) -> bool | None:
    """``True`` active, ``False`` revoked or expired, ``None`` unknown."""
    if not sid:
        return None
    record = get(sid)
    return record.active if record else None


def touch(sid: str, *, ip: str = "", user_agent: str = "", activity: bool = False) -> None:
    """Refresh last-seen (at most once a minute per session; never raises)."""
    if not sid:
        return
    from .session_policy import idle_minutes

    try:
        idle = idle_minutes()
    except (TypeError, ValueError, OSError):
        return
    if idle and not activity:
        return  # Background requests never extend the inactivity limit.
    now = time.time()
    interval = min(_TOUCH_INTERVAL_SECONDS, idle * 15) if idle else _TOUCH_INTERVAL_SECONDS
    last = _TOUCHED.get(sid)
    if last is not None and now - last < interval:
        return  # This process wrote a refresh inside the window: the UPDATE would match nothing.
    summary = user_agent_summary(user_agent) if user_agent else ""
    try:
        with _connect() as conn:
            if idle or activity:
                rows = _rows(conn, "WHERE sid = ?", (sid,))
                if not rows or not rows[0].active:
                    return  # A late heartbeat cannot revive an ended session.
            written = conn.execute(
                "UPDATE sessions SET last_seen = ?, ip = COALESCE(NULLIF(?, ''), ip), "
                "user_agent = CASE WHEN ? = '' THEN user_agent ELSE ? END "
                "WHERE sid = ? AND last_seen < ?",
                (now, str(ip or ""), summary, summary, sid, now - interval),
            ).rowcount
    except SessionStoreError:
        return
    if written != 1:
        # Refreshed recently by another process (or gone): its time is unknown
        # here, so the next touch asks the store again, as before.
        return
    if len(_TOUCHED) > 4096:
        _TOUCHED.clear()
    _TOUCHED[sid] = now


def _rows(conn, where: str, params: tuple) -> list[SessionRecord]:
    cur = conn.execute(
        "SELECT sid, principal, via, mfa, mfa_at, issued_at, expires_at, last_seen, ip, "
        f"user_agent, revoked_at, revoked_by FROM sessions {where} "
        "ORDER BY last_seen DESC", params)
    return [SessionRecord(sid=r[0], principal=r[1], via=r[2], mfa=bool(r[3]), mfa_at=r[4],
                          issued_at=r[5], expires_at=r[6], last_seen=r[7], ip=r[8],
                          user_agent=r[9], revoked_at=r[10], revoked_by=r[11])
            for r in cur.fetchall()]


def list_for(principal: str, *, include_ended: bool = False) -> list[SessionRecord]:
    with _connect() as conn:
        rows = _rows(conn, "WHERE principal = ?", (str(principal or ""),))
    return rows if include_ended else [r for r in rows if r.active]


def list_all(*, include_ended: bool = False) -> list[SessionRecord]:
    with _connect() as conn:
        rows = _rows(conn, "", ())
    return rows if include_ended else [r for r in rows if r.active]


def get(sid: str) -> SessionRecord | None:
    with _connect() as conn:
        rows = _rows(conn, "WHERE sid = ?", (sid,))
    return rows[0] if rows else None


def current(sid: str, *, principal: str) -> SessionRecord | None:
    """Read current own authority and retain an observed time-limit expiry."""
    with _connect() as conn:
        rows = _rows(conn, "WHERE sid = ? AND principal = ?", (sid, principal))
        if not rows:
            return None
        record = rows[0]
        if record.active:
            return record
        if record.revoked_at is None:
            conn.execute(
                "UPDATE sessions SET revoked_at = ?, revoked_by = 'sign-in time limit' "
                "WHERE sid = ? AND revoked_at IS NULL", (time.time(), sid),
            )
        return None


def revoke(sid: str, *, by: str) -> SessionRecord | None:
    """End one session. Returns the record, or ``None`` when unknown."""
    with _connect() as conn:
        rows = _rows(conn, "WHERE sid = ?", (sid,))
        if not rows:
            return None
        conn.execute(
            "UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?), revoked_by = ? "
            "WHERE sid = ?", (time.time(), str(by or ""), sid))
        return _rows(conn, "WHERE sid = ?", (sid,))[0]


def revoke_all(principal: str, *, by: str, keep_sid: str | None = None) -> int:
    """End every active session of ``principal`` (optionally keeping one).
    Returns how many were ended."""
    now = time.time()
    with _connect() as conn:
        active = [r for r in _rows(conn, "WHERE principal = ?", (str(principal or ""),))
                  if r.active and r.sid != keep_sid]
        for record in active:
            conn.execute(
                "UPDATE sessions SET revoked_at = ?, revoked_by = ? WHERE sid = ?",
                (now, str(by or ""), record.sid))
    return len(active)


def _retention_seconds() -> float:
    try:
        from maverick.config import get_auth_sessions

        return float(get_auth_sessions()["retention_days"]) * 86400.0
    except Exception:
        return 30 * 86400.0


def _prune(conn) -> None:
    cutoff = time.time() - _retention_seconds()
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (cutoff,))


__all__ = [
    "SessionRecord",
    "SessionStoreError",
    "get",
    "list_all",
    "list_for",
    "new_sid",
    "register",
    "revoke",
    "revoke_all",
    "status",
    "touch",
    "user_agent_summary",
]
