"""Comments and @mentions on tasks, runs, approvals and policies (NOT-4).

People discuss a piece of work where it lives, the way they would review a
colleague's work: a comment thread on the task, the workflow run, the
approval request or the policy page, and an @mention that reaches the person
through their own personal notifications.

This module only stores the thread. Who may read or write a thread, and who
may be mentioned in it, is decided by the dashboard against the object's own
access rules, at write time and again before a mention is shown. The store is
one small SQLite file per workspace; deleting a comment hides it at once and
keeps a tombstone so a notification about it is withdrawn too.

Turned on with ``[collaboration] comments`` (on by default).
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import closing

KINDS = ("task", "run", "approval", "policy")
MAX_BODY = 4000
MAX_MENTIONS = 20
_OBJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    mentions TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL,
    deleted_at REAL
);
CREATE INDEX IF NOT EXISTS comments_object ON comments (kind, object_id, id);
"""


class CommentError(ValueError):
    """A comment the store refuses, with a plain sentence for the page."""


def enabled() -> bool:
    """Comments are on unless ``[collaboration] comments = false``."""
    from .config import load_config

    section = load_config().get("collaboration") or {}
    return section.get("comments", True) is not False


def _path():
    from .paths import data_dir

    return data_dir("collaboration", "comments.sqlite3")


def _exists() -> bool:
    """Reads never create the store: no file means no comments yet."""
    return _path().is_file()


def _connect() -> sqlite3.Connection:
    from .file_lock import ensure_private_directory

    path = _path()
    ensure_private_directory(path.parent)
    connection = sqlite3.connect(str(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.executescript(_SCHEMA)
    return connection


def _row(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "kind": row["kind"], "object_id": row["object_id"],
            "author": row["author"], "body": row["body"],
            "mentions": json.loads(row["mentions"] or "[]"), "created_at": row["created_at"]}


def _check_object(kind: str, object_id: str) -> str:
    if kind not in KINDS:
        raise CommentError("Comments work on tasks, runs, approvals and policies.")
    object_id = str(object_id or "")
    if not _OBJECT_ID.fullmatch(object_id):
        raise CommentError("That item can't take comments.")
    return object_id


def add(kind: str, object_id: str, *, author: str, body: str, mentions: list[str] | tuple = ()) -> dict:
    """Save one comment; ``mentions`` are already checked by the caller."""
    object_id = _check_object(kind, object_id)
    text = str(body or "").strip()
    if not text:
        raise CommentError("Write a comment before posting it.")
    if len(text) > MAX_BODY:
        raise CommentError(f"Keep a comment under {MAX_BODY:,} characters.")
    if not isinstance(author, str) or not author.startswith("user:"):
        raise CommentError("Sign in with your own account to comment.")
    named = list(dict.fromkeys(str(m) for m in mentions if str(m).startswith("user:") and m != author))
    if len(named) > MAX_MENTIONS:
        raise CommentError(f"Mention up to {MAX_MENTIONS} people in one comment.")
    with closing(_connect()) as db, db:
        cursor = db.execute(
            "INSERT INTO comments (kind, object_id, author, body, mentions, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (kind, object_id, author, text, json.dumps(named), time.time()))
        row = db.execute("SELECT * FROM comments WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row(row)


def list_for(kind: str, object_id: str, *, limit: int = 200) -> list[dict]:
    """The thread on one object: its newest ``limit`` comments, oldest first,
    without deleted ones (a long thread keeps showing what was just said)."""
    object_id = _check_object(kind, object_id)
    if not _exists():
        return []
    with closing(_connect()) as db:
        rows = db.execute(
            "SELECT * FROM (SELECT * FROM comments WHERE kind = ? AND object_id = ? AND deleted_at IS NULL"
            " ORDER BY id DESC LIMIT ?) ORDER BY id",
            (kind, object_id, int(limit))).fetchall()
    return [_row(row) for row in rows]


def get(comment_id: int) -> dict | None:
    if not _exists():
        return None
    with closing(_connect()) as db:
        row = db.execute("SELECT * FROM comments WHERE id = ? AND deleted_at IS NULL",
                         (int(comment_id),)).fetchone()
    return _row(row) if row else None


def remove(comment_id: int, *, by: str) -> bool:
    """Delete a comment. Only its author can; the thread and mentions drop it."""
    with closing(_connect()) as db, db:
        changed = db.execute(
            "UPDATE comments SET deleted_at = ? WHERE id = ? AND author = ? AND deleted_at IS NULL",
            (time.time(), int(comment_id), str(by))).rowcount
    return bool(changed)


def mentions_for(principal: str, *, since: float, limit: int = 100) -> list[dict]:
    """Comments that mention ``principal`` since ``since``, newest first."""
    if not _exists():
        return []
    needle = json.dumps(str(principal))
    with closing(_connect()) as db:
        rows = db.execute(
            "SELECT * FROM comments WHERE deleted_at IS NULL AND created_at >= ? AND author != ?"
            " AND instr(mentions, ?) > 0 ORDER BY id DESC LIMIT ?",
            (float(since), str(principal), needle, int(limit))).fetchall()
    return [row for row in (_row(r) for r in rows) if principal in row["mentions"]]


def count_by(principal: str) -> int:
    """How many comments a person wrote (for their personal data request)."""
    if not _exists():
        return 0
    with closing(_connect()) as db:
        return int(db.execute("SELECT COUNT(*) FROM comments WHERE author = ?", (str(principal),)).fetchone()[0])


def erase_person(principal: str) -> int:
    """Erase a person's comments (their personal data request)."""
    if not _exists():
        return 0
    with closing(_connect()) as db, db:
        return db.execute("DELETE FROM comments WHERE author = ?", (str(principal),)).rowcount
