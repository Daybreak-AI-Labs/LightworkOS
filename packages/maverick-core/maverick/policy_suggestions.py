"""Suggested edits to policy documents, accepted or rejected by a person (NOT-4).

An AI assistant, an agent or a colleague proposes a change to one part of a
policy document (its title, its description or the wording of one rule). The
proposal is kept here as a suggestion: the part it changes, the text before
and after, who or what proposed it (and which model, for the AI assistant)
and why. A suggestion never changes the document. A person accepts it, which
the dashboard applies through the document's own save path and permission
check, or rejects it; either decision is recorded with an optional reason.

Documents: ``ai-policy`` (AI use rules), ``data-use-rule`` and
``privacy-notice``; the dashboard saves an accepted one through each
document's own flow (``maverick_dashboard.suggestion_documents``).
The store is one small SQLite file per workspace; reads never create it.

Settings: ``[collaboration] suggestions`` (on by default) and
``[collaboration] ai_suggestions`` (on by default; the AI assistant drafts a
suggestion only when a person asks, within the task spending caps).
"""
from __future__ import annotations

import difflib
import re
import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from typing import Any

KINDS = ("ai-policy", "data-use-rule", "privacy-notice")
PROPOSER_KINDS = ("ai", "agent", "person")
STATES = ("open", "accepted", "rejected")
MAX_TEXT = 20000
MAX_REASON = 1000
_DOCUMENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_FIELD = re.compile(r"(?:title|description|document|jurisdictions|locales|statement:[A-Za-z0-9][A-Za-z0-9_.:-]{0,127})\Z")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS suggestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    document_id TEXT NOT NULL,
    field TEXT NOT NULL,
    base_version INTEGER NOT NULL,
    before TEXT NOT NULL,
    after TEXT NOT NULL,
    proposer TEXT NOT NULL,
    proposer_kind TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    decided_by TEXT NOT NULL DEFAULT '',
    decided_at REAL,
    decision_reason TEXT NOT NULL DEFAULT '',
    applied_version INTEGER
);
CREATE INDEX IF NOT EXISTS suggestions_document ON suggestions (kind, document_id, state, id);
"""


class SuggestionError(ValueError):
    """A suggestion the store refuses, with a plain sentence for the page."""


def _section() -> Mapping[str, Any]:
    from .config import load_config

    section = load_config().get("collaboration") or {}
    return section if isinstance(section, Mapping) else {}


def enabled() -> bool:
    """Suggested edits are on unless ``[collaboration] suggestions = false``."""
    return _section().get("suggestions", True) is not False


def ai_enabled() -> bool:
    """The AI assistant may draft suggestions unless ``ai_suggestions = false``."""
    return enabled() and _section().get("ai_suggestions", True) is not False


def _path():
    from .paths import data_dir

    return data_dir("collaboration", "policy_suggestions.sqlite3")


def _exists() -> bool:
    return _path().is_file()


def _connect() -> sqlite3.Connection:
    from .file_lock import ensure_private_directory

    path = _path()
    ensure_private_directory(path.parent)
    connection = sqlite3.connect(str(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.executescript(_SCHEMA)
    return connection


def diff(before: str, after: str) -> list[dict]:
    """Word-level changes: ``[{"op": "same"|"del"|"ins", "text": ...}]``.

    Changes separated only by spaces read as one change ("hide part of each
    value" becomes "block it"), not as word-by-word swaps.
    """
    old, new = re.findall(r"\S+|\s+", before), re.findall(r"\S+|\s+", after)
    opcodes = difflib.SequenceMatcher(a=old, b=new, autojunk=False).get_opcodes()
    out: list[dict] = []
    removed: list[str] = []
    added: list[str] = []

    def flush() -> None:
        for op, words in (("del", removed), ("ins", added)):
            text = "".join(words).strip()
            if text:
                out.append({"op": op, "text": text})
        removed.clear()
        added.clear()

    for index, (tag, i1, i2, j1, j2) in enumerate(opcodes):
        words = old[i1:i2]
        between = (tag == "equal" and (removed or added) and index + 1 < len(opcodes)
                   and not "".join(words).strip())
        if tag != "equal" or between:
            removed.extend(words)
            added.extend(new[j1:j2])
            continue
        flush()
        out.append({"op": "same", "text": "".join(words)})
    flush()
    return out


def _row(row: sqlite3.Row) -> dict:
    value = {key: row[key] for key in row.keys()}
    value["diff"] = diff(value["before"], value["after"])
    return value


def _text(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        raise SuggestionError(f"Keep the {label} under {limit:,} characters.")
    return text


def propose(kind: str, document_id: str, *, field: str, before: str, after: str, base_version: int,
            proposer: str, proposer_kind: str, reason: str = "", model: str = "") -> dict:
    """Keep one suggested change. Nothing in the document changes."""
    if kind not in KINDS:
        raise SuggestionError("Suggestions work on AI use rules, data use rules and privacy notices.")
    if not _DOCUMENT_ID.fullmatch(str(document_id or "")):
        raise SuggestionError("Choose the rules to suggest a change to.")
    if not _FIELD.fullmatch(str(field or "")):
        raise SuggestionError("Choose the part of the document to change.")
    if proposer_kind not in PROPOSER_KINDS or not str(proposer or "").strip():
        raise SuggestionError("A suggestion needs to say who or what proposed it.")
    old = _text(before, "current text", MAX_TEXT)
    new = _text(after, "suggested text", MAX_TEXT)
    if not new:
        raise SuggestionError("Write the suggested wording.")
    if new == old:
        raise SuggestionError("This suggestion does not change the wording.")
    why = _text(reason, "reason", MAX_REASON)
    with closing(_connect()) as db, db:
        cursor = db.execute(
            "INSERT INTO suggestions (kind, document_id, field, base_version, before, after, proposer,"
            " proposer_kind, model, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (kind, document_id, field, int(base_version), old, new, str(proposer)[:256], proposer_kind,
             str(model or "")[:128], why, time.time()))
        row = db.execute("SELECT * FROM suggestions WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row(row)


def list_for(kind: str, document_id: str | None = None, *, states: tuple[str, ...] = ("open",),
             limit: int = 200) -> list[dict]:
    """Suggestions on one document (or every document of ``kind``), oldest first."""
    if not _exists():
        return []
    marks = ",".join("?" for _ in states)
    sql = f"SELECT * FROM suggestions WHERE kind = ? AND state IN ({marks})"  # noqa: S608 -- placeholders only
    args: list[Any] = [kind, *states]
    if document_id is not None:
        sql += " AND document_id = ?"
        args.append(document_id)
    with closing(_connect()) as db:
        rows = db.execute(sql + " ORDER BY id LIMIT ?", (*args, int(limit))).fetchall()
    return [_row(row) for row in rows]


def get(suggestion_id: int) -> dict | None:
    if not _exists():
        return None
    with closing(_connect()) as db:
        row = db.execute("SELECT * FROM suggestions WHERE id = ?", (int(suggestion_id),)).fetchone()
    return _row(row) if row else None


def decide(suggestion_id: int, *, accepted: bool, by: str, reason: str = "",
           applied_version: int | None = None) -> dict | None:
    """Record the decision once; None when it was already decided."""
    why = _text(reason, "reason", MAX_REASON)
    with closing(_connect()) as db, db:
        changed = db.execute(
            "UPDATE suggestions SET state = ?, decided_by = ?, decided_at = ?, decision_reason = ?,"
            " applied_version = ? WHERE id = ? AND state = 'open'",
            ("accepted" if accepted else "rejected", str(by)[:256], time.time(), why,
             applied_version, int(suggestion_id))).rowcount
        row = db.execute("SELECT * FROM suggestions WHERE id = ?", (int(suggestion_id),)).fetchone()
    return _row(row) if changed and row else None


def count_by(principal: str) -> int:
    """Suggestions a person proposed plus decisions they made (personal data)."""
    if not _exists():
        return 0
    with closing(_connect()) as db:
        return int(db.execute("SELECT COUNT(*) FROM suggestions WHERE proposer = ? OR decided_by = ?",
                              (str(principal), str(principal))).fetchone()[0])


def erase_person(principal: str) -> int:
    """Delete a person's suggestions and remove their name and note from decisions.

    The decision itself stays (the rules' history depends on it), and the
    activity record keeps its own entry under its own retention.
    """
    if not _exists():
        return 0
    who = str(principal)
    with closing(_connect()) as db, db:
        removed = db.execute("DELETE FROM suggestions WHERE proposer = ?", (who,)).rowcount
        cleared = db.execute("UPDATE suggestions SET decided_by = '', decision_reason = '' WHERE decided_by = ?",
                             (who,)).rowcount
    return removed + cleared
