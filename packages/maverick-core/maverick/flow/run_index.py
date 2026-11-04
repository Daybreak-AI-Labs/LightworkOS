"""Rebuildable private metadata index; checkpoint JSON remains authoritative.

A committed dirty intent precedes each JSON mutation. Even a process crash
between the two stores leaves enough information to repair exactly that row.
Readers never hold this lock while acquiring an execution/checkpoint lock.
"""
from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from itertools import islice
from pathlib import Path

from ..file_lock import (
    atomic_create_bytes,
    atomic_read_text,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .payloads import FlowPayloadError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dirty (run_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS runs (
 run_id TEXT PRIMARY KEY, flow_id TEXT NOT NULL, owner TEXT NOT NULL,
 status TEXT NOT NULL, updated REAL NOT NULL, resume_at REAL,
 idem_key TEXT NOT NULL, release_id TEXT NOT NULL,
 stamp TEXT NOT NULL, metadata TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_updated ON runs(updated DESC, run_id DESC);
CREATE INDEX IF NOT EXISTS runs_owner ON runs(owner, updated DESC, run_id DESC);
CREATE INDEX IF NOT EXISTS runs_flow ON runs(flow_id, updated DESC, run_id DESC);
CREATE INDEX IF NOT EXISTS runs_active ON runs(flow_id, status);
CREATE INDEX IF NOT EXISTS runs_due ON runs(status, resume_at, run_id);
CREATE INDEX IF NOT EXISTS runs_idem ON runs(flow_id, idem_key, owner, release_id);
CREATE INDEX IF NOT EXISTS runs_release ON runs(flow_id, owner, release_id, updated DESC, run_id DESC);
"""


def _stamp(path: Path) -> str:
    try:
        stat = path.stat()
        return f"{stat.st_mtime_ns}:{stat.st_size}:{stat.st_ino}"
    except FileNotFoundError:
        return ""


def _path(root: Path, run_id: str) -> Path:
    from .store import _safe_id

    return root / (_safe_id(run_id) + ".json")


def _sync_row(c, root: Path, run_id: str, *, row=None) -> None:
    path = _path(root, run_id)
    try:
        if row is None:
            row = json.loads(atomic_read_text(path))
        if not isinstance(row, dict) or row.get("run_id") != run_id:
            raise ValueError("invalid checkpoint identity")
        # Result bodies belong to detail/execute calls, not history or admission.
        row.pop("data_state", None)
        row["data"] = {}
        row["input_data"] = {}
        values = (run_id, str(row["flow_id"]), str(row.get("owner", "")),
                  str(row["status"]), float(row.get("updated", 0)), row.get("resume_at"),
                  str(row.get("idem_key", "")), str(row.get("release_id", "")),
                  _stamp(path), json.dumps(row, sort_keys=True))
    except FileNotFoundError:
        c.execute("DELETE FROM runs WHERE run_id=?", (run_id,))
        return
    except (ValueError, TypeError, KeyError) as exc:
        # Corrupt canonical rows must not disappear from concurrency accounting.
        raise FlowPayloadError("flow checkpoint metadata needs recovery") from exc
    c.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)", values)


def _read_metadata(path: Path) -> tuple[str, dict]:
    try:
        row = json.loads(atomic_read_text(path))
        run_id = row["run_id"]
        if not isinstance(run_id, str) or _path(path.parent, run_id) != path:
            raise ValueError("invalid checkpoint filename")
        return run_id, row
    except (ValueError, TypeError, KeyError) as exc:
        raise FlowPayloadError("flow checkpoint metadata needs recovery") from exc


def _rebuild(c, root: Path) -> None:
    c.execute("BEGIN IMMEDIATE")
    try:
        c.execute("DELETE FROM runs")
        paths = iter(root.glob("*.json"))
        # Only cold migration/recovery uses these four bounded read workers.
        # The index lock fences JSON publishers; SQLite stays on this thread.
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="flow-index") as readers:
            while batch := list(islice(paths, 128)):
                for run_id, row in readers.map(_read_metadata, batch):
                    _sync_row(c, root, run_id, row=row)
        c.execute("DELETE FROM dirty")
        c.execute("INSERT OR REPLACE INTO state VALUES ('version','1')")
        c.commit()
    except BaseException:
        c.rollback()
        raise


@contextmanager
def _connection(root: Path, *, rebuild_all=False):
    parent = ensure_private_directory(root.parent)
    path = parent / "run-index.sqlite3"
    with cross_process_lock(parent / ".run-index", strict=True):
        if not path.exists():
            atomic_create_bytes(path, b"")
        ensure_private_file(path)
        c = sqlite3.connect(str(path), isolation_level=None)
        try:
            try:
                c.executescript(_SCHEMA)
            except sqlite3.DatabaseError as exc:
                if not any(word in str(exc).lower() for word in ("malformed", "not a database")):
                    raise
                c.close()
                # The index is disposable; canonical rows/artifacts are untouched.
                atomic_write_bytes(path, b"")
                c = sqlite3.connect(str(path), isolation_level=None)
                c.executescript(_SCHEMA)
            c.row_factory = sqlite3.Row
            marker = parent / ".run-index-rebuild"
            if marker.exists():
                ensure_private_file(marker)
            if rebuild_all or marker.exists() or not c.execute("SELECT 1 FROM state WHERE key='version' AND value='1'").fetchone():
                _rebuild(c, root)
                marker.unlink(missing_ok=True)
            for row in c.execute("SELECT run_id FROM dirty").fetchall():
                c.execute("BEGIN IMMEDIATE")
                try:
                    _sync_row(c, root, row[0])
                    c.execute("DELETE FROM dirty WHERE run_id=?", (row[0],))
                    c.commit()
                except BaseException:
                    c.rollback()
                    raise
            yield c
        finally:
            c.close()


@contextmanager
def mutation(root: Path, run_id: str):
    """Record intent before changing JSON; acknowledge only after index repair."""
    with _connection(root) as c:
        c.execute("INSERT OR IGNORE INTO dirty VALUES (?)", (run_id,))
        yield
        c.execute("BEGIN IMMEDIATE")
        try:
            _sync_row(c, root, run_id)
            c.execute("DELETE FROM dirty WHERE run_id=?", (run_id,))
            c.commit()
        except BaseException:
            c.rollback()
            raise


def rebuild(root: Path) -> None:
    """Reconcile restored/legacy files at startup or after an offline restore."""
    with _connection(root, rebuild_all=True):
        pass


def query(root: Path, *, flow_id=None, owner=None, statuses=None, due_before=None,
          limit=50, cursor=None, idem_key=None, release_id=None) -> list[dict]:
    clauses, args = [], []
    for column, value in (("flow_id", flow_id), ("owner", owner), ("idem_key", idem_key),
                          ("release_id", release_id)):
        if value is not None:
            clauses.append(column + "=?")
            args.append(value)
    if statuses is not None:
        if not statuses:
            return []
        clauses.append("status IN (" + ",".join("?" for _ in statuses) + ")")
        args.extend(sorted(statuses))
    due = due_before is not None
    if due:
        clauses.append("resume_at IS NOT NULL AND resume_at<=?")
        args.append(due_before)
    if cursor is not None:
        clauses.append("(resume_at,run_id)>(?,?)" if due else "(updated,run_id)<(?,?)")
        args.extend(cursor)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    order = "resume_at, run_id" if due else "updated DESC, run_id DESC"
    sql = "SELECT * FROM runs" + where + " ORDER BY " + order
    if limit is not None:
        sql += " LIMIT ?"
        args.append(max(0, int(limit)))
    with _connection(root) as c:
        # External deletion/corruption of a selected JSON file is never hidden
        # by a cached record. Re-query after repairs because ordering may change.
        for _ in range(3):
            rows = c.execute(sql, args).fetchall()
            changed = [row for row in rows if row["stamp"] != _stamp(_path(root, row["run_id"]))]
            if not changed:
                return [json.loads(row["metadata"]) for row in rows]
            for row in changed:
                _sync_row(c, root, row["run_id"])
        raise FlowPayloadError("flow checkpoint metadata changed during read; retry")
