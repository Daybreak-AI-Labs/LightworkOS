"""Read-only bounded metadata windows; no private body or persistent search index."""
from __future__ import annotations

import hashlib
import json
import time
from contextlib import contextmanager
from dataclasses import dataclass

WINDOW = 250
MAX_METADATA = 50_000
MAX_SCAN_SECONDS = 3.0
SQLITE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_goals_owner_created_history ON goals(owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_projects_owner_created_history ON projects(owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_facts_shared_updated_history ON facts(updated_at,key) WHERE LOWER(key) NOT LIKE 'user:%' AND LOWER(key) NOT LIKE 'goal:%'",
]
POSTGRES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_goals_owner_created_history ON goals(tenant_id,owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_projects_owner_created_history ON projects(tenant_id,owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_facts_shared_updated_history ON facts(tenant_id,updated_at,key) WHERE LOWER(key) NOT LIKE 'user:%' AND LOWER(key) NOT LIKE 'goal:%'",
]


class HistoryNarrowing(ValueError):
    """A bounded history proof needs a narrower source/date selection."""


def check_scan(count, started):
    if count > MAX_METADATA or time.monotonic() - started > MAX_SCAN_SECONDS:
        raise HistoryNarrowing("Choose a narrower date range to keep historical search within its scan budget.")


class HistoryChanged(ValueError):
    pass


@dataclass
class Window:
    rows: list
    snapshot: str
    next_offset: int | None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def sql_window(execute, *, table, columns, stamp, where="1=1", params=(), order, offset=0, limit=WINDOW):
    """SQL fragments are trusted source constants, never request strings.

    Hash only indexed/native metadata, streaming in bounded batches. Re-read the
    epoch after the page for read-committed backends. Titles are decrypted only
    for this window. No inaccessible counts are returned to a caller.
    """
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Invalid history position")
    if not 1 <= limit <= WINDOW:
        raise ValueError("Invalid history window")

    started = time.monotonic()

    def epoch():
        current = hashlib.sha256()
        count = 0
        cursor = execute(f"SELECT {stamp} FROM {table} WHERE {where} ORDER BY {order}", params)
        while batch := cursor.fetchmany(WINDOW):
            count += len(batch)
            check_scan(count, started)
            for row in batch:
                current.update(json.dumps(tuple(row), separators=(",", ":"), default=str).encode())
                current.update(b"\n")
        return current.hexdigest()

    before = epoch()
    rows = execute(f"SELECT {columns} FROM {table} WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
                   (*params, limit + 1, offset)).fetchall()
    if before != epoch():
        raise HistoryChanged("Records changed during search. Start a fresh search.")
    return Window(list(rows[:limit]), before, offset + limit if len(rows) > limit else None)


@contextmanager
def world_reader(world):
    from .attachment_submissions import SubmissionStore
    store = SubmissionStore(world)
    if store.sqlite:
        connection = world._reader()
        if connection is None:
            with world._write_lock:
                yield store, lambda sql, params=(): world.conn.execute(sql, params)
        else:
            yield store, lambda sql, params=(): connection.execute(sql, params)
    else:
        with world._tx() as cursor:
            yield store, lambda sql, params=(): store.execute(cursor, sql, params)
    store._check_context()


def world_window(world, *, source, owner, allowed_domain, after=None, before=None, oldest=False, offset=0):
    """Exact owner tasks/projects, or shared fact keys. Never SELECT bodies."""
    specs = {
        "tasks": ("goals", "id,title,status,created_at,updated_at,domain", "created_at", "id"),
        "projects": ("projects", "id,name,status,created_at,domain", "created_at", "id"),
        "facts": ("facts", "key,source,updated_at,tags_json", "updated_at", "key"),
    }
    table, columns, date, identity = specs[source]
    with world_reader(world) as (store, execute):
        where, params = [], []
        if not store.sqlite:
            scope, values = store.scope()
            where.append(scope)
            params.extend(values)
        if source == "facts":
            where.extend(["LOWER(key) NOT LIKE 'user:%'", "LOWER(key) NOT LIKE 'goal:%'"])
        else:
            where.append("owner=?")
            params.append(owner)
            domain_query = "SELECT DISTINCT domain FROM " + table + " WHERE " + " AND ".join(where)
            domains = [row[0] for row in execute(domain_query, tuple(params)).fetchall() if allowed_domain(row[0])]
            if not domains:
                return Window([], digest([]), None)
            where.append("domain IN (" + ",".join("?" for _ in domains) + ")")
            params.extend(domains)
        for value, operator in ((after, ">="), (before, "<")):
            if value is not None:
                where.append(date + operator + "?")
                params.append(value)
        direction = "ASC" if oldest else "DESC"
        result = sql_window(execute, table=table, columns=columns, stamp=columns,
                            where=" AND ".join(where), params=tuple(params),
                            order=f"{date} {direction},{identity}", offset=offset)
        names = columns.split(",")
        result.rows = [dict(zip(names, tuple(row), strict=True)) for row in result.rows]
        if source != "facts":
            field = "title" if source == "tasks" else "name"
            for row in result.rows:
                row[field] = store.open(row[field])
        return result
