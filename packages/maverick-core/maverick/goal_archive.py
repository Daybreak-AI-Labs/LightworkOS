"""Bounded version-one archives from one native database read snapshot."""
from __future__ import annotations

import hashlib
import json
import tempfile
import time
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass

from .attachment_submissions import SubmissionStore
from .file_lock import ensure_private_directory
from .paths import data_dir

MAX_EVENTS = 10000
MAX_EPISODES = 200
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_ROW_CHARACTERS = 1000000
PAGE_SIZE = 8


class IncompleteGoalBundle(ValueError):
    """No partial file is released when its complete snapshot cannot be exported."""


def _refuse():
    return IncompleteGoalBundle("This task exceeds the supported archive size. No partial history was downloaded. Use workspace backup to preserve the complete record.")


@contextmanager
def snapshot(world):
    """Pin one reader without committing or rolling back another caller's work."""
    try:
        store = SubmissionStore(world)
    except TypeError as exc:
        raise IncompleteGoalBundle("This storage backend cannot provide a consistent archive snapshot. No partial history was downloaded.") from exc
    store._check_context()
    if not store.sqlite:
        with world._tx(snapshot=True) as cursor:
            yield store, cursor
        return
    reader = world._reader()
    with (world._write_lock if reader is None else nullcontext()):
        connection = reader if reader is not None else world.conn
        if connection.in_transaction:
            raise IncompleteGoalBundle("Another transaction is using this reader. Retry the archive after it settles.")
        connection.execute("BEGIN")
        try:
            yield store, connection
        finally:
            connection.rollback()


@dataclass
class PreparedArchive:
    stream: object
    goal: object
    manifest: dict

    def close(self):
        self.stream.close()

    def chunks(self):
        try:
            self.stream.seek(0)
            while block := self.stream.read(65536):
                yield block
        finally:
            self.close()


class _Writer:
    def __init__(self, stream):
        self.stream, self.size, self.digest = stream, 0, hashlib.sha256()

    def write(self, value, *, hashed=True):
        data = value.encode("utf-8") if isinstance(value, str) else value
        if self.size + len(data) > MAX_ARCHIVE_BYTES:
            raise _refuse()
        self.size += len(data)
        self.stream.write(data)
        if hashed:
            self.digest.update(data)

    def json(self, value, *, hashed=True):
        for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":"), default=str).iterencode(value):
            self.write(chunk, hashed=hashed)


def _goal(store, connection, goal_id):
    scope, values = ("1=1", ()) if store.sqlite else store.scope("g.tenant_id")
    where = f"g.id=? AND {scope}"
    params = (goal_id, *values)
    size = store.execute(connection, "SELECT COALESCE(LENGTH(title),0)+COALESCE(LENGTH(description),0)+COALESCE(LENGTH(result),0)+COALESCE(LENGTH(owner),0)+COALESCE(LENGTH(execution_principal),0)+COALESCE(LENGTH(domain),0)+COALESCE(LENGTH(status),0) FROM goals g WHERE " + where, params).fetchone()
    if size is None:
        return None, where, params
    if int(size[0]) > MAX_ROW_CHARACTERS:
        raise _refuse()
    if store.sqlite:
        from .world_model import _goal_from_row
        row = store.execute(connection, "SELECT g.* FROM goals g WHERE " + where, params).fetchone()
        goal = _goal_from_row(row)
    else:
        from .world_model_backends.postgres import _dec_goal_row
        row = store.execute(connection, "SELECT id,parent_id,title,description,status,created_at,updated_at,deadline,result,owner,execution_principal,domain,project_id FROM goals g WHERE " + where, params).fetchone()
        goal = _dec_goal_row(row)
    return goal, where, params


def _limits(store, connection, where, params):
    counts = []
    for table, size_expression, limit in (("goal_events", "COALESCE(LENGTH(e.content),0)+COALESCE(LENGTH(e.agent),0)+COALESCE(LENGTH(e.kind),0)", MAX_EVENTS), ("episodes", "COALESCE(LENGTH(e.outcome),0)", MAX_EPISODES)):
        row = store.execute(connection, f"SELECT COUNT(*),COALESCE(MAX({size_expression}),0) FROM {table} e JOIN goals g ON g.id=e.goal_id WHERE " + where, params).fetchone()
        count, size = int(row[0]), int(row[1])
        if count > limit or size > MAX_ROW_CHARACTERS:
            raise _refuse()
        counts.append(count)
    return counts


def _events(store, connection, where, params):
    from .world_model import GoalEvent
    after = 0
    while True:
        rows = store.execute(connection, "SELECT e.id,e.goal_id,e.agent,e.kind,e.content,e.ts FROM goal_events e JOIN goals g ON g.id=e.goal_id WHERE " + where + " AND e.id>? ORDER BY e.id ASC LIMIT ?", (*params, after, PAGE_SIZE)).fetchall()
        for row in rows:
            yield asdict(GoalEvent(row[0], row[1], row[2], row[3], store.open(row[4]), row[5]))
        if len(rows) < PAGE_SIZE:
            return
        after = rows[-1][0]


def _episodes(store, connection, where, params):
    from .world_model import EpisodeSpend
    before = None
    while True:
        extra = "" if before is None else " AND (e.started_at<? OR (e.started_at=? AND e.id<?))"
        values = params if before is None else (*params, before[0], before[0], before[1])
        rows = store.execute(connection, "SELECT e.id,e.goal_id,e.started_at,e.ended_at,e.outcome,COALESCE(e.cost_dollars,0),COALESCE(e.input_tokens,0),COALESCE(e.output_tokens,0),COALESCE(e.tool_calls,0),COALESCE(e.cache_read_tokens,0),COALESCE(e.cache_write_tokens,0) FROM episodes e JOIN goals g ON g.id=e.goal_id WHERE " + where + extra + " ORDER BY e.started_at DESC,e.id DESC LIMIT ?", (*values, PAGE_SIZE)).fetchall()
        for row in rows:
            yield asdict(EpisodeSpend(row[0], row[1], row[2], row[3], store.open(row[4]), *row[5:11]))
        if len(rows) < PAGE_SIZE:
            return
        before = rows[-1][2], rows[-1][0]


def _array(writer, records):
    writer.write("[")
    count = 0
    for record in records:
        if count:
            writer.write(",")
        writer.json(record)
        count += 1
    writer.write("]")
    return count


def prepare_goal_archive(world, goal_id):
    """Finish a private bounded file before returning any bytes to the caller."""
    parent = ensure_private_directory(data_dir("archive-staging"))
    stream = tempfile.TemporaryFile(mode="w+b", dir=parent)
    try:
        with snapshot(world) as (store, connection):
            goal, where, params = _goal(store, connection, goal_id)
            if goal is None:
                stream.close()
                return None
            event_count, episode_count = _limits(store, connection, where, params)
            writer = _Writer(stream)
            # Canonical key order preserves the original v1 body checksum and
            # import shape; arrays are read in bounded keyset pages.
            writer.write('{"episodes":')
            actual_episodes = _array(writer, _episodes(store, connection, where, params))
            writer.write(',"events":')
            actual_events = _array(writer, _events(store, connection, where, params))
            writer.write(',"goal":')
            writer.json(asdict(goal))
            writer.write(',"v":1')
            if (actual_events, actual_episodes) != (event_count, episode_count):
                raise IncompleteGoalBundle("The archive record count could not be verified. No partial history was downloaded.")
            writer.digest.update(b"}")
            manifest = {"schema":"lightwork.goal-archive.v1", "complete_within_export_limits":True,
                        "snapshot_consistent":True, "snapshot_prepared_at":time.time(),
                        "event_count":event_count, "episode_count":episode_count,
                        "sha256":writer.digest.hexdigest(), "hash_encoding":"json-prefix-v1",
                        "scope":"Goal record, recorded events and episode summaries only. Attachments and external systems are not included.",
                        "resumable":False, "redacted":False}
            writer.write(',"manifest":', hashed=False)
            writer.json(manifest, hashed=False)
            writer.write("}", hashed=False)
        stream.seek(0)
        return PreparedArchive(stream, goal, manifest)
    except Exception:
        stream.close()
        raise
