"""Atomic, revision-bound human edits shared by the dashboard and authorized tools."""
from __future__ import annotations

import hashlib
import json
import time
from contextlib import contextmanager

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS goal_mutation_receipts ("
    "goal_id INTEGER NOT NULL REFERENCES goals(id) ON DELETE CASCADE, kind TEXT NOT NULL, "
    "operation_id TEXT NOT NULL, actor TEXT NOT NULL, request_hash TEXT NOT NULL, "
    "receipt TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, "
    "PRIMARY KEY(goal_id, kind, operation_id, actor))"
)


class GoalMutationConflict(ValueError):
    """The reviewed task changed; the caller must preserve and compare its draft."""


@contextmanager
def _transaction(world, goal_id: int):
    """Lock before reading on both engines; receipts share the mutation transaction."""
    if hasattr(world, "_writing"):
        from .world_model import _dec_field, _enc_field

        with world._writing() as conn:
            # First statement obtains SQLite's interprocess writer lock.
            conn.execute("UPDATE goals SET id=id WHERE id=?", (goal_id,))
            yield conn.execute, _enc_field, _dec_field, False, None
    else:
        from .world_model_backends.postgres import _active_tenant, _seal, _tenant_scope, _unseal

        with world._tx() as cursor:
            # All reviewed tree moves share a transaction advisory lock, so a
            # simultaneous A-under-B / B-under-A move cannot create a cycle.
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", (71940242,))
            frag, params = _tenant_scope()
            cursor.execute("SELECT id FROM goals WHERE id=%s" + (" AND " + frag if frag else "") +
                           " FOR UPDATE", (goal_id, *params))
            if cursor.fetchone() is None:
                raise GoalMutationConflict("This task is unavailable.")

            def execute(sql, params=()):
                cursor.execute(sql.replace("?", "%s"), params)
                return cursor

            yield execute, _seal, _unseal, True, _active_tenant()


def _fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _receipt(execute, decode, goal_id, kind, operation_id, actor, digest):
    row = execute("SELECT request_hash, receipt FROM goal_mutation_receipts "
                  "WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                  (goal_id, kind, operation_id, actor)).fetchone()
    if row is None:
        return None
    if row[0] != digest:
        raise GoalMutationConflict("This save reference belongs to a different draft.")
    return {**json.loads(decode(row[1])), "replayed": True}


def _record(execute, encode, goal_id, kind, operation_id, actor, digest, result):
    execute("INSERT INTO goal_mutation_receipts "
            "(goal_id,kind,operation_id,actor,request_hash,receipt,created_at) VALUES(?,?,?,?,?,?,?)",
            (goal_id, kind, operation_id, actor, digest,
             encode(json.dumps(result, sort_keys=True)), time.time()))


def edit_result(world, goal_id: int, *, text: str, expected_updated_at: float,
                operation_id: str, actor: str) -> dict:
    """Change result only; preserve prior versions and revoke approval atomically."""
    digest = _fingerprint({"text": text, "expected_updated_at": expected_updated_at})
    with _transaction(world, goal_id) as (execute, encode, decode, postgres, _tenant):
        old_receipt = _receipt(execute, decode, goal_id, "result", operation_id, actor, digest)
        if old_receipt is not None:
            return old_receipt
        row = execute("SELECT result,status,updated_at FROM goals WHERE id=?", (goal_id,)).fetchone()
        if row is None or row[1] != "done" or float(row[2]) != expected_updated_at:
            raise GoalMutationConflict("The result changed or the task is not finished. Review the current result.")
        original = decode(row[0]) or ""
        maximum = "GREATEST" if postgres else "MAX"
        execute("UPDATE goals SET result=?, updated_at=" + maximum + "(updated_at + 0.000001, ?) "
                "WHERE id=? AND status='done' AND updated_at=?",
                (encode(text), time.time(), goal_id, expected_updated_at))
        if execute("SELECT updated_at FROM goals WHERE id=?", (goal_id,)).fetchone() is None:
            raise GoalMutationConflict("This task is unavailable.")
        revision = float(execute("SELECT updated_at FROM goals WHERE id=?", (goal_id,)).fetchone()[0])
        title = "Deliverable revisions"
        version = int(execute("SELECT COALESCE(MAX(version),0) FROM artifacts WHERE goal_id=? AND title=?",
                              (goal_id, title)).fetchone()[0])
        if version == 0:
            execute("INSERT INTO artifacts(goal_id,kind,title,content,version,created_at) VALUES(?,?,?,?,?,?)",
                    (goal_id, "markdown", title, encode(original), 1, expected_updated_at))
            version = 1
        execute("INSERT INTO artifacts(goal_id,kind,title,content,version,created_at) VALUES(?,?,?,?,?,?)",
                (goal_id, "markdown", title, encode(text), version + 1, revision))
        execute("DELETE FROM signoffs WHERE goal_id=?", (goal_id,))
        result = {"revision": revision, "version": version + 1, "actor": actor,
                  "source": "human edit", "original": original, "text": text, "replayed": False}
        _record(execute, encode, goal_id, "result", operation_id, actor, digest, result)
        return result


def assert_move_boundary(world, goal_id: int, parent_id: int | None, *, execute=None) -> None:
    """A map edit cannot remove or replace an inherited handoff budget ceiling."""
    def read(sql, params):
        if execute is not None:
            return execute(sql, params).fetchone()
        rows = world.query(sql, params)
        return rows[0] if rows else None

    def anchor(current):
        seen = set()
        while current is not None:
            if current in seen or len(seen) >= 100:
                raise GoalMutationConflict("Task ancestry is unavailable. Refresh the task map.")
            seen.add(current)
            if read("SELECT 1 FROM goal_mutation_receipts WHERE goal_id=? AND kind='handoff_lineage' LIMIT 1", (current,)):
                return current
            row = read("SELECT parent_id FROM goals WHERE id=?", (current,))
            if row is None:
                raise GoalMutationConflict("The parent task is no longer available.")
            current = row[0]
        return None

    original = anchor(goal_id)
    # A continuation keeps its own durable ceiling wherever it is placed.
    if original != goal_id and original != anchor(parent_id):
        raise GoalMutationConflict("This move would change an inherited handoff spending limit. Keep the task within its current governed continuation.")


def edit_structure(world, goal_id: int, *, expected_updated_at: float,
                   title: str | None = None, parent_id: int | None = None,
                   move: bool = False, operation_id: str | None = None,
                   actor: str = "") -> dict:
    digest = _fingerprint({"title": title, "parent_id": parent_id, "move": move,
                           "expected_updated_at": expected_updated_at})
    with _transaction(world, goal_id) as (execute, encode, decode, postgres, _tenant):
        if operation_id is not None:
            previous = _receipt(execute, decode, goal_id, "structure", operation_id, actor, digest)
            if previous is not None:
                return previous
        from .task_handoffs import require_open

        require_open(world, goal_id, execute=execute, decode=decode)
        if move and parent_id is not None:
            require_open(world, parent_id, execute=execute, decode=decode)
        if move:
            assert_move_boundary(world, goal_id, parent_id, execute=execute)
        row = execute("SELECT updated_at FROM goals WHERE id=?", (goal_id,)).fetchone()
        if row is None or float(row[0]) != expected_updated_at:
            raise GoalMutationConflict("This task changed. Review its current title and parent before saving your draft.")
        if move:
            seen = {goal_id}
            current = parent_id
            while current is not None:
                if current in seen:
                    raise GoalMutationConflict("This move would create a loop in the task map.")
                seen.add(current)
                ancestor = execute("SELECT parent_id FROM goals WHERE id=?", (current,)).fetchone()
                if ancestor is None:
                    raise GoalMutationConflict("The parent task is no longer available.")
                current = ancestor[0]
        maximum = "GREATEST" if postgres else "MAX"
        column, value = ("parent_id", parent_id) if move else ("title", encode(title))
        execute("UPDATE goals SET " + column + "=?, updated_at=" + maximum +
                "(updated_at + 0.000001, ?) WHERE id=? AND updated_at=?",
                (value, time.time(), goal_id, expected_updated_at))
        saved = execute("SELECT title,parent_id,updated_at FROM goals WHERE id=?", (goal_id,)).fetchone()
        result = {"goal_id": goal_id, "title": decode(saved[0]), "parent_id": saved[1],
                  "revision": float(saved[2]), "replayed": False}
        if operation_id is not None:
            _record(execute, encode, goal_id, "structure", operation_id, actor, digest, result)
        return result


def structure_receipt(world, goal_id: int, *, expected_updated_at: float,
                      operation_id: str, actor: str, title: str | None = None,
                      parent_id: int | None = None, move: bool = False) -> dict | None:
    """Read an exact historical acknowledgement; never reapply an old edit."""
    digest = _fingerprint({"title": title, "parent_id": parent_id, "move": move,
                           "expected_updated_at": expected_updated_at})
    with _transaction(world, goal_id) as (execute, _encode, decode, _postgres, _tenant):
        return _receipt(execute, decode, goal_id, "structure", operation_id, actor, digest)


def create_child(world, goal_id: int, *, title: str, description: str,
                 operation_id: str, actor: str, owner: str) -> dict:
    digest = _fingerprint({"title": title, "description": description, "owner": owner})
    with _transaction(world, goal_id) as (execute, encode, decode, postgres, tenant):
        old_receipt = _receipt(execute, decode, goal_id, "child", operation_id, actor, digest)
        if old_receipt is not None:
            return old_receipt
        from .task_handoffs import require_open

        require_open(world, goal_id, execute=execute, decode=decode)
        now = time.time()
        columns = "parent_id,title,description,status,created_at,updated_at,owner"
        values = [goal_id, encode(title), encode(description), "pending", now, now, owner]
        if postgres:
            columns += ",tenant_id"
            values.append(tenant)
        cursor = execute("INSERT INTO goals(" + columns + ") VALUES(" +
                         ",".join("?" for _ in values) + ") RETURNING id", tuple(values))
        result = {"child_id": int(cursor.fetchone()[0]), "replayed": False}
        _record(execute, encode, goal_id, "child", operation_id, actor, digest, result)
        return result
