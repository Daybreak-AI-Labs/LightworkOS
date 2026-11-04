"""Exact human-result review receipts sharing the native sign-off transaction."""
from __future__ import annotations

import json

from .goal_mutations import GoalMutationConflict, _fingerprint, _receipt, _record, _transaction

KIND = "deliverable_signoff"


class _NativeCursor:
    """Use the existing native voter with the already-reserved transaction."""

    def __init__(self, execute):
        self._execute = execute
        self._last = None

    def execute(self, sql, params=()):
        self._last = self._execute(sql.replace("%s", "?"), params)
        return self._last

    def fetchone(self):
        return self._last.fetchone()


def _accepted(execute, decode, goal_id):
    row = execute("SELECT goal_id,decision,decided_by,note,created_at FROM signoffs WHERE goal_id=?", (goal_id,)).fetchone()
    if row is None:
        raise RuntimeError("The native result review was not recorded.")
    return {"goal_id": row[0], "decision": row[1], "decided_by": row[2],
            "note": decode(row[3]), "created_at": float(row[4])}


def decide(world, goal_id, *, decision, expected_updated_at, note, operation_id, actor, owner, context):
    material = {"decision": decision, "expected_updated_at": expected_updated_at, "note": note,
                "owner": owner, "context": context}
    fingerprint = _fingerprint(material)
    with _transaction(world, goal_id) as (execute, encode, decode, _postgres, _tenant):
        previous = _receipt(execute, decode, goal_id, KIND, operation_id, actor, fingerprint)
        if previous is not None:
            return previous
        source = execute("SELECT status,updated_at,owner FROM goals WHERE id=?", (goal_id,)).fetchone()
        if source is None or source[0] != "done" or float(source[1]) != expected_updated_at or (source[2] or "") != owner:
            raise GoalMutationConflict("The result or its owner changed. Review the current result before deciding.")
        changed = world.record_signoff(goal_id, decision, decided_by=actor, note=note,
            expected_updated_at=expected_updated_at, _cursor=_NativeCursor(execute))
        accepted = _accepted(execute, decode, goal_id)
        result = {"operation_id": operation_id, "actor": actor, "owner": owner, "context": context,
                  "deliverable_updated_at": expected_updated_at, "decision": decision, "changed": changed,
                  "signoff": accepted, "own_decision": accepted["decided_by"] == actor,
                  "effects": "not_started" if changed else "not_repeated", "replayed": False}
        _record(execute, encode, goal_id, KIND, operation_id, actor, fingerprint, result)
        return result


def receipt(world, goal_id, operation_id, actor):
    """Read only an original actor's historical acknowledgement; never vote."""
    with _transaction(world, goal_id) as (execute, _encode, decode, _postgres, _tenant):
        row = execute("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                      (goal_id, KIND, operation_id, actor)).fetchone()
        return {**json.loads(decode(row[0])), "replayed": True} if row is not None else None


def effects(world, goal_id, operation_id, actor, state):
    """Retain bounded follow-through evidence; replay never sends another handoff."""
    with _transaction(world, goal_id) as (execute, encode, decode, _postgres, _tenant):
        row = execute("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                      (goal_id, KIND, operation_id, actor)).fetchone()
        if row is None:
            raise RuntimeError("The original review receipt is unavailable.")
        result = json.loads(decode(row[0]))
        result["effects"] = state
        execute("UPDATE goal_mutation_receipts SET receipt=? WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                (encode(json.dumps(result, sort_keys=True)), goal_id, KIND, operation_id, actor))
        return result
