"""Revision-bound cooperative Stop with an atomic, replayable native receipt."""
from __future__ import annotations

import time

from .goal_mutations import GoalMutationConflict, _fingerprint, _receipt, _record, _transaction

TERMINAL = frozenset({"done", "completed", "failed", "error", "cancelled"})


def receipt(world, goal_id, *, actor, operation_id, expected_updated_at, expected_owner):
    fingerprint = _fingerprint({"expected_updated_at": expected_updated_at, "expected_owner": expected_owner})
    with _transaction(world, goal_id) as (execute, _encode, decode, _postgres, _tenant):
        return _receipt(execute, decode, goal_id, "stop", operation_id, actor, fingerprint)


def stop(world, goal_id, *, actor, operation_id, expected_updated_at, expected_owner, effect_guard=None):
    """Never overwrite a terminal result or a different reviewed task version."""
    fingerprint = _fingerprint({"expected_updated_at": expected_updated_at, "expected_owner": expected_owner})
    with _transaction(world, goal_id) as (execute, encode, decode, postgres, _tenant):
        if effect_guard is not None:
            effect_guard()
        prior = _receipt(execute, decode, goal_id, "stop", operation_id, actor, fingerprint)
        if prior is not None:
            return prior
        row = execute("SELECT status,updated_at,owner FROM goals WHERE id=?", (goal_id,)).fetchone()
        if (row is None or row[0] in TERMINAL or float(row[1]) != expected_updated_at
                or (row[2] or "") != expected_owner):
            raise GoalMutationConflict("This task changed or already finished. Refresh its current state before requesting Stop.")
        maximum = "GREATEST" if postgres else "MAX"
        if effect_guard is not None:
            effect_guard()
        execute("UPDATE goals SET status='cancelled', completed_at=NULL, updated_at=" + maximum +
                "(updated_at + 0.000001, ?) WHERE id=? AND updated_at=?",
                (time.time(), goal_id, expected_updated_at))
        execute("DELETE FROM signoffs WHERE goal_id=?", (goal_id,))
        result = {"goal_id": goal_id, "stop_requested": True, "cleanup_confirmed": False,
                  "external_effects_reversed": False, "replayed": False}
        _record(execute, encode, goal_id, "stop", operation_id, actor, fingerprint, result)
        if effect_guard is not None:
            effect_guard()
        return result
