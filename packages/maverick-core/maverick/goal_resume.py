"""Atomic reviewed restart admission; receipt replay never starts another attempt."""
from __future__ import annotations

import json

from .chat_threads import ChatThreads
from .goal_mutations import GoalMutationConflict, _fingerprint, _receipt, _record, _transaction
from .task_execution_guard import lease


def fingerprint(expected_updated_at, expected_owner, max_dollars):
    return _fingerprint({"expected_updated_at": expected_updated_at, "expected_owner": expected_owner,
                         "max_dollars": max_dollars})


def receipt(world, goal_id, *, actor, operation_id, expected_updated_at, expected_owner, max_dollars):
    with _transaction(world, goal_id) as (execute, _encode, decode, _pg, _tenant):
        return _receipt(execute, decode, goal_id, "resume", operation_id, actor,
                        fingerprint(expected_updated_at, expected_owner, max_dollars))


def reserve(world, goal_id, *, actor, operation_id, expected_updated_at, expected_owner,
            max_dollars, require_authority, require_admission):
    """Use the existing conversation transaction and runner lease before admission."""
    digest = fingerprint(expected_updated_at, expected_owner, max_dollars)
    prior = receipt(world, goal_id, actor=actor, operation_id=operation_id,
                    expected_updated_at=expected_updated_at, expected_owner=expected_owner, max_dollars=max_dollars)
    if prior is not None:
        require_authority()
        return prior
    threads = ChatThreads(world)
    with lease(world, goal_id), threads._restart_transaction(goal_id) as (connection, binding, status):
        require_authority()
        def execute(sql, args=()):
            return threads.store.execute(connection, sql, args)
        prior = _receipt(execute, threads.store.open, goal_id, "resume", operation_id, actor, digest)
        if prior is not None:
            return prior
        row = execute("SELECT owner,updated_at FROM goals WHERE id=?", (goal_id,)).fetchone()
        if (row is None or (row[0] or "") != expected_owner or float(row[1]) != expected_updated_at
                or status not in {"blocked", "cancelled", "failed"}):
            raise GoalMutationConflict("This task changed after restart review. Read current progress before deciding again.")
        if binding is not None:
            threads.require_idle(connection, binding.root_id, binding.owner, except_goal=goal_id)
        require_admission()
        threads._pending(connection, goal_id)
        result = {"received": True, "goal_id": goal_id, "operation_id": operation_id,
                  "admitted": True, "replayed": False, "max_dollars": max_dollars,
                  "conversation_id": binding.conversation_id if binding is not None else None,
                  "execution": "unconfirmed", "previous_status": status}
        _record(execute, threads.store.seal, goal_id, "resume", operation_id, actor, digest, result)
    return result


def lookup(world, goal_id, *, actor, operation_id):
    with _transaction(world, goal_id) as (execute, _encode, decode, _pg, _tenant):
        row = execute("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind='resume' AND actor=? AND operation_id=?",
                      (goal_id, actor, operation_id)).fetchone()
        return {**json.loads(decode(row[0])), "replayed": True} if row else None
