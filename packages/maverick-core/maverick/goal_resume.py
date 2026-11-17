"""Atomic reviewed restart admission; receipt replay never starts another attempt."""
from __future__ import annotations

import json

from .chat_threads import ChatThreads
from .goal_mutations import GoalMutationConflict, _fingerprint, _receipt, _record, _transaction
from .task_execution_guard import lease


def respend_notice(world, goal_id) -> str:
    """What a resume will spend again, said before it starts; "" when nothing.

    With durable execution on, a resume continues from the saved transcript,
    so finished tool calls are not repeated. Without a saved checkpoint the
    resumed attempt starts a new conversation: the model re-plans and calls
    tools again, and nothing outside that transcript holds complete results
    to reuse. The goal-event mirror is redacted and bounded, and paid tools
    that send messages must never be replayed from a store. So the honest
    remedy is to say it, with the last attempt's spend.
    """
    from . import checkpoint

    try:
        if checkpoint.enabled() and checkpoint.Checkpointer(world).orchestrator_for(goal_id) is not None:
            return ""
        episodes = world.list_episodes(goal_id=goal_id, limit=1)
    except Exception:  # an unreadable history is not evidence of no spend
        return ("Resuming may start this task again from the beginning. "
                "Finished steps, including paid searches and other paid services, may run and be charged again.")
    spent = float(episodes[0].cost_dollars or 0.0) if episodes else 0.0
    if spent <= 0:
        return ""
    return ("Resuming starts this task again from the beginning. Finished steps run again, "
            "including paid searches and other paid services. "
            f"The last attempt spent ${spent:.2f}; expect to spend about that much again before new progress.")


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
    from .decision_requests import claim_stranded, stranded

    threads = ChatThreads(world)
    recoverable = stranded(world, goal_id)  # left pending after its answer; before the lease
    with lease(world, goal_id), threads._restart_transaction(goal_id) as (connection, binding, status):
        require_authority()
        if status == "pending" and recoverable and claim_stranded(threads, connection, goal_id):
            status = "blocked"
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
