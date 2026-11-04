"""Version-bound result feedback and its original actor's durable receipt."""
from __future__ import annotations

import json
import math
import time

from .goal_mutations import GoalMutationConflict, _fingerprint, _receipt, _record, _transaction

KIND = "result_feedback"
SUMMARY_LIMIT = 5000
REASONS = {
    "wrong": "Wrong or inaccurate", "incomplete": "Missing something",
    "not_asked": "Not what I asked for", "unclear": "Hard to understand",
    "too_long": "Too long", "other": "Something else",
}


def version(goal):
    return _fingerprint({"owner": goal.owner or "", "status": goal.status, "domain": goal.domain,
                         "updated_at": float(goal.updated_at), "result": goal.result or ""})


def record(world, goal_id, *, rating, note, revision, owner, context, actor, operation_id, reason=""):
    if (rating not in {"up", "down"} or not isinstance(note, str) or len(note) > 500
            or not isinstance(reason, str) or (reason and reason not in REASONS) or (reason and rating != "down")):
        raise ValueError("Choose a rating and keep the optional note within 500 characters.")
    material = {"rating": rating, "note": note, "revision": revision, "owner": owner, "context": context}
    # Empty reasons preserve the fingerprint of previously accepted requests.
    if reason:
        material["reason"] = reason
    fingerprint = _fingerprint(material)
    with _transaction(world, goal_id) as (execute, encode, decode, _postgres, _tenant):
        previous = _receipt(execute, decode, goal_id, KIND, operation_id, actor, fingerprint)
        if previous is not None:
            return previous
        source = execute("SELECT status,updated_at,owner,result,domain FROM goals WHERE id=?", (goal_id,)).fetchone()
        binding = {"status": source[0], "updated_at": float(source[1]), "owner": source[2] or "",
                   "result": decode(source[3]) or "", "domain": source[4]} if source is not None else {}
        if (not binding or binding["owner"] != owner or binding["status"] not in {"done", "blocked", "failed"}
                or not binding["result"] or _fingerprint(binding) != revision):
            raise GoalMutationConflict("The task or answer changed. Review the current saved answer before giving feedback.")
        episode = execute("SELECT id,ended_at,summary FROM episodes WHERE goal_id=? ORDER BY started_at DESC,id DESC LIMIT 1",
                          (goal_id,)).fetchone()
        exact_episode = (episode is not None and episode[1] is not None and decode(episode[2]) == binding["result"])
        value = {"operation_id": operation_id, "actor": actor, "owner": owner, "context": context,
                 "revision": revision, "rating": rating, "note": note, "reason": reason,
                 "agent": binding["domain"] or "", "recorded_at": time.time(),
                 "episode_id": int(episode[0]) if exact_episode else None,
                 "episode_ended_at": float(episode[1]) if exact_episode else None,
                 "observation": "not_started", "replayed": False}
        _record(execute, encode, goal_id, KIND, operation_id, actor, fingerprint, value)
        return value


def observe(world, goal_id, value, *, authorize):
    """Keep an optional signal on the exact reviewed result and completed run."""
    from . import consequence
    from .logging_config import current_goal_id
    from .pilot_learning import excluded
    if value["episode_id"] is None or not consequence.enabled():
        return False
    # The request context has no running agent. Refuse inherited agent context
    # rather than let optional policy discovery open a nested world transaction.
    if current_goal_id() is not None or excluded(goal_id):
        return False
    with _transaction(world, goal_id) as (execute, _encode, decode, postgres, _tenant):
        authorize()
        source = execute("SELECT status,updated_at,owner,result,domain FROM goals WHERE id=?", (goal_id,)).fetchone()
        if source is None:
            return False
        binding = {"status": source[0], "updated_at": float(source[1]), "owner": source[2] or "", "result": decode(source[3]) or "", "domain": source[4]}
        episode = execute("SELECT id,ended_at,summary FROM episodes WHERE goal_id=? ORDER BY started_at DESC,id DESC LIMIT 1" +
                          (" FOR UPDATE" if postgres else ""), (goal_id,)).fetchone()
        if (binding["owner"] != value["owner"] or _fingerprint(binding) != value["revision"] or episode is None
                or int(episode[0]) != value["episode_id"] or episode[1] != value["episode_ended_at"]
                or decode(episode[2]) != binding["result"]):
            return False
        return consequence.record_outcome(goal_id, value["episode_id"], 1.0 if value["rating"] == "up" else 0.0,
                                          kind="feedback", source="human_feedback")


def summary_rows(world, *, owner=None):
    """Latest bounded native feedback, projected without private comments.

    Agent identity comes from the reviewed original goal, never from the client.
    Earlier receipts without that identity remain under the general/unknown group.
    """
    return summary_scan(world, owner=owner)[0]


def summary_scan(world, *, owner=None):
    """``summary_rows`` and whether the bounded read reached its limit, so some feedback may be missing."""
    from .world_model import _dec_field
    if hasattr(world, "_writing"):
        decode = _dec_field
    else:
        from .world_model_backends.postgres import _unseal
        decode = _unseal
    rows = world.query("SELECT g.id,g.owner,r.receipt FROM goals g JOIN goal_mutation_receipts r ON r.goal_id=g.id "
                       "WHERE r.kind=?" + (" AND COALESCE(g.owner,'')=?" if owner is not None else "") +
                       " ORDER BY r.created_at DESC,r.operation_id DESC LIMIT " + str(SUMMARY_LIMIT),
                       (KIND, owner) if owner is not None else (KIND,))
    latest = {}
    for row in rows:
        try:
            value = json.loads(decode(row["receipt"]))
            key = (int(row["id"]), row["owner"] or "")
            if (key in latest or value["owner"] != key[1] or value["rating"] not in {"up", "down"}
                    or type(value["recorded_at"]) not in (int, float) or not math.isfinite(value["recorded_at"])):
                continue
            latest[key] = {"goal_id": key[0], "owner": key[1], "by": value["actor"],
                           "agent": value.get("agent", ""), "rating": value["rating"],
                           "reason": value.get("reason", ""), "ts": value["recorded_at"]}
        except (KeyError, TypeError, ValueError):
            continue
    return list(latest.values()), len(rows) >= SUMMARY_LIMIT


def rated_goals(world, *, owner=None):
    """Distinct tasks in the same bounded private-free native projection."""
    return {row["goal_id"] for row in summary_rows(world, owner=owner)}


def receipt(world, goal_id, operation_id, actor):
    """Read the exact accepted request; do not append or repeat learning."""
    with _transaction(world, goal_id) as (execute, _encode, decode, _postgres, _tenant):
        row = execute("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                      (goal_id, KIND, operation_id, actor)).fetchone()
        return {**json.loads(decode(row[0])), "replayed": True} if row is not None else None


def latest(world, goal_id, owner):
    rows = world.query("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind=? ORDER BY created_at DESC LIMIT 1",
                       (goal_id, KIND))
    if not rows:
        return None
    from .world_model import _dec_field
    if hasattr(world, "_writing"):
        value = json.loads(_dec_field(rows[0]["receipt"]))
    else:
        from .world_model_backends.postgres import _unseal
        value = json.loads(_unseal(rows[0]["receipt"]))
    return value if value["owner"] == owner else None


def observed(world, goal_id, operation_id, actor, state):
    """Update follow-through for the admitted request without recording another vote."""
    if state not in {"started", "recorded", "not_recorded"}:
        raise ValueError("Invalid feedback observation state.")
    with _transaction(world, goal_id) as (execute, encode, decode, _postgres, _tenant):
        row = execute("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                      (goal_id, KIND, operation_id, actor)).fetchone()
        if row is None:
            raise RuntimeError("The original feedback receipt is unavailable.")
        value = json.loads(decode(row[0]))
        value["observation"] = state
        execute("UPDATE goal_mutation_receipts SET receipt=? WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                (encode(json.dumps(value, sort_keys=True)), goal_id, KIND, operation_id, actor))
        return value
