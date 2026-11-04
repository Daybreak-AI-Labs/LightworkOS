"""Durable goal-bound exclusion from automatic local learning.

This does not erase prior exposure, constrain a provider's training, or inspect
manually relabelled external datasets. Business history remains readable.
"""
from __future__ import annotations

import hashlib
import json

from .file_lock import atomic_create_text
from .governed_records import GovernedRecordStore
from .paths import data_dir
from .privacy_ops import RecordConflict

STORE = GovernedRecordStore("pilot_learning_exclusions", "PLE", "pilot_learning_exclusion")
MODE = "exclude_local_learning"


def _identity(goal_id):
    if isinstance(goal_id, bool) or not isinstance(goal_id, int) or goal_id < 1:
        raise ValueError("A positive goal identity is required for learning exclusion.")
    return "PLE-" + hashlib.sha256(str(goal_id).encode()).hexdigest()[:48]


def _marker(identifier):
    return data_dir("pilot_learning_exclusions", identifier + ".required")


def protect(goal_id, *, pilot_id, plan_version, input_version, actor):
    identifier = _identity(goal_id)
    expected = {"goal_id": goal_id, "pilot_id": pilot_id, "plan_version": plan_version,
                "input_version": input_version, "mode": MODE}
    previous = STORE.get(identifier)
    if previous is not None:
        if any(previous.get(key) != value for key, value in expected.items()):
            raise RecordConflict("This task already belongs to another protected evaluation plan. Prepare a new task.")
        return previous
    # If record publication fails, the retained marker still excludes local
    # capture. Failure must not make an intended holdout eligible for learning.
    try:
        atomic_create_text(_marker(identifier), "local pilot learning exclusion v1\n")
    except FileExistsError:
        pass
    try:
        return STORE.create({"id": identifier, **expected}, action="exclude_local_learning", actor=actor, max_records=100000)
    except RecordConflict:
        current = STORE.get(identifier)
        if current is None or any(current.get(key) != value for key, value in expected.items()):
            raise
        return current


def _directly_excluded(goal_id):
    identifier = _identity(goal_id)
    return STORE.get(identifier) is not None or _marker(identifier).exists()


def _excluded_ancestor(goal_id):
    from .world_model import close_world_if_owned, default_db_path, open_world
    from .world_model_backends import is_postgres_configured

    # Never create a world merely to inspect optional learning. A canonical
    # app goal can inherit its parent's policy across workers and restarts.
    if not is_postgres_configured() and not default_db_path().exists():
        return False
    world = open_world()
    try:
        seen = set()
        for _ in range(64):
            if goal_id in seen:
                return True
            seen.add(goal_id)
            goal = world.get_goal(goal_id)
            if goal is None or goal.parent_id is None:
                return False
            goal_id = goal.parent_id
            if _directly_excluded(goal_id):
                return True
        return True
    finally:
        close_world_if_owned(world)


def excluded(goal_id) -> bool:
    """Exclude a protected goal and its descendants; unreadable policy blocks."""
    if goal_id is None or goal_id == 0:
        return False
    try:
        return _directly_excluded(goal_id) or _excluded_ancestor(goal_id)
    except Exception:
        # Learning is optional; inability to inspect policy cannot admit data.
        return True


def restriction_state(goal_id) -> str:
    """Describe the effective gate without mistaking an unreadable ledger for a receipt."""
    try:
        return "excluded" if _directly_excluded(goal_id) or _excluded_ancestor(goal_id) else "permitted"
    except Exception:
        return "unavailable"


def evidence(goal_id, *, pilot_id, plan_version, input_version):
    """Read a matching policy receipt without claiming prior/external exposure."""
    try:
        record = STORE.get(_identity(goal_id))
        expected = {"goal_id": goal_id, "pilot_id": pilot_id, "plan_version": plan_version,
                    "input_version": input_version, "mode": MODE}
        valid = record is not None and all(record.get(key) == value for key, value in expected.items())
        return {"enforced": valid, "policy_id": record["id"] if valid else None,
                "policy_digest": hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest() if valid else None}
    except Exception:
        return {"enforced": False, "policy_id": None, "policy_digest": None}


def current_excluded() -> bool:
    from .logging_config import current_goal_id
    return excluded(current_goal_id())
