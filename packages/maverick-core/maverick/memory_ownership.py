"""Resolve content ownership independently of a task's execution capability."""
from __future__ import annotations


def current_owner(*, world=None, goal_id=None) -> str:
    from .logging_config import current_goal_id
    from .world_model import close_world_if_owned, open_world

    goal_id = current_goal_id() if goal_id is None else goal_id
    if not goal_id:
        return ""  # explicit local/unowned scope, never all named employees
    owned = world is None
    world = open_world() if owned else world
    try:
        goal = world.get_goal(goal_id)
        if goal is None or not isinstance(getattr(goal, "owner", None), str):
            raise ValueError("Current memory ownership is unavailable")
        return goal.owner
    finally:
        if owned:
            close_world_if_owned(world)


def source_allowed(goal_id, owner: str, *, world=None) -> bool:
    """A source must still exist, retain its owner and permit local learning."""
    from .pilot_learning import excluded
    if not goal_id:
        return owner == ""  # new explicitly local records only
    try:
        return not excluded(goal_id) and current_owner(world=world, goal_id=goal_id) == owner
    except Exception:
        return False
