"""Whose work the value pages count, and what each role is told.

Overview, Spend and Savings count the signed-in person's own tasks. A
read-only role (auditor, viewer, an executive role without ``operate``) runs
no tasks of its own, so own-task numbers would always read zero. For those
roles the same pages count the whole workspace -- totals only, the reads the
value pages already allow anyone with ``view`` (see ``value_proof_api``).
Task titles, results and per-task rows are never part of that view; they stay
with the people allowed to open the tasks. Department-scoped callers never
reach these pages (``require_unscoped_board``).
"""
from __future__ import annotations

from typing import Any

OWN = "own"
WORKSPACE = "workspace"
#: Per-task content a whole-workspace board must not carry.
_TASK_CONTENT = {"overview": ("recent",), "spend": ("per_run", "top_goals")}


def value_scope(request: Any) -> dict[str, Any]:
    """``scope`` ("own" or "workspace"), the ``owner`` filter to count with,
    and whether the caller can start tasks (``can_operate``)."""
    from .auth import goal_owner_filter, has_permission

    if has_permission(request, "operate"):
        return {"scope": OWN, "owner": goal_owner_filter(request), "can_operate": True}
    return {"scope": WORKSPACE, "owner": None, "can_operate": False}


def without_task_content(board: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Drop the per-task rows from a whole-workspace board payload."""
    for key in _TASK_CONTENT.get(board, ()):
        payload[key] = []
    return payload


def assumptions_confirmed() -> bool:
    """Whether someone entered the savings numbers (hourly cost, hours per
    task) rather than leaving Lightwork's starting values in place."""
    from maverick.config import load_config, load_global_config

    for loaded in (load_global_config(), load_config()):
        value = (loaded or {}).get("value")
        if isinstance(value, dict) and (
            "hourly_rate" in value or "hours_per_task" in value or value.get("departments")
        ):
            return True
    return False


__all__ = ["OWN", "WORKSPACE", "assumptions_confirmed", "value_scope", "without_task_content"]
