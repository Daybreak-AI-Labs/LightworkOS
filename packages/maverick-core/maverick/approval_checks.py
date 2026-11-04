"""A record of every approval check, for previewing a threshold change later.

Each time the approval gate (:mod:`maverick.safety.consent`) decides an
action, one row says when, in which workspace, at which risk level, what kind
of action, which agent or specialist was working, and the outcome: allowed
without asking, asked a person, or refused. Never the content, the arguments
or the command. The rows live in the world database (``approval_checks``),
so a Postgres deployment shares them across replicas.

Configuration (``[approval]``)::

    record_checks = true          # default on
    check_retention_days = 90     # older rows are pruned in bounded batches

Recording never changes a decision: a failure to record is logged and the
gate's answer stands.
"""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from typing import Any

from .config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS

log = logging.getLogger(__name__)

SQLITE_SCHEMA: list[str] = [
    "CREATE TABLE IF NOT EXISTS approval_checks ("
    " id TEXT PRIMARY KEY, workspace TEXT NOT NULL DEFAULT '',"
    " checked_at REAL NOT NULL, risk TEXT NOT NULL DEFAULT '',"
    " action_kind TEXT NOT NULL DEFAULT '', agent TEXT NOT NULL DEFAULT '',"
    " outcome TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_approval_checks_when"
    " ON approval_checks(workspace, checked_at)",
]
POSTGRES_SCHEMA: list[str] = [s.replace(" REAL", " DOUBLE PRECISION") for s in SQLITE_SCHEMA]

OUTCOMES = ("allowed", "asked", "refused")
DEFAULT_RETENTION_DAYS = INTEGER_SETTINGS["approval.check_retention_days"].default
MAX_RETENTION_DAYS = INTEGER_SETTINGS["approval.check_retention_days"].maximum
PRUNE_BATCH = 500
_PRUNE_EVERY_SECONDS = 600.0
_RISKS = frozenset({"low", "medium", "high", "critical"})
# A kind of action is a short identifier ("shell", "email.send"); anything
# else is recorded as "other" so free text can never land here.
_KIND = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
# Decision sources where a person was asked (or the request waited for one).
_ASKED = frozenset({"prompt", "dashboard", "dashboard-stale", "task-stopped", "no-decision"})

_pruned_at: dict[str, float] = {}
_prune_lock = threading.Lock()


def _approval_section() -> dict:
    try:
        from .config import load_config

        section = (load_config() or {}).get("approval") or {}
    except Exception:  # noqa: BLE001 -- unreadable config keeps the defaults
        return {}
    return section if isinstance(section, dict) else {}


def enabled() -> bool:
    """``[approval] record_checks``; on unless set to false."""
    value = _approval_section().get("record_checks")
    return value if isinstance(value, bool) else BOOLEAN_SETTINGS["approval.record_checks"].default


def validate_retention_days(value: object) -> int:
    """A whole number of days from 1 to 3650."""
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("must be a whole number of days")
    if not INTEGER_SETTINGS["approval.check_retention_days"].minimum <= value <= MAX_RETENTION_DAYS:
        raise ValueError(f"must be from 1 to {MAX_RETENTION_DAYS} days")
    return value


def retention_days() -> int:
    """``[approval] check_retention_days``; the default when unset or unreadable."""
    raw = _approval_section().get("check_retention_days")
    if raw is None:
        return DEFAULT_RETENTION_DAYS
    try:
        return validate_retention_days(raw)
    except ValueError:
        return DEFAULT_RETENTION_DAYS


def outcome_for(granted: bool, source: str) -> str:
    """allowed / asked / refused, from the gate's decision and its source."""
    if source in _ASKED:
        return "asked"
    return "allowed" if granted else "refused"


def _is_sqlite(world: Any) -> bool:
    return hasattr(world, "_writing")


def _write(world: Any, sql: str, params: tuple = ()) -> None:
    if _is_sqlite(world):
        with world._writing() as conn:
            conn.execute(sql, params)
        return
    with world._tx() as cur:
        cur.execute(sql.replace("?", "%s"), params)


def _rows(world: Any, sql: str, params: tuple = ()) -> list[dict]:
    # PostgresWorldModel has no _read_all; this reads through a cursor there.
    from .webhook_subscriptions import _rows as read_rows

    return read_rows(world, sql, params)


def _workspace() -> str:
    from .webhook_subscriptions import workspace_id

    return workspace_id()


def _agent(world: Any) -> str:
    """The specialist or agent working on the current task, by name only."""
    from .logging_config import current_goal_id

    goal_id = current_goal_id()
    if goal_id is None:
        return ""
    try:
        goal = world.get_goal(int(goal_id))
    except Exception:  # noqa: BLE001 -- a vanished task records no name
        return ""
    if goal is None:
        return ""
    name = str(getattr(goal, "domain", "") or "") or str(getattr(goal, "execution_principal", "") or "")
    return name if _KIND.fullmatch(name) else ""


def record_check(world: Any, *, risk: str, action: str, outcome: str,
                 agent: str = "", now: float | None = None) -> None:
    """Add one row. Only fixed words and identifiers are stored."""
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown outcome: {outcome!r}")
    risk = str(risk or "").lower()
    kind = str(action or "")
    _write(world, "INSERT INTO approval_checks(id, workspace, checked_at, risk, action_kind, agent,"
                  " outcome) VALUES(?,?,?,?,?,?,?)",
           ("apc_" + uuid.uuid4().hex, _workspace(), time.time() if now is None else float(now),
            risk if risk in _RISKS else "", kind if _KIND.fullmatch(kind) else "other",
            agent if _KIND.fullmatch(agent or "") else "", outcome))


def prune(world: Any, *, now: float | None = None, days: int | None = None,
          batch: int = PRUNE_BATCH) -> int:
    """Delete at most ``batch`` of this workspace's rows older than the
    retention period. Returns how many were deleted."""
    cutoff = (time.time() if now is None else float(now)) - 86_400.0 * (days or retention_days())
    workspace = _workspace()
    old = _rows(world, "SELECT id FROM approval_checks WHERE workspace = ? AND checked_at < ?"
                       " ORDER BY checked_at LIMIT ?", (workspace, cutoff, int(batch)))
    ids = [row["id"] for row in old]
    if ids:
        marks = ",".join("?" * len(ids))
        _write(world, f"DELETE FROM approval_checks WHERE workspace = ? AND id IN ({marks})",
               (workspace, *ids))
    return len(ids)


def _prune_due(workspace: str, now: float) -> bool:
    with _prune_lock:
        if now - _pruned_at.get(workspace, 0.0) < _PRUNE_EVERY_SECONDS:
            return False
        _pruned_at[workspace] = now
        return True


def record_decision(*, risk: str, action: str, granted: bool, source: str) -> None:
    """Called by the approval gate for every decision it returns. Never raises."""
    try:
        if not enabled():
            return
        from .world_model import close_world_if_owned, open_world

        world = open_world()
        try:
            record_check(world, risk=risk, action=action, outcome=outcome_for(granted, source),
                         agent=_agent(world))
            if _prune_due(_workspace(), time.time()):
                prune(world)
        finally:
            close_world_if_owned(world)
    except Exception as exc:  # noqa: BLE001 -- recording never changes a decision
        log.warning("approval check not recorded: %s", type(exc).__name__)


def checks_since(world: Any, since: float, *, limit: int = 10_000) -> list[dict]:
    """This workspace's recorded checks at or after ``since``, oldest first:
    ``{checked_at, risk, action_kind, agent, outcome}``."""
    rows = _rows(world, "SELECT checked_at, risk, action_kind, agent, outcome FROM approval_checks"
                        " WHERE workspace = ? AND checked_at >= ? ORDER BY checked_at, id LIMIT ?",
                 (_workspace(), float(since), int(limit)))
    return [{"checked_at": float(r["checked_at"]), "risk": r["risk"], "action_kind": r["action_kind"],
             "agent": r["agent"], "outcome": r["outcome"]} for r in rows]


def tally_since(world: Any, since: float) -> list[dict]:
    """This workspace's checks at or after ``since``, counted by risk, agent
    and outcome: ``{risk, agent, outcome, checks}``. Bounded by the few risk
    levels and outcomes times the agents and specialists, whatever the volume."""
    rows = _rows(world, "SELECT risk, agent, outcome, COUNT(*) AS checks FROM approval_checks"
                        " WHERE workspace = ? AND checked_at >= ? GROUP BY risk, agent, outcome",
                 (_workspace(), float(since)))
    return [{"risk": r["risk"], "agent": r["agent"], "outcome": r["outcome"], "checks": int(r["checks"])}
            for r in rows]


def first_check_at(world: Any) -> float | None:
    """When this workspace's oldest kept check was recorded, or None."""
    rows = _rows(world, "SELECT MIN(checked_at) AS first FROM approval_checks WHERE workspace = ?",
                 (_workspace(),))
    first = rows[0]["first"] if rows else None
    return None if first is None else float(first)


__all__ = ["DEFAULT_RETENTION_DAYS", "OUTCOMES", "checks_since", "enabled", "first_check_at",
           "outcome_for", "prune", "record_check", "record_decision", "retention_days",
           "tally_since", "validate_retention_days"]
