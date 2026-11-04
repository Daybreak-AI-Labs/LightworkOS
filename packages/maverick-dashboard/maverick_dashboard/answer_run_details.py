"""Recorded price and elapsed time for the native run matching a saved answer."""
from __future__ import annotations

import math
from decimal import Decimal

from .auth import assert_goal_access, require_permission

_SQL = "SELECT id,started_at,ended_at,summary,cost_dollars FROM episodes WHERE goal_id=? ORDER BY started_at DESC,id DESC LIMIT 1"


def _episode(world, goal_id):
    from maverick.crypto_at_rest import EncryptionUnavailable

    if hasattr(world, "_writing"):
        from sqlite3 import DatabaseError

        from maverick.world_model import _dec_field as decode
    else:
        try:
            from maverick.world_model_backends.postgres import _unseal as decode
            from psycopg import Error as DatabaseError
        except ImportError:
            return None
    try:
        rows = world.query(_SQL, (goal_id,))
        if not rows:
            return None
        row = rows[0]
        # Optional figures must not break an otherwise readable saved answer.
        for key in ("id", "started_at", "ended_at", "cost_dollars"):
            row[key]
        return row, decode(row["summary"])
    except (DatabaseError, EncryptionUnavailable, LookupError, TypeError, ValueError, OSError):
        return None


def _identity(goal):
    return (goal.id, goal.owner or "", goal.domain, goal.status, float(goal.updated_at), goal.result)


def _number(value):
    if type(value) not in {int, float, Decimal}:
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _price(value):
    amount = _number(value)
    if amount is None:
        return None, "Recorded runtime price unavailable"
    if 0 < amount < 0.000001:
        return amount, "Recorded runtime price: less than USD 0.000001"
    shown = f"{amount:,.6f}".rstrip("0").rstrip(".")
    if "." not in shown:
        shown += ".00"
    return amount, "Recorded runtime price: USD " + shown


def _elapsed(seconds):
    if seconds < 1:
        return "Less than 1 second"
    whole = int(seconds)
    hours, rest = divmod(whole, 3600)
    minutes, remainder = divmod(rest, 60)
    parts = ([str(hours) + " hr"] if hours else []) + ([str(minutes) + " min"] if minutes else [])
    if remainder or not parts:
        parts.append(str(remainder) + " sec")
    return " ".join(parts)


def read(request, world, goal_id, *, expected_goal=None):
    """Return no footer when retained run evidence cannot describe this answer."""
    require_permission(request, "view")
    goal = world.get_goal(goal_id)
    if goal is None:
        return None
    assert_goal_access(request, goal)
    if (goal.status != "done" or not goal.result
            or expected_goal is not None and _identity(expected_goal) != _identity(goal)):
        return None
    evidence = _episode(world, goal_id)
    if evidence is None:
        return None
    row, summary = evidence
    started, ended = _number(row["started_at"]), _number(row["ended_at"])
    if started is None or ended is None or ended < started or summary != goal.result:
        return None
    price, price_text = _price(row["cost_dollars"])
    fresh = world.get_goal(goal_id)
    if fresh is None:
        return None
    assert_goal_access(request, fresh)
    latest = _episode(world, goal_id)
    columns = ("id", "started_at", "ended_at", "summary", "cost_dollars")
    if (_identity(fresh) != _identity(goal) or latest is None or latest[1] != fresh.result
            or any(latest[0][key] != row[key] for key in columns)):
        return None
    seconds = ended - started
    return {"price": price, "price_text": price_text, "elapsed_seconds": seconds,
            "elapsed_text": "Elapsed including waiting: " + _elapsed(seconds),
            "scope": "This matching run only. Recorded runtime price is not a provider invoice and excludes separate external charges."}
