"""Autonomous Shoring: the engagement book of work + measured service levels.

"Shoring" moves a whole business FUNCTION (accounts payable, tier-1 support,
contract review) onto the governed agentic workforce. A shoring engagement is
sold and run against four things this module makes first-class:

* a **Book of Work** -- the functions in scope, each mapped to an operating
  department, with a scope description, an owner, target service levels, and a
  lifecycle status in {scoping, demonstrating, running, proving};
* an **SLA view** -- each function's target service levels versus the ACTUAL
  measured from real completed work (read straight from the Operating Record,
  :mod:`maverick.operating_record`), returning a met / at-risk / breached
  indicator per SLA;
* an **exception desk** -- the human sign-off queue
  (:meth:`~maverick.world_model.WorldModel.pending_approvals`) filtered to a
  shored function's department, the items awaiting a human for that function.

The book is a small governed store, NOT a world-model migration (migrations
are immutable/checksum-locked): a tenant-scoped JSON file written with the
atomic private-file helpers, mirroring :mod:`maverick.fleet_memory`. SLA and
status computation is PURE over an injected ``world`` -- no LLM, no new run
state, read-only -- so it is trivially testable and never invents a number.

On by default (``[shoring] enable`` / ``MAVERICK_SHORING``): the knob only
lets an operator turn the surface off.
"""
from __future__ import annotations

import json
import logging
import math
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import env_flag
from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_file,
)

log = logging.getLogger(__name__)

#: Lifecycle a shored function moves through: scoped -> demonstrated (the
#: demonstration-driven transition) -> running under SLA -> proving value.
LIFECYCLE = ("scoping", "demonstrating", "running", "proving")

#: The SLA metrics we can MEASURE from the Operating Record. ``direction``
#: says which way is good: ``min`` (deliver at least the target, higher is
#: better -- throughput) or ``max`` (stay under the target, lower is better --
#: exception rate). ``unit`` is display only.
METRICS: dict[str, dict[str, str]] = {
    "throughput_per_day": {"direction": "min", "unit": "/day"},
    "max_exception_rate_pct": {"direction": "max", "unit": "%"},
    "max_turnaround_hours": {"direction": "max", "unit": "h"},
}

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_MAX_TEXT = 400
_MAX_SLAS = 12
_MAX_FUNCTIONS = 500
_DEFAULT_WINDOW_DAYS = 90

# SLA banding: a ratio of actual/target. For a ``min`` metric met means the
# ratio is at/above 1.0; for a ``max`` metric met means at/below 1.0. The
# 20%/25% shoulders below give the "at-risk" amber band before "breached".
_AT_RISK_MIN = 0.8   # min metric: >= 80% of target is amber, below is red
_AT_RISK_MAX = 1.25  # max metric: <= 125% of target is amber, above is red


@dataclass
class SLATarget:
    """One named service-level target on a shored function."""
    name: str
    metric: str
    target: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Function:
    """One business function in a shoring engagement's Book of Work."""
    key: str
    name: str
    department: str = ""
    scope: str = ""
    status: str = "scoping"
    owner: str = ""
    slas: list[SLATarget] = field(default_factory=list)
    updated_at: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["slas"] = [s.to_dict() if isinstance(s, SLATarget) else s for s in self.slas]
        return d


# --------------------------------------------------------------------------- #
# The knob
# --------------------------------------------------------------------------- #
def enabled() -> bool:
    """Whether the shoring surface is on (default ON).

    Mirrors :func:`maverick.fleet_memory.enabled` in shape -- an env override
    (``MAVERICK_SHORING``) wins, else the ``[shoring] enable`` config knob --
    but shoring DEFAULTS ON.
    """
    _v = env_flag("MAVERICK_SHORING")
    if _v is not None:
        return _v
    try:
        from .config import load_config
        section = load_config().get("shoring") or {}
        value = section.get("enable", True)
        return value if isinstance(value, bool) else True
    except Exception:  # pragma: no cover -- never crash on a config read
        return True


# --------------------------------------------------------------------------- #
# The store (tenant-scoped JSON, atomic private write -- NOT a migration)
# --------------------------------------------------------------------------- #
def _dir(tenant: str | None = None) -> Path:
    from .paths import current_tenant_id, data_dir

    # Resolve the active tenant dynamically (like fleet_memory): force the
    # legacy shared root only when no tenant is active, never pin whichever
    # tenant imported this module first.
    tid = tenant if tenant is not None else current_tenant_id()
    return data_dir("shoring", tenant=tid or None)


def _book_path(tenant: str | None = None) -> Path:
    return _dir(tenant) / "book.json"


def _coerce_sla(raw: Any) -> SLATarget | None:
    if not isinstance(raw, dict):
        return None
    name = str(raw.get("name", "") or "").strip()[:_MAX_TEXT]
    metric = str(raw.get("metric", "") or "").strip()
    if not name or metric not in METRICS:
        return None
    try:
        target = float(raw.get("target", 0) or 0)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(target) or target < 0:
        return None
    return SLATarget(name=name, metric=metric, target=target)


def _coerce_function(raw: Any, *, strict: bool = False) -> Function | None:
    """Read a row defensively; strict callers must never discard damaged SLAs."""
    if not isinstance(raw, dict):
        return None
    key = str(raw.get("key", "") or "").strip()
    if not _KEY_RE.fullmatch(key):
        return None
    name = str(raw.get("name", "") or "").strip()[:_MAX_TEXT]
    if not name:
        return None
    status = str(raw.get("status", "") or "scoping")
    if status not in LIFECYCLE:
        if strict:
            return None
        status = "scoping"
    slas: list[SLATarget] = []
    raw_slas = raw.get("slas", []) if strict else raw.get("slas") or []
    if not isinstance(raw_slas, list):
        return None
    if strict and len(raw_slas) > _MAX_SLAS:
        return None
    for item in raw_slas[:_MAX_SLAS]:
        sla = _coerce_sla(item)
        if sla is not None:
            slas.append(sla)
        elif strict:
            return None
    try:
        updated_at = float(raw.get("updated_at", 0) or 0)
    except (TypeError, ValueError):
        if strict:
            return None
        updated_at = 0.0
    if not math.isfinite(updated_at):
        return None
    return Function(
        key=key, name=name,
        department=str(raw.get("department", "") or "").strip()[:_MAX_TEXT],
        scope=str(raw.get("scope", "") or "").strip()[:_MAX_TEXT],
        status=status,
        owner=str(raw.get("owner", "") or "").strip()[:_MAX_TEXT],
        slas=slas, updated_at=updated_at,
    )


def load(tenant: str | None = None, *, strict: bool = False) -> list[Function]:
    """The Book of Work for the active (or given) tenant, newest-edited first.

    Tenant-isolated: two tenants never see each other's book (the path is under
    ``data_dir("shoring", tenant=...)``). A missing book is empty. Strict reads
    reject unreadable or malformed records; recovery callers may opt into the
    permissive default, which returns the rows that can still be understood.
    """
    path = _book_path(tenant)
    if not path.exists():
        return []
    try:
        ensure_private_file(path)
        raw = json.loads(atomic_read_text(path))
    except (OSError, ValueError) as exc:
        if strict:
            raise RuntimeError("shoring book is unreadable; restore it before editing") from exc
        return []
    if strict and not isinstance(raw, list):
        raise RuntimeError("shoring book has an invalid structure; restore it before editing")
    rows = raw if isinstance(raw, list) else []
    out: list[Function] = []
    for row in rows:
        fn = _coerce_function(row, strict=strict)
        if fn is not None:
            out.append(fn)
        elif strict:
            raise RuntimeError("shoring book contains an invalid function; repair it before editing")
    if strict and len({f.key for f in out}) != len(out):
        raise RuntimeError("shoring book contains duplicate function keys; repair it before editing")
    out.sort(key=lambda f: f.updated_at, reverse=True)
    return out


def save(functions: list[Function], tenant: str | None = None) -> None:
    """Atomically persist the whole book (0600, private parent)."""
    path = _book_path(tenant)
    if len(functions) > _MAX_FUNCTIONS:
        raise ValueError(f"shoring book capacity is {_MAX_FUNCTIONS} functions")
    payload = [f.to_dict() for f in functions]
    with cross_process_lock(path, strict=True):
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True, allow_nan=False))


def upsert(function: Function, tenant: str | None = None) -> Function:
    """Create or replace a function by ``key``; returns the stored row.

    Stamps ``updated_at`` so the book orders by most-recently-touched.
    """
    if not _KEY_RE.fullmatch(function.key or ""):
        raise ValueError(
            "function key must be a slug ([a-z0-9][a-z0-9_-]{0,63})")
    if not function.name.strip():
        raise ValueError("function name must not be blank")
    with cross_process_lock(_book_path(tenant), strict=True):
        book = load(tenant, strict=True)
        book = [f for f in book if f.key != function.key]
        if len(book) >= _MAX_FUNCTIONS:
            raise ValueError(f"shoring book capacity is {_MAX_FUNCTIONS} functions")
        function.updated_at = time.time()
        book.append(function)
        save(book, tenant)
    return function


def remove(key: str, tenant: str | None = None) -> bool:
    """Drop a function from the book. Returns whether a row was removed."""
    with cross_process_lock(_book_path(tenant), strict=True):
        book = load(tenant, strict=True)
        kept = [f for f in book if f.key != key]
        if len(kept) == len(book):
            return False
        save(kept, tenant)
        return True


# --------------------------------------------------------------------------- #
# SLA + status computation (pure, read-only over an injected world)
# --------------------------------------------------------------------------- #
def _measure(department: str, world: Any, *, window_days: int,
             now: float | None = None, owner: str | None = None) -> dict:
    """Department totals; old embedders retain a visibly bounded fallback."""
    if not isinstance(window_days, int) or isinstance(window_days, bool) or window_days < 1:
        raise ValueError("window_days must be a positive integer")
    evaluated_at = now if now is not None else time.time()
    if not math.isfinite(evaluated_at):
        raise ValueError("now must be finite")
    cutoff = evaluated_at - window_days * 86400
    aggregate = getattr(world, "shoring_measurements", None)
    if callable(aggregate):
        try:
            m = aggregate(department, since=cutoff, until=evaluated_at, **({"owner": owner} if owner is not None else {}))
        except Exception as exc:
            raise RuntimeError("shoring measurements are unavailable; retry after restoring the work store") from exc
        completed = m["delivered"] + m["blocked"]
        return {
            **m, "department": department, "window_days": window_days, "completed": completed,
            "throughput_per_day": m["delivered"] / window_days,
            "exception_rate_pct": 100.0 * m["blocked"] / completed if completed else 0.0,
        }
    delivered = blocked = in_flight = 0
    try:
        goals = world.list_goals(domain=department, limit=2001, order="desc", **({"owner": owner} if owner is not None else {}))
    except Exception as exc:
        raise RuntimeError("shoring measurements are unavailable; retry after restoring the work store") from exc
    complete = len(goals) <= 2000
    for r in goals[:2000]:
        timestamp = getattr(r, "updated_at", 0) or 0
        if getattr(r, "domain", "") != department or not timestamp or not cutoff <= timestamp <= evaluated_at:
            continue
        outcome = (getattr(r, "status", "") or "").lower()
        if outcome == "done":
            delivered += 1
        elif outcome in ("blocked", "cancelled", "failed", "error"):
            blocked += 1
        else:
            in_flight += 1
    completed = delivered + blocked
    return {
        "department": department,
        "window_days": window_days,
        "delivered": delivered,
        "blocked": blocked,
        "in_flight": in_flight,
        "completed": completed,
        "measurement_complete": complete,
        "turnaround_measurement_complete": False,
        "max_turnaround_hours": None,
        "legacy_completion_count": delivered,
        "throughput_per_day": (delivered / window_days) if window_days else 0.0,
        "exception_rate_pct": (100.0 * blocked / completed) if completed else 0.0,
    }


def _band(metric: str, target: float, actual: float | None) -> str:
    """met / at_risk / breached / no_data for one SLA."""
    if actual is None:
        return "no_data"
    if target < 0:
        return "no_data"
    if target == 0:
        direction = METRICS.get(metric, {}).get("direction", "min")
        return "met" if direction == "min" or actual == 0 else "breached"
    ratio = actual / target
    direction = METRICS.get(metric, {}).get("direction", "min")
    if direction == "max":
        if ratio <= 1.0:
            return "met"
        return "at_risk" if ratio <= _AT_RISK_MAX else "breached"
    # min: higher is better
    if ratio >= 1.0:
        return "met"
    return "at_risk" if ratio >= _AT_RISK_MIN else "breached"


def sla_status(function: Function, world: Any, *,
               window_days: int = _DEFAULT_WINDOW_DAYS,
               now: float | None = None) -> list[dict]:
    """Per-SLA target-vs-actual with a met/at-risk/breached indicator.

    Actuals come from real completed work in the Operating Record, scoped to
    the function's department. A metric with no measurable data (or a function
    with no completed work) reports ``no_data`` rather than a false breach.
    """
    m = _measure(function.department, world, window_days=window_days, now=now)
    return _sla_rows(function, m)


def _sla_rows(function: Function, m: dict) -> list[dict]:
    out: list[dict] = []
    for sla in function.slas:
        metric = sla.metric
        if not m["measurement_complete"]:
            actual: float | None = None
        elif metric == "throughput_per_day":
            actual = m["throughput_per_day"] if m["completed"] else None
        elif metric == "max_exception_rate_pct":
            actual = m["exception_rate_pct"] if m["completed"] else None
        elif metric == "max_turnaround_hours":
            actual = m["max_turnaround_hours"] if m["turnaround_measurement_complete"] else None
        else:
            actual = None
        status = _band(metric, sla.target, actual)
        out.append({
            "name": sla.name,
            "metric": metric,
            "unit": METRICS.get(metric, {}).get("unit", ""),
            "target": round(float(sla.target), 2),
            "actual": round(actual, 2) if actual is not None else None,
            "status": status,
        })
    return out


_STATUS_RANK = {"breached": 3, "at_risk": 2, "met": 1, "no_data": 0}


def _matches_department(approval: Any, department: str) -> bool:
    """Match the department recorded from trusted goal context at creation.

    Free text can mention other teams or be model supplied. Legacy and
    goal-less approvals stay in the shared queue as unassigned; never guess.
    """
    return bool(department) and getattr(approval, "department", "") == department


def exceptions_for(function: Function, approvals: list) -> list[dict]:
    """The pending approvals awaiting human sign-off for this function.

    ``approvals`` is a list of pending approval rows
    (``world.pending_approvals()``); this is the exception-desk lens over that
    shared queue -- it never forks the approval logic, only filters it.
    """
    out: list[dict] = []
    for a in approvals:
        if not _matches_department(a, function.department):
            continue
        out.append({
            "id": getattr(a, "id", None),
            "action": getattr(a, "action", ""),
            "risk": getattr(a, "risk", ""),
            "scope": getattr(a, "scope", None),
            "detail": getattr(a, "detail", None),
            "requested_at": getattr(a, "requested_at", None),
            "goal_id": getattr(a, "goal_id", None),
        })
    return out


def function_status(function: Function, world: Any, *,
                    window_days: int = _DEFAULT_WINDOW_DAYS,
                    now: float | None = None, owner: str | None = None) -> dict:
    """One function's full status card: measured throughput, per-SLA
    indicators, the exception-desk count, and a rolled-up overall indicator
    (the worst SLA band)."""
    m = _measure(function.department, world, window_days=window_days, now=now, owner=owner)
    slas = _sla_rows(function, m)
    try:
        pending = list(world.pending_approvals())
        if owner is not None:
            pending = [a for a in pending if (a.requested_by or "") == owner
                       and (not a.goal_id or getattr(world.get_goal(a.goal_id), "owner", None) == owner)]
    except Exception as exc:
        raise RuntimeError("shoring exception desk is unavailable; retry after restoring the work store") from exc
    exceptions = exceptions_for(function, pending)
    graded = [s for s in slas if s["status"] != "no_data"]
    overall = max((s["status"] for s in graded),
                  key=lambda s: _STATUS_RANK[s], default="no_data")
    return {
        "key": function.key,
        "name": function.name,
        "department": function.department,
        "scope": function.scope,
        "lifecycle": function.status,
        "owner": function.owner,
        "delivered": m["delivered"],
        "blocked": m["blocked"],
        "in_flight": m["in_flight"],
        "throughput_per_day": round(m["throughput_per_day"], 2),
        "exception_rate_pct": round(m["exception_rate_pct"], 1),
        "window_days": window_days,
        "measurement_complete": m["measurement_complete"],
        "turnaround_measurement_complete": m["turnaround_measurement_complete"],
        "max_turnaround_hours": m["max_turnaround_hours"],
        "legacy_completion_count": m["legacy_completion_count"],
        "slas": slas,
        "exceptions": exceptions,
        "exception_count": len(exceptions),
        "unassigned_exception_count": sum(1 for a in pending if not getattr(a, "department", "")),
        "overall": overall,
    }


def book_status(world: Any, *, tenant: str | None = None,
                window_days: int = _DEFAULT_WINDOW_DAYS,
                now: float | None = None, owner: str | None = None) -> list[dict]:
    """Every function in the book with its computed status (the page/API feed)."""
    return [
        function_status(fn, world, window_days=window_days, now=now, owner=owner)
        for fn in load(tenant, strict=True)
    ]


__all__ = [
    "LIFECYCLE", "METRICS", "SLATarget", "Function", "enabled",
    "load", "save", "upsert", "remove",
    "sla_status", "exceptions_for", "function_status", "book_status",
]
