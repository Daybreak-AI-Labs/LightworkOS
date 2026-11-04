"""Assumption-based savings estimates from completed task counts.

The question this answers is "what did this save?" The platform records
completed episodes (with recorded runtime pricing) in the world model,
attributed to departments -- but the human side of the comparison comes from
the operator's own assumptions, not from the platform. This module joins the
two:

  * The operator's own assumptions (``[value]`` in config, editable from the
    dashboard Savings page or the installer wizard): fully-loaded human
    hourly rate, human hours one comparable deliverable takes, with optional
    per-department overrides (legal != support).
  * Real throughput/spend from :mod:`maverick.workforce_value` (read-only,
    fail-open): completed tasks and recorded runtime cost per department.

  savings = (deliverables x hours_per_task x hourly_rate) - agent_cost

Descriptive only -- it never tunes anything (cost pressure must not defund
safety); pure read path, no LLM, no new state. Fail-open: with no run history
the report says zero. Customer acceptance, observed baseline effort, human
review/rework and provider invoice reconciliation are separate evidence;
this arithmetic alone does not establish realized savings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import workforce_value
from .config import get_value


@dataclass
class DepartmentSavings:
    department: str
    deliverables: int = 0
    agent_cost: float = 0.0
    hourly_rate: float = 0.0
    hours_per_task: float = 0.0

    @property
    def human_hours(self) -> float:
        return self.deliverables * self.hours_per_task

    @property
    def human_cost(self) -> float:
        return self.human_hours * self.hourly_rate

    @property
    def saved(self) -> float:
        return self.human_cost - self.agent_cost


@dataclass
class SavingsReport:
    available: bool = True
    incomplete: bool = False
    unavailable_reason: str = ""
    window_days: int = 0
    currency: str = "USD"
    hourly_rate: float = 0.0
    hours_per_task: float = 0.0
    deliverables: int = 0
    agent_cost: float = 0.0
    human_hours: float = 0.0
    human_cost: float = 0.0
    by_department: list[DepartmentSavings] = field(default_factory=list)

    @property
    def saved(self) -> float:
        return self.human_cost - self.agent_cost

    @property
    def roi_multiple(self) -> float:
        return self.human_cost / self.agent_cost if self.agent_cost else 0.0


def assumptions_for(dept: str, cfg: dict | None = None) -> tuple[float, float]:
    """The (hourly_rate, hours_per_task) that price ``dept``: the operator's
    per-department override when one exists, else their global assumption."""
    v = cfg if cfg is not None else get_value()
    ov = (v.get("departments") or {}).get(dept)
    if isinstance(ov, dict):
        return (float(ov.get("hourly_rate", v["hourly_rate"])),
                float(ov.get("hours_per_task", v["hours_per_task"])))
    return float(v["hourly_rate"]), float(v["hours_per_task"])


def compute(world: Any, *, window_days: int = 90,
            cfg: dict | None = None, now: float | None = None, owner: str | None = None) -> SavingsReport:
    """Assemble the savings report from real completed work (read-only).

    ``cfg`` is a pre-loaded ``get_value()`` dict (tests inject one); omitted,
    the operator's live config is read. An unreadable world produces an explicit
    unavailable report, without claiming zero activity or savings.
    """
    v = cfg if cfg is not None else get_value()
    if str(v.get("currency", "USD")).upper() != "USD":
        return SavingsReport(window_days=window_days, available=False,
            unavailable_reason="Recorded runtime costs are in USD. Review and enter your assumptions in USD before comparing costs; no exchange rate has been assumed.")

    def _cost_for(dept: str) -> float:
        rate, hours = assumptions_for(dept, v)
        return rate * hours

    wv = workforce_value.compute(world, window_days=window_days,
                                 human_cost_for=_cost_for, now=now, owner=owner)
    out = SavingsReport(
        available=wv.available, incomplete=wv.incomplete, unavailable_reason=wv.unavailable_reason,
        window_days=window_days,
        currency=str(v.get("currency", "USD")),
        hourly_rate=float(v["hourly_rate"]),
        hours_per_task=float(v["hours_per_task"]),
        deliverables=wv.deliverables,
        agent_cost=wv.agent_cost,
        human_cost=wv.human_baseline,
    )
    for d in wv.by_department:
        rate, hours = assumptions_for(d.department, v)
        ds = DepartmentSavings(
            department=d.department, deliverables=d.deliverables,
            agent_cost=d.agent_cost, hourly_rate=rate, hours_per_task=hours)
        out.by_department.append(ds)
        out.human_hours += ds.human_hours
    out.by_department.sort(key=lambda d: d.saved, reverse=True)
    return out


def to_dict(r: SavingsReport) -> dict:
    if not r.available:
        return {"available": False, "incomplete": True, "unavailable_reason": r.unavailable_reason,
                "currency": "USD", "window_days": r.window_days, "by_department": [],
                "assumptions": {"hourly_rate": None, "hours_per_task": None},
                **dict.fromkeys(("deliverables", "agent_cost", "human_hours", "human_cost", "saved", "roi_multiple"))}
    return {
        "available": True, "incomplete": r.incomplete, "unavailable_reason": "",
        "window_days": r.window_days,
        "currency": r.currency,
        "assumptions": {
            "hourly_rate": round(r.hourly_rate, 2),
            "hours_per_task": round(r.hours_per_task, 2),
        },
        "deliverables": r.deliverables,
        "agent_cost": round(r.agent_cost, 2),
        "human_hours": round(r.human_hours, 2),
        "human_cost": round(r.human_cost, 2),
        "saved": round(r.saved, 2),
        "roi_multiple": round(r.roi_multiple, 2),
        "by_department": [
            {
                "department": d.department,
                "deliverables": d.deliverables,
                "agent_cost": round(d.agent_cost, 2),
                "hourly_rate": round(d.hourly_rate, 2),
                "hours_per_task": round(d.hours_per_task, 2),
                "human_hours": round(d.human_hours, 2),
                "human_cost": round(d.human_cost, 2),
                "saved": round(d.saved, 2),
            }
            for d in r.by_department
        ],
    }


__all__ = ["DepartmentSavings", "SavingsReport", "assumptions_for",
           "compute", "to_dict"]
