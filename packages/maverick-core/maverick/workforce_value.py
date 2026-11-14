"""Descriptive workforce signals and assumption-based value estimates.

Completed episodes and recorded runtime prices do not establish accepted
customer outcomes, realized savings, or provider invoice accuracy. Those
require separate measured baseline, review, and cost evidence.

The platform's compounding advantage (it improves with use, safely) is real
but latent -- buried across budget receipts, episode history, the hindsight
ledger, and the signed audit log. This assembles those existing signals into
one deterministic, read-only report per department:

  * **Throughput**   -- deliverables completed (done episodes), per suite.
  * **Economics**    -- agent cost vs a human-baseline cost per deliverable
    (operator-set), i.e. cost avoided. Descriptive only -- it never tunes
    anything away (cost pressure must not defund
    safety).
  * **Compounding**  -- the improvement curve from the hindsight ledger
    (coverage trend over snapshots): "better than 90 days ago, here's the
    slope."
  * **Governance**   -- policy adherence from the audit log (gates honored,
    chain verifiable): the workforce stayed in-policy while doing it.

Nothing here changes agent behavior or autonomy -- it only measures. Pure
read path, no LLM, no new state; fail-open (a missing signal degrades to
"n/a", never an error). Opt-in CLI: ``maverick proof``.
"""
from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# A conservative default for the fully-loaded human cost of one comparable
# deliverable, used only when the operator doesn't set their own. Deliberately
# low so the ROI claim is defensible, not inflated.
DEFAULT_HUMAN_COST_PER_DELIVERABLE = 50.0

_DONE = {"success", "succeeded", "done", "complete", "completed", "ok", "passed"}


@dataclass
class DepartmentValue:
    department: str
    deliverables: int = 0
    agent_cost: float = 0.0
    human_baseline: float = 0.0

    @property
    def cost_avoided(self) -> float:
        return self.human_baseline - self.agent_cost

    @property
    def cost_per_deliverable(self) -> float:
        return self.agent_cost / self.deliverables if self.deliverables else 0.0


@dataclass
class WorkforceValue:
    available: bool = True
    incomplete: bool = False
    unavailable_reason: str = ""
    window_days: int = 0
    deliverables: int = 0
    agent_cost: float = 0.0
    human_baseline: float = 0.0
    by_department: list[DepartmentValue] = field(default_factory=list)
    coverage_trend: list[tuple[str, int]] = field(default_factory=list)  # (label, covered)
    governance: dict = field(default_factory=dict)

    @property
    def cost_avoided(self) -> float:
        return self.human_baseline - self.agent_cost

    @property
    def roi_multiple(self) -> float:
        return self.human_baseline / self.agent_cost if self.agent_cost else 0.0

    @property
    def improvement(self) -> int | None:
        """Coverage delta from the first to the last point of the curve, or
        None when there isn't enough history to claim a trend."""
        if len(self.coverage_trend) < 2:
            return None
        return self.coverage_trend[-1][1] - self.coverage_trend[0][1]


def _is_done(outcome: str | None) -> bool:
    return (outcome or "").strip().lower() in _DONE


def _department_of(world: Any, goal_id: int, cache: dict[int, str]) -> str:
    if goal_id in cache:
        return cache[goal_id]
    dept = ""
    try:
        g = world.get_goal(goal_id)
        dept = (getattr(g, "domain", "") or "") if g else ""
    except Exception:  # pragma: no cover -- a read miss is just "(unattributed)"
        dept = ""
    cache[goal_id] = dept or "(unattributed)"
    return cache[goal_id]


def compute(
    world: Any, *, window_days: int = 90, human_cost: float | None = None,
    human_cost_for: Any = None, episode_limit: int = 5000,
    now: float | None = None, owner: str | None = None,
) -> WorkforceValue:
    """Assemble the workforce value report from existing signals (read-only).

    ``human_cost`` is the operator's fully-loaded cost of one comparable
    human deliverable (defaults conservative). ``human_cost_for`` is an optional
    callable ``(department) -> float`` that overrides ``human_cost`` per
    department -- how the savings dashboard prices legal work differently from
    support (rate x hours per department). An unreadable cost population is
    explicitly unavailable, and a callable that raises falls back to the flat
    ``human_cost``.
    """
    ts_now = now if now is not None else time.time()
    cutoff = ts_now - window_days * 86400.0
    hc = DEFAULT_HUMAN_COST_PER_DELIVERABLE if human_cost is None else float(human_cost)

    def _human_cost(dept: str) -> float:
        if human_cost_for is None:
            return hc
        try:
            return float(human_cost_for(dept))
        except Exception:  # pragma: no cover -- a bad override never breaks the report
            return hc

    out = WorkforceValue(window_days=window_days)

    depts: dict[str, DepartmentValue] = {}
    cache: dict[int, str] = {}
    try:
        if callable(getattr(world, "query", None)):
            from .episode_reporting import iter_episodes
            # The window's end is checked in record(), inclusively: iter_episodes'
            # ``until`` is exclusive, and a run started at this report's own
            # clock reading must still count.
            episodes = iter_episodes(world, owner=owner, since=cutoff, finished_only=True)
        else:
            if owner is not None:
                raise ValueError("This history adapter cannot enforce an owner scope.")
            episodes = world.list_episodes(limit=episode_limit)
            out.incomplete = len(episodes) >= episode_limit
    except Exception as e:  # pragma: no cover -- report never blocks
        log.debug("workforce_value: episode read failed: %s", e)
        out.available = False
        out.unavailable_reason = "Task history could not be read. Savings are unavailable; no zero-activity claim was made."
        return out
    def record(ep):
        started = float(getattr(ep, "started_at", 0) or 0)
        if started < cutoff or started > ts_now:
            return
        raw_cost = getattr(ep, "cost_dollars", None)
        if raw_cost is None:
            raise ValueError("A finished episode has no recorded cost.")
        cost = float(raw_cost)
        done = _is_done(getattr(ep, "outcome", None))
        domain = getattr(ep, "domain", None)
        if domain is None:
            dept = _department_of(world, getattr(ep, "goal_id", 0), cache)
        else:
            # Read with its goal's domain (iter_episodes): a goal without one
            # is unattributed, as reading the goal again (once per goal) says.
            dept = domain or "(unattributed)"
        dv = depts.setdefault(dept, DepartmentValue(department=dept))
        dv.agent_cost += cost
        out.agent_cost += cost
        if done:
            per = _human_cost(dept)
            dv.deliverables += 1
            dv.human_baseline += per
            out.deliverables += 1
            out.human_baseline += per
    try:
        for ep in episodes:
            record(ep)
    except Exception as exc:
        log.debug("workforce_value: complete history read failed: %s", type(exc).__name__)
        return WorkforceValue(window_days=window_days, available=False,
                              unavailable_reason="Task history could not be read completely. Savings are unavailable.")
    out.by_department = sorted(
        depts.values(), key=lambda d: d.cost_avoided, reverse=True,
    )
    out.coverage_trend = _coverage_trend(cutoff)
    out.governance = _governance_summary()
    return out


def _coverage_trend(cutoff: float) -> list[tuple[str, int]]:
    """The improvement curve: (date, covered) points from the hindsight ledger.

    Each `maverick hindsight --ledger` run recorded coverage at a point in
    time; plotting covered-count over those runs is the 'better than before'
    slope. Empty until hindsight has been run with --ledger a few times."""
    try:
        from . import dreaming
        path = Path(dreaming._tenant_path(
            "dreams/hindsight.ndjson", dreaming.DEFAULT_DIR / "hindsight.ndjson"))
    except Exception:  # pragma: no cover
        return []
    if not path.exists():
        return []
    points: list[tuple[str, int]] = []
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                # A malformed line (valid JSON of the wrong shape, a
                # non-numeric or non-finite value) is skipped, never raised.
                try:
                    d = json.loads(raw)
                    if not isinstance(d, dict):
                        continue
                    ts = float(d.get("ts", 0) or 0)
                    if not math.isfinite(ts) or ts < cutoff:
                        continue
                    label = time.strftime("%Y-%m-%d", time.gmtime(ts))
                    points.append((label, int(d.get("covered_now", 0) or 0)))
                except (ValueError, TypeError, OverflowError, OSError):
                    continue
    except OSError:
        return []
    return points


def _governance_summary() -> dict:
    """Policy-adherence evidence from the signed audit log (best-effort).

    A signed chain is only present when at least one audit day-file exists and
    the same verifier used by ``maverick audit verify --all`` finds no per-file
    or cross-file breaks. Crypto-library availability alone is not evidence that
    signing was enabled or that existing rows are signed and intact.
    """
    summary: dict = {"chain_verifiable": None, "denials": None}
    try:
        from .audit import signing
        from .paths import data_dir

        audit_dir = data_dir("audit")
        if not signing._have_crypto() or not audit_dir.is_dir():
            summary["chain_verifiable"] = False
            return summary
        day_files = [
            p for p in sorted(audit_dir.glob("*.ndjson"))
            if p.name != signing.ANCHOR_FILENAME
        ]
        if not day_files:
            summary["chain_verifiable"] = False
            return summary
        has_breaks = any(signing.verify_chain(path) for path in day_files)
        has_breaks = has_breaks or bool(signing.verify_anchors(audit_dir))
        summary["chain_verifiable"] = not has_breaks
    except Exception:  # pragma: no cover
        pass
    return summary


def format_report(v: WorkforceValue) -> str:
    """Render the value report as an executive-readable block."""
    if not v.available:
        return "Workforce value unavailable: " + v.unavailable_reason
    lines = [
        f"AI Workforce — last {v.window_days} days",
        "=" * 44,
        f"Deliverables completed : {v.deliverables}",
        f"Agent cost             : ${v.agent_cost:,.2f}",
        f"Human-baseline cost    : ${v.human_baseline:,.2f}",
        f"Cost avoided           : ${v.cost_avoided:,.2f}",
    ]
    if v.agent_cost:
        lines.append(f"ROI                    : {v.roi_multiple:.1f}x "
                     "(human cost / agent cost)")
    imp = v.improvement
    if imp is not None:
        verb = "improved" if imp >= 0 else "REGRESSED"
        lines.append(f"Capability ({len(v.coverage_trend)} checkpoints): "
                     f"{verb} {imp:+d} in recall coverage")
    if v.governance.get("chain_verifiable"):
        lines.append("Governance             : signed audit chain present "
                     "(`maverick audit verify`)")
    if v.by_department:
        lines.append("")
        lines.append("By department (cost avoided):")
        for d in v.by_department[:12]:
            if not d.deliverables and d.agent_cost == 0:
                continue
            lines.append(
                f"  {d.department:<22} {d.deliverables:>4} done  "
                f"${d.cost_avoided:>10,.2f} avoided  "
                f"(${d.cost_per_deliverable:,.2f}/ea)"
            )
    return "\n".join(lines)


def to_dict(v: WorkforceValue) -> dict:
    if not v.available:
        return {"available": False, "incomplete": True, "unavailable_reason": v.unavailable_reason,
                "window_days": v.window_days, "by_department": [], "governance": v.governance,
                "coverage_trend": [], "improvement": None,
                **dict.fromkeys(("deliverables", "agent_cost", "human_baseline", "cost_avoided", "roi_multiple"))}
    return {
        "available": True, "incomplete": v.incomplete, "unavailable_reason": "",
        "window_days": v.window_days,
        "deliverables": v.deliverables,
        "agent_cost": round(v.agent_cost, 2),
        "human_baseline": round(v.human_baseline, 2),
        "cost_avoided": round(v.cost_avoided, 2),
        "roi_multiple": round(v.roi_multiple, 2),
        "improvement": v.improvement,
        "coverage_trend": v.coverage_trend,
        "governance": v.governance,
        "by_department": [
            {
                "department": d.department,
                "deliverables": d.deliverables,
                "agent_cost": round(d.agent_cost, 2),
                "cost_avoided": round(d.cost_avoided, 2),
            }
            for d in v.by_department
        ],
    }


def fleet_breakdown(inbox: Path | str | None = None) -> dict[str, dict]:
    """Cross-vendor proof: per-vendor deliverables/failures from fleet-ingested
    records — "your Agentforce agents improved; your Copilot agents are flat"
    becomes a measured sentence. Empty unless fleet memory has ingested."""
    try:
        from . import fleet_memory
        d = Path(inbox) if inbox is not None else fleet_memory.inbox_dir()
    except Exception:  # pragma: no cover
        return {}
    if not d.is_dir():
        return {}
    out: dict[str, dict] = {}
    for p in d.glob("*.json"):
        try:
            row = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        vendor = str(row.get("vendor", "") or "(unknown)")
        v = out.setdefault(vendor, {"deliverables": 0, "failures": 0})
        if row.get("outcome") == "success":
            v["deliverables"] += 1
        else:
            v["failures"] += 1
    return out


__all__ = [
    "DEFAULT_HUMAN_COST_PER_DELIVERABLE",
    "DepartmentValue",
    "WorkforceValue",
    "compute",
    "fleet_breakdown",
    "format_report",
    "to_dict",
]
