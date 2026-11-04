"""Outcome metrics: what the workforce delivered, not what it consumed.

Billing meters tokens and credits; the useful question is "what did it get
*done*?" This rolls the Operating Record (:mod:`maverick.operating_record`) up
into per-worker *outcomes* — goals completed, completion rate, spend — so a
worker card can lead with delivery ("12 of 14 goals completed this period")
instead of usage. A firm-level rollup adds human approvals and total spend
across the whole record.

Read-only and pure: every number is derived from
:class:`~maverick.operating_record.DecisionRecord` rows. Honest when empty — no
records yields zeroes, never a fabricated metric.
"""
from __future__ import annotations

from dataclasses import dataclass

from .departments import department_title
from .domain import suite_for
from .operating_record import DecisionRecord, assemble


@dataclass
class Outcome:
    """Delivery metrics for one worker (a specialist pack / domain)."""
    worker: str                       # domain/pack name, e.g. "finance_sox"
    suite: str | None = None          # business suite via suite_for
    suite_title: str = ""             # human department label
    goals_total: int = 0
    goals_completed: int = 0
    spend_dollars: float = 0.0

    @property
    def completion_rate(self) -> float:
        return self.goals_completed / self.goals_total if self.goals_total else 0.0

    def headline(self) -> str:
        """The single line a worker card leads with."""
        if not self.goals_total:
            return "No work recorded yet"
        return f"{self.goals_completed} of {self.goals_total} goals completed"

    def to_dict(self) -> dict:
        return {
            "worker": self.worker,
            "suite": self.suite,
            "suite_title": self.suite_title,
            "goals_total": self.goals_total,
            "goals_completed": self.goals_completed,
            "completion_rate": round(self.completion_rate, 3),
            "spend_dollars": round(self.spend_dollars, 2),
            "headline": self.headline(),
        }


@dataclass
class FirmTotals:
    """Firm-wide rollup across the whole Operating Record."""
    goals_total: int = 0
    goals_completed: int = 0
    approvals: int = 0
    human_decisions: int = 0
    spend_dollars: float = 0.0

    def to_dict(self) -> dict:
        return {
            "goals_total": self.goals_total,
            "goals_completed": self.goals_completed,
            "approvals": self.approvals,
            "human_decisions": self.human_decisions,
            "spend_dollars": round(self.spend_dollars, 2),
        }


def _is_completed(outcome: str) -> bool:
    return (outcome or "").strip().lower() in {"done", "success", "completed"}


def by_worker(records: list[DecisionRecord]) -> dict[str, Outcome]:
    """Aggregate goal decisions into one :class:`Outcome` per worker.

    Keyed by ``DecisionRecord.department`` (the specialist's domain). Approvals
    carry no department and are excluded here — they belong to the firm rollup
    (:func:`firm_totals`), not to a single worker."""
    out: dict[str, Outcome] = {}
    for r in records:
        if r.kind != "goal" or not r.department:
            continue
        oc = out.get(r.department)
        if oc is None:
            suite = suite_for(r.department)
            oc = Outcome(
                worker=r.department,
                suite=suite,
                suite_title=department_title(suite) if suite else "",
            )
            out[r.department] = oc
        oc.goals_total += 1
        if _is_completed(r.outcome):
            oc.goals_completed += 1
        oc.spend_dollars += float(r.cost_dollars or 0)
    return out


def firm_totals(records: list[DecisionRecord]) -> FirmTotals:
    """Firm-wide delivery + governance rollup across every record."""
    t = FirmTotals()
    for r in records:
        if r.kind == "goal":
            t.goals_total += 1
            if _is_completed(r.outcome):
                t.goals_completed += 1
            t.spend_dollars += float(r.cost_dollars or 0)
        elif r.kind == "approval":
            t.approvals += 1
            if r.decided_by:
                t.human_decisions += 1
    return t


def worker_cards(
    world, *, limit: int = 500, top: int | None = None,
    owner: str | None = None, records: list[DecisionRecord] | None = None,
) -> list[Outcome]:
    """Outcome cards for every worker with recorded work, best delivery first.

    ``top`` keeps only the N highest-delivering workers (for a dashboard
    leaderboard); ``None`` returns all. ``records`` is an Operating Record the
    caller already assembled with the same ``limit`` and ``owner``."""
    if records is None:
        records = assemble(world, limit=limit, owner=owner)
    cards = list(by_worker(records).values())
    cards.sort(key=lambda o: (o.goals_completed, o.goals_total), reverse=True)
    return cards[:top] if top else cards
