"""Worker performance reviews: the governed counterpart to a human review.

A hosted black-box agent can't show its work; a governed one can. This composes
a *department review* from evidence that already exists:

* **identity** — the team and its charter (:mod:`maverick.departments`),
* **delivery** — what it got done (:mod:`maverick.outcomes`),
* **authority** — exactly what the team may and may not do, read off the
  capability envelopes of its packs (the documented "capabilities and
  limitations" a reviewer asks for), and
* **learning** — how much of its recent work the learned state already covers
  (:func:`maverick.hindsight.coverage_under`), so "it improves with use" is a
  number, not a claim.

Read-only and never raises on missing data: an empty record yields an honest
``insufficient_data`` learning status and zeroed delivery, never a fabricated
review.
"""
from __future__ import annotations

from . import departments, outcomes
from .operating_record import assemble

_RISK_RANK = {None: 0, "": 0, "low": 1, "medium": 2, "high": 3}


def _authority(profiles) -> dict:
    """The union capability envelope across a department's roster — what the
    whole team is permitted to do, and where the hard stops are."""
    allow: set[str] = set()
    deny: set[str] = set()
    top_risk = "low"
    for p in profiles:
        allow.update(p.allow_tools or [])
        deny.update(p.deny_tools or [])
        if _RISK_RANK.get(p.max_risk, 0) > _RISK_RANK.get(top_risk, 0):
            top_risk = p.max_risk or "low"
    # Cross-suite hard stops worth surfacing on the card.
    writes_files = "write_file" in allow
    runs_shell = "shell" in allow
    return {
        "allow_tools": sorted(allow),
        "deny_tools": sorted(deny),
        "max_risk": top_risk,
        "can_write_files": writes_files,
        "can_run_shell": runs_shell,
        "summary": (
            f"Max risk {top_risk}; "
            f"{'can' if writes_files else 'cannot'} write files, "
            f"{'can' if runs_shell else 'cannot'} run shell. "
            f"{len(deny)} tool(s) explicitly denied."
        ),
    }


def _delivery(
    world, member_set: set[str], *, limit: int, owner: str | None = None,
) -> dict:
    """Department-level delivery rollup over its workers' outcomes."""
    cards = [
        c for c in outcomes.by_worker(assemble(world, limit=limit, owner=owner)).values()
        if c.worker in member_set
    ]
    goals_total = sum(c.goals_total for c in cards)
    goals_completed = sum(c.goals_completed for c in cards)
    spend = sum(c.spend_dollars for c in cards)
    return {
        "goals_total": goals_total,
        "goals_completed": goals_completed,
        "completion_rate": round(goals_completed / goals_total, 3)
        if goals_total else 0.0,
        "spend_dollars": round(spend, 2),
        "active_workers": len(cards),
        "workers": [c.to_dict() for c in
                    sorted(cards, key=lambda c: c.goals_completed, reverse=True)],
    }


# Coverage is computed per goal (reflexion + insight + skill recall each), so a
# department with hundreds of goals would make the review endpoint slow. Evaluate
# only the most recent N (assemble() is newest-first) — a representative sample,
# reported honestly as the count evaluated.
_LEARNING_SAMPLE = 50


def _learning(
    world, member_set: set[str], *, limit: int, owner: str | None = None,
) -> dict:
    """How much of the department's recent work the live learned state covers.

    Uses :func:`maverick.hindsight.coverage_under` (reflexions + insights +
    learned skills) against the live store over the most recent
    ``_LEARNING_SAMPLE`` goals. Never raises; honest when there is nothing to
    evaluate yet."""
    from . import hindsight

    goals = [r for r in assemble(world, limit=limit, owner=owner)
             if r.kind == "goal" and r.department in member_set and r.subject]
    goals = goals[:_LEARNING_SAMPLE]
    if not goals:
        return {"status": "insufficient_data", "goals_evaluated": 0,
                "covered": 0, "coverage_rate": 0.0}
    covered = 0
    for r in goals:
        cov = hindsight.coverage_under(r.subject, None, domain=r.department)
        if cov.covered:
            covered += 1
    return {
        "status": "ok",
        "goals_evaluated": len(goals),
        "covered": covered,
        "coverage_rate": round(covered / len(goals), 3),
    }


def _governance_note() -> str:
    """An honest description of the governance posture actually in effect.

    The earlier text asserted unconditionally that every action "passed the
    shield" and is in the "signed, tamper-evident audit log" -- but the kernel
    runs WITHOUT the agent-shield SDK (built-in rules only) by default, and
    audit signing is opt-in, so the claim could be false on a given deployment.
    Probe the real state instead of asserting it."""
    try:
        from .shield_policy import shield_available
        shielded = shield_available()
    except Exception:  # pragma: no cover -- never break a review on a probe
        shielded = False
    try:
        from .deployment import _verify_audit_signing
        signed = bool(_verify_audit_signing().passed)
    except Exception:  # pragma: no cover
        signed = False

    log_desc = ("the signed, tamper-evident audit log" if signed
                else "the append-only audit log (signing not enabled)")
    if shielded:
        return ("Every action counted here passed the shield's input/tool/output "
                f"checks and is recorded in {log_desc}.")
    return ("Actions counted here are screened by the built-in safety rules "
            "(the agent-shield SDK is not installed) and recorded in "
            f"{log_desc}.")


def review(world, department_key: str, *, cfg: dict | None = None,
           limit: int = 500, owner: str | None = None) -> dict | None:
    """A governed performance review for one department.

    Returns ``None`` if the department has no enabled packs. Composes identity,
    delivery, authority, and learning, plus a governance note describing the
    shield/audit posture actually in effect (see :func:`_governance_note`)."""
    dept = departments.get_department(department_key, cfg)
    if dept is None:
        return None
    member_set = set(dept.members)
    profiles = departments.roster(department_key, cfg)
    return {
        "department": dept.to_dict(),
        "delivery": _delivery(world, member_set, limit=limit, owner=owner),
        "authority": _authority(profiles),
        "learning": _learning(world, member_set, limit=limit, owner=owner),
        "governance_note": _governance_note(),
    }
