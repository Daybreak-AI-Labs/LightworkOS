"""Local comparison of deliberately separate accounting populations."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Query, Request, Response
from maverick.authority_effects import authority_effect_fence

from . import auth
from .product_errors import product_error

router = APIRouter()


def _app():
    from . import app
    return app


def projection(request, *, day: str | None = None, goal_id: int | None = None):
    from maverick import cost_provenance, quotas
    from maverick.episode_reporting import iter_episodes

    from .budget_guidance_api import _goal
    auth.require_permission(request, "view")
    owner = auth.caller_principal(request) or ""
    _goal(request, goal_id)
    try:
        selected = date.fromisoformat(day) if day else datetime.now(timezone.utc).date()
        if day and selected.isoformat() != day:
            raise ValueError("noncanonical day")
    except ValueError as exc:
        raise product_error(422, "cost_period_invalid", "Choose a valid UTC day in year-month-day order.") from exc
    start = datetime.combine(selected, datetime.min.time(), timezone.utc)
    end = start + timedelta(days=1)
    result = {"day": selected.isoformat(), "goal_id": goal_id, "currency": "USD", "ledgers": [], "receipts": [],
        "exclusions": cost_provenance.EXCLUDED,
        "notice": "These records measure different things. Never add the ledgers together or subtract a reservation as if it were a refund. No live provider access is used.",
        "reasons": ["An interrupted run may have a provider reservation without a finished episode or acknowledged usage.",
                    "Episode amounts are grouped by start time; personal usage is grouped by the day its settlement was acknowledged.",
                    "Provider receipts retain their original day or month and can cover multiple attempts of the selected task.",
                    "Invoice rating can apply a markup, minimum or token rate; subscription fees and provider invoices are separate."]}
    task_ids = set()
    if goal_id is not None:
        task_ids.add(goal_id)
    stamps = []  # when each shown record last changed, for "Spending updated"
    try:
        total, unknown, count, unfinished = 0.0, 0, 0, 0
        for episode in iter_episodes(_app()._world(), owner=owner, since=start.timestamp(), until=end.timestamp()):
            if goal_id is not None and episode.goal_id != goal_id:
                continue
            if episode.goal_id is not None:
                task_ids.add(episode.goal_id)
            stamps.append(episode.ended_at or episode.started_at)
            count += 1
            unfinished += episode.ended_at is None
            value = cost_provenance.amount(episode.cost_dollars)
            if value is None:
                unknown += 1
            else:
                total += value
        result["ledgers"].append({"name": "Runtime episode record", "state": "available", "period": selected.isoformat(),
            "currency": "USD", "amount": total, "basis": "Recorded subtotal; may contain estimates", "unknown_count": unknown,
            "scope": f"{count} owned episode attempts started in this UTC day; {unfinished} unfinished. " + ("Selected task only." if goal_id else "All owned tasks."),
            "href": "/spend"})
    except (ValueError, OSError, RuntimeError):
        result["ledgers"].append({"name": "Runtime episode record", "state": "unavailable", "amount": None,
                                  "scope": "The runtime record could not be read completely; missing amounts are not zero."})
    try:
        if not owner:
            raise ValueError("unidentified principal")
        usage = quotas.UsageLedger().usage(owner, day=selected.isoformat())
        result["ledgers"].append({"name": "Acknowledged personal usage", "state": "available", "period": selected.isoformat(),
            "currency": "USD", "amount": usage["dollars"], "basis": "Recorded acknowledged usage, not a final provider invoice",
            "scope": "All of this account's acknowledged usage on this UTC day, including other tasks; an interrupted settlement may be absent.",
            "href": "/budget"})
    except (ValueError, OSError, RuntimeError):
        result["ledgers"].append({"name": "Acknowledged personal usage", "state": "unavailable", "amount": None,
                                  "scope": "A named identity and readable usage ledger are required."})
    if goal_id is None:
        _practice_ledgers(result, owner, selected, start, end)
    # Exact work-item receipts remain separately grouped by their original period.
    # An all-task day report can only associate tasks with episodes in that day;
    # selecting a task also reveals receipts for a run interrupted before that row.
    result["provider_coverage"] = ("Exact selected task across all attempts and periods." if goal_id is not None else
        "Tasks with owned episode attempts in the selected day; select an owned task directly to inspect pre-episode or older-run reservations.")
    groups, unavailable = {}, 0
    for identity in sorted(task_ids):
        _goal(request, identity)
        evidence = cost_provenance.for_goal(identity)
        if evidence["state"] != "available":
            unavailable += 1
        for receipt in evidence["receipts"]:
            row = {**receipt, "goal_id": identity}
            result["receipts"].append(row)
            group = groups.setdefault((row["provider"], row["period"], row["currency"]),
                {"recorded": 0.0, "estimated": 0.0, "reconciled": 0.0, "ceiling": 0.0, "unknown": 0.0, "unknown_amounts": 0})
            amount = row["actual"] if row["state"] == "settled" else row["projected"]
            if amount is None:
                group["unknown_amounts"] += 1
            else:
                group[row["basis"]] += amount
    result["provider_groups"] = [{"provider": key[0], "period": key[1], "currency": key[2], **value} for key, value in groups.items()]
    result["tasks_without_complete_receipt_evidence"] = unavailable
    from maverick.spending_limits import spend_recorded_at
    stamps.append(spend_recorded_at())
    result["spend_recorded_at"] = max((stamp for stamp in stamps if stamp), default=None)
    result["ledgers"].append({"name": "Rated invoice and subscription", "state": "separate", "amount": None,
        "scope": "An employee episode total is not an invoice. Open Billing for your runtime statement; only authorized installation administrators can review workspace invoice rating and retained Stripe dispatch receipts. A configured Stripe price does not reveal its live fee amount locally.",
        "basis": "Subscription, taxes, credits, minimums and markup are not silently included in episode or reservation totals.", "href": "/billing"})
    if owner != (auth.caller_principal(request) or ""):
        raise product_error(409, "cost_account_changed", "Your account changed. Refresh the cost evidence.")
    return result


def _practice_ledgers(result, owner, selected, start, end):
    """Practice runs cost real provider money and their calls are in the
    provider receipts, so they are listed as their own records here: never
    inside the runtime or personal-usage totals, and never against limits."""
    from maverick import practice, practice_costs, quotas

    line = practice_costs.summary(owner, since=start.timestamp(), until=end.timestamp())
    if line:
        result["ledgers"].append({"name": "Practice runs", "state": "available", "period": selected.isoformat(),
            "currency": "USD", "amount": line["dollars"], "unknown_count": line["unknown_runs"],
            "basis": f"Real provider cost of practice runs; {practice_costs.NOT_COUNTED}",
            "scope": f"{line['runs']} practice runs started in this UTC day. Provider receipts include these calls; "
                     "the runtime record above does not.", "href": "/spend"})
    try:
        if not owner or practice.active():
            return
        with practice.scope():
            usage = quotas.UsageLedger().usage(owner, day=selected.isoformat())
    except (ValueError, OSError, RuntimeError):
        return
    if usage.get("dollars"):
        result["ledgers"].append({"name": "Practice usage", "state": "available", "period": selected.isoformat(),
            "currency": "USD", "amount": usage["dollars"],
            "basis": f"Acknowledged practice usage; {practice_costs.NOT_COUNTED} or quotas",
            "scope": "This account's practice usage on this UTC day, kept on its own ledger.", "href": "/budget"})


@router.get("/cost-reconciliation")
def page(request: Request, day: str | None = None, goal_id: int | None = Query(default=None, gt=0)):
    with authority_effect_fence():
        value = projection(request, day=day, goal_id=goal_id)
        return _app().templates.TemplateResponse(request, "cost_reconciliation.html", {"report": value},
                                                headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/cost/reconciliation")
def read(request: Request, response: Response, day: str | None = None, goal_id: int | None = Query(default=None, gt=0)):
    response.headers["Cache-Control"] = "private, no-store"
    with authority_effect_fence():
        return projection(request, day=day, goal_id=goal_id)
