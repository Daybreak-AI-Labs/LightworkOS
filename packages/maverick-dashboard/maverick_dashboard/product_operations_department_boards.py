"""Copilot reads the same current, owned department boards as ordinary pages."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from maverick.governed_operations import digest

from . import department_boards as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class Period(StrictInput):
    days: Literal[30, 90, 180, 365] = 90


def _summary(board, value):
    if board == "overview":
        return {"Your tasks, all time": value["totals"]["total"], "In progress": value["totals"]["active"],
                "Finished, all time": value["totals"]["done"], "Waiting": value["totals"]["blocked"],
                "Started in this period": value["window"]["started"], "Finished tasks last updated in this period": value["window"]["delivered"]}
    if board == "workforce":
        return {"Specialists observed on your tasks": value["totals"]["specialists"], "Your tasks, all time": value["totals"]["tasks"],
                "In progress": value["totals"]["active"], "Finished, all time": value["totals"]["done"]}
    if board == "savings":
        return {"Finished tasks, all time": value["totals"]["finished"], "Current human-approved results": value["totals"]["accepted"],
                "Visible recorded comparisons": value["totals"]["comparisons"], "Cases with current paired observations": value["totals"]["paired"]}
    if board == "oversight":
        return {"Your pending readable requests": value["totals"]["pending"], "Your active tasks": value["totals"]["active"],
                "Your recorded stop requests": value["totals"]["stop_requests"]}
    return {"Known runtime cost in USD": value["totals"]["dollars"], "Finished attempts": value["totals"]["runs"],
            "Attempts with missing prices": value["totals"]["unknown_prices"], "Running attempts": value["outcomes"]["running"],
            "Known runtime cost, all time in USD": value["all_time"]["dollars"]}


def _adapter(board, label, family):
    def snapshot(request, selection):
        value = native.build(request, board)
        summary = _summary(board, value)
        # The model guide receives counts and scope only, never titles, task
        # results, decrypted outcomes, owner identities or unscoped totals.
        return Snapshot(digest({"context": value["context"], "figures": summary}),
            "Current native records for your own permitted work", native.SCOPE_NOTICE,
            {"figures": summary}, fields=[] if board == "oversight" else [{"name": "days", "label": "Report period", "kind": "select", "value": 90,
                "choices": [{"value": days, "label": label} for days, label in
                            ((30, "30 days"), (90, "90 days"), (180, "6 months"), (365, "1 year"))]}])
    def prepare(request, selection, arguments):
        value = native.build(request, board, arguments["days"])
        details = {}
        if board == "savings":
            details["Your comparisons"] = [{"Comparison": row["title"], "Planned cases": row["planned"],
                "Current accepted results": row["accepted"], "Current paired observations": row["paired"],
                "Missing pairs": row["missing"], "Reported minutes difference": row["minutes_difference"],
                "Effort comparison coverage": "All planned cases" if row["ready"] else "Paired cases only; missing pairs can bias this figure",
                "Reported cost difference": (str(row["cost_difference"]) + " " + str(row["currency"])) if row["cost_difference"] is not None else "Complete cost evidence is missing",
                "Next steps": row["next_steps"]} for row in value["comparisons"]]
        elif board == "workforce":
            details["Your specialists"] = [{"Specialist": row["label"], "Your tasks": row["total"],
                "In progress": row["active"], "Finished": row["done"], "Finished attempts in this period": row["runs"],
                "Known runtime cost in USD": row["cost"], "Attempts with missing prices": row["unknown_prices"]}
                for row in value["specialists"]]
            details["Source coverage"] = value["source_notice"]
        elif board == "oversight":
            details["Requests needing review"] = [{"Request": row["label"], "Current review": row["detail"],
                "Next step": {"label": "Open full review", "href": row["href"]}} for row in value["requests"]]
            details["Your stop records"] = [{"Task": row["title"], "Recorded at": datetime.fromtimestamp(row["recorded_at"], timezone.utc).strftime("%b %d, %Y at %H:%M UTC"),
                "Meaning": row["detail"], "Next step": {"label": "Open the original task", "href": row["href"]}} for row in value["stop_requests"]]
        return Preview("Current permitted report. No work or settings changed.",
            native={"Scope": native.SCOPE_NOTICE, "Period in days": value["days"], "Figures": _summary(board, value),
                    "Checked at": datetime.fromtimestamp(value["generated_at"], timezone.utc).strftime("%b %d, %Y at %H:%M UTC"),
                    **({"Cost limits": native.COST_NOTICE} if board in {"spend", "workforce", "savings"} else {}),
                    **({"Source coverage": value["source_notice"], "Comparison limits": native.SAVINGS_NOTICE} if board == "savings" else {}),
                    **({"Oversight limits": native.OVERSIGHT_NOTICE} if board == "oversight" else {}), **details})
    return Adapter("boards." + board + ".read", label, family, "/" + board, ("/" + board,), Period, snapshot, prepare)


def entries():
    return [_adapter("overview", "Read my permitted work overview", "tasks"),
            _adapter("spend", "Read my permitted spending", "budget"),
            _adapter("workforce", "Read my specialists and task activity", "tasks"),
            _adapter("savings", "Read my recorded value comparisons", "budget"),
            _adapter("oversight", "Read my requests and stop records", "tasks")]
