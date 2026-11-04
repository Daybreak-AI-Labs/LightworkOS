"""Copilot uses the same owned preview and accounting-case services as /budget."""
from __future__ import annotations

import hashlib
import json

from maverick import budget_guidance
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import budget_guidance_api as native
from .draft_api import context_for
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class Limits(StrictInput):
    max_dollars: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    max_wall_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class Help(StrictInput):
    provider: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$")
    period: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?$")


def _goal_id(selection):
    value = selection.get("goal_id")
    if value is not None and (type(value) is not int or value < 1):
        from .product_errors import product_error
        raise product_error(422, "budget_task_invalid", "Select one owned task or clear the selection.")
    return value


def snapshot(request, selection):
    actor = native._actor(request)
    goal_id = _goal_id(selection)
    native._goal(request, goal_id)
    value = budget_guidance.preview(actor, goal_id=goal_id)
    stable = {key: val for key, val in value.items() if key not in {"observed_at", "notice"}}
    return Snapshot(digest(stable), "Current launch policy and scoped accounting ledgers",
        "Compare effective ceilings and accounting blocks without spending or raising a cap.", details=stable,
        fields=[{"name": "max_dollars", "label": "Requested ceiling (USD, optional)", "kind": "number", "value": None},
                {"name": "max_wall_seconds", "label": "Requested time ceiling (seconds, optional)", "kind": "number", "value": None}])


def prepare_preview(request, selection, arguments):
    value = native._projection(request, goal_id=_goal_id(selection), **arguments)
    return Preview("Current advisory budget preview. No money reserved and no task started.", native=value)


def help_snapshot(request, selection):
    native._actor(request, named=True)
    base = snapshot(request, selection)
    blocked = [row for row in base.details["providers"] if row["state"] in {"blocked", "unavailable"}]
    return Snapshot(base.revision, base.source, "Ask the installation administrator to review a current accounting block.",
        details={"blocked_providers": blocked}, blocked="No current provider accounting block in this scope." if not blocked else "",
        fields=[{"name": "provider", "label": "Blocked provider", "kind": "select", "value": blocked[0]["provider"] if blocked else "",
                 "choices": [{"value": row["provider"], "label": row["provider"]} for row in blocked]},
                {"name": "period", "label": "Original accounting period", "kind": "text", "value": blocked[0]["period"] if blocked else ""}])


def prepare_help(request, selection, arguments):
    state = help_snapshot(request, selection)
    if not any(row["provider"] == arguments["provider"] and row["period"] == arguments["period"] for row in state.details["blocked_providers"]):
        from .product_errors import product_error
        raise product_error(409, "budget_block_changed", "Choose a currently blocked provider and its original period.")
    return Preview("Share only provider, period and your exact receipt references with the installation administrator.",
                   changes=[{"field": "Accounting help request", "before": "No new request", "after": arguments["provider"] + " / " + arguments["period"]}])


def execute_help(request, selection, arguments, review, operation_id):
    value = native.request_help(request, native.CaseIn(context=context_for(request), goal_id=_goal_id(selection), **arguments))
    return Outcome("confirmed", "Accounting help request saved. No paid work was retried.", value)


def recover_help(request, selection, arguments, review, operation_id):
    actor = native._actor(request, named=True)
    native._goal(request, _goal_id(selection))
    identity = "BAC-" + hashlib.sha256(json.dumps([actor, arguments["provider"], arguments["period"], _goal_id(selection)]).encode()).hexdigest()[:48]
    row = native.CASES.get(identity)
    return Outcome("replayed", "The existing accounting request was recovered without replay.", {"case": native._public(row)}) if row else None


def _case(request, selection):
    auth.require_global_permission(request, "admin")
    native._actor(request, named=True)
    identity = selection.get("case_id")
    row = native.CASES.get(identity) if isinstance(identity, str) else None
    if row is None:
        from .product_errors import product_error
        raise product_error(404, "budget_case_missing", "Select an accounting request from this workspace.")
    return row


def case_snapshot(request, selection):
    row = _case(request, selection)
    return Snapshot(str(row["revision"]), "Current governed accounting case", "Review or verify the original accounting period.", native._public(row))


def _case_adapter(action, label):
    def prepare(request, selection, arguments):
        row = _case(request, selection)
        return Preview(label + "; no ledger mutation or provider retry.", native={"revision": row["revision"]})
    def execute(request, selection, arguments, review, operation_id):
        value = native.progress(request, selection["case_id"], native.ProgressIn(context=context_for(request),
            expected_revision=review["revision"], action=action))
        return Outcome("confirmed", "Accounting review progress saved.", value)
    return Adapter("budget.accounting." + action, label, "budget", "/budget", ("/budget",), EmptyInput, case_snapshot, prepare, execute)


def entries():
    return [Adapter("budget.preview", "Check budget before work", "budget", "/budget", ("/budget", "/chat", "/chat/goal/*", "/spend"), Limits, snapshot, prepare_preview),
            Adapter("budget.accounting.request", "Request accounting help", "budget", "/budget", ("/budget",), Help, help_snapshot, prepare_help, execute_help, recover_help),
            *[_case_adapter(action, label) for action, label in [("claim", "Assign accounting review to me"),
              ("request_evidence", "Request final receipt evidence"), ("verify", "Verify original-period accounting")]]]
