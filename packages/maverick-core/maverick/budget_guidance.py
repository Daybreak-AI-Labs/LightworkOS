"""Read-only task ceilings and explicitly scoped, non-additive ledger headroom.

This does not reserve money or replace admission. Each ledger has its own
population and acknowledgement timing; combining their amounts would double
count physical calls. Unknown reservations remain held until reconciled.
"""
from __future__ import annotations

import hashlib
import math
import time
from datetime import datetime, timedelta, timezone

from .config_contracts import BOOLEAN_SETTINGS, NUMBER_LIST_SETTINGS


def policy():
    from . import config
    if config.config_source_errors(include_tenant=True):
        raise ValueError("Budget guidance policy is unavailable. Refresh the page and try again.")
    values = config.load_config().get("budget") or {}
    contract = NUMBER_LIST_SETTINGS["budget.warning_thresholds"]
    thresholds = values.get("warning_thresholds", list(contract.default))
    if (not isinstance(thresholds, list) or not thresholds or len(thresholds) > contract.max_items
            or any(isinstance(v, bool) or not isinstance(v, (int, float))
                   or not math.isfinite(v) or not contract.minimum_exclusive < v <= contract.maximum
                   for v in thresholds)):
        raise ValueError("Budget warning thresholds must be numbers greater than zero and at most one.")
    for key in ("guidance", "warnings"):
        if type(values.get(key, BOOLEAN_SETTINGS[f"budget.{key}"].default)) is not bool:
            raise ValueError("Budget guidance and warnings must be enabled or disabled explicitly.")
    return {"guidance": values.get("guidance", BOOLEAN_SETTINGS["budget.guidance"].default),
            "warnings": values.get("warnings", BOOLEAN_SETTINGS["budget.warnings"].default),
            "warning_thresholds": sorted(set(thresholds))}


def _number(value):
    return float(value) if value is not None and math.isfinite(float(value)) else None


def _scope_holds(tenant, principal):
    from .tenant import provider_admission as admission

    if not tenant:
        return {"reserved": 0.0, "unknown": 0.0, "unknown_amount": False}
    state = admission._load(tenant)
    reserved = unknown = 0.0
    unknown_amount = False
    for call in state["calls"].values():
        run = state["runs"][call["run_id"]]
        if principal is not None and run["principal"] != principal:
            continue
        amount = admission._held(call)
        if call["state"] == "unknown" and not call["released"]:
            unknown_amount |= not math.isfinite(amount)
            if math.isfinite(amount):
                unknown += amount
        elif math.isfinite(amount):
            reserved += amount
    return {"reserved": reserved, "unknown": unknown, "unknown_amount": unknown_amount}


def preview(principal=None, *, max_dollars=None, max_wall_seconds=None, goal_id=None, provider=None):
    """Resolve the same task ceilings as launch, without constructing a Budget.

The caller must authorize principal and any goal before passing them. A local
CLI without an identified launch principal gets exact task ceilings, with
personal-quota headroom explicitly unavailable rather than an invented identity.
"""
    from .paths import current_tenant_id_strict
    from .quotas import UsageLedger, _quota_config
    from .runner import (
        configured_max_dollars,
        configured_max_wall_seconds,
        requested_goal_dollars,
        requested_goal_wall_seconds,
    )
    from .tenant import registry

    for value in (max_dollars, max_wall_seconds):
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0):
            raise ValueError("Requested task limits must be finite non-negative numbers.")
    now = time.time()
    settings = policy()
    if not settings["guidance"]:
        raise ValueError("Budget guidance is disabled by the installation administrator.")
    today = datetime.fromtimestamp(now, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    tenant = current_tenant_id_strict()
    result = {"available": True, "currency": "USD", "observed_at": now,
              "reset_at": (today + timedelta(days=1)).isoformat(), "reset_basis": "Midnight UTC; local time is displayed by the client.",
              "requested": {"max_dollars": max_dollars, "max_wall_seconds": max_wall_seconds},
              "effective": {}, "binding_ceiling": None, "headroom": None,
              "person": {}, "workspace": {}, "providers": [], "task_receipts": [],
              "headroom_complete": True, "admission_allowed": True,
              "notice": "These are current policy ceilings and advisory headroom, not a price quote or provider invoice. Admission rechecks policy and durable reservations at dispatch. Ledger figures are not additive.",
              "increase_owner": "An installation administrator controls task/provider ceilings; the workspace administrator controls its assigned allowance.",
              "repair_href": "/budget"}
    candidates = []
    try:
        task = {"max_dollars": configured_max_dollars(), "max_wall_seconds": configured_max_wall_seconds()}
        # A request may exceed the first-install default, never an operator
        # ceiling: the resolution goal launches (REST, worker, CLI) apply.
        result["effective"] = {"max_dollars": requested_goal_dollars(max_dollars),
                               "max_wall_seconds": requested_goal_wall_seconds(max_wall_seconds)}
        result["task_ceiling"] = task
        if result["effective"]["max_dollars"] is not None:
            candidates.append((result["effective"]["max_dollars"], "task"))
    except (ValueError, OSError, RuntimeError):
        result.update(available=False, headroom_complete=False, admission_allowed=False)
        result["task_error"] = "Task budget policy could not be resolved. No allowance has been assumed. Refresh the page and try again."

    try:
        quota_policy = _quota_config()
        if not principal:
            result["person"] = {"state": "unidentified", "enforced": quota_policy["enforce"],
                                "message": "No launch principal is bound to this preview. Its personal quota cannot be established."}
            if quota_policy["enforce"]:
                result.update(headroom_complete=False, admission_allowed=False)
        else:
            usage = UsageLedger().usage(principal)
            holds = _scope_holds(tenant, principal)
            cap = quota_policy["max_dollars_per_day"] if quota_policy["enforce"] and quota_policy["max_dollars_per_day"] > 0 else None
            remaining = max(0, cap - usage["dollars"] - holds["reserved"] - holds["unknown"]) if cap is not None else None
            if holds["unknown_amount"]:
                remaining = None
                result["headroom_complete"] = False
            token_cap = quota_policy["max_tokens_per_day"] if quota_policy["enforce"] and quota_policy["max_tokens_per_day"] > 0 else None
            result["person"] = {"state": "available", "cap": cap, "confirmed": usage["dollars"], **holds,
                                "remaining": remaining, "token_cap": token_cap,
                                "recorded_tokens": usage["in_tokens"] + usage["out_tokens"],
                                "basis": "Acknowledged usage plus own pending organization reservations for the UTC day."}
            if remaining is not None:
                candidates.append((remaining, "person"))
            if holds["unknown_amount"] or (token_cap and usage["in_tokens"] + usage["out_tokens"] >= token_cap):
                result["admission_allowed"] = False
    except (ValueError, OSError, RuntimeError):
        result["person"] = {"state": "unavailable", "message": "Personal usage or policy is unavailable; unknown is not zero. Refresh the page and try again."}
        result.update(headroom_complete=False, admission_allowed=False)

    try:
        if tenant:
            cap = registry._tenant_daily_cap(tenant) or None
            spent = registry.tenant_spend_today(tenant)
            held = registry._outstanding_reservations(tenant)
            holds = _scope_holds(tenant, None)
            if not math.isfinite(spent) or not math.isfinite(held):
                raise ValueError("unknown organization accounting")
            remaining = max(0, cap - spent - held) if cap is not None else None
            result["workspace"] = {"state": "available", "cap": cap, "confirmed": spent,
                                   "reserved": max(0, held - holds["unknown"]), "unknown": holds["unknown"],
                                   "remaining": remaining, "basis": "Workspace allowance uses the same ledger and durable holds as admission."}
            if remaining is not None:
                candidates.append((remaining, "workspace"))
        else:
            result["workspace"] = {"state": "not_bound", "message": "No workspace allowance is bound to this runtime."}
    except (ValueError, OSError, RuntimeError):
        result["workspace"] = {"state": "unavailable", "message": "Workspace accounting is unavailable or has an unknown amount. Nothing was refunded or reset. Refresh the page and try again."}
        result.update(headroom_complete=False, admission_allowed=False)

    _provider_projection(result, provider, goal_id, candidates)
    if candidates:
        headroom, binding = min(candidates)
        result.update(headroom=_number(headroom), binding_ceiling=binding)
        if headroom <= 0:
            result["admission_allowed"] = False
    if not result["headroom_complete"]:
        result["headroom"] = None
    return result


def _provider_projection(result, provider, goal_id, candidates):
    from . import provider_cost_cap as caps
    from . import provider_spending_recovery
    try:
        names = {str(provider).strip().lower()} if provider else set(caps.caps_from_config())
        result["provider_coverage"] = "Selected provider" if provider else "Configured provider ceilings and this task's recorded providers; a future route may use another provider."
        if goal_id is not None:
            # Same exact goal work-item convention as runtime provider admission.
            receipt_set = caps.reservation_catalogue_for_work_item(f"goal:{goal_id}")
            for row in receipt_set.receipts:
                names.add(row.provider)
                result["task_receipts"].append({"reference": row.reference, "provider": row.provider,
                    "period": row.period, "state": row.state, "projected": row.projected,
                    "actual": row.actual, "currency": row.currency, "cost_basis": row.cost_basis})
        for name in sorted(names):
            projection = provider_spending_recovery.status(provider=name)
            if not projection["available"]:
                result["providers"].append({"provider": name, "state": "unavailable", "period": projection["period"]})
                result.update(headroom_complete=False, admission_allowed=False)
                continue
            state = projection["providers"][0]
            # Global provider balances can span workspaces. Expose the binding
            # ceiling/headroom and blocker, never other workspaces' receipts.
            result["providers"].append({"provider": name, "state": "blocked" if not state["allowed"] else "available",
                "period": projection["period"], "cap": state["cap"], "remaining": state["remaining"],
                "accounting_blocked": not state["allowed"], "basis": "Shared provider authority; other-workspace amounts and receipts are private."})
            if state["remaining"] is not None:
                candidates.append((state["remaining"], "provider:" + name))
            if not state["allowed"]:
                result["admission_allowed"] = False
    except (ValueError, OSError, RuntimeError):
        result.update(headroom_complete=False, admission_allowed=False)
        result["provider_error"] = "Provider reservation accounting could not be read. A missing receipt is not evidence of zero cost. Refresh the page and try again."


def _warnings_store():
    from .governed_records import GovernedRecordStore
    return GovernedRecordStore("personal_budget_warnings", "PBW", "budget_warning")


def observe_warnings(principal, projection=None):
    """Record each crossed threshold once per principal, dimension and UTC day.

    No provider call, reservation change, delivery attempt or automatic increase.
    Independent ledger dimensions are deliberately never added together.
    """
    settings = policy()
    if not principal or not settings["warnings"] or not settings["guidance"]:
        return []
    from .privacy_ops import RecordConflict
    view = projection if projection is not None else preview(principal)
    day = datetime.fromtimestamp(view["observed_at"], timezone.utc).date().isoformat()
    dimensions = [("person", view["person"]), ("workspace", view["workspace"])]
    dimensions.extend(("provider:" + row["provider"], row) for row in view["providers"])
    store = _warnings_store()
    recorded = []
    for name, row in dimensions:
        cap, remaining = row.get("cap"), row.get("remaining")
        if cap is None or cap <= 0 or remaining is None:
            continue
        consumed = max(0, 1 - remaining / cap)
        for threshold in settings["warning_thresholds"]:
            if consumed < threshold:
                continue
            period = row.get("period") or day
            identity = "PBW-" + hashlib.sha256(f"{principal}|{period}|{name}|{threshold}".encode()).hexdigest()[:48]
            existing = store.get(identity)
            if existing is None:
                try:
                    existing = store.create({"id": identity, "principal": principal, "day": day,
                        "period": period, "dimension": name, "threshold": threshold, "cap": cap, "remaining_at_notice": remaining,
                        "currency": "USD", "observed_at": view["observed_at"],
                        "basis": "Confirmed and reserved allowance; this is not an invoice or automatic increase."},
                        action="threshold_observed", actor=principal, max_records=10000)
                except RecordConflict:
                    existing = store.get(identity)
            if existing is not None:
                recorded.append(existing)
    return recorded


def warning_sources(principal):
    if not principal or not policy()["warnings"]:
        return []
    today = datetime.now(timezone.utc).date().isoformat()
    rows = _warnings_store().list(limit=10001)
    if len(rows) > 10000:
        raise ValueError("Budget notification inventory exceeded its supported capacity.")
    return [{"ref": row["id"], "version": row["id"], "category": "blocked", "goal_id": None,
             "project_id": None, "title": "Budget needs attention",
             "label": f"{row['dimension']} allowance crossed {row['threshold']:.0%}; review scheduled work",
             "href": "/budget", "reason": "Your spending allowance crossed a warning level",
             "action": "Review the work scheduled against your allowance"}
            for row in rows if row.get("principal") == principal and row.get("day") == today]
