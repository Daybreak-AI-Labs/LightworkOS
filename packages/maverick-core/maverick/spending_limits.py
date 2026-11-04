"""Workspace and per-person spending limits an administrator sets.

There are no limits unless an administrator sets one. Three kinds exist:

* a workspace limit: the most the whole workspace may spend per day or month;
* a default limit for each person, per task, day or month;
* a limit for one named person, which replaces the default for them.

Limits are kept per workspace (``<data>/spending-limits.json``) and set from
the dashboard's Admin > Spending limits page. ``[spending_limits]`` in
config.toml (written by the installer) seeds the workspace and default limits
until an administrator saves them on that page.

:func:`admit` runs before every paid model request, alongside the task budget
and the organization cap. Spend is read from the usage ledger (the same
per-person, per-day record billing and quotas use) plus the unrecorded spend of
runs still going in this process. Runs in other worker processes reach the
ledger when they settle, so several runs going at once in separate workers can
pass a limit by what they spend before settling.
"""
from __future__ import annotations

import json
import math
import threading
import time
import weakref
from datetime import datetime, timezone

from .budget import BudgetExceeded
from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .paths import current_tenant, data_dir

PERIODS = ("task", "day", "month")
WORKSPACE_PERIODS = ("day", "month")
PERIOD_LABELS = {"task": "per task", "day": "per day", "month": "per month"}
_FORMAT = "lightwork-spending-limits-v1"
_MAX_USERS = 10_000
_MAX_AMOUNT = 1e9
_LOCK = threading.RLock()
# Runs admitted in this process, by identity (a Budget is not hashable). Weak,
# so a finished run drops out once nothing else holds it.
_ACTIVE: dict[int, weakref.ref] = {}


def _track(budget) -> None:
    key = id(budget)
    known = _ACTIVE.get(key)
    if known is not None and known() is budget:
        return

    def _forget(ref, key=key):
        if _ACTIVE.get(key) is ref:
            _ACTIVE.pop(key, None)
    _ACTIVE[key] = weakref.ref(budget, _forget)


def _active_budgets() -> list:
    return [b for b in (ref() for ref in list(_ACTIVE.values())) if b is not None]


class SpendingLimitReached(BudgetExceeded):
    """A workspace or per-person spending limit stops this request."""


class SpendingLimitError(ValueError):
    """A limit is invalid or the saved limits cannot be read. ``code`` names
    the problem (``amount``, ``period``, ``person``, ``full``, ``unreadable``)
    so a page can show its own wording for it."""

    def __init__(self, message: str, code: str = "unreadable") -> None:
        super().__init__(message)
        self.code = code


def _path():
    return data_dir("spending-limits.json")


def _limit(amount, period, *, periods=PERIODS) -> dict:
    try:
        value = float(amount)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SpendingLimitError("Enter the limit as an amount in dollars.", "amount") from exc
    if not math.isfinite(value) or value <= 0 or value > _MAX_AMOUNT:
        raise SpendingLimitError("The limit must be more than $0.", "amount")
    if period not in periods:
        raise SpendingLimitError("Choose how often the limit resets.", "period")
    return {"amount": round(value, 2), "period": period}


def _principal(principal) -> str:
    if not isinstance(principal, str) or not principal.strip() or len(principal) > 1024:
        raise SpendingLimitError("Choose a person.", "person")
    return principal.strip()


def _empty() -> dict:
    return {"workspace": None, "default": None, "users": {}}


def _validate(data) -> dict:
    if not isinstance(data, dict) or data.get("format") != _FORMAT:
        raise SpendingLimitError("The saved spending limits could not be read.")
    out = _empty()
    for key, periods in (("workspace", WORKSPACE_PERIODS), ("default", PERIODS)):
        entry = data.get(key)
        if entry is not None:
            out[key] = _limit(entry.get("amount"), entry.get("period"), periods=periods)
    users = data.get("users") or {}
    if not isinstance(users, dict) or len(users) > _MAX_USERS:
        raise SpendingLimitError("The saved spending limits could not be read.")
    for principal, entry in users.items():
        out["users"][_principal(principal)] = _limit(entry.get("amount"), entry.get("period"))
    out["updated_by"] = str(data.get("updated_by") or "")
    out["updated_at"] = float(data.get("updated_at") or 0)
    return out


def _config_seed() -> dict:
    """``[spending_limits]`` from config: 0 or absent means no limit."""
    from .config import load_config

    section = load_config().get("spending_limits") or {}
    if not isinstance(section, dict):
        raise SpendingLimitError("[spending_limits] must be a table")
    seed = _empty()
    for key, periods in (("workspace", WORKSPACE_PERIODS), ("default_user", PERIODS)):
        amount = section.get(f"{key}_dollars", 0) or 0
        if amount:
            seed["workspace" if key == "workspace" else "default"] = _limit(
                amount, section.get(f"{key}_period", "month"), periods=periods)
    return seed


def load() -> dict:
    """The limits in force for the current workspace.

    What an administrator saved on the dashboard wins; until then the
    installer's ``[spending_limits]`` values apply. An unreadable file raises
    so a broken limit cannot silently become no limit."""
    path = _path()
    if not path.exists():
        return _config_seed()
    try:
        return _validate(json.loads(atomic_read_text(path)))
    except SpendingLimitError:
        raise
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        raise SpendingLimitError("The saved spending limits could not be read.") from exc


def _mark(value) -> dict | None:
    """One "who set this limit, and when" record, or None when absent or odd.
    Informational only: a damaged mark never changes what a limit enforces."""
    if not isinstance(value, dict):
        return None
    by, at = value.get("by"), value.get("at")
    if not isinstance(by, str) or not by.strip() or len(by) > 1024:
        return None
    try:
        at = float(at)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(at) or at <= 0:
        return None
    return {"by": by, "at": at}


def _marks_from(data) -> dict:
    marks = {"workspace": None, "default": None, "users": {}}
    raw = data.get("set_by") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        return marks
    marks["workspace"] = _mark(raw.get("workspace"))
    marks["default"] = _mark(raw.get("default"))
    users = raw.get("users")
    if isinstance(users, dict):
        for who, value in list(users.items())[:_MAX_USERS]:
            mark = _mark(value)
            if isinstance(who, str) and mark is not None:
                marks["users"][who] = mark
    return marks


def provenance() -> dict:
    """Who set each saved limit and when: ``{"workspace": mark, "default":
    mark, "users": {principal: mark}}`` with ``mark = {"by", "at"}`` or None.
    Limits saved before this was recorded, or seeded by the installer, have
    no mark."""
    path = _path()
    if not path.exists():
        return _marks_from(None)
    try:
        return _marks_from(json.loads(atomic_read_text(path)))
    except (OSError, ValueError):
        return _marks_from(None)


def _apply_mark(marks: dict, state: dict, key: tuple, actor: str, now: float) -> None:
    mark = {"by": str(actor or "local")[:1024], "at": now}
    if key[0] == "users":
        if key[1] in state["users"]:
            marks["users"][key[1]] = mark
        else:
            marks["users"].pop(key[1], None)
    else:
        marks[key[0]] = mark if state[key[0]] is not None else None
    marks["users"] = {who: m for who, m in marks["users"].items() if who in state["users"]}


def _save(update, actor: str, mark: tuple | None = None) -> dict:
    path = _path()
    with _LOCK:
        ensure_private_directory(path.parent)
        with cross_process_lock(path):
            state = load()
            marks = provenance()
            update(state)
            now = time.time()
            if mark is not None:
                _apply_mark(marks, state, mark, actor, now)
            document = {
                "format": _FORMAT,
                "workspace": state["workspace"],
                "default": state["default"],
                "users": dict(sorted(state["users"].items())),
                "updated_by": str(actor or "local")[:1024],
                "updated_at": now,
                "set_by": {"workspace": marks["workspace"], "default": marks["default"],
                           "users": dict(sorted(marks["users"].items()))},
            }
            _validate(document)
            atomic_write_text(path, json.dumps(document, sort_keys=True, allow_nan=False))
    _audit(actor, document)
    return load()


def _audit(actor: str, document: dict) -> None:
    """A tamper-evident row for every change. Writer outages are fail-soft
    (the saved file is the record); an explicit audit refusal propagates."""
    from .audit import EventKind, audit_event

    audit_event(EventKind.SPENDING_LIMITS_CHANGED, agent="operator",
                actor=str(actor or "local"), workspace=document["workspace"],
                default=document["default"], people=len(document["users"]))


def set_workspace_limit(amount, period, *, actor: str) -> dict:
    limit = _limit(amount, period, periods=WORKSPACE_PERIODS)
    return _save(lambda s: s.update(workspace=limit), actor, ("workspace",))


def clear_workspace_limit(*, actor: str) -> dict:
    return _save(lambda s: s.update(workspace=None), actor, ("workspace",))


def set_default_limit(amount, period, *, actor: str) -> dict:
    limit = _limit(amount, period)
    return _save(lambda s: s.update(default=limit), actor, ("default",))


def clear_default_limit(*, actor: str) -> dict:
    return _save(lambda s: s.update(default=None), actor, ("default",))


def set_user_limit(principal, amount, period, *, actor: str) -> dict:
    who, limit = _principal(principal), _limit(amount, period)

    def update(state):
        if who not in state["users"] and len(state["users"]) >= _MAX_USERS:
            raise SpendingLimitError("There are too many personal limits to add another.", "full")
        state["users"][who] = limit
    return _save(update, actor, ("users", who))


def clear_user_limit(principal, *, actor: str) -> dict:
    who = _principal(principal)
    return _save(lambda s: s["users"].pop(who, None), actor, ("users", who))


def limit_for(principal: str, limits: dict | None = None) -> dict | None:
    """This person's own limit, else the default, else None (no limit)."""
    limits = limits if limits is not None else load()
    return limits["users"].get(principal) or limits["default"]


def _window(period: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d" if period == "day" else "%Y-%m")


def _ledger() -> tuple[dict, dict]:
    from .quotas import UsageLedger

    return UsageLedger()._load_state()


def spend_recorded_at() -> float | None:
    """When spending last reached the usage ledger (epoch seconds), or None
    when nothing has been recorded. Pages show it as "Updated ..." beside the
    totals, which also count runs still going in this process."""
    from .quotas import _ledger_path

    try:
        return _ledger_path().stat().st_mtime
    except OSError:
        return None


def recorded_spend(period: str, principal: str | None = None, usage: dict | None = None) -> float:
    """Dollars on the usage ledger for today or this month (UTC), for one
    person or, with ``principal=None``, the whole workspace."""
    usage = usage if usage is not None else _ledger()[0]
    prefix = _window(period)
    total = 0.0
    for who, days in (usage or {}).items():
        if principal is not None and who != principal:
            continue
        for day, cell in (days or {}).items():
            if str(day).startswith(prefix):
                total += float((cell or {}).get("dollars", 0.0))
    return total


def _budget_principal(budget) -> str:
    principal = getattr(budget, "_organization_principal", None) if budget is not None else None
    if not principal:
        from .connections import current_principal
        principal = current_principal()
    return principal or "local"


def _unrecorded(budget, receipts: dict | None = None) -> float:
    """This run's spend (and in-flight holds) not yet on the usage ledger:
    what it spent less what already reached the ledger -- at the run's end,
    per settled call under an organization, or by an earlier resumed attempt."""
    settled = getattr(budget, "_checkpoint_settled", None) or {}
    receipt = (receipts or {}).get(getattr(budget, "_organization_scope", None) or "")
    on_ledger = 0.0
    if receipt and receipt.get("principal") == _budget_principal(budget):
        on_ledger = float(receipt["total"].get("dollars", 0.0))
    recorded = max(float(getattr(budget, "_spending_recorded", 0.0) or 0.0),
                   float(settled.get("dollars", 0) or 0), on_ledger)
    spent = float(getattr(budget, "dollars", 0.0) or 0.0)
    return max(0.0, spent - recorded) + float(getattr(budget, "_reserved", 0.0) or 0.0)


def mark_recorded(budget) -> None:
    """Called once a run's spend is on the usage ledger, so it is not counted
    twice while the run object is still alive."""
    if budget is not None:
        budget._spending_recorded = float(getattr(budget, "dollars", 0.0) or 0.0)


def _live(tenant, principal=None, receipts: dict | None = None) -> float:
    from . import practice

    practising = practice.active()
    total = 0.0
    for budget in _active_budgets():
        if getattr(budget, "_spending_tenant", None) != tenant:
            continue
        if bool(getattr(budget, "_spending_practice", False)) != practising:
            continue  # practice and live spending are counted apart
        if principal is not None and _budget_principal(budget) != principal:
            continue
        total += _unrecorded(budget, receipts)
    return total


def _money(value: float) -> str:
    return f"${value:,.2f}"


def _message(scope: str, limit: dict, used: float) -> str:
    when = {"task": "for this task", "day": "today", "month": "this month"}[limit["period"]]
    return (f"{scope} spending limit of {_money(limit['amount'])} "
            f"{PERIOD_LABELS[limit['period']]} has been reached "
            f"({_money(used)} spent {when}). An administrator can change it "
            "in Admin > Spending limits.")


def practice_cap(principal: str, limits: dict | None = None) -> float:
    """The daily practice spending cap for ``principal``: ``[practice]
    daily_spend_cap``, never more than a real limit that applies to them."""
    from . import practice

    limits = limits if limits is not None else load()
    amounts = [practice.spend_cap()]
    for limit in (limit_for(principal, limits), limits["workspace"]):
        if limit is not None:
            amounts.append(float(limit["amount"]))
    return min(amounts)


def practice_spent_today(principal: str, ledger: tuple[dict, dict] | None = None) -> float:
    """Practice spending today (call inside practice: it reads the practice ledger)."""
    usage, receipts = ledger or _ledger()
    return recorded_spend("day", principal, usage) + _live(current_tenant(), principal, receipts)


def _practice_message(cap: float, used: float) -> str:
    return (f"The practice spending limit of {_money(cap)} per day has been reached "
            f"({_money(used)} spent today in practice). Practice spending is kept apart, so your "
            "real spending limits are not affected. An administrator can change the practice limit "
            "in Settings.")


def _admit_practice(budget, projected: float, limits: dict) -> None:
    principal = _budget_principal(budget)
    if budget is not None:
        budget._spending_tenant = current_tenant()
        budget._spending_practice = True
        _track(budget)
    cap = practice_cap(principal, limits)
    used = practice_spent_today(principal)  # includes this run's unrecorded spend
    if used + projected > cap:
        raise SpendingLimitReached(_practice_message(cap, used))


def admit(budget, projected: float = 0.0) -> None:
    """Refuse a paid request that would take a person or the workspace past
    its limit. Raises :class:`SpendingLimitReached`; no limit set = no cost.

    In practice mode the practice cap applies instead, on the practice ledger,
    so practice spending never uses up a real limit (:mod:`maverick.practice`)."""
    from . import practice

    try:
        limits = load()
    except SpendingLimitError as exc:
        raise SpendingLimitReached(
            "The spending limits could not be read, so paid requests are paused. "
            "An administrator can fix them in Admin > Spending limits.") from exc
    projected = float(projected or 0.0)
    projected = max(0.0, projected) if math.isfinite(projected) else math.inf
    if practice.active():
        _admit_practice(budget, projected, limits)
        return
    if budget is not None:
        budget._spending_practice = False
    if limits["workspace"] is None and limits["default"] is None and not limits["users"]:
        return
    tenant = current_tenant()
    principal = _budget_principal(budget)
    if budget is not None:
        budget._spending_tenant = tenant
        _track(budget)
    own = limit_for(principal, limits)
    ledger = None
    if own is not None:
        if own["period"] == "task":
            used = 0.0 if budget is None else (
                float(getattr(budget, "dollars", 0.0) or 0.0)
                + float(getattr(budget, "_reserved", 0.0) or 0.0))
        else:
            usage, receipts = ledger = ledger or _ledger()
            used = (recorded_spend(own["period"], principal, usage)
                    + _live(tenant, principal, receipts))
        if used + projected > own["amount"]:
            raise SpendingLimitReached(_message("Your", own, used))
    workspace = limits["workspace"]
    if workspace is not None:
        usage, receipts = ledger or _ledger()
        used = recorded_spend(workspace["period"], None, usage) + _live(tenant, None, receipts)
        if used + projected > workspace["amount"]:
            raise SpendingLimitReached(_message("The workspace", workspace, used))


def start_refusal(principal: str) -> str | None:
    """A plain reason to refuse starting a goal because a daily or monthly
    limit is already used up, else None."""
    from . import practice

    limits = load()
    if practice.active():
        cap, used = practice_cap(principal, limits), practice_spent_today(principal)
        return _practice_message(cap, used) if used >= cap else None
    own = limit_for(principal, limits)
    workspace = limits["workspace"]
    if workspace is None and (own is None or own["period"] == "task"):
        return None
    tenant = current_tenant()
    usage, receipts = _ledger()
    if own is not None and own["period"] != "task":
        used = recorded_spend(own["period"], principal, usage) + _live(tenant, principal, receipts)
        if used >= own["amount"]:
            return _message("Your", own, used)
    if workspace is not None:
        used = recorded_spend(workspace["period"], None, usage) + _live(tenant, None, receipts)
        if used >= workspace["amount"]:
            return _message("The workspace", workspace, used)
    return None


def standing(principal: str) -> dict:
    """The spending limits that apply to ``principal`` right now.

    Uses the same choice of limit (:func:`limit_for`) and the same spend
    totals (the usage ledger plus runs still going) as :func:`admit`, so what
    a page shows is what stops work. Each row names its kind (``person`` for a
    personal limit, ``everyone`` for the limit for everyone, ``workspace``),
    what was spent and is left in the current day or month (a per-task limit
    has no running total), and who set it."""
    limits = load()
    marks = provenance()
    tenant = current_tenant()
    usage, receipts = _ledger()
    rows = []
    own = limit_for(principal, limits)
    if own is not None:
        personal = principal in limits["users"]
        row = {"kind": "person" if personal else "everyone", "limit": own,
               "set": marks["users"].get(principal) if personal else marks["default"]}
        if own["period"] != "task":
            spent = recorded_spend(own["period"], principal, usage) + _live(tenant, principal, receipts)
            row.update(spent=spent, remaining=max(0.0, own["amount"] - spent))
        rows.append(row)
    workspace = _workspace_row(limits, marks, tenant, usage, receipts)
    if workspace is not None:
        rows.append(workspace)
    return {"limits": rows, "installer_defaults": not _path().exists(),
            "spend_recorded_at": spend_recorded_at()}


def _workspace_row(limits, marks, tenant, usage, receipts) -> dict | None:
    workspace = limits["workspace"]
    if workspace is None:
        return None
    spent = recorded_spend(workspace["period"], None, usage) + _live(tenant, None, receipts)
    return {"kind": "workspace", "limit": workspace, "set": marks["workspace"],
            "spent": spent, "remaining": max(0.0, workspace["amount"] - spent)}


def workspace_standing() -> dict | None:
    """The workspace limit with what is spent and left, as :func:`standing`
    shows it, or None when the workspace has no limit."""
    limits = load()
    if limits["workspace"] is None:
        return None
    usage, receipts = _ledger()
    row = _workspace_row(limits, provenance(), current_tenant(), usage, receipts)
    return {**row, "spend_recorded_at": spend_recorded_at()} if row is not None else None


def overview(people: list[str]) -> dict:
    """Everything the admin page shows: the limits, and spend so far today
    and this month for the workspace and for each person listed."""
    limits = load()
    tenant = current_tenant()
    usage, receipts = _ledger()
    listed = sorted(set(people) | set(limits["users"]))
    rows = []
    for who in listed:
        own = limits["users"].get(who)
        rows.append({
            "principal": who,
            "limit": own,
            "uses_default": own is None and limits["default"] is not None,
            "today": recorded_spend("day", who, usage) + _live(tenant, who, receipts),
            "month": recorded_spend("month", who, usage) + _live(tenant, who, receipts),
        })
    return {
        "workspace": limits["workspace"],
        "default": limits["default"],
        "people": rows,
        "workspace_today": recorded_spend("day", None, usage) + _live(tenant, None, receipts),
        "workspace_month": recorded_spend("month", None, usage) + _live(tenant, None, receipts),
        "updated_by": limits.get("updated_by", ""),
        "updated_at": limits.get("updated_at", 0.0),
        "spend_recorded_at": spend_recorded_at(),
    }


__all__ = [
    "PERIODS", "PERIOD_LABELS", "WORKSPACE_PERIODS", "SpendingLimitError",
    "SpendingLimitReached", "admit", "clear_default_limit", "clear_user_limit",
    "clear_workspace_limit", "limit_for", "load", "mark_recorded", "overview",
    "provenance", "recorded_spend", "set_default_limit", "set_user_limit",
    "set_workspace_limit", "spend_recorded_at", "standing", "start_refusal", "workspace_standing",
]
