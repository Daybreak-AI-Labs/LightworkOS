"""One paid call a tool makes, charged to the run budget (kernel rule 3).

The same bracket the ``vertex`` tool uses: ``budget.check()``, a hold for the
call's projected cost, a provider spend receipt charged to the run budget
(``metered_provider_call(..., organization_budget=budget, settlement=...)``),
the real charge recorded once the reply says how much was used, and the hold
released. The price comes from ``[budget.tool_prices]``, else the per-call
safety ceiling (``budget.tool_call_price``).

A backend on this machine or a private network is free and is not charged,
by the rule self-hosted model servers use (``budget._is_private_endpoint``).
A call with no run budget is refused before anything is sent.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..budget import (
    BudgetExceeded,
    ToolPricesUnavailable,
    UsageAccountingError,
    _is_private_endpoint,
    max_unmetered_hold,
    record_tool_dollars,
    tool_call_price,
    tool_ceiling_reason,
)
from ..provider_cost_cap import (
    ProviderAccountingUnavailable,
    ProviderCapExceeded,
    metered_provider_call,
)


class PaidCallRefused(RuntimeError):
    """A paid tool call with no run budget to charge; nothing was sent."""


# Signals a tool must let through: catching them would skip the spending limit.
# A ``PaidCallRefused`` is shown to the caller as an ERROR line instead.
STOP_SIGNALS = (BudgetExceeded, ProviderCapExceeded, ProviderAccountingUnavailable,
                UsageAccountingError)


def is_free_backend(url: str | None) -> bool:
    """Whether ``url`` is on this machine or a private network, so it is free."""
    return bool(url) and _is_private_endpoint(url)


def _remaining(budget) -> float | None:
    """Dollars left on ``budget`` after spend and holds; ``None`` with no cap."""
    if callable(getattr(budget, "remaining_dollars", None)):
        return budget.remaining_dollars()
    if budget.max_dollars is None:
        return None
    return budget.max_dollars - budget.dollars - getattr(budget, "_reserved", 0.0)


def charged_call(
    service: str,
    send: Callable[..., Any],
    *,
    budget,
    label: str,
    units: dict[str, float] | None = None,
    measure: Callable[[Any], dict[str, float | None]] | None = None,
    bounded: bool = False,
    unit_bound: dict[str, float] | None = None,
    fallback: dict[str, float] | None = None,
    category: str = "inference",
    operation_id: str | None = None,
    attempt_no: int | None = None,
    parent_category: str | None = None,
):
    """Run ``send`` (one paid request to ``service``) charged to ``budget``.

    ``units`` is what the call uses that is known before it is sent (one
    request, the characters in the text); ``measure`` reads more from the
    reply (seconds of audio or compute, bytes scanned). When the priced unit
    never comes back, the call is charged everything it held. ``measure`` returns ``None`` when
    ``send`` stopped before anything was sent, so nothing is charged.

    When the priced unit is known only from the reply, the call holds what
    it may cost: the smaller of what the run has left and ``[budget]
    max_unmetered_hold_dollars``. With ``bounded``, ``send`` is called with
    the most units that fit in that hold, for a service that accepts a limit.
    ``unit_bound`` caps the units a call can use (the seconds a file's size
    allows), so the hold is no more than that costs. ``fallback`` fills in
    units the reply does not report (a header's length within that bound).
    The charge is settled to the real cost, or to the full hold when the
    reply never reports the units. Returns what ``send`` returned.
    """
    if budget is None:
        raise PaidCallRefused(
            f"{label} calls are charged to a run's spending limit, and this call has "
            "none. Call it from an agent step or a flow with a spending allowance; "
            "nothing was sent")
    budget.check()
    try:
        price = tool_call_price(service)
    except ToolPricesUnavailable as exc:
        raise PaidCallRefused(str(exc)) from exc
    projected, priced = price.cost(units)
    max_units = None
    if price.unit is not None and (units or {}).get(price.unit) is None:
        remaining = _remaining(budget)
        if remaining is not None and remaining <= 0:
            raise BudgetExceeded(
                f"no spending left for {label}, whose cost is known only after it runs")
        try:
            bound = max_unmetered_hold()
        except ToolPricesUnavailable as exc:
            raise PaidCallRefused(str(exc)) from exc
        projected = bound if remaining is None else min(remaining, bound)
        limit = (unit_bound or {}).get(price.unit)
        if limit is not None:
            projected = min(projected, limit * price.dollars_per_unit)
        if price.dollars_per_unit > 0:
            max_units = projected / price.dollars_per_unit
    outcome: dict[str, Any] = {}

    def call():
        result = send(max_units) if bounded else send()
        used = dict(units or {})
        measured = {} if measure is None else measure(result)
        if measured is None:
            outcome["charge"] = None
            return result
        used.update({unit: amount for unit, amount in measured.items() if amount is not None})
        for unit, amount in (fallback or {}).items():
            used.setdefault(unit, amount)
        dollars, charged_as_priced = price.cost(used)
        # The priced unit never came back: charge everything held (all the
        # run had left), so the run stops on its limit rather than guess low.
        unreported = price.unit is not None and used.get(price.unit) is None
        if unreported:
            dollars = projected
        try:
            outcome["charge"] = record_tool_dollars(budget, price, dollars, priced=charged_as_priced,
                                                    unreported=unreported)
        except BudgetExceeded as exc:
            outcome["charge"] = getattr(exc, "token_charge", None)
            if outcome["charge"] is None:
                raise
            outcome["stop"] = exc
        return result

    def settlement(_result):
        # An operator's unit price is a planning ceiling, not invoice
        # evidence, so the receipt's cost is always marked estimated.
        charge = outcome["charge"]
        if charge is None:
            return 0.0, "estimated", None
        return charge.dollars, "estimated", charge.pricing_evidence

    try:
        held = budget.reserve(projected)
    except BudgetExceeded as exc:
        if priced or price.unit is not None:
            raise
        raise BudgetExceeded(f"{exc}{tool_ceiling_reason(service)}") from exc
    try:
        result = metered_provider_call(
            service, call, projected_dollars=projected, settlement=settlement,
            organization_budget=budget, category=category,
            parent_category=parent_category or category, service=service,
            operation_id=operation_id, attempt_no=attempt_no,
        )
    finally:
        budget.release(held)
    if outcome.get("stop") is not None:
        raise outcome["stop"]
    return result
