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
from ..governed_http import dispatch_tracking, never_connected
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


def _never_sent(error: BaseException, dispatch: dict[str, bool]) -> bool:
    """Whether ``send`` raised ``error`` before any request left this machine.

    A send through the governed HTTP layer reports that itself, whatever the
    error. For any other send, only a refusal here or a connection never made
    counts as not sent; anything else may have reached the service.
    """
    if dispatch["reported"]:
        return not dispatch["sent"]
    from ..enterprise import EgressBlocked
    from ._ssrf import BlockedHost

    return isinstance(error, (PaidCallRefused, EgressBlocked, BlockedHost)) or never_connected(error)


def _charge_if_sent(budget, price, held: float, error: BaseException,
                    dispatch: dict[str, bool], outcome: dict[str, Any]) -> None:
    """A ``send`` that raised ``error`` may have reached the service: charge
    everything ``held``, as for usage the reply never reported, so a retry
    cannot spend it again. A send known to have sent nothing is free.
    ``outcome`` keeps what was charged, for the provider receipt."""
    if held <= 0 or _never_sent(error, dispatch):
        outcome["free"] = True
        return
    try:
        outcome["charge"] = record_tool_dollars(budget, price, held, priced=False,
                                                unconfirmed=True)
    except BudgetExceeded as exc:
        outcome["charge"] = getattr(exc, "token_charge", None)
        raise


def _failure_receipt(outcome: dict[str, Any]):
    """The provider receipt of a failed send: what the run was charged, $0
    when it cost nothing, else unknown. Every ledger then counts it once."""
    if outcome.get("charge") is not None:
        return outcome["charge"].dollars, "estimated", outcome["charge"].pricing_evidence
    if outcome.get("free"):
        return 0.0, "estimated", None
    return None, None, None


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
    ``send`` stopped before anything was sent, so nothing is charged. When
    ``send`` raises after a request may have left, the call is charged
    everything it held; it is not charged when no request left.

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
    if price.unit is not None and not priced:
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
        with dispatch_tracking() as dispatch:
            try:
                result = send(max_units) if bounded else send()
            except BaseException as error:
                _charge_if_sent(budget, price, projected, error, dispatch, outcome)
                raise
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
        unreported = price.unit is not None and not charged_as_priced
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
            organization_budget=budget, failure_settlement=lambda _error: _failure_receipt(outcome),
            category=category,
            parent_category=parent_category or category, service=service,
            operation_id=operation_id, attempt_no=attempt_no,
        )
    finally:
        budget.release(held)
    if outcome.get("stop") is not None:
        raise outcome["stop"]
    return result
