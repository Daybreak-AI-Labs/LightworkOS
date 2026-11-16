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
    PAID_TOOL_SERVICES,
    BudgetExceeded,
    UsageAccountingError,
    _is_private_endpoint,
    record_tool_dollars,
    tool_call_price,
)
from ..provider_cost_cap import (
    ProviderAccountingUnavailable,
    ProviderCapExceeded,
    metered_provider_call,
)


def paid_tool_services() -> dict[str, str]:
    """Every service name a [budget.tool_prices] entry can price, with a label."""
    from .enterprise_connectors import PAID_CONNECTOR_NAMES

    services = dict(PAID_TOOL_SERVICES)
    for name in sorted(PAID_CONNECTOR_NAMES - set(services)):
        services[name] = f"{name} connector"
    return services


class PaidCallRefused(RuntimeError):
    """A paid tool call with no run budget to charge; nothing was sent."""


# Signals a tool must let through: catching them would skip the spending limit.
# A ``PaidCallRefused`` is shown to the caller as an ERROR line instead.
STOP_SIGNALS = (BudgetExceeded, ProviderCapExceeded, ProviderAccountingUnavailable,
                UsageAccountingError)


def is_free_backend(url: str | None) -> bool:
    """Whether ``url`` is on this machine or a private network, so it is free."""
    return bool(url) and _is_private_endpoint(url)


def charged_call(
    service: str,
    send: Callable[[], Any],
    *,
    budget,
    label: str,
    units: dict[str, float] | None = None,
    measure: Callable[[Any], dict[str, float | None]] | None = None,
    category: str = "inference",
    operation_id: str | None = None,
    attempt_no: int | None = None,
    parent_category: str | None = None,
):
    """Run ``send`` (one paid request to ``service``) charged to ``budget``.

    ``units`` is what the call uses that is known before it is sent (one
    request, the characters in the text); ``measure`` reads more from the
    reply (seconds of audio or compute). A unit that stays unknown is charged
    the per-call ceiling. ``measure`` returns ``None`` when ``send`` stopped
    before anything was sent, so nothing is charged. Returns what ``send``
    returned.
    """
    if budget is None:
        raise PaidCallRefused(
            f"{label} calls are charged to a run's spending limit, and this call has "
            "none (a flow's tool step, for example). Call it from an agent step "
            "instead; nothing was sent")
    budget.check()
    price = tool_call_price(service)
    projected, _priced = price.cost(units)
    outcome: dict[str, Any] = {}

    def call():
        result = send()
        used = dict(units or {})
        measured = {} if measure is None else measure(result)
        if measured is None:
            outcome["charge"] = None
            return result
        used.update({unit: amount for unit, amount in measured.items() if amount is not None})
        dollars, priced = price.cost(used)
        try:
            outcome["charge"] = record_tool_dollars(budget, price, dollars, priced=priced)
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

    held = budget.reserve(projected)
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
