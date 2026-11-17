"""Setup steps for decisions a run must ask a person about and for the prices
of paid tool services (``[approval] decision_*`` and ``[budget.tool_prices]``).

They live outside the facade to keep it under its size ratchet; prompts go
through ``_seams`` so tests that patch the facade's prompt helpers still apply.
"""
from __future__ import annotations

import math
from typing import Any

from maverick.config_contracts import INTEGER_SETTINGS

from ._common import _safe_int
from ._seams import _q_checkbox, _q_text, console


def _pick_decision_requests() -> dict[str, Any]:
    """``[approval] decision_*``: where a run must ask a person to decide,
    which of those need an administrator, and how long a decision waits."""
    from maverick.decision_requests import AREAS, DEFAULT_ADMIN_AREAS, DEFAULT_AREAS

    contract = INTEGER_SETTINGS["approval.decision_expiry_hours"]
    console.print()
    console.print(
        "[dim]A run can stop and ask a person to choose between options, with its "
        "recommendation. In the areas you pick it must ask instead of deciding alone. "
        "The run waits, spending nothing, until someone answers on the Approvals page, "
        "in Slack or with the CLI. If nobody answers in time, the run stops.[/dim]"
    )
    titles = {f"{key} - {label}": key for key, label in AREAS.items()}
    picked = _q_checkbox(
        "  Areas where a run must ask a person to decide",
        list(titles), default=[t for t, key in titles.items() if key in DEFAULT_AREAS])
    admin = _q_checkbox(
        "  Areas whose decisions need a workspace administrator",
        list(titles), default=[t for t, key in titles.items() if key in DEFAULT_ADMIN_AREAS])
    hours = _safe_int(
        _q_text("  Hours a decision waits before the run stops", default=str(contract.default)),
        default=contract.default,
    )
    return {
        "decision_areas": [titles[t] for t in picked if t in titles],
        "decision_admin_areas": [titles[t] for t in admin if t in titles],
        "decision_expiry_hours": max(contract.minimum, min(hours, contract.maximum)),
    }


def _parse_tool_prices(raw: str) -> dict[str, dict[str, Any]]:
    """``service=dollars/unit`` entries separated by commas; ValueError if any
    entry names an unknown service or unit, or an amount outside 0..10,000."""
    from maverick.budget import TOOL_PRICE_UNITS, paid_tool_services

    services = paid_tool_services()
    prices: dict[str, dict[str, Any]] = {}
    for part in filter(None, (piece.strip() for piece in raw.split(","))):
        service, _, rest = part.partition("=")
        amount, _, unit = rest.partition("/")
        service, unit = service.strip().lower(), unit.strip().lower()
        dollars = float(amount)
        if (service not in services or unit not in TOOL_PRICE_UNITS
                or not math.isfinite(dollars) or not 0 <= dollars <= 10_000):
            raise ValueError(part)
        prices[service] = {"dollars": dollars, "per": unit}
    return prices


def _pick_tool_prices(ceiling: float) -> dict[str, dict[str, Any]]:
    """Optional ``[budget.tool_prices]`` entries: a USD price per unit for a
    paid tool service. A service left out is charged the per-call ceiling,
    so search, the paid tool agents call most, is asked about first."""
    from maverick.budget import PAID_TOOL_SERVICES, TOOL_PRICE_UNITS

    while True:
        raw = _q_text("  Prices for paid tool services, search first, as service=USD/unit separated "
                      "by commas (for example tavily=PRICE/request, where PRICE is your rate in USD). "
                      f"Unpriced, each search counts ${ceiling:.2f}. Leave blank to set them "
                      "later in Settings",
                      default="")
        try:
            return _parse_tool_prices(raw)
        except ValueError:
            console.print("[yellow]Services: " + ", ".join(PAID_TOOL_SERVICES)
                          + ", or a pay-per-use connector's name. Units: "
                          + ", ".join(TOOL_PRICE_UNITS) + ". Amounts from 0 to 10,000.[/yellow]")
