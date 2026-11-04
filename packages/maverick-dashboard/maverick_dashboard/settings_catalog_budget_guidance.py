"""Read-only budget guidance controls; none increases an execution cap."""
from __future__ import annotations

import math

from maverick.config_contracts import BOOLEAN_SETTINGS, NUMBER_LIST_SETTINGS


def thresholds(value):
    contract = NUMBER_LIST_SETTINGS["budget.warning_thresholds"]
    if not isinstance(value, list) or not 1 <= len(value) <= contract.max_items:
        raise ValueError("Use one to ten warning thresholds between 0 and 1.")
    result = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float, str)):
            raise ValueError("Warning thresholds must be finite numbers above 0 and at most 1.")
        try:
            number = float(item)
        except (ValueError, OverflowError) as exc:
            raise ValueError("Warning thresholds must be finite numbers above 0 and at most 1.") from exc
        if not math.isfinite(number) or not contract.minimum_exclusive < number <= contract.maximum:
            raise ValueError("Warning thresholds must be finite numbers above 0 and at most 1.")
        result.append(number)
    return sorted(set(result))


def entries(S, C, Column):
    common = {"group": "Spending & limits", "reader": "maverick.budget_guidance", "subgroup": "Spending guidance"}
    return (
        S("budget", "guidance", "Show budget headroom before work", "Show known spending limits and available headroom before a task. Guidance never raises a cap or estimates an unknown provider price.", "toggle", default=BOOLEAN_SETTINGS["budget.guidance"].default, **common),
        S("budget", "warnings", "Warn when work approaches its limits", "Show deduplicated in-product warnings as a task approaches its existing limits. Turning warnings off does not disable hard limits.", "toggle", default=BOOLEAN_SETTINGS["budget.warnings"].default, **common),
        S("budget", "warning_thresholds", "Limit warning thresholds", "Fractions of a task limit at which to warn: 0.8 means 80 percent. Use one to ten numbers above 0 and at most 1. Duplicate values are combined; limits remain unchanged.", "list", default=list(NUMBER_LIST_SETTINGS["budget.warning_thresholds"].default), max_items=NUMBER_LIST_SETTINGS["budget.warning_thresholds"].max_items, max_length=NUMBER_LIST_SETTINGS["budget.warning_thresholds"].dashboard_max_length, item_label="Threshold", item_hint="0.8", item_error="a number above 0 and at most 1", **common),
    )
