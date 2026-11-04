"""What past tasks by one agent or specialist usually cost.

History only, never a prediction: the recorded cost of this workspace's most
recent finished tasks run by that agent or specialist, summarized as the
middle half (25th to 75th percentile) and the median. Below a minimum number
of finished tasks (``[spending_limits] typical_cost_min_runs``, default 10)
there is no range, only the count.
"""
from __future__ import annotations

import statistics
from typing import Any

DEFAULT_MIN_RUNS = 10
MIN_RUNS_FLOOR = 2
MIN_RUNS_CEILING = 1000
# The most recent finished tasks the range is drawn from.
HISTORY_LIMIT = 500


def validate_min_runs(value: object) -> int:
    """A whole number of finished tasks from 2 to 1000."""
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("must be a whole number")
    number = value
    if not MIN_RUNS_FLOOR <= number <= MIN_RUNS_CEILING:
        raise ValueError(f"must be from {MIN_RUNS_FLOOR} to {MIN_RUNS_CEILING}")
    return number


def min_runs() -> int:
    """``[spending_limits] typical_cost_min_runs``; the default when unset or unreadable."""
    try:
        from .config import load_config

        raw = ((load_config() or {}).get("spending_limits") or {}).get("typical_cost_min_runs")
    except Exception:  # noqa: BLE001 -- unreadable config keeps the default
        return DEFAULT_MIN_RUNS
    if raw is None:
        return DEFAULT_MIN_RUNS
    try:
        return validate_min_runs(raw)
    except ValueError:
        return DEFAULT_MIN_RUNS


def summarize(costs: list[float], minimum: int) -> dict[str, Any]:
    """The range and median of ``costs``, or only the count below ``minimum``."""
    runs = len(costs)
    result: dict[str, Any] = {"runs": runs, "min_runs": minimum, "enough": runs >= minimum,
                              "low": None, "median": None, "high": None}
    if result["enough"] and runs >= 2:
        low, median, high = statistics.quantiles(costs, n=4, method="inclusive")
        result.update(low=low, median=median, high=high)
    else:
        result["enough"] = False
    return result


def typical_cost(world, *, specialist: str = "", agent_principal: str = "",
                 owner: str = "", minimum: int | None = None) -> dict[str, Any]:
    """Typical cost of one specialist's (by pack name) or one agent's (by its
    principal) finished tasks, or of one person's own (``owner``, shown under
    the chat's Start button), in the world the caller opened, which is already
    scoped to the viewer's workspace. A store that can't be read gives no
    range rather than a guess."""
    needed = min_runs() if minimum is None else minimum
    try:
        costs = world.task_costs_for(domain=specialist, execution_principal=agent_principal,
                                     limit=HISTORY_LIMIT, **({"owner": owner} if owner else {}))
    except Exception:  # noqa: BLE001 -- no history is shown as no history
        costs = []
    return summarize(costs, needed)


__all__ = ["DEFAULT_MIN_RUNS", "min_runs", "summarize", "typical_cost", "validate_min_runs"]
