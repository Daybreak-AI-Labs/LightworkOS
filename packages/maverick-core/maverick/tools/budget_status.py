"""Budget status tool.

Lets the agent ask "how much budget do I have left?" so long-running
goals can self-throttle (cut planning depth, skip optional searches,
or wrap up) before they hit the hard cap.

The tool reads the current Budget instance from the runtime context.
Returns dollars spent, dollars cap, token counts (in/out), tool calls,
and wall-clock elapsed.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_BUDGET_STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}


def _run_budget_status(_: dict[str, Any], *, budget=None) -> str:
    if budget is None:
        return (
            "ERROR: no Budget bound to this tool. The tool factory must "
            "be called with budget=<Budget instance>."
        )
    def cap(name, spec="", prefix=""):
        value = getattr(budget, name, None)
        return prefix + format(value, spec) if value is not None else "no task limit"

    lines = [
        f"dollars:        ${getattr(budget, 'dollars', 0.0):.4f}"
        f" / {cap('max_dollars', '.2f', '$')}",
        f"input tokens:   {getattr(budget, 'input_tokens', 0):,}"
        f" / {cap('max_input_tokens', ',')}",
        f"output tokens:  {getattr(budget, 'output_tokens', 0):,}"
        f" / {cap('max_output_tokens', ',')}",
        f"cache reads:    {getattr(budget, 'cache_read_tokens', 0):,}",
        f"cache writes:   {getattr(budget, 'cache_write_tokens', 0):,}",
        f"tool calls:     {getattr(budget, 'tool_calls', 0)}"
        f" / {cap('max_tool_calls')}",
    ]
    try:
        elapsed = budget.elapsed()
        lines.append(f"wall seconds:   {elapsed:.0f}"
                     f" / {cap('max_wall_seconds')}")
    except AttributeError:
        pass

    # Headroom hints for the agent (most useful field).
    try:
        spent = float(getattr(budget, "dollars", 0.0))
        cap = float(getattr(budget, "max_dollars", 0.0))
        if cap > 0:
            pct = (spent / cap) * 100
            if pct >= 90:
                lines.append("WARNING: >=90% of dollar budget consumed -- wrap up soon.")
            elif pct >= 50:
                lines.append("Note: >=50% of dollar budget consumed.")
    except (TypeError, ValueError):
        pass
    return "\n".join(lines)


def budget_status(budget=None) -> Tool:
    """Factory: builds the budget_status tool.

    Bind the agent's active Budget via the ``budget`` kwarg so the tool
    can self-report. If unbound, calling returns an error rather than
    misleading zeros.
    """
    def fn(args: dict[str, Any]) -> str:
        return _run_budget_status(args, budget=budget)
    return Tool(
        name="budget_status",
        description=(
            "Report how much of the run's budget has been consumed: "
            "dollars, tokens (in/out + cache reads/writes), tool calls, "
            "and wall-clock seconds. Use this when planning long work "
            "or before kicking off expensive searches -- if budget is "
            ">=90% spent, prefer concise output and skip non-essentials."
        ),
        input_schema=_BUDGET_STATUS_SCHEMA,
        fn=fn,
    )
