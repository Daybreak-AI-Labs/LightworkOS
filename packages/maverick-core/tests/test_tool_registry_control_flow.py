"""ToolRegistry.run must NOT swallow control-flow stop signals.

A spawned child (spawn_subagent/spawn_swarm/spawn_specialist) shares the
parent Budget and killswitch, and re-raises BudgetExceeded / killswitch.Halted
to stop the whole run immediately (see tools/spawn.py:_run_child_and_report
and _run_swarm). The agent loop has a matching
``except (BudgetExceeded, killswitch.Halted): ...; raise`` handler
(agent.py) that relies on those exceptions PROPAGATING out of the tool call.

Regression: ToolRegistry.run wrapped the tool fn in a blanket
``except Exception as e: return f"ERROR: ..."``. Both signals are Exception
subclasses, so they were caught and folded into an ordinary "ERROR:" tool
result string -- the agent loop's re-raise could never fire and the budget
cap / killswitch was not enforced. Ordinary tool errors must still surface as
strings.
"""
from __future__ import annotations

import asyncio

import pytest
from maverick import killswitch
from maverick.budget import BudgetExceeded
from maverick.tools import Tool, ToolRegistry


def _registry_with(name: str, fn) -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(
        Tool(
            name=name,
            description="d",
            input_schema={"type": "object", "properties": {}},
            fn=fn,
        )
    )
    return reg


def test_budget_exceeded_propagates_not_swallowed():
    def boom(args):
        raise BudgetExceeded("child blew the cap")

    reg = _registry_with("spawn_subagent", boom)
    with pytest.raises(BudgetExceeded):
        asyncio.run(reg.run("spawn_subagent", {}))


def test_halted_propagates_not_swallowed():
    def halt(args):
        raise killswitch.Halted("test", "file")

    reg = _registry_with("spawn_swarm", halt)
    with pytest.raises(killswitch.Halted):
        asyncio.run(reg.run("spawn_swarm", {}))


def test_ordinary_error_still_becomes_string():
    def err(args):
        raise ValueError("boom")

    reg = _registry_with("read_file", err)
    out = asyncio.run(reg.run("read_file", {}))
    assert out == "ERROR: ValueError: boom"
