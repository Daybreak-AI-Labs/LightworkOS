"""A tool that returns None must not crash the agent turn.

A tool fn returning None (a latent bug in tool code) would propagate None into
agent._cap_tool_output, whose ``len(text)`` raises ``TypeError: object of type
'NoneType' has no len()`` -- crashing the whole tool-call. The fn contract is
``-> str``; the framework coerces a non-str result to a stable string at both
the execution boundary and the cap.
"""
from __future__ import annotations

import asyncio

from maverick.agent import _cap_tool_output
from maverick.tools import _execute_tool_fn


def test_cap_tool_output_tolerates_non_str():
    assert _cap_tool_output(None) == ""
    assert _cap_tool_output(123) == "123"
    assert _cap_tool_output("ok") == "ok"


def test_execute_tool_fn_coerces_non_str_result():
    async def run(fn):
        return await _execute_tool_fn(fn, {}, lambda c: c)

    assert asyncio.run(run(lambda a: None)) == ""
    assert asyncio.run(run(lambda a: "hi")) == "hi"
    assert asyncio.run(run(lambda a: 42)) == "42"
