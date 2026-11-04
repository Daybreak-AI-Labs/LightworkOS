"""Regression tests: async/agent-bus/spawn tools must return a string (or a
handled ``ERROR:``) for hostile, type-confused, or missing model args -- never
raise an uncaught exception.

The agent loop dispatches tools through ``ToolRegistry.run``, which wraps every
call in a broad ``except`` -- but these fns are also driven directly (and a
non-conforming MCP client or a loose LLM can supply wrong-typed args that the
JSON schema declares as strings/numbers/arrays). The pre-fix code did
``(args.get("url") or "").strip()`` / ``float(args["timeout"])`` /
``args["role"]``, which raised ``AttributeError`` / ``ValueError`` / ``KeyError``
on a non-string / non-numeric / missing value. These exercise those paths.
"""
from __future__ import annotations

import asyncio

import pytest

# ---- websocket: non-string url must not AttributeError on .strip() ----------

@pytest.mark.parametrize("bad_url", [123, 1.5, True, ["x"], {"a": 1}])
def test_websocket_nonstring_url(bad_url):
    from maverick.tools.websocket_tool import websocket_tool

    out = asyncio.run(websocket_tool().fn({"url": bad_url}))
    assert isinstance(out, str) and out.startswith("ERROR")


# ---- send_to_agent: non-string to_id must not AttributeError ---------------

@pytest.mark.parametrize("bad", [123, 1.5, ["x"], {"a": 1}, True])
def test_send_to_agent_nonstring_to_id(bad):
    from maverick.tools.agent_bus_tool import send_to_agent

    # Invariant: a string back, never an AttributeError on .strip().
    out = send_to_agent("me").fn({"to_id": bad, "payload": "p"})
    assert isinstance(out, str)


# ---- recv_from_agent: non-numeric timeout must not raise -------------------

@pytest.mark.parametrize("bad", ["not-a-number", "  ", ["x"], {"a": 1}])
def test_recv_from_agent_bad_timeout(bad):
    from maverick.tools.agent_bus_tool import recv_from_agent

    out = asyncio.run(recv_from_agent("me").fn({"timeout": bad}))
    assert isinstance(out, str) and out.startswith("ERROR")


# ---- delegate_to_agent: non-string to_id/task must not raise ---------------

@pytest.mark.parametrize("args", [
    {"to_id": 123, "task": "t"},
    {"to_id": "x", "task": ["junk"]},
    {"to_id": {"a": 1}, "task": "t"},
])
def test_delegate_to_agent_nonstring(args):
    from maverick.tools.agent_bus_tool import delegate_to_agent

    class _Agent:
        name = "me"
        capability = None

        class ctx:  # noqa: N801 -- test stub
            goal_id = 1

    out = delegate_to_agent(_Agent()).fn(args)
    assert isinstance(out, str)
    # Fail-open path (no authority) or a validation error -- either way a string.
    assert out.startswith("ERROR") or "delegated" in out


# ---- spawn tools: missing required keys / wrong types must not KeyError ----

class _Ctx:
    goal_id = 1
    max_depth = 3
    max_total_spawns = 10

    class budget:  # noqa: N801 -- test stub
        dollars = 0.0
        max_dollars = 100.0

    class blackboard:  # noqa: N801 -- test stub
        @staticmethod
        def post(*a, **k):
            pass

    def try_reserve_spawns(self, n):
        return True

    def release_spawns(self, n):
        pass


class _Parent:
    name = "p"
    depth = 0
    max_steps = 5
    role = "r"
    brief = "b"
    capability = None
    ctx = _Ctx()

    def _effective_capability(self, t):
        return None


def test_spawn_subagent_missing_keys():
    from maverick.tools import spawn

    out = asyncio.run(spawn.spawn_subagent_tool(_Parent()).fn({}))
    assert isinstance(out, str) and out.startswith("ERROR")
    out = asyncio.run(spawn.spawn_subagent_tool(_Parent()).fn({"role": "coder"}))
    assert isinstance(out, str) and out.startswith("ERROR")


def test_spawn_swarm_missing_agents():
    from maverick.tools import spawn

    out = asyncio.run(spawn.spawn_swarm_tool(_Parent()).fn({}))
    assert isinstance(out, str) and out.startswith("ERROR")


def test_spawn_swarm_spec_missing_role_or_task():
    from maverick.tools import spawn

    # A spec dict that is well-formed JSON but lacks the required keys must be
    # rejected with a string, not crash at Agent(role=spec["role"]).
    out = asyncio.run(
        spawn.spawn_swarm_tool(_Parent()).fn({"agents": [{"role": "coder"}]})
    )
    assert isinstance(out, str) and out.startswith("ERROR")
    out = asyncio.run(
        spawn.spawn_swarm_tool(_Parent()).fn({"agents": [{"task": "do x"}]})
    )
    assert isinstance(out, str) and out.startswith("ERROR")


def test_spawn_specialist_missing_keys_and_unhashable_domain():
    from maverick.tools import spawn

    out = asyncio.run(spawn.spawn_specialist_tool(_Parent()).fn({}))
    assert isinstance(out, str) and out.startswith("ERROR")
    # An unhashable (list/dict) domain used to TypeError at domains.get(domain).
    out = asyncio.run(
        spawn.spawn_specialist_tool(_Parent()).fn({"domain": ["x"], "task": "t"})
    )
    assert isinstance(out, str) and out.startswith("ERROR")
