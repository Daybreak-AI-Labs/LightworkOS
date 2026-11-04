"""LangChain / LangGraph interop adapter."""
from __future__ import annotations

import importlib.util
import sys
import types

import pytest
from maverick.langchain_adapter import (
    maverick_langchain_tool,
    run_maverick_goal,
    wrap_langchain_tool,
)

_HAS_LANGCHAIN = importlib.util.find_spec("langchain_core") is not None


class _FakeGoal:
    def __init__(self, gid, result=None):
        self.id = gid
        self.result = result


class _FakeWorld:
    def __init__(self, shared):
        self.s = shared

    def create_goal(self, title, description=""):
        self.s["seq"] += 1
        self.s["goals"][self.s["seq"]] = _FakeGoal(self.s["seq"], result=None)
        self.s["titles"][self.s["seq"]] = title
        return self.s["seq"]

    def get_goal(self, gid):
        return self.s["goals"].get(gid)

    def close(self):
        self.s["closes"] += 1


def _shared():
    return {"seq": 0, "goals": {}, "titles": {}, "closes": 0, "dispatched": []}


def test_run_maverick_goal_creates_dispatches_and_returns_result():
    shared = _shared()

    def dispatch(gid, **kw):
        shared["dispatched"].append((gid, kw))
        shared["goals"][gid].result = "the answer is 42"
        return "done"

    out = run_maverick_goal(
        "Compute the answer", "to everything",
        max_dollars=3.0,
        world_factory=lambda: _FakeWorld(shared),
        dispatch=dispatch,
    )
    assert out == "the answer is 42"
    assert shared["titles"][1] == "Compute the answer"
    assert shared["dispatched"][0][1]["max_dollars"] == 3.0


def test_run_maverick_goal_forwards_security_context():
    shared = _shared()
    capability = object()

    run_maverick_goal(
        "Do a scoped thing",
        max_dollars=4.0,
        channel="discord",
        user_id="discord:alice",
        capability=capability,
        world_factory=lambda: _FakeWorld(shared),
        dispatch=lambda gid, **kw: shared["dispatched"].append((gid, kw)) or "done",
    )

    assert shared["dispatched"] == [
        (
            1,
            {
                "max_dollars": 4.0,
                "channel": "discord",
                "user_id": "discord:alice",
                "capability": capability,
            },
        )
    ]


def test_langchain_tool_binds_security_context_outside_model_schema(monkeypatch):
    captured = {}
    calls = []

    class FakeStructuredTool:
        @staticmethod
        def from_function(fn, **kw):
            captured["fn"] = fn
            captured["kw"] = kw
            return types.SimpleNamespace(name=kw["name"], fn=fn)

    monkeypatch.setitem(
        sys.modules, "langchain_core", types.ModuleType("langchain_core")
    )
    fake_tools = types.ModuleType("langchain_core.tools")
    fake_tools.StructuredTool = FakeStructuredTool
    monkeypatch.setitem(sys.modules, "langchain_core.tools", fake_tools)
    monkeypatch.setattr(
        "maverick.langchain_adapter.run_maverick_goal",
        lambda *args, **kw: calls.append((args, kw)) or "ok",
    )

    capability = object()
    tool = maverick_langchain_tool(
        max_dollars=5.0,
        channel="slack",
        user_id="slack:bob",
        capability=capability,
    )

    assert tool.fn("ship it", "safely") == "ok"
    assert captured["fn"].__annotations__ == {
        "goal": "str",
        "description": "str",
        "return": "str",
    }
    assert calls == [
        (
            ("ship it", "safely"),
            {
                "max_dollars": 5.0,
                "channel": "slack",
                "user_id": "slack:bob",
                "capability": capability,
            },
        )
    ]


def test_run_maverick_goal_status_line_when_no_result():
    shared = _shared()

    out = run_maverick_goal(
        "Do a thing",
        world_factory=lambda: _FakeWorld(shared),
        dispatch=lambda gid, **kw: "blocked",
    )
    assert "goal #1 ended blocked" in out


def test_run_maverick_goal_requires_goal():
    with pytest.raises(ValueError):
        run_maverick_goal("   ")


def test_wrap_langchain_tool_invokes_underlying():
    class FakeLCTool:
        name = "search"
        description = "search the web"

        def invoke(self, value):
            return f"results for {value}"

    tool = wrap_langchain_tool(FakeLCTool())
    assert tool.name == "search"
    assert tool.description == "search the web"
    assert tool.fn({"input": "agents"}) == "results for agents"


def test_wrap_langchain_tool_supports_legacy_run():
    class LegacyTool:
        name = "calc"
        description = "calculate"

        def run(self, value):
            return "ok:" + value

    assert wrap_langchain_tool(LegacyTool()).fn({"input": "1+1"}) == "ok:1+1"


@pytest.mark.skipif(_HAS_LANGCHAIN, reason="langchain-core IS installed")
def test_langchain_tool_raises_clean_error_without_extra():
    with pytest.raises(ImportError, match="langchain"):
        maverick_langchain_tool()


@pytest.mark.skipif(not _HAS_LANGCHAIN, reason="needs langchain-core")
def test_langchain_tool_builds_when_available():
    t = maverick_langchain_tool()
    assert t.name == "maverick"
