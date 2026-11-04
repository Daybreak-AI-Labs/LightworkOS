"""Tests for speculative tool execution (tool-cache pre-warming).

Deterministic, no network: fake Tool-shaped objects in a dict registry, the
tool-output cache enabled per-test via env, and ``tool_cache.reset()`` around
every test so state never leaks.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from maverick import speculative_tools as st
from maverick.cache import tool as tool_cache


@dataclass
class FakeTool:
    name: str
    parallel_safe: bool
    fn: Callable[[dict[str, Any]], Any]
    calls: list[dict] = field(default_factory=list)


def _make_tool(name: str, *, safe: bool = True, result: str | None = None,
               fn: Callable | None = None) -> FakeTool:
    tool = FakeTool(name=name, parallel_safe=safe, fn=lambda a: a)

    def _default(args: dict) -> str:
        tool.calls.append(args)
        return result if result is not None else f"{name}-output"

    tool.fn = fn if fn is not None else _default
    return tool


@pytest.fixture
def cache_on(monkeypatch):
    """Enable the tool-output cache for the test and leave no residue."""
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    monkeypatch.delenv("MAVERICK_TOOL_CACHE_SNAPSHOT", raising=False)
    tool_cache.reset()
    yield
    tool_cache.reset()


# ---- speculate ----------------------------------------------------------------

def test_unsafe_tools_never_execute(cache_on):
    writer = _make_tool("write_file", safe=False)
    report = st.speculate({"write_file": writer}, [("write_file", {"path": "x"})])
    assert writer.calls == []
    assert report.skipped_unsafe == ["write_file"]
    assert report.executed == []


def test_unknown_tools_are_skipped_not_fatal(cache_on):
    report = st.speculate({}, [("no_such_tool", {})])
    assert report.skipped_unsafe == ["no_such_tool"]
    assert report.executed == [] and report.errors == []


def test_already_cached_candidates_are_skipped(cache_on):
    tool = _make_tool("read_file")
    args = {"path": "a.py"}
    tool_cache.store_cached(tool, args, "warm already")

    report = st.speculate({"read_file": tool}, [("read_file", args)])

    assert tool.calls == []  # never re-executed
    assert report.skipped_cached == ["read_file"]


def test_results_land_in_the_cache(cache_on):
    tool = _make_tool("read_file", result="file contents")
    args = {"path": "a.py"}

    report = st.speculate({"read_file": tool}, [("read_file", args)])

    assert report.executed == ["read_file"]
    hit, value = tool_cache.get_cached(tool, args)
    assert hit is True and value == "file contents"


def test_exploding_tool_records_error_without_raising(cache_on):
    def _boom(_args):
        raise RuntimeError("backend down")

    bad = _make_tool("flaky", fn=_boom)
    good = _make_tool("read_file", result="ok")
    registry = {"flaky": bad, "read_file": good}

    report = st.speculate(registry, [("flaky", {}), ("read_file", {})])

    assert report.executed == ["read_file"]  # the failure didn't stop the rest
    assert len(report.errors) == 1
    name, message = report.errors[0]
    assert name == "flaky" and "backend down" in message
    hit, _ = tool_cache.get_cached(bad, {})
    assert hit is False  # errors are never cached


def test_budget_guard_false_stops_execution(cache_on):
    tool = _make_tool("read_file")
    report = st.speculate(
        {"read_file": tool}, [("read_file", {"path": "a"})],
        budget_guard=lambda: False,
    )
    assert tool.calls == [] and report.executed == []


def test_budget_guard_checked_before_each_execution(cache_on):
    tool = _make_tool("read_file")
    answers = [True, False, False]
    candidates = [("read_file", {"path": p}) for p in ("a", "b", "c")]

    report = st.speculate({"read_file": tool}, candidates,
                          budget_guard=lambda: answers.pop(0))

    assert len(report.executed) == 1  # only the first prediction ran
    assert tool.calls == [{"path": "a"}]


def test_broken_budget_guard_fails_safe(cache_on):
    def _bad_guard():
        raise ValueError("guard bug")

    tool = _make_tool("read_file")
    report = st.speculate({"read_file": tool}, [("read_file", {})],
                          budget_guard=_bad_guard)
    assert tool.calls == [] and report.executed == []


def test_noop_when_tool_cache_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_TOOL_CACHE", raising=False)
    tool_cache.reset()
    tool = _make_tool("read_file")

    report = st.speculate({"read_file": tool}, [("read_file", {})])

    assert tool.calls == []  # nowhere to store the result: don't burn work
    assert report == st.SpeculationReport()
    tool_cache.reset()


def test_duplicate_predictions_execute_once(cache_on):
    tool = _make_tool("read_file")
    args = {"path": "a.py"}
    report = st.speculate({"read_file": tool}, [("read_file", args)] * 3)
    assert len(tool.calls) == 1
    assert report.executed == ["read_file"]


def test_async_tool_fn_is_drained(cache_on):
    async def _async_fn(args):
        return f"async:{args['path']}"

    tool = _make_tool("read_file", fn=_async_fn)
    report = st.speculate({"read_file": tool}, [("read_file", {"path": "a"})])
    assert report.executed == ["read_file"]
    hit, value = tool_cache.get_cached(tool, {"path": "a"})
    assert hit and value == "async:a"


def test_works_with_a_real_tool_registry(cache_on):
    from maverick.tools import Tool, ToolRegistry

    registry = ToolRegistry()
    registry.register(Tool(name="read_file", description="read",
                           input_schema={}, fn=lambda a: "regdata",
                           parallel_safe=True))
    report = st.speculate(registry, [("read_file", {"path": "x"}),
                                     ("missing", {})])
    assert report.executed == ["read_file"]
    assert report.skipped_unsafe == ["missing"]


def test_malformed_candidates_never_throw(cache_on):
    tool = _make_tool("read_file")
    report = st.speculate({"read_file": tool},
                          [None, ("read_file",), ("read_file", {"path": "a"})])
    assert report.executed == ["read_file"]


# ---- predict_from_history -------------------------------------------------------

def test_predictor_returns_repeated_calls_most_frequent_first():
    history = [
        ("read_file", {"path": "a.py"}),
        ("list_dir", {"path": "."}),
        ("read_file", {"path": "a.py"}),
        ("grep", {"q": "once"}),
        ("read_file", {"path": "a.py"}),
        ("list_dir", {"path": "."}),
    ]
    assert st.predict_from_history(history) == [
        ("read_file", {"path": "a.py"}),
        ("list_dir", {"path": "."}),
    ]


def test_predictor_never_suggests_one_off_calls():
    history = [("a", {"x": 1}), ("b", {}), ("c", {})]
    assert st.predict_from_history(history) == []


def test_predictor_distinguishes_same_tool_different_args():
    history = [("read_file", {"path": "a"}), ("read_file", {"path": "b"}),
               ("read_file", {"path": "b"})]
    assert st.predict_from_history(history) == [("read_file", {"path": "b"})]


def test_predictor_ties_keep_first_seen_order_and_top_k_caps():
    history = [("b", {}), ("a", {}), ("b", {}), ("a", {}), ("c", {}), ("c", {})]
    assert st.predict_from_history(history) == [("b", {}), ("a", {}), ("c", {})]
    assert st.predict_from_history(history, top_k=1) == [("b", {})]
    assert st.predict_from_history(history, top_k=0) == []


def test_predictor_is_deterministic():
    history = [("a", {"k": 1}), ("b", {}), ("a", {"k": 1}), ("b", {})]
    runs = {tuple(repr(p) for p in st.predict_from_history(history)) for _ in range(20)}
    assert len(runs) == 1


# ---- enabled() ------------------------------------------------------------------

def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_SPECULATIVE_TOOLS", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    assert st.enabled() is False


def test_enabled_via_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_SPECULATIVE_TOOLS", "1")
    assert st.enabled() is True


def test_enabled_via_config(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SPECULATIVE_TOOLS", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"  # conftest pins HOME to tmp_path
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.toml").write_text("[tools]\nspeculative = true\n")
    assert st.enabled() is True
