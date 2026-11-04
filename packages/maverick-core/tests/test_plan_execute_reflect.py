"""Tests for the plan-execute-reflect loop topology. Driven by scripted fake
``complete`` callables (no real LLM), like the other topology helpers."""
from __future__ import annotations

import types

import pytest
from maverick.budget import Budget, BudgetExceeded
from maverick.plan_execute_reflect import run_plan_execute_reflect


def _resp(text: str):
    return types.SimpleNamespace(text=text)


def _const(text: str):
    return lambda **kw: _resp(text)


def _planner(steps):
    import json
    return _const(json.dumps({"steps": steps}))


def test_done_first_pass():
    res = run_plan_execute_reflect(
        "ship the feature",
        planner_complete=_planner(["write code", "test"]),
        executor_complete=lambda **kw: _resp("done step"),
        reflector_complete=_const('{"status": "done", "notes": "looks good"}'),
    )
    assert res.status == "done"
    assert res.plan == ["write code", "test"]
    assert len(res.results) == 2 and res.iterations == 1
    assert res.reflections[0].notes == "looks good"


def test_revise_then_done():
    # First reflection revises the plan; second pass is accepted.
    scripted = iter([
        '{"status": "revise", "notes": "missing tests", "revised_plan": ["add tests"]}',
        '{"status": "done", "notes": "ok now"}',
    ])
    res = run_plan_execute_reflect(
        "ship safely",
        planner_complete=_planner(["write code"]),
        executor_complete=lambda **kw: _resp("ran"),
        reflector_complete=lambda **kw: _resp(next(scripted)),
        max_iterations=3,
    )
    assert res.status == "done"
    assert res.iterations == 2
    assert res.plan == ["add tests"]  # plan was revised
    # 1 step pass 1 + 1 step pass 2
    assert [r.step for r in res.results] == ["write code", "add tests"]


def test_continue_without_revision_stalls():
    res = run_plan_execute_reflect(
        "do a thing",
        planner_complete=_planner(["step"]),
        executor_complete=lambda **kw: _resp("x"),
        reflector_complete=_const('{"status": "continue", "notes": "keep going"}'),
    )
    assert res.status == "stalled" and res.iterations == 1


def test_malformed_reflector_stalls_not_done():
    # A reflector whose output can't be parsed as JSON must NOT be read as
    # "goal met": the run should surface as stalled, not a false success.
    res = run_plan_execute_reflect(
        "do a thing",
        planner_complete=_planner(["step"]),
        executor_complete=lambda **kw: _resp("x"),
        reflector_complete=_const("I refuse to answer (not JSON)"),
    )
    assert res.status == "stalled" and res.iterations == 1


def test_max_iterations_cap():
    res = run_plan_execute_reflect(
        "endless",
        planner_complete=_planner(["s"]),
        executor_complete=lambda **kw: _resp("x"),
        # Always revise -> never done; capped.
        reflector_complete=_const('{"status": "revise", "notes": "again", "revised_plan": ["s"]}'),
        max_iterations=2,
    )
    assert res.status == "max_iterations" and res.iterations == 2


def test_malformed_planner_gives_empty_plan():
    res = run_plan_execute_reflect(
        "goal",
        planner_complete=_const("not json"),
        executor_complete=lambda **kw: _resp("x"),
        reflector_complete=_const('{"status": "done", "notes": ""}'),
    )
    assert res.plan == [] and res.results == [] and res.status == "done"


def test_executor_exception_is_captured_not_raised():
    def _boom(**kw):
        raise RuntimeError("tool down")

    res = run_plan_execute_reflect(
        "goal",
        planner_complete=_planner(["step"]),
        executor_complete=_boom,
        reflector_complete=_const('{"status": "done", "notes": ""}'),
    )
    assert "step failed" in res.results[0].output


def test_budget_exceeded_propagates():
    def _boom(**kw):
        raise BudgetExceeded("over")

    with pytest.raises(BudgetExceeded):
        run_plan_execute_reflect(
            "goal",
            planner_complete=_planner(["step"]),
            executor_complete=_boom,
            reflector_complete=_const('{"status": "done"}'),
            budget=Budget(max_dollars=1.0),
        )


def test_validation():
    with pytest.raises(ValueError):
        run_plan_execute_reflect("", planner_complete=_const("{}"),
                                 executor_complete=_const("x"), reflector_complete=_const("{}"))
    with pytest.raises(ValueError):
        run_plan_execute_reflect("g", planner_complete=_const("{}"),
                                 executor_complete=_const("x"), reflector_complete=_const("{}"),
                                 max_iterations=0)


def test_plan_reflect_command_registered():
    from maverick.cli import main
    assert "plan-reflect" in main.commands


def test_plan_reflect_command_prints_trace(monkeypatch):
    # The commands now preflight providers; the LLM is
    # still mocked -- a dummy key just satisfies the gate.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    import maverick.plan_execute_reflect as per_mod
    from maverick import cli as cli_mod
    from maverick.plan_execute_reflect import (
        PlanExecuteReflectResult,
        Reflection,
        StepResult,
    )

    class _FakeLLM:
        def __init__(self, model=None):
            self.model = model

        def complete(self, **kw):  # never reached -- run is stubbed
            raise AssertionError("run_plan_execute_reflect is stubbed")

    monkeypatch.setattr(
        cli_mod, "_kernel",
        lambda: types.SimpleNamespace(LLM=_FakeLLM, DEFAULT_MODEL="fake"),
    )

    captured: dict = {}

    def _fake_run(goal, **kw):
        captured["goal"] = goal
        captured["max_iterations"] = kw.get("max_iterations")
        return PlanExecuteReflectResult(
            goal=goal,
            plan=["a", "b"],
            results=[StepResult("a", "did a")],
            reflections=[Reflection("done", "ok")],
            iterations=1,
            status="done",
            total_dollars=0.01,
        )

    monkeypatch.setattr(per_mod, "run_plan_execute_reflect", _fake_run)

    from click.testing import CliRunner
    res = CliRunner().invoke(
        cli_mod.main, ["plan-reflect", "build a thing", "--max-iterations", "2"],
    )
    assert res.exit_code == 0, res.output
    assert captured["goal"] == "build a thing"
    assert captured["max_iterations"] == 2
    assert "Status: done" in res.output
