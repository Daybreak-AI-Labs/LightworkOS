"""Tests for the workflow DAG runner (maverick.workflow)."""
from __future__ import annotations

# ---------- workflow: callable from inside a running event loop ----------

def test_workflow_runs_inside_running_loop():
    import asyncio

    from maverick.tools import Tool, ToolRegistry
    from maverick.workflow import Step, Workflow

    reg = ToolRegistry()
    reg.register(Tool(
        name="echo", description="echo",
        input_schema={"type": "object", "properties": {}},
        fn=lambda args: "ok",
    ))
    wf = Workflow(steps=[Step("a", "echo", {})])

    async def _driver():
        # Calling the SYNC wf.run() from inside a running loop must not
        # raise "asyncio.run() cannot be called from a running event loop".
        return wf.run(reg)

    result = asyncio.run(_driver())
    assert not result.failed
    assert result.steps[0].output == "ok"


def test_workflow_still_runs_without_loop():
    from maverick.tools import Tool, ToolRegistry
    from maverick.workflow import Step, Workflow
    reg = ToolRegistry()
    reg.register(Tool(
        name="echo", description="echo",
        input_schema={"type": "object", "properties": {}},
        fn=lambda args: "sync-ok",
    ))
    res = Workflow(steps=[Step("a", "echo", {})]).run(reg)
    assert res.steps[0].output == "sync-ok"


# ---------- Workflow engine ----------

def test_workflow_runs_simple_dag():
    from unittest.mock import MagicMock

    from maverick.workflow import Step, Workflow

    reg = MagicMock()
    outputs = iter(["A-out", "B-out", "C-out"])

    async def _run(name, args):
        return next(outputs)

    reg.run = _run
    wf = Workflow(steps=[
        Step("a", "toolA", {"x": 1}),
        Step("b", "toolB", {"x": "${a.out}"}),
        Step("c", "toolC", {"x": "${b.out}", "y": "${a.out}"}),
    ])
    res = wf.run(reg)
    assert [s.name for s in res.steps] == ["a", "b", "c"]
    assert res.steps[1].output == "B-out"
    # placeholders were resolved
    # (we can't see them directly via reg here; just confirm no failures)
    assert not res.failed


def test_workflow_stops_on_error():
    from maverick.workflow import Step, Workflow

    class _Reg:
        async def run(self, name, args):
            if name == "boom":
                return "ERROR: nope"
            return "ok"

    wf = Workflow(steps=[
        Step("a", "ok-tool"),
        Step("b", "boom"),
        Step("c", "ok-tool", depends_on=["b"]),
    ])
    res = wf.run(_Reg())
    assert res.failed
    # Should run a + b only, not c.
    assert [s.name for s in res.steps] == ["a", "b"]


def test_workflow_rejects_cycle():
    from maverick.workflow import Step, Workflow, WorkflowCycle
    try:
        Workflow(steps=[
            Step("a", "x", depends_on=["b"]),
            Step("b", "x", depends_on=["a"]),
        ])
    except WorkflowCycle:
        return
    raise AssertionError("expected WorkflowCycle")


def test_workflow_rejects_self_dep():
    from maverick.workflow import Step, Workflow, WorkflowCycle
    try:
        Workflow(steps=[Step("a", "x", depends_on=["a"])])
    except WorkflowCycle:
        return
    raise AssertionError("expected WorkflowCycle")


def test_workflow_rejects_unknown_dep():
    from maverick.workflow import Step, Workflow
    try:
        Workflow(steps=[Step("a", "x", {"y": "${nope.out}"})])
    except ValueError as e:
        assert "unknown dependency" in str(e)
        return
    raise AssertionError("expected ValueError")


def test_workflow_resolves_string_placeholders():
    from maverick.workflow import Step, Workflow

    seen: list[dict] = []

    class _Reg:
        async def run(self, name, args):
            seen.append(args)
            return "first-output"

    wf = Workflow(steps=[
        Step("first", "echo", {"msg": "hi"}),
        Step("second", "echo",
             {"prefix": "got: ${first.out}!", "n": 1}),
    ])
    wf.run(_Reg())
    assert seen[1]["prefix"] == "got: first-output!"
    assert seen[1]["n"] == 1
