"""Harden-tool inference: capture the tool an agent node calls, infer it when
consistent, and let it drive a no-prompt / autonomous harden (agent -> action)."""
from __future__ import annotations

from maverick.flow import evolve, node_tools
from maverick.flow.ir import NODE_ACTION, NODE_AGENT, Flow, FlowNode


def _agent_flow():
    return Flow(id="f", name="f", start="a",
                nodes={"a": FlowNode(id="a", kind="agent", brief="summarize {{x}}")})


# ---- node_tools.dominant_tool: conservative single-tool inference ------------

def test_dominant_tool_needs_min_support(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    for _ in range(3):                       # below the default min_support of 5
        node_tools.record("f", "a", ["summarize_tool"])
    assert node_tools.dominant_tool("f", "a") is None


def test_dominant_tool_infers_the_consistent_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    for _ in range(6):
        node_tools.record("f", "a", ["summarize_tool"])
    assert node_tools.dominant_tool("f", "a") == "summarize_tool"


def test_dominant_tool_none_when_tools_are_mixed(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    for _ in range(3):
        node_tools.record("f", "a", ["tool_x"])
    for _ in range(3):
        node_tools.record("f", "a", ["tool_y"])   # no single tool dominates
    assert node_tools.dominant_tool("f", "a") is None


def test_dominant_tool_none_when_multiple_tools_per_run(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    for _ in range(6):
        node_tools.record("f", "a", ["tool_x", "tool_y"])   # not a single-tool step
    assert node_tools.dominant_tool("f", "a") is None


# ---- propose attaches the inferred tool to a harden proposal -----------------

def test_harden_proposal_carries_the_inferred_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    for _ in range(6):
        node_tools.record("f", "a", ["summarize_tool"])
    stats = {"a": {"n": 20, "mean": 0.95, "kind": NODE_AGENT}}   # reliable agent
    props = evolve.propose(_agent_flow(), stats=stats)
    assert len(props) == 1
    p = props[0]
    assert p.from_kind == NODE_AGENT and p.to_kind == NODE_ACTION
    assert p.inferred_tool == "summarize_tool"
    assert p.applicable is False
    assert "parameters" in p.blocking_reason
    assert "summarize_tool" in p.reason


def test_harden_proposal_without_capture_has_no_inferred_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    stats = {"a": {"n": 20, "mean": 0.95, "kind": NODE_AGENT}}
    p = evolve.propose(_agent_flow(), stats=stats)[0]
    assert p.inferred_tool == ""          # nothing captured -> human still picks the tool


# ---- apply a harden with the inferred tool -----------------------------------

def test_apply_harden_with_inferred_tool_produces_the_action(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    changed = evolve.apply_proposal(
        _agent_flow(), "a", NODE_ACTION, tool="summarize_tool", params={},
    )
    n = changed.nodes["a"]
    assert n.kind == NODE_ACTION and n.tool == "summarize_tool" and n.brief == ""


# ---- the driver publishes the running node so the runner can attribute tools --

def test_driver_publishes_the_active_node_to_the_runner(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    from maverick.flow import execution
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    seen = {}

    def runner(brief, d, **kw):
        seen["node"] = execution._active_node.get()   # what the driver published
        return ("ok", 1.0)
    execution.execute(_agent_flow(), agent_runner=runner,
                      action_runner=lambda t, p, d: ("", None))
    assert seen["node"] == ("f", "a", "", "")


def test_tool_capture_records_only_on_success_not_per_retry(tmp_path, monkeypatch):
    # A node with retries invokes the runner once PER ATTEMPT; recording every
    # attempt would let one retried run look like many. Only a SUCCESSFUL attempt
    # records, so a run yields ~one tool row -- aligned with node_outcomes.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TRAJECTORY_CAPTURE", "1")
    from maverick import trajectory_store, world_model
    from maverick.flow import execution, node_tools
    trajectory_store.reset_shared()
    monkeypatch.setattr(trajectory_store, "tools_for_goal", lambda gid, **k: ["summarize_tool"])
    w = world_model.WorldModel(tmp_path / "world.db")

    def succeed(gid, **kw):
        w.set_goal_status(gid, "done", result="ok")
        return "ok"
    monkeypatch.setattr("maverick.runner.run_goal_in_thread", succeed)
    run = execution.default_agent_runner(w)
    token = execution._active_node.set(("f", "a", "", ""))
    try:
        run("brief", {})                              # two successful runs -> two rows
        run("brief", {})
        monkeypatch.setattr("maverick.runner.run_goal_in_thread",
                            lambda gid, **kw: "boom")  # goal never 'done' -> outcome 0.0
        run("brief", {})                              # two FAILED runs -> no rows
        run("brief", {})
    finally:
        execution._active_node.reset(token)
    assert len(node_tools._rows_for("f", "a")) == 2   # only the two successes recorded
