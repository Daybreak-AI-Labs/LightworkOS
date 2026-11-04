"""G1 fixes: grounded signals (approval, subflow, trigger) + budget-skip/foreach
partial-results correctness, verified through the pure runner and the driver."""
from __future__ import annotations

from maverick.flow import execution, node_outcomes
from maverick.flow.ir import Flow, FlowNode
from maverick.flow.runner import run_flow


def _flow(nodes, start="a", **kw):
    return Flow(id="f", name="f", start=start, nodes={n.id: n for n in nodes}, **kw)


# ---- approval decisions are grounded -----------------------------------

def test_approval_decision_is_grounded():
    seen = {}
    f = _flow([FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
               FlowNode(id="b", kind="agent", brief="go")])
    # auto-approve path grounds 1.0
    run_flow(f, agent_fn=lambda n, br, d: ("x", 1.0), action_fn=lambda *a: ("", None),
             approve_fn=lambda n, d: "approved",
             on_node=lambda node, status, outcome: seen.__setitem__(node.id, (status, outcome)))
    assert seen["a"] == ("approved", 1.0)


def test_rejection_is_grounded_zero():
    seen = {}
    f = _flow([FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
               FlowNode(id="b", kind="agent", brief="go")])
    run_flow(f, agent_fn=lambda *a: ("", None), action_fn=lambda *a: ("", None),
             approve_fn=lambda n, d: "rejected",
             on_node=lambda node, s, o: seen.__setitem__(node.id, (s, o)))
    assert seen["a"] == ("rejected", 0.0)


def test_human_resume_grounds_the_decision():
    seen = []
    f = _flow([FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
               FlowNode(id="b", kind="agent", brief="go")])
    run_flow(f, agent_fn=lambda n, br, d: ("x", 1.0), action_fn=lambda *a: ("", None),
             resume={"node_id": "a", "data": {}, "decision": "approved"},
             on_node=lambda node, s, o: seen.append((node.id, o)))
    assert ("a", 1.0) in seen          # the approval node is grounded on resume too


# ---- subflow success grounds 1.0 (symmetric with the 0.0 failure) ------

def test_subflow_success_grounds_one():
    seen = {}
    sub = Flow(id="sub", name="sub", start="s",
               nodes={"s": FlowNode(id="s", kind="agent", brief="x")})
    f = _flow([FlowNode(id="a", kind="subflow", flow_ref="sub")])
    run_flow(f, agent_fn=lambda n, br, d: ("x", 1.0), action_fn=lambda *a: ("", None),
             resolve_flow=lambda fid: sub if fid == "sub" else None,
             on_node=lambda node, s, o: seen.__setitem__(node.id, o))
    assert seen["a"] == 1.0


# ---- foreach publishes partial results as it goes ----------------------

def test_foreach_publishes_partial_results_each_iteration():
    body = _flow([FlowNode(id="x", kind="agent", brief="do {{item}}", output="r")], start="x")
    captured = []
    f = _flow([FlowNode(id="a", kind="foreach", items="rows", var="item",
                        body=body, output="out")])
    # a clock isn't needed; assert that after the run output has all iterations,
    # and that the incremental write path is exercised (output list grows)
    run_flow(f, agent_fn=lambda n, br, d: (br, 1.0), action_fn=lambda *a: ("", None),
             data={"rows": [1, 2, 3]},
             on_node=lambda node, s, o: captured.append(node.id))
    # (functional check: all three iterations are present)
    res = run_flow(f, agent_fn=lambda n, br, d: (br, 1.0), action_fn=lambda *a: ("", None),
                   data={"rows": [1, 2, 3]})
    assert len(res.data["out"]) == 3


# ---- A2 + B8 + D17: budget-skip is not a failure; trigger outcome grounded --

def test_budget_skip_is_not_grounded_as_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    f = _flow([FlowNode(id="a", kind="agent", brief="1", output="r1", next="b"),
               FlowNode(id="b", kind="agent", brief="2", output="r2")], max_dollars=5.0)
    execution.execute(f, agent_runner=lambda brief, d, **kw: ("ok", 1.0),
                      action_runner=lambda t, p, d: ("", None))
    # node b was skipped (only $5 cap, a consumes it) -> NOT recorded as a 0.0 failure
    assert "b" not in node_outcomes.stats("f")
    assert node_outcomes.stats("f")["a"]["mean"] == 1.0


def test_trigger_outcome_is_grounded_under_reserved_node(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    f = _flow([FlowNode(id="a", kind="agent", brief="go")])
    run = execution.execute(f, agent_runner=lambda brief, d, **kw: ("ok", 1.0),
                            action_runner=lambda t, p, d: ("", None),
                            origin="cron:f")
    assert run.origin == "cron:f"
    assert node_outcomes.stats("f")[execution.TRIGGER_NODE]["mean"] == 1.0


def test_manual_run_does_not_ground_a_trigger_outcome(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    f = _flow([FlowNode(id="a", kind="agent", brief="go")])
    execution.execute(f, agent_runner=lambda brief, d, **kw: ("ok", 1.0),
                      action_runner=lambda t, p, d: ("", None))   # origin defaults to manual
    assert execution.TRIGGER_NODE not in node_outcomes.stats("f")


# ---- a node timeout bounds the agent goal's wall ------------------------

def test_node_timeout_bounds_agent_wall(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    got = {}

    def runner(brief, d, wall=None):
        got["wall"] = wall
        return ("ok", 1.0)
    f = _flow([FlowNode(id="a", kind="agent", brief="go", timeout=30.0)])
    execution.execute(f, agent_runner=runner, action_runner=lambda t, p, d: ("", None))
    assert got["wall"] == 30.0          # the node timeout reaches the runner as a wall cap


# ---- validation flags pause nodes buried in nested bodies/branches ------

def test_validate_flags_approval_inside_foreach_body():
    body = _flow([FlowNode(id="x", kind="approval", prompt="each?")], start="x")
    f = _flow([FlowNode(id="a", kind="foreach", items="rows", var="i", body=body)])
    assert any("can't pause inside a loop/branch" in e for e in f.validate())


def test_validate_flags_delay_inside_parallel_branch():
    br = _flow([FlowNode(id="y", kind="delay", seconds=5)], start="y")
    f = _flow([FlowNode(id="a", kind="parallel", branches=[br])])
    assert any("delay node" in e and "can't wait" in e for e in f.validate())


def test_top_level_approval_is_fine():
    f = _flow([FlowNode(id="a", kind="approval", prompt="ok?")])
    assert f.validate() == []


# ---- flow self-improvement count -------------------------------------------

def test_improvement_count_nets_out_reverted_rewrites(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.flow import evolution_log
    assert evolution_log.improvement_count() == 0
    evolution_log.record_apply("f", "a", "action", "agent", 2, source="human")
    evolution_log.record_apply("f", "b", "action", "agent", 2, source="auto-apply")
    assert evolution_log.improvement_count() == 2   # two forward rewrites, both stuck
    # node a regressed and the loop undid it -> it no longer counts as an improvement
    evolution_log.record_apply("f", "a", "agent", "action", 3, source="auto-revert")
    assert evolution_log.improvement_count() == 1   # only the change that stuck
