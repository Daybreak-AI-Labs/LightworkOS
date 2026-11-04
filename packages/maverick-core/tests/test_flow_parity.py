"""Flow node kinds: setvar, subflow output, foreach runaway guard.
(switch / while / scope / foreach-concurrent are covered in test_flow_kinds.py.)"""
from __future__ import annotations

from maverick.flow.ir import Flow, FlowNode
from maverick.flow.runner import run_flow


def _flow(nodes, start="a", **kw):
    return Flow(id="f", name="f", start=start, nodes={n.id: n for n in nodes}, **kw)


def _ag(n, br, d):
    return (br, 1.0)


# ---- setvar + a while-loop via setvar/branch/cycle --------------------------

def test_setvar_composes_and_counts():
    f = _flow([
        FlowNode(id="a", kind="setvar", assignments={"greeting": "hi {{name}}", "n": "{{add(count,1)}}"},
                 next="b"),
        FlowNode(id="b", kind="agent", brief="{{greeting}}|{{n}}", output="r")])
    r = run_flow(f, agent_fn=_ag, action_fn=lambda *a: ("", None), data={"name": "sam", "count": 4})
    assert r.data["r"] == "hi sam|5"


def test_while_loop_via_setvar_and_branch():
    # count from 0, increment via setvar, branch back until count == 3
    f = _flow([
        FlowNode(id="a", kind="setvar", assignments={"count": "{{add(count,1)}}"}, next="b"),
        FlowNode(id="b", kind="branch", condition="count < 3", if_true="a", if_false="done"),
        FlowNode(id="done", kind="agent", brief="{{count}}", output="r")])
    r = run_flow(f, agent_fn=_ag, action_fn=lambda *a: ("", None), data={"count": 0})
    assert r.data["r"] == "3"


# ---- subflow output capture -------------------------------------------------

def test_subflow_output_captures_added_keys():
    sub = Flow(id="sub", name="sub", start="s",
               nodes={"s": FlowNode(id="s", kind="agent", brief="x", output="sub_result")})
    f = _flow([FlowNode(id="a", kind="subflow", flow_ref="sub", output="ret")])
    r = run_flow(f, agent_fn=_ag, action_fn=lambda *a: ("", None),
                 resolve_flow=lambda fid: sub if fid == "sub" else None, data={})
    assert r.data["ret"] == {"sub_result": "x"}


# ---- subflow argument passing / isolation -----------------------------------

def test_subflow_inputs_isolate_the_child_from_parent_keys():
    # The child echoes whatever it sees under "seen"; with mapped inputs it must
    # see ONLY the mapped value, not the parent's other keys.
    sub = Flow(id="sub", name="sub", start="s",
               nodes={"s": FlowNode(id="s", kind="agent", brief="{{who}}|{{private}}", output="seen")})
    f = _flow([FlowNode(id="a", kind="subflow", flow_ref="sub",
                        subflow_inputs={"who": "{{name}}"}, output="ret")])
    r = run_flow(f, agent_fn=_ag, action_fn=lambda *a: ("", None),
                 resolve_flow=lambda fid: sub if fid == "sub" else None,
                 data={"name": "sam", "private": "parent-only"})
    # the child saw the mapped "who" but NOT the parent's "private" key (stays literal)
    assert r.data["ret"]["seen"] == "sam|{{private}}"


def test_subflow_inputs_prevent_the_child_clobbering_parent_data():
    # The child writes a key named the same as a parent key; in isolated mode that
    # write stays in the child, so the parent's value is preserved.
    sub = Flow(id="sub", name="sub", start="s",
               nodes={"s": FlowNode(id="s", kind="setvar", assignments={"status": "child-set"})})
    f = _flow([FlowNode(id="a", kind="subflow", flow_ref="sub",
                        subflow_inputs={"in": "{{x}}"}, output="ret", next="b"),
               FlowNode(id="b", kind="agent", brief="{{status}}", output="r")])
    r = run_flow(f, agent_fn=_ag, action_fn=lambda *a: ("", None),
                 resolve_flow=lambda fid: sub if fid == "sub" else None,
                 data={"x": 1, "status": "parent-set"})
    assert r.data["status"] == "parent-set"          # parent key untouched by the child
    assert r.data["ret"] == {"status": "child-set"}  # child's write returned via output


def test_subflow_without_inputs_keeps_shared_data_behaviour():
    # No subflow_inputs -> the child still reads parent data and its outputs flow back.
    sub = Flow(id="sub", name="sub", start="s",
               nodes={"s": FlowNode(id="s", kind="agent", brief="{{name}}", output="greeting")})
    f = _flow([FlowNode(id="a", kind="subflow", flow_ref="sub", next="b"),
               FlowNode(id="b", kind="agent", brief="{{greeting}}", output="r")])
    r = run_flow(f, agent_fn=_ag, action_fn=lambda *a: ("", None),
                 resolve_flow=lambda fid: sub if fid == "sub" else None, data={"name": "sam"})
    assert r.data["r"] == "sam"                       # child read parent + result flowed back


# ---- foreach runaway guard --------------------------------------------------

def test_foreach_without_limit_refuses_over_cap_and_surfaces_why(monkeypatch):
    from maverick.flow import runner
    monkeypatch.setattr(runner, "_FOREACH_DEFAULT_CAP", 5)
    calls = []

    def agent(n, br, d):
        calls.append(br)
        return (br, 1.0)

    body = _flow([FlowNode(id="x", kind="agent", brief="{{item}}", output="r")], start="x")
    f = _flow([FlowNode(id="a", kind="foreach", items="rows", var="item", body=body, output="out")])
    r = run_flow(f, agent_fn=agent, action_fn=lambda *a: ("", None),
                 data={"rows": list(range(20))})       # no explicit limit
    # The implicit ceiling is not consent to drop the tail: nothing runs, and the
    # refusal is surfaced instead of reporting a silent partial result as complete.
    assert r.status == "failed"
    assert calls == [] and "out" not in r.data and "_foreach_truncated" not in r.data
    assert "processed no items" in r.error and "explicit item limit" in r.error
    # A deliberately chosen limit still bounds the list to its prefix.
    limited = _flow([FlowNode(id="a", kind="foreach", items="rows", var="item", body=body,
                              output="out", limit=5)])
    r = run_flow(limited, agent_fn=agent, action_fn=lambda *a: ("", None),
                 data={"rows": list(range(20))})
    assert r.status == "completed" and len(r.data["out"]) == 5 and len(calls) == 5

