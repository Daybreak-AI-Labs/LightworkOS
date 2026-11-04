"""The flow engine: IR (validate/serialise), the interpreter (control flow,
data threading, approval pause/resume), and the run/definition store."""
from __future__ import annotations

from maverick.flow import Flow, FlowNode, single_agent_flow
from maverick.flow.runner import (
    STATUS_COMPLETED,
    STATUS_PAUSED_APPROVAL,
    STATUS_PAUSED_DELAY,
    STATUS_REJECTED,
    eval_condition,
    render,
    run_flow,
)


def _agent(node, brief, data):
    return (f"[{brief}]", 0.9)


def _action(node, params, data):
    return ({"called": node.tool, "params": params}, None)


def _flow(nodes, start="a"):
    return Flow(id="f", name="f", start=start, nodes={n.id: n for n in nodes})


# ---- IR ---------------------------------------------------------------------

class TestFlowIR:
    def test_single_agent_flow_is_a_template(self):
        f = single_agent_flow("t1", "Draft memo", "Write a memo about {{topic}}")
        assert f.is_single_agent()
        assert f.validate() == []

    def test_validate_catches_bad_routing_and_kinds(self):
        f = _flow([
            FlowNode(id="a", kind="agent", brief="x", next="missing"),
            FlowNode(id="b", kind="bogus"),
        ])
        errs = f.validate()
        assert any("unknown node 'missing'" in e for e in errs)
        assert any("unknown kind" in e for e in errs)

    def test_validate_requires_kind_fields(self):
        f = _flow([FlowNode(id="a", kind="action")])   # no tool
        assert any("has no tool" in e for e in f.validate())

    def test_nested_event_wait_is_rejected_before_a_run(self):
        body = _flow([FlowNode(id="wait", kind="wait_event", prompt="Payment arrived?")], start="wait")
        outer = _flow([FlowNode(id="a", kind="foreach", items="orders", body=body)])
        assert any("Wait for another app step 'wait' cannot wait inside" in e
                   for e in outer.validate())

    def test_schedule_roundtrips_and_validates(self):
        f = _flow([FlowNode(id="a", kind="agent", brief="x")])
        f.schedule = "0 9 * * 1"
        again = Flow.from_dict(f.to_dict())
        assert again.schedule == "0 9 * * 1"
        assert again.validate() == []

    def test_max_concurrent_roundtrips(self):
        f = _flow([FlowNode(id="a", kind="agent", brief="x")])
        f.max_concurrent = 1
        assert Flow.from_dict(f.to_dict()).max_concurrent == 1

    def test_invalid_schedule_is_a_validation_error(self):
        f = _flow([FlowNode(id="a", kind="agent", brief="x")])
        f.schedule = "not a cron"
        assert any("invalid schedule" in e for e in f.validate())

    def test_unarmable_schedule_is_a_validation_error(self):
        f = _flow([FlowNode(id="a", kind="agent", brief="x")])
        f.schedule = "0 0 31 2 *"
        assert any("invalid schedule" in e for e in f.validate())

    def test_roundtrip_serialisation_nested(self):
        body = _flow([FlowNode(id="x", kind="agent", brief="do {{item}}")], start="x")
        f = _flow([
            FlowNode(id="a", kind="foreach", items="rows", var="item", body=body, next="p"),
            FlowNode(id="p", kind="parallel",
                     branches=[_flow([FlowNode(id="y", kind="agent", brief="b")], start="y")]),
        ])
        again = Flow.from_dict(f.to_dict())
        assert again.validate() == []
        assert again.nodes["a"].body.nodes["x"].brief == "do {{item}}"
        assert again.nodes["p"].branches[0].nodes["y"].brief == "b"


# ---- interpreter ------------------------------------------------------------

class TestRunner:
    def test_render_and_condition_helpers(self):
        assert render("hi {{name}}", {"name": "sam"}) == "hi sam"
        assert render("{{missing}}", {}) == "{{missing}}"
        assert eval_condition("amount >= 100", {"amount": 100}) is True
        assert eval_condition("status == paid", {"status": "paid"}) is True
        assert eval_condition("tags contains urgent", {"tags": "a,urgent"}) is True
        assert eval_condition("flagged", {"flagged": True}) is True
        assert eval_condition("amount > 100", {"amount": 5}) is False

    def test_sequential_threads_data(self):
        f = _flow([
            FlowNode(id="a", kind="agent", brief="assess {{order}}", output="a_out", next="b"),
            FlowNode(id="b", kind="action", tool="notify", params={"m": "{{a_out}}"}),
        ])
        seen = {}
        r = run_flow(f, agent_fn=_agent,
                     action_fn=lambda n, p, d: seen.update(p) or ("ok", None),
                     data={"order": "42"})
        assert r.status == STATUS_COMPLETED
        assert seen["m"] == "[assess 42]"      # branch output flows into the action

    def test_branch_routes_on_condition(self):
        f = _flow([
            FlowNode(id="a", kind="branch", condition="amount > 100",
                     if_true="big", if_false="small"),
            FlowNode(id="big", kind="agent", brief="big", output="path"),
            FlowNode(id="small", kind="agent", brief="small", output="path"),
        ])
        big = run_flow(f, agent_fn=_agent, action_fn=_action, data={"amount": 500})
        assert big.data["path"] == "[big]"
        small = run_flow(f, agent_fn=_agent, action_fn=_action, data={"amount": 5})
        assert small.data["path"] == "[small]"

    def test_foreach_runs_body_per_item(self):
        body = _flow([FlowNode(id="x", kind="agent", brief="do {{item}}", output="r")], start="x")
        f = _flow([FlowNode(id="a", kind="foreach", items="rows", var="item",
                            body=body, output="results")])
        r = run_flow(f, agent_fn=_agent, action_fn=_action, data={"rows": [1, 2, 3]})
        assert r.status == STATUS_COMPLETED
        assert [row["r"] for row in r.data["results"]] == ["[do 1]", "[do 2]", "[do 3]"]

    def test_parallel_merges_branch_outputs(self):
        f = _flow([FlowNode(id="a", kind="parallel", branches=[
            _flow([FlowNode(id="x", kind="agent", brief="x", output="left")], start="x"),
            _flow([FlowNode(id="y", kind="agent", brief="y", output="right")], start="y"),
        ])])
        r = run_flow(f, agent_fn=_agent, action_fn=_action, data={})
        assert r.data["left"] == "[x]" and r.data["right"] == "[y]"

    def test_parallel_branches_are_isolated(self):
        # branch B references a key only branch A writes; with real parallel
        # isolation it must NOT see A's output (kept as the literal placeholder).
        f = _flow([FlowNode(id="a", kind="parallel", branches=[
            _flow([FlowNode(id="x", kind="agent", brief="a", output="from_a")], start="x"),
            _flow([FlowNode(id="y", kind="agent", brief="see {{from_a}}", output="from_b")], start="y"),
        ])])
        r = run_flow(f, agent_fn=_agent, action_fn=_action, data={})
        assert r.data["from_b"] == "[see {{from_a}}]"     # no cross-branch leakage

    def test_parallel_branches_run_concurrently(self):
        # Two branches that each block on a barrier: the run only completes if
        # both are in flight at once. A sequential runner would deadlock here
        # (branch 1 waits for branch 2 which hasn't started) and time out.
        import threading
        barrier = threading.Barrier(2, timeout=5.0)

        def rendezvous(node, brief, data):
            barrier.wait()                # both branches must arrive together
            return (brief, 0.9)

        f = _flow([FlowNode(id="a", kind="parallel", branches=[
            _flow([FlowNode(id="x", kind="agent", brief="l", output="left")], start="x"),
            _flow([FlowNode(id="y", kind="agent", brief="r", output="right")], start="y"),
        ])])
        r = run_flow(f, agent_fn=rendezvous, action_fn=_action, data={})
        assert r.status == STATUS_COMPLETED
        assert r.data["left"] == "l" and r.data["right"] == "r"

    def test_parallel_agent_ambiguity_propagates(self):
        # A raising agent branch may already have used mutating tools. Quarantine
        # the whole run rather than swallowing it or replaying the trajectory.
        def maybe_boom(node, brief, data):
            if brief == "boom":
                raise RuntimeError("branch blew up")
            return (brief, 0.9)

        f = _flow([FlowNode(id="a", kind="parallel", branches=[
            _flow([FlowNode(id="x", kind="agent", brief="ok", output="left")], start="x"),
            _flow([FlowNode(id="y", kind="agent", brief="boom", output="right")], start="y"),
        ])])
        r = run_flow(f, agent_fn=maybe_boom, action_fn=_action, data={})
        assert r.status == "indeterminate" and "branch blew up" in r.error

    def test_parallel_branch_cycle_detection_is_per_branch(self):
        # Both branches run the SAME subflow. With a shared flow_stack the second
        # branch would falsely trip cycle detection; per-branch stacks let both run.
        sub = Flow(id="shared", name="shared", start="s", nodes={
            "s": FlowNode(id="s", kind="agent", brief="{{who}}", output="r"),
        })
        f = _flow([FlowNode(id="a", kind="parallel", branches=[
            _flow([FlowNode(id="x", kind="subflow", flow_ref="shared", output="l")], start="x"),
            _flow([FlowNode(id="y", kind="subflow", flow_ref="shared", output="r")], start="y"),
        ])])
        r = run_flow(f, agent_fn=_agent, action_fn=_action,
                     resolve_flow=lambda fid: sub if fid == "shared" else None, data={})
        assert r.status == STATUS_COMPLETED

    def test_nested_parallel_threads_are_globally_bounded(self):
        import threading
        import time

        lock = threading.Lock()
        baseline = threading.active_count()
        max_threads = baseline

        def note_threads(node, brief, data):
            nonlocal max_threads
            with lock:
                max_threads = max(max_threads, threading.active_count())
            time.sleep(0.01)
            return (brief, 0.9)

        def nested_parallel(depth):
            if depth == 0:
                return _flow([FlowNode(id="leaf", kind="agent", brief="leaf")], start="leaf")
            return _flow([FlowNode(
                id=f"p{depth}", kind="parallel",
                branches=[nested_parallel(depth - 1) for _ in range(8)],
            )], start=f"p{depth}")

        r = run_flow(nested_parallel(3), agent_fn=note_threads, action_fn=_action, data={})
        assert r.status == STATUS_COMPLETED
        assert max_threads <= baseline + 12

    def test_approval_pauses_then_resumes(self):
        f = _flow([
            FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
            FlowNode(id="b", kind="agent", brief="proceed", output="done"),
        ])
        paused = run_flow(f, agent_fn=_agent, action_fn=_action, data={"x": 1})
        assert paused.status == STATUS_PAUSED_APPROVAL and paused.cursor == "a"
        assert paused.prompt == "ok?"
        resumed = run_flow(f, agent_fn=_agent, action_fn=_action,
                           resume={"node_id": "a", "data": paused.data, "decision": "approved"})
        assert resumed.status == STATUS_COMPLETED and resumed.data["done"] == "[proceed]"

    def test_pause_prompts_use_redacted_run_values(self):
        for kind in ("approval", "wait_event"):
            flow = _flow([FlowNode(
                id="a", kind=kind,
                prompt="Approve paying {{vendor}} {{amount}}? Token: {{api_key}}",
            )])
            paused = run_flow(
                flow, agent_fn=_agent, action_fn=_action,
                data={"vendor": "Acme Corp", "amount": 5000, "api_key": "private-value"},
            )
            assert paused.prompt == "Approve paying Acme Corp 5000? Token: ***redacted***"
            assert "private-value" not in paused.prompt

    def test_approval_rejected_ends_the_flow(self):
        f = _flow([
            FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
            FlowNode(id="b", kind="agent", brief="proceed", output="done"),
        ])
        r = run_flow(f, agent_fn=_agent, action_fn=_action,
                     approve_fn=lambda n, d: "rejected", data={})
        assert r.status == STATUS_REJECTED and "done" not in r.data

    def test_approval_autoapprove_policy_runs_through(self):
        f = _flow([FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
                   FlowNode(id="b", kind="agent", brief="go", output="d")])
        r = run_flow(f, agent_fn=_agent, action_fn=_action,
                     approve_fn=lambda n, d: "approved", data={})
        assert r.status == STATUS_COMPLETED and r.data["d"] == "[go]"

    def test_delay_pauses_with_resume_at(self):
        f = _flow([FlowNode(id="a", kind="delay", seconds=60, next="b"),
                   FlowNode(id="b", kind="agent", brief="later", output="d")])
        r = run_flow(f, agent_fn=_agent, action_fn=_action, data={}, now=lambda: 1000.0)
        assert r.status == STATUS_PAUSED_DELAY and r.resume_at == 1060.0
        done = run_flow(f, agent_fn=_agent, action_fn=_action,
                        resume={"node_id": "a", "data": r.data})
        assert done.status == STATUS_COMPLETED and done.data["d"] == "[later]"

    def test_per_node_outcomes_are_reported(self):
        f = _flow([FlowNode(id="a", kind="agent", brief="x", next="b"),
                   FlowNode(id="b", kind="branch", condition="ok", if_true=None, if_false=None)])
        seen = []
        run_flow(f, agent_fn=_agent, action_fn=_action,
                 on_node=lambda node, status, outcome: seen.append((node.id, status, outcome)),
                 data={"ok": True})
        assert ("a", "done", 0.9) in seen
        assert ("b", "true", None) in seen

    def test_ambiguous_agent_node_surfaces_not_raises(self):
        def boom(node, brief, data):
            raise RuntimeError("kaboom")
        f = _flow([FlowNode(id="a", kind="agent", brief="x")])
        r = run_flow(f, agent_fn=boom, action_fn=_action, data={})
        assert r.status == "indeterminate" and "kaboom" in r.error


# ---- store ------------------------------------------------------------------

class TestFlowStore:
    def test_flow_definition_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
        from maverick.flow import store
        f = single_agent_flow("f1", "Memo", "write {{topic}}")
        store.save_flow(f)
        assert store.load_flow("f1").name == "Memo"
        assert [x.id for x in store.list_flows()] == ["f1"]
        assert store.delete_flow("f1") is True
        assert store.load_flow("f1") is None

    def test_run_state_roundtrip_and_resume_fields(self, tmp_path, monkeypatch):
        monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
        from maverick.flow import store
        rid = store.new_run_id()
        run = store.FlowRun(run_id=rid, flow_id="f1", status="paused_approval",
                            data={"x": 1}, cursor="ap", prompt="ok?", owner="user:a")
        store.save_run(run)
        got = store.load_run(rid)
        assert got.cursor == "ap" and got.data == {"x": 1} and got.created > 0
        assert [r.run_id for r in store.list_runs(flow_id="f1")] == [rid]
        assert store.list_runs(flow_id="other") == []

    def test_safe_id_prevents_traversal(self, tmp_path, monkeypatch):
        monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
        from maverick.flow import store
        store.save_flow(Flow(id="../../etc/evil", name="x", start="n",
                             nodes={"n": FlowNode(id="n", kind="agent", brief="b")}))
        # written inside the flows dir, not outside it
        assert not (tmp_path.parent / "etc" / "evil.json").exists()
        assert list((tmp_path / "flows").glob("*.json"))
