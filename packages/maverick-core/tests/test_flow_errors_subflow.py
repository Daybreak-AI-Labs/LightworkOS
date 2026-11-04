"""Per-node error handling (retry + on_error routing) and sub-flow composition
(call a saved flow by id, with cycle protection)."""
from __future__ import annotations

from maverick.flow import Flow, FlowNode
from maverick.flow.runner import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_INDETERMINATE,
    run_flow,
)


def _flow(nodes, start="a"):
    return Flow(id="f", name="f", start=start, nodes={n.id: n for n in nodes})


class TestRetryAndOnError:
    def test_retry_recovers_a_transient_failure(self):
        calls = {"n": 0}

        def action(node, params, data):
            calls["n"] += 1
            return ("ok", 1.0) if calls["n"] >= 3 else ("ERROR", 0.0)
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=3, output="r")])
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert res.status == STATUS_COMPLETED and calls["n"] == 3 and res.data["r"] == "ok"

    def test_exhausted_retries_route_to_on_error(self):
        f = _flow([
            FlowNode(id="a", kind="action", tool="web_search", retries=1, on_error="b", next="c"),
            FlowNode(id="b", kind="agent", brief="handle", output="handled"),
            FlowNode(id="c", kind="agent", brief="normal", output="normal")])
        seen = []

        def agent(node, brief, data):
            seen.append(node.id)
            return ("x", 1.0)
        res = run_flow(f, agent_fn=agent, action_fn=lambda *a: ("ERROR", 0.0))
        assert "handled" in res.data and "normal" not in res.data     # took the error arm
        assert seen == ["b"]

    def test_no_on_error_fails_closed_before_next(self):
        f = _flow([
            FlowNode(id="a", kind="action", tool="web_search", next="b"),
            FlowNode(id="b", kind="agent", brief="x", output="done")])
        res = run_flow(f, agent_fn=lambda *a: ("x", 1.0), action_fn=lambda *a: ("ERROR", 0.0))
        assert res.status == STATUS_FAILED and res.cursor == "a"
        assert "done" not in res.data

    def test_high_risk_action_is_not_retried_after_ambiguous_failure(self):
        calls = {"n": 0}

        def action(node, params, data):
            calls["n"] += 1
            return ("ERROR: upstream response lost", 0.0)

        f = _flow([FlowNode(id="a", kind="action", tool="stripe", retries=5)])
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert res.status == STATUS_INDETERMINATE and res.cursor == "a"
        assert calls["n"] == 1

    def test_agent_retry_is_runtime_clamped_after_possible_side_effect(self):
        calls = {"n": 0}

        def agent(node, brief, data):
            calls["n"] += 1
            return ("goal failed after using tools", 0.0)

        f = _flow([FlowNode(id="a", kind="agent", brief="mutate", retries=5)])
        res = run_flow(f, agent_fn=agent, action_fn=lambda *a: ("", None))
        assert res.status == STATUS_INDETERMINATE and res.cursor == "a"
        assert calls["n"] == 1

    def test_raising_high_risk_action_is_quarantined_without_error_route(self):
        f = _flow([
            FlowNode(id="a", kind="action", tool="stripe", on_error="recover"),
            FlowNode(id="recover", kind="agent", brief="must not run", output="recovered"),
        ])

        def ambiguous(*_args):
            raise ConnectionError("response lost after commit")

        res = run_flow(f, agent_fn=lambda *a: ("bad", 1.0), action_fn=ambiguous)
        assert res.status == STATUS_INDETERMINATE and res.cursor == "a"
        assert "recovered" not in res.data

    def test_a_raising_executor_is_retried_not_instantly_fatal(self):
        # Before: a hard exception bypassed retries and killed the run at attempt 1.
        calls = {"n": 0}

        def action(node, params, data):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("transient boom")
            return ("ok", 1.0)
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=3, output="r")])
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert res.status == STATUS_COMPLETED and calls["n"] == 3 and res.data["r"] == "ok"

    def test_a_persistently_raising_executor_stays_terminal_after_retries(self):
        calls = {"n": 0}

        def action(node, params, data):
            calls["n"] += 1
            raise RuntimeError("always boom")
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=2)])
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert res.status == "failed" and res.cursor == "a"           # still records WHERE
        assert calls["n"] == 3                                        # 1 + 2 retries

    def test_retry_backoff_waits_between_attempts(self, monkeypatch):
        slept = []
        monkeypatch.setattr("maverick.flow.runner.time.sleep", lambda s: slept.append(s))
        calls = {"n": 0}

        def action(node, params, data):
            calls["n"] += 1
            return ("ok", 1.0) if calls["n"] >= 3 else ("ERROR", 0.0)
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=3,
                            retry_backoff=2.0, output="r")])
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert res.status == STATUS_COMPLETED
        assert slept == [2.0, 4.0]        # exponential: 2*2^0 before retry 1, 2*2^1 before retry 2

    def test_no_backoff_never_sleeps(self, monkeypatch):
        slept = []
        monkeypatch.setattr("maverick.flow.runner.time.sleep", lambda s: slept.append(s))
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=2, output="r")])
        run_flow(f, agent_fn=lambda *a: ("", None), action_fn=lambda *a: ("ERROR", 0.0))
        assert slept == []                # backoff 0 -> tight loop, no added latency

    def test_validation_rejects_excessive_retries(self):
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=11)])
        assert "node 'a': retries must be <= 10" in f.validate()

    def test_validation_rejects_excessive_retry_backoff_total(self):
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=10, retry_backoff=30.0)])
        assert "node 'a': retry backoff total must be <= 120s" in f.validate()

    def test_runner_caps_unvalidated_retry_count(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_FLOW_MAX_NODE_RETRIES", "10")
        calls = {"n": 0}

        def action(node, params, data):
            calls["n"] += 1
            return ("ERROR", 0.0)
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=999)])
        run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert calls["n"] == 11

    def test_retry_backoff_honours_flow_deadline(self, monkeypatch):
        slept = []
        monkeypatch.setattr("maverick.flow.runner.time.sleep", lambda s: slept.append(s))
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=3, retry_backoff=2.0)])
        f.max_seconds = 0.5
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=lambda *a: ("ERROR", 0.0),
                       now=lambda: 100.0)
        assert res.status == "failed"
        assert "deadline" in res.error
        assert slept == [0.5]

    def test_runtime_clamps_retries_to_configured_cap(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_FLOW_MAX_NODE_RETRIES", "2")
        calls = {"n": 0}

        def action(node, params, data):
            calls["n"] += 1
            return ("ERROR", 0.0)
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=100)])
        res = run_flow(f, agent_fn=lambda *a: ("", None), action_fn=action)
        assert res.status == STATUS_FAILED
        assert calls["n"] == 3   # initial attempt + capped two retries


class TestSubflow:
    def _child(self):
        return Flow(id="child", name="child", start="s",
                    nodes={"s": FlowNode(id="s", kind="agent", brief="do", output="child_out")})

    def test_subflow_runs_and_threads_data_both_ways(self):
        child = self._child()
        parent = _flow([
            FlowNode(id="a", kind="subflow", flow_ref="child", next="b"),
            FlowNode(id="b", kind="agent", brief="after {{child_out}}", output="after")])
        got = {}

        def agent(node, brief, data):
            got[node.id] = brief
            return ("ran", 1.0)
        res = run_flow(parent, agent_fn=agent, action_fn=lambda *a: ("", None),
                       resolve_flow=lambda ref: child if ref == "child" else None)
        assert res.status == STATUS_COMPLETED
        assert res.data["child_out"] == "ran"                         # sub output flowed back
        assert got["b"] == "after ran"                                # parent read it

    def test_missing_subflow_routes_on_error(self):
        parent = _flow([
            FlowNode(id="a", kind="subflow", flow_ref="ghost", on_error="e", next="b"),
            FlowNode(id="e", kind="agent", brief="recover", output="recovered"),
            FlowNode(id="b", kind="agent", brief="x", output="normal")])
        res = run_flow(parent, agent_fn=lambda n, b, d: ("y", 1.0),
                       action_fn=lambda *a: ("", None), resolve_flow=lambda ref: None)
        assert "recovered" in res.data and "normal" not in res.data

    def test_missing_subflow_without_error_route_fails_closed(self):
        parent = _flow([
            FlowNode(id="a", kind="subflow", flow_ref="ghost", next="b"),
            FlowNode(id="b", kind="agent", brief="must not run", output="normal"),
        ])
        res = run_flow(parent, agent_fn=lambda n, b, d: ("y", 1.0),
                       action_fn=lambda *a: ("", None), resolve_flow=lambda ref: None)
        assert res.status == STATUS_FAILED and res.cursor == "a"
        assert "normal" not in res.data

    def test_cyclic_subflow_is_blocked_not_infinite(self):
        loop = Flow(id="loop", name="loop", start="a", nodes={
            "a": FlowNode(id="a", kind="subflow", flow_ref="loop", next="b"),
            "b": FlowNode(id="b", kind="agent", brief="end", output="end")})
        res = run_flow(loop, agent_fn=lambda n, bf, d: ("z", 1.0),
                       action_fn=lambda *a: ("", None),
                       resolve_flow=lambda ref: loop if ref == "loop" else None)
        assert res.status == STATUS_FAILED and res.cursor == "a"
        assert "end" not in res.data


class TestValidation:
    def test_subflow_needs_flow_ref(self):
        assert any("flow_ref" in e for e in _flow([FlowNode(id="a", kind="subflow")]).validate())

    def test_on_error_must_point_to_a_real_node(self):
        f = _flow([FlowNode(id="a", kind="agent", brief="x", on_error="ghost")])
        assert any("on_error" in e for e in f.validate())

    def test_retries_cannot_exceed_configured_cap(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_FLOW_MAX_NODE_RETRIES", "3")
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=4)])
        assert any("retries 4 exceeds max_node_retries 3" in e for e in f.validate())

    def test_negative_retries_are_rejected(self):
        f = _flow([FlowNode(id="a", kind="action", tool="web_search", retries=-1)])
        assert any("retries must be >= 0" in e for e in f.validate())

    def test_agent_retries_are_rejected(self):
        f = _flow([FlowNode(id="a", kind="agent", brief="do it", retries=1)])
        assert any("cannot be automatically retried" in e for e in f.validate())
