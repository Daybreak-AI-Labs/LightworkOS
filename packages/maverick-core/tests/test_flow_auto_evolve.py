"""Autonomous self-correction primitives: the regression test that decides when
an applied rewrite clearly hurt, the node-level revert that undoes it while
keeping topology, and the double-gated enable switch."""
from __future__ import annotations

from maverick.flow import Flow, FlowNode, evolve


class TestRegressed:
    def test_clear_drop_with_enough_evidence_is_a_regression(self):
        assert evolve.regressed({"after": {"n": 10}, "delta": -0.5}) is True

    def test_small_drop_is_noise(self):
        assert evolve.regressed({"after": {"n": 10}, "delta": -0.05}) is False

    def test_thin_evidence_is_not_a_regression(self):
        assert evolve.regressed({"after": {"n": 2}, "delta": -0.9}) is False

    def test_improvement_is_not_a_regression(self):
        assert evolve.regressed({"after": {"n": 10}, "delta": 0.3}) is False

    def test_no_delta_is_not_a_regression(self):
        assert evolve.regressed({"after": {"n": 10}, "delta": None}) is False


class TestRevertNode:
    def test_restores_work_fields_but_keeps_routing_and_layout(self):
        prior = FlowNode(id="a", kind="agent", brief="do the thing")
        cur = Flow(id="f", name="F", start="a", nodes={
            "a": FlowNode(id="a", kind="action", tool="t", params={"x": 1},
                          next="b", label="L", x=5.0, y=6.0),
            "b": FlowNode(id="b", kind="agent", brief="next")})
        out = evolve.revert_node(cur, "a", prior)
        n = out.nodes["a"]
        assert n.kind == "agent" and n.brief == "do the thing" and n.tool == ""
        assert n.params == {}
        assert n.next == "b" and n.label == "L" and n.x == 5.0    # routing/layout kept
        assert cur.nodes["a"].kind == "action"                   # original untouched

    def test_unknown_node_raises(self):
        import pytest
        with pytest.raises(KeyError):
            evolve.revert_node(Flow(id="f", name="F", start="a", nodes={}), "a",
                               FlowNode(id="a", kind="agent", brief="x"))


class TestAutoEvolveGate:
    def test_needs_both_engine_and_auto_evolve(self, monkeypatch):
        from maverick import flow
        monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
        monkeypatch.delenv("MAVERICK_FLOWS_AUTO", raising=False)
        monkeypatch.setattr("maverick.config.load_config", dict)
        assert flow.auto_evolve_enabled() is False
        monkeypatch.setenv("MAVERICK_FLOWS", "1")
        assert flow.auto_evolve_enabled() is False           # engine on, auto off
        monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
        assert flow.auto_evolve_enabled() is True
        monkeypatch.setenv("MAVERICK_FLOWS", "0")
        assert flow.auto_evolve_enabled() is False           # auto on but engine off

    def test_auto_apply_needs_auto_evolve_plus_its_own_flag(self, monkeypatch):
        from maverick import flow
        monkeypatch.setenv("MAVERICK_FLOWS", "1")
        monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")        # auto_evolve on
        monkeypatch.setattr("maverick.config.get_flows", lambda: {"auto_apply": False})
        assert flow.auto_apply_enabled() is False            # forward-apply still off
        monkeypatch.setattr("maverick.config.get_flows", lambda: {"auto_apply": True})
        assert flow.auto_apply_enabled() is True
        monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "0")
        assert flow.auto_apply_enabled() is False            # apply requires auto_evolve too
