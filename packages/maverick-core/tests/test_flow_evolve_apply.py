"""The apply + measure arrows of the flow self-learning loop: enacting a
node-kind swap proposal, and scoring a node's grounded outcomes before vs. after
the change so an improvement can be proven rather than asserted."""
from __future__ import annotations

import pytest
from maverick.flow import Flow, FlowNode, evolve


def _flow():
    return Flow(id="f", name="F", start="a", nodes={
        "a": FlowNode(id="a", kind="agent", brief="summarize the ticket", label="Summarize"),
        "b": FlowNode(id="b", kind="action", tool="slack_bot", params={"channel": "#x"}),
    })


class TestApplyProposal:
    def test_harden_agent_to_action_needs_a_tool(self):
        with pytest.raises(ValueError):
            evolve.apply_proposal(_flow(), "a", "action")   # no tool -> rejected

    def test_harden_agent_to_action_needs_reviewed_parameter_bindings(self):
        with pytest.raises(ValueError, match="parameter bindings"):
            evolve.apply_proposal(_flow(), "a", "action", tool="web_search")

    def test_harden_agent_to_action(self):
        f = _flow()
        new = evolve.apply_proposal(
            f, "a", "action", tool="web_search", params={"query": "{{topic}}"},
        )
        assert new.nodes["a"].kind == "action"
        assert new.nodes["a"].tool == "web_search" and new.nodes["a"].brief == ""
        assert new.validate() == []
        assert f.nodes["a"].kind == "agent"                 # original untouched (copy)

    def test_harden_with_unclassified_tool_remains_unsaveable(self):
        new = evolve.apply_proposal(
            _flow(), "a", "action", tool="unreviewed_connector", params={})

        assert any("unclassified direct action tool" in error
                   for error in new.validate())

    def test_harden_agent_to_action_clears_stale_params(self):
        f = _flow()
        f.nodes["a"].params = {"path": "/tmp/hidden", "content": "stale"}

        new = evolve.apply_proposal(f, "a", "action", tool="web_search", params={})

        assert new.nodes["a"].params == {}
        assert f.nodes["a"].params == {"path": "/tmp/hidden", "content": "stale"}

    def test_soften_action_to_agent(self):
        new = evolve.apply_proposal(_flow(), "b", "agent", brief="post to slack, judging tone")
        assert new.nodes["b"].kind == "agent"
        assert new.nodes["b"].brief == "post to slack, judging tone"
        assert new.nodes["b"].tool == "" and new.nodes["b"].params == {}
        assert new.validate() == []

    def test_soften_falls_back_to_label_when_no_brief_given(self):
        f = Flow(id="f", name="F", start="b",
                 nodes={"b": FlowNode(id="b", kind="action", tool="x", label="Post update")})
        assert evolve.apply_proposal(f, "b", "agent").nodes["b"].brief == "Post update"

    def test_soften_needs_something_to_become_a_brief(self):
        f = Flow(id="f", name="F", start="b",
                 nodes={"b": FlowNode(id="b", kind="action", tool="x")})   # no brief/label
        with pytest.raises(ValueError):
            evolve.apply_proposal(f, "b", "agent")

    def test_unknown_node_raises_keyerror(self):
        with pytest.raises(KeyError):
            evolve.apply_proposal(_flow(), "zzz", "action", tool="t")

    def test_cannot_swap_a_control_node(self):
        f = Flow(id="f", name="F", start="c",
                 nodes={"c": FlowNode(id="c", kind="branch", condition="x == 1")})
        with pytest.raises(ValueError):
            evolve.apply_proposal(f, "c", "agent")


class TestMeasure:
    def test_before_after_split_and_positive_delta(self):
        series = [(10.0, 0.4), (11.0, 0.4), (20.0, 1.0), (21.0, 0.8)]
        m = evolve.measure("f", "a", since_ts=15.0, series=series)
        assert m["before"] == {"n": 2, "mean": pytest.approx(0.4)}
        assert m["after"]["n"] == 2 and m["after"]["mean"] == pytest.approx(0.9)
        assert m["delta"] == pytest.approx(0.5) and m["improved"] is True

    def test_no_after_data_is_not_improved(self):
        m = evolve.measure("f", "a", since_ts=15.0, series=[(10.0, 0.4)])
        assert m["after"]["mean"] is None and m["delta"] is None
        assert m["improved"] is False

    def test_regression_is_not_improved(self):
        m = evolve.measure("f", "a", since_ts=15.0, series=[(10.0, 1.0), (20.0, 0.2)])
        assert m["delta"] == pytest.approx(-0.8) and m["improved"] is False
