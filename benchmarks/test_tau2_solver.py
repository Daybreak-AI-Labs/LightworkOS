"""The live tau2 solver runs an agent<->user-simulator conversation that drives
the domain tools to satisfy the task.

Both sides are scripted FakeLLMs, so the dual-control loop (user message -> agent
tool-loop -> reply -> ... -> user '###DONE###') runs with no key and no network --
the contract that lets tau2-bench be validated for free, then run live by
swapping the two factories.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import eval_tau2 as H  # noqa: E402
import tau2_solver  # noqa: E402
from maverick.llm import LLMResponse, ToolCall  # noqa: E402


class FakeLLM:
    """Replays scripted responses; once exhausted returns a '###DONE###' text so
    neither loop can run forever."""

    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.model = "fake:test"
        self.calls = 0

    def complete(self, **kwargs) -> LLMResponse:
        self.calls += 1
        if self.scripted:
            return self.scripted.pop(0)
        return LLMResponse(text="###DONE###", thinking=None, tool_calls=[], stop_reason="end_turn")


def _say(text: str) -> LLMResponse:
    return LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason="end_turn")


def _tool(*calls) -> LLMResponse:
    return LLMResponse(
        text="", thinking=None, stop_reason="tool_use",
        tool_calls=[ToolCall(id=cid, name=name, input=args) for cid, name, args in calls],
    )


def test_tool_specs_cover_retail_tools():
    tools = H.build_retail_tools(H.Tau2Env({}))
    by = {s["name"]: s for s in tau2_solver._tool_specs(tools)}
    assert set(by) == set(tools)
    assert "order_id" in by["cancel_order"]["input_schema"]["required"]
    assert "reason" not in by["cancel_order"]["input_schema"]["required"]  # has a default


def test_dual_control_resolves_task():
    task = H.Tau2Task(
        task_id="t",
        prompt="You want to cancel order O1; give the id 'O1' when the agent asks.",
        initial_state={"orders": {"O1": {"status": "open"}}},
        expected_state={"orders.O1.status": "cancelled"},
        required_actions=[{"name": "cancel_order", "args": {"order_id": "O1"}}],
    )
    env = H.Tau2Env(task.initial_state)
    tools = H.build_retail_tools(env)
    user = FakeLLM([_say("Hi, I'd like to cancel an order."), _say("It's O1."), _say("###DONE###")])
    agent = FakeLLM([
        _say("Sure -- what's the order id?"),
        _tool(("c1", "cancel_order", {"order_id": "O1"})),
        _say("Done, order O1 is cancelled."),
    ])
    solver = tau2_solver.make_tau2_solver(
        agent_llm_factory=lambda: agent, user_llm_factory=lambda: user, max_turns=6)

    solver(task, tools)

    score, detail = H.verify(task, env)
    assert score == 1.0, detail
    assert env.db["orders"]["O1"]["status"] == "cancelled"
    assert user.calls >= 3 and agent.calls >= 3  # both parties actually conversed


def test_user_done_immediately_ends_conversation():
    task = H.Tau2Task(
        task_id="t", prompt="anything",
        required_actions=[{"name": "cancel_order", "args": {"order_id": "O1"}}],
    )
    env = H.Tau2Env({})
    agent = FakeLLM([])  # must never be consulted
    user = FakeLLM([_say("###DONE###")])
    tau2_solver.make_tau2_solver(
        agent_llm_factory=lambda: agent, user_llm_factory=lambda: user)(task, H.build_retail_tools(env))
    assert agent.calls == 0
    assert H.verify(task, env)[0] == 0.0  # required action never happened


def test_dry_run_scores_zero():
    task = H.Tau2Task(task_id="t", prompt="x",
                      initial_state={"orders": {"O1": {"status": "open"}}},
                      expected_state={"orders.O1.status": "cancelled"})
    env = H.Tau2Env(task.initial_state)
    tau2_solver.dry_run_tau2_solver(task, H.build_retail_tools(env))
    assert H.verify(task, env)[0] == 0.0
