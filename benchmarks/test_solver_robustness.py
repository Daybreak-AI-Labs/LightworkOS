"""Robustness / failure-mode coverage for the live benchmark solvers.

The happy-path tests prove the solvers solve; these prove they DEGRADE
GRACEFULLY -- a runaway model, an LLM/budget error, malformed tool args, a
user-simulator that never finishes -- must terminate (bounded) and let `verify`
grade partial work rather than hang, overspend, or crash. All free (FakeLLM).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import eval_tau2 as T  # noqa: E402
import eval_terminal_bench as H  # noqa: E402
import tau2_solver  # noqa: E402
import terminal_solver  # noqa: E402
from maverick.budget import BudgetExceeded  # noqa: E402
from maverick.llm import LLMResponse, ToolCall  # noqa: E402


class FakeLLM:
    def __init__(self, factory):
        self._factory = factory  # called per complete() to build a response
        self.model = "fake:test"
        self.calls = 0

    def complete(self, **kwargs) -> LLMResponse:
        self.calls += 1
        return self._factory(self.calls)


def _tool_write():
    return LLMResponse(text="", thinking=None, stop_reason="tool_use",
                       tool_calls=[ToolCall(id="x", name="write_file",
                                            input={"path": "/x", "content": "y"})])


# ---------- terminal solver ----------

def test_terminal_runaway_loop_is_bounded():
    # A model that ALWAYS calls a tool must stop at max_steps, not loop forever.
    env = H.TerminalEnv({})
    fake = FakeLLM(lambda n: _tool_write())
    terminal_solver.make_terminal_solver(llm_factory=lambda: fake, max_steps=3)(
        H.TerminalTask(task_id="t", prompt="loop"), H.build_shell_tools(env))
    assert fake.calls == 3  # exactly max_steps, then returns


def test_terminal_llm_error_ends_gracefully():
    def boom(n):
        raise RuntimeError("provider down")
    env = H.TerminalEnv({"/a": "keep"})
    terminal_solver.make_terminal_solver(llm_factory=lambda: FakeLLM(boom), max_steps=5)(
        H.TerminalTask(task_id="t", prompt="x"), H.build_shell_tools(env))
    assert env.files == {"/a": "keep"}  # nothing mutated, no crash


def test_terminal_budget_exceeded_ends_gracefully():
    def over(n):
        raise BudgetExceeded("$2.00 > $2.00")
    env = H.TerminalEnv({})
    terminal_solver.make_terminal_solver(llm_factory=lambda: FakeLLM(over))(
        H.TerminalTask(task_id="t", prompt="x"), H.build_shell_tools(env))  # must not raise


def test_terminal_malformed_tool_args_dont_crash():
    # First a tool_use with WRONG kwargs (TypeError on call), then finish.
    def script(n):
        if n == 1:
            return LLMResponse(text="", thinking=None, stop_reason="tool_use",
                               tool_calls=[ToolCall(id="1", name="write_file", input={"nope": "z"})])
        return LLMResponse(text="giving up", thinking=None, tool_calls=[], stop_reason="end_turn")
    env = H.TerminalEnv({})
    terminal_solver.make_terminal_solver(llm_factory=lambda: FakeLLM(script), max_steps=5)(
        H.TerminalTask(task_id="t", prompt="x"), H.build_shell_tools(env))
    assert env.files == {}  # the bad call mutated nothing; loop survived and ended


# ---------- tau2 solver ----------

def test_tau2_user_never_done_is_bounded():
    # A customer who never says ###DONE### must stop at max_turns.
    user = FakeLLM(lambda n: LLMResponse(text="still here", thinking=None, tool_calls=[], stop_reason="end_turn"))
    agent = FakeLLM(lambda n: LLMResponse(text="how else can I help?", thinking=None, tool_calls=[], stop_reason="end_turn"))
    env = T.Tau2Env({})
    tau2_solver.make_tau2_solver(agent_llm_factory=lambda: agent, user_llm_factory=lambda: user,
                                 max_turns=3)(T.Tau2Task(task_id="t", prompt="vague"), T.build_retail_tools(env))
    assert user.calls == 3 and agent.calls == 3  # bounded by max_turns


def test_tau2_agent_never_finishes_turn_is_bounded():
    # An agent that only ever calls tools (never a text reply) ends the turn at
    # max_steps_per_turn, and the conversation then stops.
    user = FakeLLM(lambda n: LLMResponse(text="hi", thinking=None, tool_calls=[], stop_reason="end_turn"))
    agent = FakeLLM(lambda n: LLMResponse(text="", thinking=None, stop_reason="tool_use",
                                          tool_calls=[ToolCall(id="g", name="get_user", input={"user_id": "U1"})]))
    env = T.Tau2Env({"users": {"U1": {}}})
    tau2_solver.make_tau2_solver(agent_llm_factory=lambda: agent, user_llm_factory=lambda: user,
                                 max_turns=5, max_steps_per_turn=3)(
        T.Tau2Task(task_id="t", prompt="x"), T.build_retail_tools(env))
    assert agent.calls == 3  # one turn capped at max_steps_per_turn, then solve returns


def test_tau2_user_llm_error_ends_gracefully():
    def boom(n):
        raise RuntimeError("user sim down")
    agent = FakeLLM(lambda n: LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn"))
    env = T.Tau2Env({})
    tau2_solver.make_tau2_solver(agent_llm_factory=lambda: agent, user_llm_factory=lambda: FakeLLM(boom))(
        T.Tau2Task(task_id="t", prompt="x"), T.build_retail_tools(env))
    assert agent.calls == 0  # user error -> treated as DONE -> agent never consulted, no crash


# ---------- hard fixtures load (free CI guard so a malformed row fails here,
#            not at live-run cost) ----------

def test_hard_terminal_fixture_loads():
    tasks = H.load_tasks(Path(__file__).resolve().parent / "eval_fixtures" / "terminal_bench_hard.jsonl")
    assert len(tasks) == 8
    assert all(t.prompt and isinstance(t.expected_files, dict) for t in tasks)


def test_hard_tau2_fixture_loads():
    tasks = T.load_tasks(Path(__file__).resolve().parent / "eval_fixtures" / "tau2_retail_hard.jsonl")
    assert len(tasks) == 6
    assert all(t.prompt and isinstance(t.required_actions, list) for t in tasks)
