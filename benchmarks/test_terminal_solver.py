"""The live terminal solver drives the env tools to satisfy a task.

Uses a scripted FakeLLM, so the whole loop (tool_calls -> env mutation -> the
harness verifier) runs with no API key and no network -- the contract that lets
the terminal benchmark be validated for free, then run for real by swapping the
llm_factory.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import eval_terminal_bench as H  # noqa: E402
import terminal_solver  # noqa: E402
from maverick.llm import LLMResponse, ToolCall  # noqa: E402


class FakeLLM:
    """Replays scripted responses; once exhausted, returns a no-tool 'done'
    message so the solver loop terminates."""

    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.model = "fake:test"
        self.calls = 0

    def complete(self, **kwargs) -> LLMResponse:
        self.calls += 1
        if self.scripted:
            return self.scripted.pop(0)
        return LLMResponse(text="done", thinking=None, tool_calls=[], stop_reason="end_turn")


def _tool_turn(*calls) -> LLMResponse:
    return LLMResponse(
        text="", thinking=None, stop_reason="tool_use",
        tool_calls=[ToolCall(id=cid, name=name, input=args) for cid, name, args in calls],
    )


def test_tool_specs_cover_the_shell_tools():
    tools = H.build_shell_tools(H.TerminalEnv({}))
    by = {s["name"]: s for s in terminal_solver.tool_specs(tools)}
    assert set(by) == set(tools)
    assert "path" in by["read_file"]["input_schema"]["required"]      # no default -> required
    assert "content" not in by["write_file"]["input_schema"]["required"]  # has default -> optional


def test_live_loop_satisfies_a_file_task():
    task = H.TerminalTask(
        task_id="t", prompt="Create /out.txt containing exactly 'hi'.",
        expected_files={"/out.txt": "hi"}, required_commands=[r"write /out\.txt"],
    )
    env = H.TerminalEnv(task.initial_files)
    tools = H.build_shell_tools(env)
    fake = FakeLLM([_tool_turn(("1", "write_file", {"path": "/out.txt", "content": "hi"}))])
    solver = terminal_solver.make_terminal_solver(llm_factory=lambda: fake, max_steps=5)

    solver(task, tools)

    score, detail = H.verify(task, env)
    assert score == 1.0, detail
    assert env.files["/out.txt"] == "hi"
    assert fake.calls >= 2  # one tool turn + one terminating turn


def test_multi_step_read_then_write():
    task = H.TerminalTask(
        task_id="t", prompt="Append ' world' to /a.txt.",
        initial_files={"/a.txt": "hello"}, expected_files={"/a.txt": "hello world"},
    )
    env = H.TerminalEnv(task.initial_files)
    tools = H.build_shell_tools(env)
    fake = FakeLLM([
        _tool_turn(("1", "read_file", {"path": "/a.txt"})),
        _tool_turn(("2", "append_file", {"path": "/a.txt", "content": " world"})),
    ])
    terminal_solver.make_terminal_solver(llm_factory=lambda: fake, max_steps=5)(task, tools)
    assert H.verify(task, env)[0] == 1.0


def test_dry_run_scores_zero_on_a_required_task():
    task = H.TerminalTask(task_id="t", prompt="Create /out.txt",
                          expected_files={"/out.txt": "hi"})
    env = H.TerminalEnv(task.initial_files)
    terminal_solver.dry_run_terminal_solver(task, H.build_shell_tools(env))
    assert H.verify(task, env)[0] == 0.0


def test_unknown_tool_call_does_not_crash():
    task = H.TerminalTask(task_id="t", prompt="anything")
    env = H.TerminalEnv({})
    tools = H.build_shell_tools(env)
    fake = FakeLLM([_tool_turn(("1", "no_such_tool", {"x": "y"}))])
    # Must complete without raising (the bad result is fed back as an error).
    terminal_solver.make_terminal_solver(llm_factory=lambda: fake, max_steps=3)(task, tools)
    assert env.files == {}
