"""The containerized solver's loop + grading, validated WITHOUT Docker.

A scripted FakeLLM drives an in-memory FakeContainerEnv, so the tool-loop, the
tool wrappers, and verify() are all exercised free (no daemon, no key). The real
container path is exercised by the live run.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import container_terminal_solver as M  # noqa: E402
from maverick.llm import LLMResponse, ToolCall  # noqa: E402


class FakeLLM:
    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.model = "fake:test"
        self.calls = 0

    def complete(self, **kwargs) -> LLMResponse:
        self.calls += 1
        if self.scripted:
            return self.scripted.pop(0)
        return LLMResponse(text="done", thinking=None, tool_calls=[], stop_reason="end_turn")


def _tool(*calls):
    return LLMResponse(text="", thinking=None, stop_reason="tool_use",
                       tool_calls=[ToolCall(id=c, name=n, input=a) for c, n, a in calls])


class FakeContainerEnv:
    """In-memory stand-in for ContainerEnv (duck-typed)."""

    def __init__(self, files=None, run_result=("", 0)):
        self.files = dict(files or {})
        self._run_result = run_result
        self.ran: list[str] = []

    def start(self):
        pass

    def close(self):
        pass

    def run(self, command):
        self.ran.append(command)
        return self._run_result

    def write_file(self, path, content=""):
        self.files[path] = content
        return "written"

    def read_file(self, path):
        return self.files.get(path)

    def list_dir(self, path="/"):
        return "\n".join(sorted(self.files))


def test_tool_specs_cover_container_tools():
    tools = M.build_container_tools(FakeContainerEnv())
    by = {s["name"]: s for s in M._tool_specs(tools)}
    assert set(by) == {"run_command", "write_file", "read_file", "list_dir"}
    assert "command" in by["run_command"]["input_schema"]["required"]


def test_run_command_tool_reports_exit_and_output():
    tools = M.build_container_tools(FakeContainerEnv(run_result=("hello\n", 0)))
    assert tools["run_command"](command="echo hello") == "[exit 0]\nhello\n"


def test_solver_drives_tools_and_grades_expected_files():
    env = FakeContainerEnv()
    fake = FakeLLM([_tool(("1", "write_file", {"path": "/work/out.txt", "content": "55"}))])
    M.make_container_solver(llm_factory=lambda: fake, max_steps=5)(
        M.ContainerTask(task_id="t", prompt="write 55", expected_files={"/work/out.txt": "55"}),
        M.build_container_tools(env))
    task = M.ContainerTask(task_id="t", prompt="x", expected_files={"/work/out.txt": "55"})
    assert M.verify(task, env)[0] == 1.0
    assert fake.calls >= 2


def test_verify_command_pass_and_fail():
    ok_env = FakeContainerEnv(run_result=("", 0))
    bad_env = FakeContainerEnv(run_result=("AssertionError", 1))
    task = M.ContainerTask(task_id="t", prompt="x", verify_command="python -m unittest")
    assert M.verify(task, ok_env)[0] == 1.0
    assert M.verify(task, bad_env)[0] == 0.0


def test_unknown_tool_call_does_not_crash():
    env = FakeContainerEnv()
    fake = FakeLLM([_tool(("1", "no_such", {"x": "y"}))])
    M.make_container_solver(llm_factory=lambda: fake, max_steps=3)(
        M.ContainerTask(task_id="t", prompt="x"), M.build_container_tools(env))
    assert env.files == {}  # nothing written, no crash
