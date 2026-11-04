"""Programmatic tool calling: the code_exec tool.

The model declares tool calls + a Python script; the host runs the calls through
the agent's shielded path, injects their (unframed) outputs as a `tools` dict,
runs the script in the sandbox, and returns only its stdout. These tests use a
minimal fake agent + a stubbed sandbox_run so they need no real LLM/sandbox.
"""
from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from maverick.tools.code_exec import code_exec_tool


@pytest.fixture(autouse=True)
def _approved_execution(monkeypatch):
    import maverick.tools.code_exec as module

    monkeypatch.setattr(module, "request_execution_consent", lambda *a, **kw: object())
    monkeypatch.setattr(module, "consume_operation_consent", lambda permit: nullcontext())


class _Budget:
    def __init__(self):
        self.calls = 0

    def record_tool_call(self):
        self.calls += 1


class _FakeAgent:
    """Minimal surface code_exec needs: a shielded _run_tool, budget, sandbox."""

    def __init__(self, tool_output="DATA"):
        self.ctx = SimpleNamespace(budget=_Budget(), sandbox=object())
        self.ran: list[tuple] = []
        self._tool_output = tool_output

    async def _run_tool(self, name, args):
        self.ran.append((name, args))
        # Mirror _run_tool's <tool_output …> framing so unframe is exercised.
        return (f"<tool_output tool={name!r} id=abcd>\n"
                f"{self._tool_output}:{name}\n</tool_output abcd>")


def _patch_sandbox(monkeypatch, *, rc=0, out="OUT", err=""):
    captured: dict = {}

    def fake_sandbox_run(sandbox, argv, *, timeout=None, stdin=None):
        captured["argv"] = argv
        captured["stdin"] = stdin
        return rc, out, err

    import maverick.tools.code_exec as ce
    monkeypatch.setattr(ce, "sandbox_run", fake_sandbox_run)
    return captured


@pytest.mark.asyncio
async def test_runs_declared_tools_then_script(monkeypatch):
    captured = _patch_sandbox(monkeypatch, rc=0, out="42")
    agent = _FakeAgent(tool_output="DATA")
    tool = code_exec_tool(agent)
    result = await tool.fn({
        "code": "print(len(tools))",
        "tool_calls": [
            {"name": "web_search", "arguments": {"q": "x"}},
            {"name": "http_fetch", "arguments": {"url": "y"}, "as": "page"},
        ],
    })
    assert result == "42"   # ONLY the script's stdout returns to the model
    assert agent.ran == [("web_search", {"q": "x"}), ("http_fetch", {"url": "y"})]
    assert agent.ctx.budget.calls == 2  # each declared call is budget-accounted
    # The script received the UNFRAMED outputs, keyed by `as` / '<name>_<i>'.
    assert '"web_search_0": "DATA:web_search"' in captured["stdin"]
    assert '"page": "DATA:http_fetch"' in captured["stdin"]
    assert captured["stdin"].rstrip().endswith("print(len(tools))")
    assert "<tool_output" not in captured["stdin"]  # frame stripped


@pytest.mark.asyncio
async def test_denied_code_exec_does_not_dispatch_declared_calls(monkeypatch):
    import maverick.tools.code_exec as module
    from maverick.safety import ConsentDenied

    def deny(*args, **kwargs):
        raise ConsentDenied("code_exec")

    monkeypatch.setattr(module, "request_execution_consent", deny)
    captured = _patch_sandbox(monkeypatch)
    agent = _FakeAgent()
    out = await code_exec_tool(agent).fn({"code": "print(1)",
                                          "tool_calls": [{"name": "shell", "arguments": {"cmd": "true"}}]})
    assert "not approved" in out
    assert agent.ran == []
    assert captured == {}


@pytest.mark.asyncio
async def test_code_exec_runs_with_real_one_use_approval(monkeypatch):
    import maverick.safety.consent as consent
    import maverick.tools.code_exec as module
    from maverick.safety import consume_operation_consent
    from maverick.tools.execution_consent import request_execution_consent

    monkeypatch.setattr(module, "request_execution_consent", request_execution_consent)
    monkeypatch.setattr(module, "consume_operation_consent", consume_operation_consent)
    monkeypatch.setattr(consent, "require_consent", lambda *a, **kw: SimpleNamespace(
        granted=True, source="dashboard", actor="user:reviewer"))
    captured = _patch_sandbox(monkeypatch, out="approved")
    out = await code_exec_tool(_FakeAgent()).fn({"code": "print('approved')"})
    assert out == "approved"
    assert captured["stdin"].endswith("print('approved')")


@pytest.mark.asyncio
async def test_requires_code(monkeypatch):
    _patch_sandbox(monkeypatch)
    assert "code` is required" in await code_exec_tool(_FakeAgent()).fn({"code": "  "})


@pytest.mark.asyncio
async def test_no_tool_calls_is_fine(monkeypatch):
    captured = _patch_sandbox(monkeypatch, out="hi")
    out = await code_exec_tool(_FakeAgent()).fn({"code": "print('hi')"})
    assert out == "hi"
    assert "tools = {}" in captured["stdin"]


@pytest.mark.asyncio
async def test_too_many_calls_rejected(monkeypatch):
    _patch_sandbox(monkeypatch)
    out = await code_exec_tool(_FakeAgent()).fn(
        {"code": "x", "tool_calls": [{"name": "t"}] * 25})
    assert "too many tool_calls" in out


@pytest.mark.asyncio
async def test_script_error_surfaces_stderr(monkeypatch):
    _patch_sandbox(monkeypatch, rc=1, out="", err="Traceback: boom")
    out = await code_exec_tool(_FakeAgent()).fn({"code": "raise SystemExit(1)"})
    assert "script exited 1" in out and "boom" in out


@pytest.mark.asyncio
async def test_budget_exhaustion_stops_before_running(monkeypatch):
    _patch_sandbox(monkeypatch)
    from maverick.budget import BudgetExceeded
    agent = _FakeAgent()

    def boom():
        raise BudgetExceeded("out of money")

    agent.ctx.budget.record_tool_call = boom
    out = await code_exec_tool(agent).fn(
        {"code": "x", "tool_calls": [{"name": "web_search"}]})
    assert "budget exhausted" in out
    assert agent.ran == []  # the declared tool never ran


@pytest.mark.asyncio
async def test_empty_stdout_gives_a_hint(monkeypatch):
    _patch_sandbox(monkeypatch, out="")
    out = await code_exec_tool(_FakeAgent()).fn({"code": "x = 1"})
    assert "no stdout" in out


# ---- unframe_tool_output ----------------------------------------------------

def test_unframe_tool_output():
    from maverick.agent import unframe_tool_output
    framed = "<tool_output tool='shell' id=ab>\nhello\nworld\n</tool_output ab>"
    assert unframe_tool_output(framed) == "hello\nworld"
    # A loop-guard note appended after the close tag is excluded.
    assert unframe_tool_output(framed + "\n\n[loop-guard] stop") == "hello\nworld"
    # Unframed block/plain messages pass through unchanged.
    assert unframe_tool_output("⚠ BLOCKED by Shield") == "⚠ BLOCKED by Shield"
    assert unframe_tool_output("plain text") == "plain text"
