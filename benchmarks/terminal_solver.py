"""Live Lightwork solver for the terminal-bench harness.

``eval_terminal_bench.py`` is a Docker-free virtual-filesystem domain: a task
gives a request + starting files, and a ``TerminalSolver`` drives the env's
shell tools (read/write/append/delete/move/mkdir/ls/run_command) until the
filesystem matches ``expected_files``/``absent_files`` and the required commands
were issued. This is the live seam beside the harness's no-op stub -- a real
Lightwork LLM driven in a tool-calling loop over those tools.

Injected like any solver, so it is validated for FREE with a scripted FakeLLM
(``test_terminal_solver.py``: tool_calls -> env mutation -> verify, no key/
network) and runs live by swapping ``llm_factory``.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

SYSTEM = (
    "You are operating a virtual UNIX filesystem through the provided tools to "
    "satisfy the user's request EXACTLY. First inspect the filesystem with "
    "list_dir / read_file, then create, modify, move, or delete files and run "
    "commands as needed. File contents must match the request precisely (exact "
    "bytes -- no trailing newline unless asked). When the request is fully "
    "satisfied, reply WITHOUT calling any tool to finish."
)


def tool_specs(tools: dict[str, Callable]) -> list[dict]:
    """Anthropic-style tool specs derived from each callable's signature.

    Every parameter is typed as a string (the shell tools take string paths /
    content / commands); a parameter with no default is required."""
    specs: list[dict] = []
    for name, fn in tools.items():
        props: dict = {}
        required: list[str] = []
        for pname, param in inspect.signature(fn).parameters.items():
            props[pname] = {"type": "string", "description": f"the {pname}"}
            if param.default is inspect.Parameter.empty:
                required.append(pname)
        doc = (inspect.getdoc(fn) or f"{name} tool").strip().splitlines()[0]
        specs.append({
            "name": name,
            "description": doc,
            "input_schema": {"type": "object", "properties": props, "required": required},
        })
    return specs


def make_terminal_solver(
    *,
    max_steps: int = 25,
    max_dollars: float = 2.0,
    max_wall_seconds: float = 600.0,
    max_tokens: int = 2048,
    llm_factory: Callable[[], Any] | None = None,
) -> Callable[[Any, dict], None]:
    """Build a ``TerminalSolver`` that drives a real LLM tool-loop over the env.

    ``llm_factory`` builds the LLM per task (default ``maverick.llm.LLM()``);
    tests pass a factory returning a scripted FakeLLM. The env is mutated in
    place through the bound ``tools``; the harness's ``verify`` grades it. Cost
    is bounded per task by a fresh ``Budget`` and a ``max_steps`` ceiling; any
    LLM/budget error ends the loop gracefully so partial work is still graded.
    """
    from maverick.budget import Budget

    def _llm():
        if llm_factory is not None:
            return llm_factory()
        from maverick.llm import LLM
        return LLM()

    def solve(task: Any, tools: dict[str, Callable]) -> None:
        llm = _llm()
        budget = Budget(max_dollars=max_dollars, max_wall_seconds=max_wall_seconds)
        specs = tool_specs(tools)
        start = sorted(getattr(task, "initial_files", None) or {})
        messages: list[dict] = [{
            "role": "user",
            "content": f"Request:\n{task.prompt}\n\nFiles present at start: {start}",
        }]
        for _ in range(max_steps):
            try:
                resp = llm.complete(
                    system=SYSTEM, messages=messages, tools=specs,
                    budget=budget, max_tokens=max_tokens,
                )
            except Exception:
                return  # budget/network/API error -> stop; verify grades partial work
            calls = list(getattr(resp, "tool_calls", None) or [])
            if not calls:
                return  # the model finished (no tool call)
            assistant: list[dict] = []
            text = getattr(resp, "text", "") or ""
            if text.strip():
                assistant.append({"type": "text", "text": text})
            for tc in calls:
                assistant.append(
                    {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.input}
                )
            messages.append({"role": "assistant", "content": assistant})
            results: list[dict] = []
            for tc in calls:
                fn = tools.get(tc.name)
                try:
                    out = fn(**(tc.input or {})) if fn else f"ERROR: no such tool {tc.name!r}"
                except Exception as e:
                    out = f"ERROR: {type(e).__name__}: {e}"
                results.append({
                    "type": "tool_result", "tool_use_id": tc.id,
                    "content": "" if out is None else str(out),
                })
            messages.append({"role": "user", "content": results})

    return solve


def dry_run_terminal_solver(task: Any, tools: dict) -> None:
    """No-op solver: structure smoke (every task with requirements scores 0)."""
