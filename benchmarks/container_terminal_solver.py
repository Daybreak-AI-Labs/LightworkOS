"""Containerized terminal solver: a Lightwork LLM driving a REAL isolated shell.

The virtual-FS ``eval_terminal_bench.py`` can only manipulate file *contents* --
``run_command`` just logs. This solver handles tasks that need **real command
execution** (run code, run a test suite, chmod+exec): each task gets a throwaway Docker container (``--network none``, memory/pid-capped), the
agent drives real ``run_command``/``write_file``/``read_file`` tools that exec
inside it, and grading runs the task's ``verify_command`` IN the container
(exit 0 = pass) and/or checks ``expected_files``.

Same injected-solver shape as the others, so the loop + grading are validated
for FREE with a scripted FakeLLM over a fake in-memory container
(``test_container_terminal_solver.py``); a live run needs Docker + a provider
key. Requires a running Docker daemon (``docker info``).
"""
from __future__ import annotations

import inspect
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

SYSTEM = (
    "You are working inside a real Linux container with a POSIX shell. Use "
    "run_command to execute commands (python, shell, test runners), and "
    "write_file / read_file to manage files. Actually RUN things to satisfy the "
    "request -- do not just describe them. When the request is fully done, reply "
    "WITHOUT calling a tool to finish."
)


# --------------------------------------------------------------- container env
class ContainerEnv:
    """A throwaway Docker container exposing run / read / write / list. Isolated:
    no network, capped memory + pids, force-removed on close."""

    def __init__(self, image: str = "python:3.11-slim", *, exec_timeout: int = 60):
        self.image = image
        self.exec_timeout = exec_timeout
        self.name = "mavbench-" + uuid.uuid4().hex[:12]
        self.started = False

    def start(self) -> None:
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", self.name,
             "--network", "none", "--memory", "512m", "--pids-limit", "256",
             self.image, "sleep", "3600"],
            capture_output=True, text=True, check=True, timeout=120,
        )
        self.started = True

    def run(self, command: str) -> tuple[str, int]:
        """Execute ``command`` in the container's shell -> (combined output, exit)."""
        try:
            r = subprocess.run(
                ["docker", "exec", self.name, "sh", "-lc", command],
                capture_output=True, text=True, timeout=self.exec_timeout,
            )
        except subprocess.TimeoutExpired:
            return ("ERROR: command timed out", 124)
        return ((r.stdout or "") + (r.stderr or ""), r.returncode)

    def write_file(self, path: str, content: str = "") -> str:
        # mkdir -p the parent, then write stdin to the file (path is $0 to sh).
        r = subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-c",
             'mkdir -p "$(dirname "$0")" && cat > "$0"', path],
            input=content, capture_output=True, text=True, timeout=self.exec_timeout,
        )
        return "written" if r.returncode == 0 else f"ERROR: {(r.stderr or '').strip()[:120]}"

    def read_file(self, path: str):
        r = subprocess.run(["docker", "exec", self.name, "cat", path],
                           capture_output=True, text=True, timeout=self.exec_timeout)
        return r.stdout if r.returncode == 0 else None

    def list_dir(self, path: str = "/") -> str:
        out, _ = self.run(f"ls -1A {path}")
        return out

    def close(self) -> None:
        if self.started:
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, timeout=30)
            self.started = False


def build_container_tools(env: ContainerEnv) -> dict[str, Callable]:
    """Real shell tools bound to ``env`` (they execute inside the container)."""

    def run_command(command: str):
        out, code = env.run(command)
        return f"[exit {code}]\n{out}" if out else f"[exit {code}]"

    def write_file(path: str, content: str = ""):
        return env.write_file(path, content)

    def read_file(path: str):
        out = env.read_file(path)
        return out if out is not None else f"no such file {path!r}"

    def list_dir(path: str = "/"):
        return env.list_dir(path)

    return {"run_command": run_command, "write_file": write_file,
            "read_file": read_file, "list_dir": list_dir}


# ----------------------------------------------------------------- task + grade
@dataclass
class ContainerTask:
    """A real-execution task. Graded on ``verify_command`` (exit 0) AND/OR
    ``expected_files`` (exact content)."""
    task_id: str
    prompt: str
    image: str = "python:3.11-slim"
    setup_files: dict = field(default_factory=dict)
    verify_command: str = ""
    expected_files: dict = field(default_factory=dict)


def verify(task: ContainerTask, env: ContainerEnv) -> tuple[float, str]:
    if not task.expected_files and not task.verify_command:
        # Nothing to check is "not evaluated", never a vacuous pass.
        return 0.0, "no grading criteria (verify_command/expected_files): not evaluated"
    fails: list[str] = []
    for path, content in (task.expected_files or {}).items():
        got = env.read_file(path)
        if got != content:
            fails.append(f"{path}={got!r} (want {content!r})")
    if task.verify_command:
        out, code = env.run(task.verify_command)
        if code != 0:
            fails.append(f"verify exit {code}: {out.strip()[:80]}")
    return (1.0, "ok") if not fails else (0.0, " | ".join(fails))


def _tool_specs(tools: dict[str, Callable]) -> list[dict]:
    specs: list[dict] = []
    for name, fn in tools.items():
        props: dict = {}
        required: list[str] = []
        for pname, param in inspect.signature(fn).parameters.items():
            props[pname] = {"type": "string", "description": f"the {pname}"}
            if param.default is inspect.Parameter.empty:
                required.append(pname)
        specs.append({"name": name, "description": (inspect.getdoc(fn) or name),
                      "input_schema": {"type": "object", "properties": props, "required": required}})
    return specs


def make_container_solver(
    *, max_steps: int = 30, max_dollars: float = 2.0, max_wall_seconds: float = 600.0,
    max_tokens: int = 2048, llm_factory: Callable[[], Any] | None = None,
) -> Callable[[ContainerTask, dict], None]:
    """Build a solver that drives a real LLM tool-loop over the container tools."""
    from maverick.budget import Budget

    def _llm():
        if llm_factory is not None:
            return llm_factory()
        from maverick.llm import LLM
        return LLM()

    def solve(task: ContainerTask, tools: dict) -> None:
        llm = _llm()
        budget = Budget(max_dollars=max_dollars, max_wall_seconds=max_wall_seconds)
        specs = _tool_specs(tools)
        messages: list[dict] = [{"role": "user", "content": task.prompt}]
        for _ in range(max_steps):
            try:
                resp = llm.complete(system=SYSTEM, messages=messages, tools=specs,
                                    budget=budget, max_tokens=max_tokens)
            except Exception:
                return
            calls = list(getattr(resp, "tool_calls", None) or [])
            if not calls:
                return
            assistant: list[dict] = []
            text = (getattr(resp, "text", "") or "")
            if text.strip():
                assistant.append({"type": "text", "text": text})
            for tc in calls:
                assistant.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.input})
            messages.append({"role": "assistant", "content": assistant})
            results: list[dict] = []
            for tc in calls:
                fn = tools.get(tc.name)
                try:
                    out = fn(**(tc.input or {})) if fn else f"ERROR: no such tool {tc.name!r}"
                except Exception as e:
                    out = f"ERROR: {type(e).__name__}: {e}"
                results.append({"type": "tool_result", "tool_use_id": tc.id,
                                "content": "" if out is None else str(out)})
            messages.append({"role": "user", "content": results})

    return solve


def run_container_bench(tasks: list[ContainerTask], solver, *, keep: bool = False) -> dict:
    """Spin a fresh container per task, write setup files, solve, grade, tear down."""
    results = []
    for t in tasks:
        env = ContainerEnv(t.image)
        try:
            env.start()
            for path, content in (t.setup_files or {}).items():
                env.write_file(path, content)
            try:
                solver(t, build_container_tools(env))
                score, detail = verify(t, env)
            except Exception as e:
                score, detail = 0.0, f"ERROR: {type(e).__name__}: {e}"
        finally:
            if not keep:
                env.close()
        results.append({"task_id": t.task_id, "score": score, "passed": score >= 1.0, "detail": detail})
    n = len(results)
    passed = sum(r["passed"] for r in results)
    return {"benchmark": "container_terminal", "n": n, "passed": passed,
            "pass_at_1": round(passed / n, 4) if n else 0.0, "results": results}
