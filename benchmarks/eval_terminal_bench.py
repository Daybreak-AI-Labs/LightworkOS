"""terminal-bench-style harness: stateful shell-agent eval with file+command checks.

``eval_tau2.py`` grades a stateful *retail DB* domain on final state + required
actions. terminal-bench is the same *shape* on a different domain -- a terminal:
the agent runs shell-ish operations against a filesystem, and a task is graded on
BOTH the final filesystem (the outcome) AND whether the required commands were
run (the process). This module is that harness, with a small self-contained
virtual-filesystem domain so it runs end-to-end in CI with **no Docker**; real
terminal-bench task files (same row shape) plug in via ``--dataset``.

Like ``eval_tau2.py``, the **solver is injected** so the whole thing runs with a
deterministic stub (no LLM / network / container): a solver receives a task + the
domain's shell tools (name -> callable) and drives them to satisfy the request,
mutating the virtual FS. The verifier then checks the FS + the command log.

The real-environment seam is the solver: ``terminal_solver.py`` drives a live
LLM over these virtual-FS tools, and ``container_terminal_solver.py`` runs tasks
that need real command execution in an isolated Docker container. The env +
verifier + task format are the harness, and they are Docker-free by construction
so CI can exercise both grading legs without a daemon.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path


def _load_framework():
    """Path-load ``evals.py`` (benchmarks/ is a flat script dir, not a package)."""
    name = "benchmarks_evals"
    if name in sys.modules:
        return sys.modules[name]
    p = Path(__file__).parent / "evals.py"
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_E = _load_framework()
EvalResult = _E.EvalResult
FIXTURES = _E.FIXTURES


@dataclass
class TerminalTask:
    """One terminal task: a request, the starting filesystem, and grade keys.

    - ``initial_files``: ``path -> content`` the env starts with.
    - ``expected_files``: ``path -> content`` the FS MUST hold at the end (exact
      match). Empty = no file-content requirement.
    - ``absent_files``: paths that MUST NOT exist at the end (e.g. a cleanup task).
    - ``required_commands``: regex patterns that MUST each match at least one
      entry of the command log -- the *process* check (e.g. ``r"rm /var/log/old\\.log"``).
    """

    task_id: str
    prompt: str
    initial_files: dict = field(default_factory=dict)
    expected_files: dict = field(default_factory=dict)
    absent_files: list = field(default_factory=list)
    required_commands: list = field(default_factory=list)


# ---- the virtual-terminal domain: a stateful shell environment --------------

class TerminalEnv:
    """Holds the mutable virtual filesystem plus an append-only command log."""

    def __init__(self, files: dict):
        self.files: dict = copy.deepcopy(files or {})
        self.commands: list[str] = []

    def _log(self, command: str) -> None:
        self.commands.append(command)


def build_shell_tools(env: TerminalEnv) -> dict[str, Callable]:
    """Return the virtual-terminal tools, bound to ``env`` (mutate FS + log).

    Each tool logs the canonical command string it represents so a task's
    ``required_commands`` regexes can assert the *process*, not just the outcome
    (deleting a file via ``rm`` is different from it never existing). ``run_command``
    is the escape hatch for asserting an arbitrary command was issued.
    """

    def read_file(path: str):
        env._log(f"cat {path}")
        return env.files.get(path)

    def write_file(path: str, content: str = ""):
        env._log(f"write {path}")
        env.files[path] = content
        return "written"

    def append_file(path: str, content: str = ""):
        env._log(f"append {path}")
        env.files[path] = env.files.get(path, "") + content
        return "appended"

    def delete_file(path: str):
        env._log(f"rm {path}")
        existed = path in env.files
        env.files.pop(path, None)
        return "removed" if existed else f"no such file {path!r}"

    def move_file(src: str, dst: str):
        env._log(f"mv {src} {dst}")
        if src not in env.files:
            return f"no such file {src!r}"
        env.files[dst] = env.files.pop(src)
        return "moved"

    def make_dir(path: str):
        env._log(f"mkdir {path}")
        return "created"

    def list_dir(path: str = "/"):
        env._log(f"ls {path}")
        prefix = path if path.endswith("/") else path + "/"
        return sorted(p for p in env.files if p == path or p.startswith(prefix))

    def run_command(command: str):
        """Escape hatch: record an arbitrary command (for required_commands)."""
        env._log(command)
        return ""

    return {
        "read_file": read_file,
        "write_file": write_file,
        "append_file": append_file,
        "delete_file": delete_file,
        "move_file": move_file,
        "make_dir": make_dir,
        "list_dir": list_dir,
        "run_command": run_command,
    }


# A solver drives the shell tools to satisfy the task. Injected for testability.
TerminalSolver = Callable[[TerminalTask, dict], None]

_MISSING = object()


def _command_present(commands: list[str], pattern: str) -> bool:
    """True iff some logged command matches ``pattern`` (regex search)."""
    try:
        rx = re.compile(pattern)
    except re.error:
        # A malformed pattern degrades to a literal-substring match rather than
        # sinking the whole task on a bad fixture row.
        return any(pattern in c for c in commands)
    return any(rx.search(c) for c in commands)


def verify(task: TerminalTask, env: TerminalEnv) -> tuple[float, str]:
    """Grade a finished task: outcome (filesystem) AND process (commands run).

    Returns (1.0, "ok") only if every expected file matches, no absent file
    exists, AND every required command was logged; else (0.0, "<what failed>").
    A task with no criteria at all cannot be evaluated and scores 0.0, never a
    vacuous pass.
    """
    if not task.expected_files and not task.absent_files and not task.required_commands:
        return 0.0, "no grading criteria: not evaluated"
    file_fails = [
        f"{path}={env.files.get(path, _MISSING)!r} (want {content!r})"
        for path, content in (task.expected_files or {}).items()
        if env.files.get(path, _MISSING) != content
    ]
    file_fails += [
        f"{path} should be absent"
        for path in (task.absent_files or [])
        if path in env.files
    ]
    cmd_fails = [
        pat
        for pat in (task.required_commands or [])
        if not _command_present(env.commands, pat)
    ]
    if not file_fails and not cmd_fails:
        return 1.0, "ok"
    parts = []
    if file_fails:
        parts.append("files: " + "; ".join(file_fails))
    if cmd_fails:
        parts.append("missing commands: " + ", ".join(cmd_fails))
    return 0.0, " | ".join(parts)


def load_tasks(dataset: Path | None = None, *, limit: int | None = None) -> list[TerminalTask]:
    path = dataset if dataset is not None else FIXTURES / "terminal_bench_sample.jsonl"
    rows = _E._read_jsonl(Path(path))
    tasks = [
        TerminalTask(
            task_id=str(r.get("task_id", r.get("id", ""))),
            prompt=str(r.get("prompt", r.get("instruction", ""))),
            initial_files=r.get("initial_files") or {},
            expected_files=r.get("expected_files") or {},
            absent_files=r.get("absent_files") or [],
            required_commands=r.get("required_commands") or [],
        )
        for r in rows
    ]
    return tasks[:limit] if limit is not None else tasks


def run_terminal_bench(
    solver: TerminalSolver,
    *,
    dataset: Path | None = None,
    limit: int | None = None,
) -> dict:
    """Run each task in a fresh env through ``solver``, verify, and aggregate.

    A solver that raises is recorded as a 0-score result (its error text becomes
    ``got``) rather than aborting the whole run."""
    tasks = load_tasks(dataset, limit=limit)
    results: list = []
    for t in tasks:
        env = TerminalEnv(t.initial_files)
        tools = build_shell_tools(env)
        try:
            solver(t, tools)
        except Exception as e:  # one bad task != a dead benchmark
            results.append(EvalResult(task_id=t.task_id, score=0.0, passed=False,
                                      expected="ok", got=f"ERROR: {type(e).__name__}: {e}"))
            continue
        score, detail = verify(t, env)
        results.append(EvalResult(task_id=t.task_id, score=score, passed=score >= 1.0,
                                  expected="ok", got=detail))
    n = len(results)
    passed = sum(1 for r in results if r.passed)
    return {
        "benchmark": "terminal_bench",
        "n": n,
        "passed": passed,
        "pass_at_1": round(passed / n, 4) if n else 0.0,
        "mean_score": round(sum(r.score for r in results) / n, 4) if n else 0.0,
        "results": results,
    }


def _dry_run_solver(task: TerminalTask, tools: dict) -> None:
    """No-op solver: structure smoke (every task scores 0)."""


def _load_terminal_solver():
    """Path-load the live solver (benchmarks/ is a flat script dir)."""
    name = "benchmarks_terminal_solver"
    if name in sys.modules:
        return sys.modules[name]
    p = Path(__file__).parent / "terminal_solver.py"
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    """Run the terminal-bench harness. By default the LIVE Lightwork solver drives
    each task with a tool-calling loop over the virtual-FS tools (needs a provider
    key); ``MAVERICK_EVAL_DRY_RUN=1`` swaps in the no-op stub for CI / smoke."""
    import argparse
    import os
    ap = argparse.ArgumentParser(prog="eval_terminal_bench")
    ap.add_argument("--dataset", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--max-dollars", type=float, default=2.0)
    ap.add_argument("--tag", default="local")
    ap.add_argument("--scores", type=Path, default=Path(__file__).parent / "SCORES.md")
    args = ap.parse_args()
    if os.environ.get("MAVERICK_EVAL_DRY_RUN") == "1":
        solver = _dry_run_solver
    else:
        solver = _load_terminal_solver().make_terminal_solver(max_dollars=args.max_dollars)
    summary = run_terminal_bench(solver, dataset=args.dataset, limit=args.limit)
    _E.append_scores(summary, args.scores, tag=args.tag)
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2))
    return 0


__all__ = [
    "TerminalTask", "TerminalEnv", "TerminalSolver",
    "build_shell_tools", "verify", "load_tasks", "run_terminal_bench",
]


if __name__ == "__main__":
    sys.exit(main())
