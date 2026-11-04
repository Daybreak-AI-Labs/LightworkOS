"""In-process live solver: run an eval task as a real Lightwork goal.

The eval framework (``evals.py``) injects a ``Solver = Callable[[EvalTask], str]``.
This solver runs each task through the SAME ``run_goal`` path a user hits,
in-process, so it (a) reads the agent's
final answer directly (``run_goal_sync -> str``, with the world-model goal
result as a fallback), (b) bounds cost per task with a fresh ``Budget``, and
(c) isolates each task in its own throwaway world DB.

Injected like any solver, so it is fully testable with a scripted ``FakeLLM``
(no key, no network -- see ``test_agent_solver.py``) and runs for real when a
provider key is configured.
"""
from __future__ import annotations

import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

# GAIA's prompting convention: the agent ends with this marker and the scorer
# reads the text after it. Harmless for other string-answer benchmarks.
ANSWER_INSTRUCTION = (
    "\n\nWhen you are confident in the answer, end your final message with a "
    "line of exactly this form:\nFINAL ANSWER: <answer>\n"
    "Put only the answer after the marker -- no working, no extra words, and no "
    "units unless the question asks for them."
)


def make_agent_solver(
    *,
    max_dollars: float = 2.0,
    max_wall_seconds: float = 900.0,
    max_depth: int = 2,
    append_answer_instruction: bool = True,
    llm_factory: Callable[[], Any] | None = None,
    sandbox_factory: Callable[[], Any] | None = None,
) -> Callable[[Any], str]:
    """Build a solver that runs one task as a goal and returns the answer text.

    Args:
        max_dollars / max_wall_seconds / max_depth: per-task caps (cost control).
        append_answer_instruction: nudge the agent to emit a ``FINAL ANSWER:``
            marker so GAIA-style scorers can extract a clean answer.
        llm_factory: builds the LLM per task (default ``maverick.llm.LLM()``);
            tests pass a factory returning a ``FakeLLM``.
        sandbox_factory: builds the sandbox (default ``build_sandbox()``).
    """
    from maverick.budget import Budget
    from maverick.orchestrator import run_goal_sync
    from maverick.world_model import WorldModel

    def _llm():
        if llm_factory is not None:
            return llm_factory()
        from maverick.llm import LLM
        return LLM()

    def _sandbox():
        if sandbox_factory is not None:
            return sandbox_factory()
        from maverick.sandbox import build_sandbox
        return build_sandbox()

    def solve(task: Any) -> str:
        prompt = str(task.prompt)
        if append_answer_instruction:
            prompt += ANSWER_INSTRUCTION
        # Per-task temp dir (one SQLite world DB each). Clean it up in a
        # finally so a long benchmark run doesn't leak a directory per task.
        tmp = Path(tempfile.mkdtemp(prefix="mav-eval-"))
        world = WorldModel(path=tmp / "world.db")
        try:
            gid = world.create_goal(str(task.prompt)[:80], prompt)
            budget = Budget(max_dollars=max_dollars, max_wall_seconds=max_wall_seconds)
            out = run_goal_sync(
                llm=_llm(), world=world, budget=budget, goal_id=gid,
                sandbox=_sandbox(), max_depth=max_depth,
            )
            if out and str(out).strip():
                return _strip_run_meta(str(out))
            # Fallback: the agent may have recorded its answer on the goal row.
            try:
                g = world.get_goal(gid)
                return str(getattr(g, "result", None) or getattr(g, "answer", None) or "")
            except Exception:
                return ""
        finally:
            try:
                world.close()
            except Exception:
                pass
            shutil.rmtree(tmp, ignore_errors=True)

    return solve


def dry_run_solver(task: Any) -> str:
    """No-LLM stub: smoke-tests the harness wiring (every task 'answered' empty)."""
    return ""


def _strip_run_meta(text: str) -> str:
    """Return the agent's answer without run_goal's UI chrome.

    ``run_goal`` returns the final message wrapped as ``DONE.\\n\\n<answer>\\n\\n
    [skill distill ...]\\n\\n[tokens ...]``. Scorers want the answer, not the
    status word or the bracketed metadata footers, so strip both."""
    text = (text or "").strip()
    while True:
        stripped = re.sub(r"(?:\n\s*)\[[^\]\n]*\]\s*$", "", text).rstrip()
        if stripped == text:
            break
        text = stripped
    return re.sub(r"^DONE\.\s*", "", text, flags=re.IGNORECASE).strip()
