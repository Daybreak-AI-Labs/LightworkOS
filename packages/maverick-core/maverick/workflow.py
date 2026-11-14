"""Workflow engine — chain tool calls into a DAG.

A workflow is a list of `Step` nodes; each step names a tool, supplies
its args (which may reference outputs from earlier steps), and declares
optional dependencies. The engine resolves the DAG, runs ready steps,
records each step's output, and lets you reference prior outputs via a
``${step_name.out}`` placeholder inside string args.

This is intentionally tiny — no checkpointing, no resume, no rollback.
It's the "glue" piece that lets the agent (or a power user) compose 3-7
existing tools into a one-shot workflow without spawning a sub-agent.

Use:

    from maverick.workflow import Step, Workflow

    wf = Workflow(steps=[
        Step("fetch", "http_fetch", {"url": "https://news.ycombinator.com"}),
        Step("note",  "notify",     {"title": "Fetched",
                                       "body": "${fetch.out}"}),
    ])
    result = wf.run(registry)

``${step.out}`` is the only placeholder form. With ``stop_on_error=False``
a step whose dependency failed is recorded as failed and not run.

Cycles are rejected at construction. Output of each step is whatever
the underlying tool returned (string).
"""
from __future__ import annotations

import asyncio
import logging
import re
from contextvars import copy_context
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][\w]*)\.out\}")


@dataclass
class Step:
    name: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)


@dataclass
class StepResult:
    name: str
    tool: str
    ok: bool
    output: str
    error: str = ""
    elapsed_ms: float = 0.0


@dataclass
class WorkflowResult:
    steps: list[StepResult] = field(default_factory=list)
    failed: bool = False

    def by_name(self) -> dict[str, StepResult]:
        return {s.name: s for s in self.steps}


class WorkflowCycle(Exception):
    """Raised when a workflow's depends_on creates a cycle."""


class Workflow:
    def __init__(self, steps: list[Step]) -> None:
        if not steps:
            raise ValueError("workflow requires at least one step")
        seen: set[str] = set()
        for s in steps:
            if s.name in seen:
                raise ValueError(f"duplicate step name {s.name!r}")
            seen.add(s.name)
        self.steps = list(steps)
        # Validate dependency graph + detect cycles.
        self._topo_order = self._topo_sort()

    @staticmethod
    def _scan_placeholders(value: Any, into: set[str]) -> None:
        """Collect ``${step.out}`` refs anywhere in a nested arg value, mirroring
        _interpolate's recursion. Scanning only top-level strings missed a
        placeholder inside a dict/list arg, so the step could be ordered BEFORE
        its dependency and interpolate to an empty/stale value at run time."""
        if isinstance(value, str):
            into |= {m.group(1) for m in _PLACEHOLDER.finditer(value)}
        elif isinstance(value, dict):
            for v in value.values():
                Workflow._scan_placeholders(v, into)
        elif isinstance(value, list):
            for v in value:
                Workflow._scan_placeholders(v, into)

    def _all_deps(self, step: Step, known: set[str]) -> list[str]:
        # Explicit deps + implicit template deps (nested-aware).
        deps = set(step.depends_on)
        for v in step.args.values():
            self._scan_placeholders(v, deps)
        unknown = [d for d in deps if d not in known]
        if unknown:
            raise ValueError(
                f"step {step.name!r}: unknown dependency {unknown}"
            )
        return sorted(deps)

    def _topo_sort(self) -> list[Step]:
        names = {s.name for s in self.steps}
        # Build forward-dep map.
        forward: dict[str, set[str]] = {s.name: set() for s in self.steps}
        for s in self.steps:
            for d in self._all_deps(s, names):
                if d == s.name:
                    raise WorkflowCycle(f"step {s.name!r} depends on itself")
                forward[d].add(s.name)
        in_deg: dict[str, int] = {
            s.name: len(self._all_deps(s, names)) for s in self.steps
        }
        ready = [s for s in self.steps if in_deg[s.name] == 0]
        order: list[Step] = []
        by_name = {s.name: s for s in self.steps}
        while ready:
            nxt = ready.pop(0)
            order.append(nxt)
            for child in forward[nxt.name]:
                in_deg[child] -= 1
                if in_deg[child] == 0:
                    ready.append(by_name[child])
        if len(order) != len(self.steps):
            unresolved = [s.name for s in self.steps if in_deg[s.name] > 0]
            raise WorkflowCycle(f"cycle involving {unresolved}")
        return order

    def _interpolate(self, value: Any, outputs: dict[str, str]) -> Any:
        if isinstance(value, str):
            return _PLACEHOLDER.sub(
                lambda m: outputs.get(m.group(1), m.group(0)),
                value,
            )
        if isinstance(value, dict):
            return {k: self._interpolate(v, outputs) for k, v in value.items()}
        if isinstance(value, list):
            return [self._interpolate(v, outputs) for v in value]
        return value

    def run(
        self,
        registry,
        *,
        stop_on_error: bool = True,
    ) -> WorkflowResult:
        import time

        from .tool_authz import non_agent_capability_required
        result = WorkflowResult()
        outputs: dict[str, str] = {}
        names = {s.name for s in self.steps}
        not_ok: set[str] = set()
        for step in self._topo_order:
            blocked = [d for d in self._all_deps(step, names) if d in not_ok]
            if blocked:
                # A dependency failed (or was itself skipped): never run the
                # dependent on an unresolved ``${step.out}`` placeholder.
                not_ok.add(step.name)
                result.steps.append(StepResult(
                    name=step.name, tool=step.tool, ok=False, output="",
                    error=f"skipped: dependency {', '.join(blocked)} did not succeed"))
                continue
            if non_agent_capability_required():
                raise RuntimeError(
                    "workflow tool dispatch is unavailable while capability enforcement or an inherited grant is active"
                )
            args = self._interpolate(step.args, outputs)
            t0 = time.monotonic()
            try:
                # Not routed through the full tool_authz gate. This is a library
                # API: the caller supplies the registry, so its tools need not
                # appear in the deployment's risk classifier, and applying the
                # flow gate here would reject every in-process registry rather
                # than protect anything. This remains a library-only API; its
                # capability-on refusal above prevents executing without a
                # bound grant. It is safe to omit the other gates only
                # because nothing in production calls Workflow.run -- and that
                # is not left to a comment: maverick.dispatch_contract asserts
                # the absence of a production caller and fails the build the
                # moment one appears, at which point this must be gated.
                raw = _drive(registry.run(step.tool, args))
                from .tool_results import tool_result_failed

                ok = not tool_result_failed(raw)
                err = "" if ok else str(raw)
            except Exception as e:
                raw = ""
                ok = False
                err = f"{type(e).__name__}: {e}"
            elapsed_ms = (time.monotonic() - t0) * 1000
            sr = StepResult(
                name=step.name, tool=step.tool, ok=ok,
                output=str(raw or ""), error=err, elapsed_ms=elapsed_ms,
            )
            result.steps.append(sr)
            if not ok:
                result.failed = True
                not_ok.add(step.name)
                log.warning("workflow step %s failed: %s", step.name, err)
                if stop_on_error:
                    break
                # Don't expose a failed step's (empty) output: its dependents
                # are skipped above rather than run on the raw placeholder.
                continue
            outputs[step.name] = sr.output
        return result


def _drive(coro):
    """Run an awaitable to completion from a SYNC caller, whether or not
    an event loop is already running on this thread.

    ``asyncio.run`` raises "cannot be called from a running event loop"
    when invoked from inside async code (the agent kernel runs in a
    loop). When a loop is already running we off-load the coroutine to a
    dedicated thread with its own loop and block for the result; the
    short-lived thread keeps the workflow callable from both sync and
    async contexts.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(copy_context().run, asyncio.run, coro).result()


__all__ = [
    "Step", "StepResult", "Workflow", "WorkflowResult", "WorkflowCycle",
]
