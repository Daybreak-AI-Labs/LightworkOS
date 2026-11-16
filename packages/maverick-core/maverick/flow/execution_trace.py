"""Thread-safe per-node trace and outcome recording for live flow runs."""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from . import node_outcomes
from .ir import FlowNode

# Where the running chain sits inside the flow: "" for the flow's own steps,
# "<container id>/" (repeated per level, with the lane number under a parallel
# step) for a nested body, branch or subflow. Nested graphs have their own id
# space, so a bare id would record a nested step as the top-level step that
# happens to share it. A ContextVar so the runner's telemetry contract stays
# ``on_node(node, status, outcome)``; parallel lanes run in a copied context.
_scope: ContextVar[str] = ContextVar("_flow_node_scope", default="")


@contextmanager
def node_scope(scope: str) -> Iterator[None]:
    """Trace the steps run inside this block under ``scope``."""
    token = _scope.set(scope)
    try:
        yield
    finally:
        _scope.reset(token)


def scoped_id(node_id: str) -> str:
    """``node_id`` qualified by the nesting it is running in; unchanged at top level."""
    return _scope.get() + node_id


class ExecutionTrace:
    """Collect timing and node state without losing parallel-branch updates."""

    def __init__(self, *, flow_id: str, revision: str, cohort: str,
                 initial_states: dict, record_outcomes: bool,
                 execution_guard: Callable[[], None] | None):
        self.flow_id = flow_id
        self.revision = revision
        self.cohort = cohort
        self.states = dict(initial_states)
        self.record_outcomes = record_outcomes
        self.execution_guard = execution_guard
        self._durations: dict[str, float] = {}
        self._lock = threading.Lock()

    def timed(self, node_id: str, fn: Callable[..., Any], *args: Any) -> Any:
        start = time.perf_counter()
        try:
            return fn(*args)
        finally:
            elapsed = time.perf_counter() - start
            key = scoped_id(node_id)
            with self._lock:
                self._durations[key] = self._durations.get(key, 0.0) + elapsed

    def on_node(self, node: FlowNode, status: str, outcome: float | None) -> None:
        if self.execution_guard is not None:
            self.execution_guard()
        key = scoped_id(node.id)
        with self._lock:
            entry: dict = {"status": status, "outcome": outcome}
            if key in self._durations:
                entry["seconds"] = round(self._durations[key], 3)
            self.states[key] = entry
        if outcome is not None and self.record_outcomes:
            node_outcomes.record(
                self.flow_id, key, node.kind, outcome,
                revision=self.revision, cohort=self.cohort,
            )
