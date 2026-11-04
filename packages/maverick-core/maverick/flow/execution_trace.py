"""Thread-safe per-node trace and outcome recording for live flow runs."""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from . import node_outcomes
from .ir import FlowNode


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
            with self._lock:
                self._durations[node_id] = self._durations.get(node_id, 0.0) + elapsed

    def on_node(self, node: FlowNode, status: str, outcome: float | None) -> None:
        if self.execution_guard is not None:
            self.execution_guard()
        with self._lock:
            entry: dict = {"status": status, "outcome": outcome}
            if node.id in self._durations:
                entry["seconds"] = round(self._durations[node.id], 3)
            self.states[node.id] = entry
        if outcome is not None and self.record_outcomes:
            node_outcomes.record(
                self.flow_id, node.id, node.kind, outcome,
                revision=self.revision, cohort=self.cohort,
            )
