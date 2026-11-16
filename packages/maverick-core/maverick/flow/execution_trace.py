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
# "<container>/" (repeated per level, with the lane number under a parallel
# step) for a nested body, branch or subflow. Nested graphs have their own id
# space, so a bare id would record a nested step as the top-level step that
# happens to share it. A ContextVar so the runner's telemetry contract stays
# ``on_node(node, status, outcome)``; parallel lanes run in a copied context.
_scope: ContextVar[str] = ContextVar("_flow_node_scope", default="")

# A key is its path components joined by "/". Node ids are free text, so each
# component escapes the separator and the escape character: "~" becomes "~~"
# and "/" becomes "~s". A top-level step named "loop/a" is recorded as
# "loop~sa" and can never equal the path "loop/a" of a step "a" inside "loop".
# An id with neither character is recorded exactly as it is.


def trace_key(node_id: str) -> str:
    """The key a top-level step is recorded under: its id as one path component."""
    return node_id.replace("~", "~~").replace("/", "~s")


def trace_path(key: str) -> list[str]:
    """The ids a recorded key was built from, outermost first."""
    parts, current, index = [], [], 0
    while index < len(key):
        char = key[index]
        if char == "~" and index + 1 < len(key):
            current.append("/" if key[index + 1] == "s" else key[index + 1])
            index += 2
            continue
        if char == "/":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    return [*parts, "".join(current)]


def child_scope(scope: str, container_id: str, lane: str = "") -> str:
    """The scope of the steps nested under ``container_id`` (and one parallel lane)."""
    return f"{scope}{trace_key(container_id)}/" + (f"{trace_key(lane)}/" if lane else "")


@contextmanager
def node_scope(scope: str) -> Iterator[None]:
    """Trace the steps run inside this block under ``scope``."""
    token = _scope.set(scope)
    try:
        yield
    finally:
        _scope.reset(token)


def scoped_id(node_id: str) -> str:
    """The key of ``node_id`` in the nesting it is running in.

    At top level this is :func:`trace_key`, which leaves an ordinary id unchanged."""
    return _scope.get() + trace_key(node_id)


def trace_node(flow, key: str):
    """The step a recorded key names inside ``flow``, or ``None``.

    Walks loop bodies and parallel lanes; a step inside a saved subflow is not
    part of this flow's own definition."""
    path = trace_path(key)
    node = flow.nodes.get(path[0])
    index = 1
    while node is not None and index < len(path):
        if node.branches:
            lane = path[index]
            inner = node.branches[int(lane)] if lane.isdigit() and int(lane) < len(node.branches) else None
            index += 1
        else:
            inner = node.body
        if inner is None or index >= len(path):
            return None
        node = inner.nodes.get(path[index])
        index += 1
    return node


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
