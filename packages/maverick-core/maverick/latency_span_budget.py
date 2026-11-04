"""Latency-budget propagation across spans.

A request can carry an end-to-end wall-clock budget that must be *shared* across
the nested work it spawns (LLM calls, tool calls, sub-spans). ``SpanBudget``
models that: the root holds the total, each child ``consume(elapsed_ms)`` debits
it, and ``remaining()`` / ``exhausted()`` tell a caller whether there's time left
to start more work. ``child()`` derives a sub-budget that draws from the same pool
so a deep call tree can't collectively overspend.

Pure and dependency-free (unit-tested). When the optional OpenTelemetry tagging
helper is used, it stamps the remaining budget on the current span; absent OTel
it's a no-op.
"""
from __future__ import annotations


class SpanBudget:
    """A shared wall-clock budget (ms) drawn down by nested spans."""

    def __init__(self, total_ms: float, *, parent: SpanBudget | None = None):
        self.total_ms = max(0.0, float(total_ms))
        self._spent = 0.0
        self._parent = parent

    def consume(self, elapsed_ms: float) -> float:
        """Debit ``elapsed_ms`` (and the parent's pool); return remaining ms."""
        amt = max(0.0, float(elapsed_ms or 0.0))
        self._spent += amt
        if self._parent is not None:
            self._parent.consume(amt)
        return self.remaining()

    def remaining(self) -> float:
        return max(0.0, self.total_ms - self._spent)

    def exhausted(self) -> bool:
        return self.remaining() <= 0.0

    def child(self, budget_ms: float | None = None) -> SpanBudget:
        """Derive a sub-budget bounded by what's left (drains the same pool).

        A child may request less than the remaining budget, but never more —
        ``budget_ms=None`` gives it the full remaining amount.
        """
        avail = self.remaining()
        want = avail if budget_ms is None else min(avail, max(0.0, float(budget_ms)))
        return SpanBudget(want, parent=self)


def tag_span_budget(budget: SpanBudget) -> bool:
    """Stamp the remaining budget on the current OTel span. No-op without OTel.

    Returns True if a span was tagged.
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return False
    span = trace.get_current_span()
    if span is None:  # pragma: no cover -- defensive
        return False
    try:
        span.set_attribute("latency.remaining_budget_ms", round(budget.remaining(), 3))
        return True
    except Exception:  # pragma: no cover -- exporter quirks
        return False


__all__ = ["SpanBudget", "tag_span_budget"]
