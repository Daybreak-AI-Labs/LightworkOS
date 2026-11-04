"""Latency-budget propagation across spans."""
from __future__ import annotations

from maverick.latency_span_budget import SpanBudget


def test_consume_and_remaining():
    b = SpanBudget(500)
    assert b.remaining() == 500
    b.consume(200)
    assert b.remaining() == 300
    assert not b.exhausted()


def test_exhaustion_clamps_at_zero():
    b = SpanBudget(100)
    b.consume(150)  # over-spend
    assert b.remaining() == 0.0
    assert b.exhausted()


def test_child_draws_from_parent_pool():
    root = SpanBudget(1000)
    child = root.child(400)
    child.consume(400)
    assert child.remaining() == 0.0
    assert root.remaining() == 600  # parent debited by child's spend


def test_child_cannot_exceed_remaining():
    root = SpanBudget(300)
    root.consume(250)
    child = root.child(500)  # asks more than the 50 left
    assert child.total_ms == 50


def test_child_none_takes_all_remaining():
    root = SpanBudget(300)
    root.consume(100)
    child = root.child()
    assert child.total_ms == 200


def test_nested_spans_share_pool():
    root = SpanBudget(1000)
    a = root.child()
    b = a.child()
    b.consume(700)
    assert root.remaining() == 300
    assert a.remaining() == 300
