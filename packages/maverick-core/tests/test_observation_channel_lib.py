"""Multi-agent observation channel: broadcast pub/sub + blackboard tee."""
from __future__ import annotations

from maverick import observation_channel as oc
from maverick.blackboard import Blackboard


def _fresh():
    oc.reset_shared()
    return oc.shared()


def test_subscriber_receives_published_events():
    ch = oc.ObservationChannel()
    sub = ch.subscribe()
    ch.publish("tool_call", "coder", "ran read_file")
    ch.publish("verdict", "verifier", "accept")
    events = sub.drain()
    assert [e.kind for e in events] == ["tool_call", "verdict"]
    assert events[0].agent == "coder" and events[0].content == "ran read_file"
    assert sub.drain() == []  # drained


def test_broadcast_each_subscriber_gets_all():
    ch = oc.ObservationChannel()
    a, b = ch.subscribe(), ch.subscribe()
    ch.publish("e", "x", "1")
    assert len(a.drain()) == 1 and len(b.drain()) == 1


def test_only_events_after_subscribe():
    ch = oc.ObservationChannel()
    ch.publish("before", "x")
    sub = ch.subscribe()
    ch.publish("after", "x")
    assert [e.kind for e in sub.drain()] == ["after"]


def test_no_op_when_no_subscribers():
    ch = oc.ObservationChannel()
    assert ch.has_subscribers() is False
    ch.maybe_publish("e", "x")  # must not raise / nothing buffered
    sub = ch.subscribe()
    ch.maybe_publish("e2", "x")
    assert [e.kind for e in sub.drain()] == ["e2"]


def test_slow_subscriber_drops_oldest_not_blocks():
    ch = oc.ObservationChannel()
    sub = ch.subscribe(capacity=3)
    for i in range(10):
        ch.publish("e", "x", str(i))
    drained = sub.drain()
    assert len(drained) == 3                       # bounded
    assert [e.content for e in drained] == ["7", "8", "9"]  # newest kept


def test_close_unsubscribes():
    ch = oc.ObservationChannel()
    sub = ch.subscribe()
    assert ch.subscriber_count() == 1
    sub.close()
    assert ch.subscriber_count() == 0
    ch.publish("e", "x")  # no longer delivered anywhere


def test_context_manager_closes():
    ch = oc.ObservationChannel()
    with ch.subscribe() as sub:
        ch.publish("e", "x")
        assert sub.pending() == 1
    assert ch.subscriber_count() == 0


def test_module_shared_and_reset():
    ch = _fresh()
    assert ch is oc.shared()
    oc.reset_shared()
    assert oc.shared() is not ch


# ---- blackboard tee ----

def test_blackboard_post_tees_to_observers():
    _fresh()
    sub = oc.subscribe()
    bb = Blackboard()
    bb.post("coder", "status", "working on it")
    events = sub.drain()
    assert len(events) == 1
    assert events[0].kind == "status" and events[0].agent == "coder"
    assert events[0].content == "working on it"
    oc.reset_shared()


def test_blackboard_post_noop_without_observers():
    _fresh()
    bb = Blackboard()
    # No subscriber -> tee is a no-op; post still works (entry recorded).
    bb.post("coder", "status", "x")
    assert oc.shared().has_subscribers() is False
    assert any(e.content == "x" for e in bb.entries)
