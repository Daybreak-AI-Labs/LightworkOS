"""Tests for the cross-agent message bus (maverick.agent_bus) and its tool."""
from __future__ import annotations

from unittest.mock import MagicMock

# ---------- cross-agent bus ----------

def test_agent_bus_send_and_recv():
    from maverick import agent_bus
    agent_bus.clear()
    ok = agent_bus.send("alice", "bob", {"hello": 1})
    assert ok
    msg = agent_bus.recv("bob")
    assert msg is not None
    assert msg.sender == "alice"
    assert msg.payload == {"hello": 1}
    # Inbox now empty.
    assert agent_bus.recv("bob") is None


def test_agent_bus_recv_with_timeout():
    from maverick import agent_bus
    agent_bus.clear()
    import threading
    import time

    def _send_later():
        time.sleep(0.05)
        agent_bus.send("alice", "bob", "later")

    threading.Thread(target=_send_later, daemon=True).start()
    msg = agent_bus.recv("bob", timeout=1.0)
    assert msg is not None
    assert msg.payload == "later"


def test_agent_bus_correlation_id_filter():
    from maverick import agent_bus
    agent_bus.clear()
    agent_bus.send("alice", "bob", "wrong", correlation_id="x1")
    agent_bus.send("alice", "bob", "right", correlation_id="x2")
    msg = agent_bus.recv("bob", correlation_id="x2", timeout=0.5)
    assert msg is not None
    assert msg.payload == "right"


def test_agent_bus_correlation_filter_preserves_nonmatching_in_order():
    # A correlated recv must not DROP or REORDER the non-matching
    # messages it skips over. The match sits behind two non-matching ones.
    from maverick import agent_bus
    agent_bus.clear()
    agent_bus.send("a", "bob", "n1", correlation_id="other")
    agent_bus.send("a", "bob", "hit", correlation_id="want")
    agent_bus.send("a", "bob", "n2", correlation_id="other")
    agent_bus.send("a", "bob", "n3", correlation_id="other")

    got = agent_bus.recv("bob", correlation_id="want", timeout=0.5)
    assert got is not None and got.payload == "hit"
    # The three non-matching messages survive, in original FIFO order.
    assert agent_bus.peek("bob") == 3
    rest = [agent_bus.recv("bob").payload for _ in range(3)]
    assert rest == ["n1", "n2", "n3"]


def test_agent_bus_correlation_no_match_keeps_all():
    # No message matches -> recv returns None and nothing is lost/reordered.
    from maverick import agent_bus
    agent_bus.clear()
    for i in range(3):
        agent_bus.send("a", "bob", f"m{i}", correlation_id="nope")
    assert agent_bus.recv("bob", correlation_id="absent", timeout=0.2) is None
    assert agent_bus.peek("bob") == 3
    assert [agent_bus.recv("bob").payload for _ in range(3)] == ["m0", "m1", "m2"]


def test_agent_bus_correlation_filter_no_drop_when_inbox_full():
    # Re-queueing via put_nowait into a full inbox would silently drop
    # messages. Fill the inbox to capacity with non-matching messages
    # plus one match; the held-buffer restore must not lose any.
    from maverick import agent_bus
    agent_bus.clear()
    cap = 4
    ib = agent_bus._Inbox()
    ib.maxsize = cap
    agent_bus._inboxes["bob"] = ib
    ib.put_nowait(agent_bus.Message(sender="a", recipient="bob", payload="n1", correlation_id="o"))
    ib.put_nowait(agent_bus.Message(sender="a", recipient="bob", payload="n2", correlation_id="o"))
    ib.put_nowait(agent_bus.Message(sender="a", recipient="bob", payload="hit", correlation_id="w"))
    ib.put_nowait(agent_bus.Message(sender="a", recipient="bob", payload="n3", correlation_id="o"))
    assert ib.full()

    got = agent_bus.recv("bob", correlation_id="w")
    assert got is not None and got.payload == "hit"
    # All three non-matching messages preserved (none dropped on restore).
    assert agent_bus.peek("bob") == 3
    assert [agent_bus.recv("bob").payload for _ in range(3)] == ["n1", "n2", "n3"]


def test_agent_bus_correlation_timeout_not_extended_by_nonmatching_flood():
    # A correlated recv must honor its overall timeout even when producers keep
    # sending non-matching messages. It also must not use an out-of-queue held
    # buffer that lets more successful sends accumulate than the inbox can hold.
    import threading
    import time

    from maverick import agent_bus

    agent_bus.clear()
    cap = 16
    ib = agent_bus._Inbox()
    ib.maxsize = cap
    agent_bus._inboxes["bob"] = ib
    sent_ok = 0
    end = time.monotonic() + 0.25

    def _send_noise():
        nonlocal sent_ok
        i = 0
        while time.monotonic() < end:
            if agent_bus.send("noise", "bob", i, correlation_id="noise"):
                sent_ok += 1
            i += 1
            time.sleep(0.001)

    producer = threading.Thread(target=_send_noise)
    producer.start()

    start = time.monotonic()
    assert agent_bus.recv("bob", correlation_id="target", timeout=0.05) is None
    elapsed = time.monotonic() - start
    producer.join()

    assert elapsed < 0.15
    assert sent_ok <= cap
    assert agent_bus.peek("bob") == sent_ok


def test_agent_bus_peek():
    from maverick import agent_bus
    agent_bus.clear()
    assert agent_bus.peek("bob") == 0
    agent_bus.send("a", "bob", 1)
    agent_bus.send("a", "bob", 2)
    assert agent_bus.peek("bob") == 2


def test_agent_bus_inboxes_bounded_under_unique_recipient_flood(monkeypatch):
    """Regression: `_inboxes` must stay bounded over a long-running process.

    Each goal mints fresh per-run agent ids and the model can address arbitrary
    recipients, so without eviction the registry grew one Queue per distinct id
    forever. Empty inboxes carry no undelivered messages, so they may be evicted
    once over the cap.
    """
    from maverick import agent_bus
    agent_bus.clear()
    monkeypatch.setattr(agent_bus, "_MAX_INBOXES", 64)
    # Each send is to a unique never-recurring recipient that nobody drains, but
    # the message is immediately consumed below so the inbox goes empty and is
    # eligible for eviction. Simulate the realistic case: peek (touch) many ids.
    for i in range(10_000):
        agent_bus.peek(f"ephemeral-{i}")  # creates an empty inbox per id
    # Empty inboxes are evicted once over the cap, so the live set stays near
    # the cap rather than growing to O(ids).
    assert len(agent_bus._inboxes) <= agent_bus._MAX_INBOXES


def test_agent_bus_hard_cap_refuses_nonempty_unique_recipient_flood(monkeypatch):
    """Non-empty queues are preserved, but may not grow the registry past cap."""
    from maverick import agent_bus

    agent_bus.clear()
    monkeypatch.setattr(agent_bus, "_MAX_INBOXES", 8)
    for i in range(8):
        assert agent_bus.send("sender", f"recipient-{i}", f"message-{i}")

    assert not agent_bus.send("sender", "recipient-over-cap", "blocked")
    assert len(agent_bus._inboxes) == 8
    first = agent_bus.recv("recipient-0")
    assert first is not None and first.payload == "message-0"


def test_agent_bus_eviction_keeps_nonempty_inboxes(monkeypatch):
    """A pending (non-empty) inbox is never silently dropped by eviction."""
    from maverick import agent_bus
    agent_bus.clear()
    monkeypatch.setattr(agent_bus, "_MAX_INBOXES", 8)
    agent_bus.send("a", "keepme", {"important": True})  # non-empty inbox
    for i in range(100):
        agent_bus.peek(f"empty-{i}")  # flood with evictable empty inboxes
    assert "keepme" in agent_bus._inboxes
    msg = agent_bus.recv("keepme")
    assert msg is not None and msg.payload == {"important": True}


def test_agent_bus_tools_round_trip():
    """send_to_agent then recv_from_agent (bound to the recipient) returns
    the payload; both tools register in a ToolRegistry."""
    import asyncio

    from maverick import agent_bus
    from maverick.tools import ToolRegistry
    from maverick.tools.agent_bus_tool import recv_from_agent, send_to_agent

    agent_bus.clear()
    reg = ToolRegistry()
    reg.register(send_to_agent("alice"))   # alice is sender
    reg.register(recv_from_agent("bob"))   # bob drains its own inbox
    names = {t.name for t in reg.all()}
    assert "send_to_agent" in names
    assert "recv_from_agent" in names

    sent = asyncio.run(reg.run("send_to_agent", {"to_id": "bob", "payload": {"hi": 1}}))
    assert "sent to 'bob'" in sent
    got = asyncio.run(reg.run("recv_from_agent", {}))
    assert "alice" in got
    assert "{'hi': 1}" in got
    # Inbox now empty.
    assert "(no messages)" in asyncio.run(reg.run("recv_from_agent", {}))


def test_agent_bus_send_tool_requires_args():
    from maverick.tools.agent_bus_tool import send_to_agent
    tool = send_to_agent("alice")
    assert "to_id is required" in tool.fn({"payload": "x"})
    assert "payload is required" in tool.fn({"to_id": "bob"})


def test_agent_bus_recv_tool_bounds_timeout(monkeypatch):
    import asyncio

    from maverick.tools.agent_bus_tool import MAX_RECV_TIMEOUT_SECONDS, recv_from_agent

    observed: dict[str, float] = {}

    def fake_recv(agent_id: str, *, timeout: float = 0.0, correlation_id=None):
        observed["agent_id"] = agent_id
        observed["timeout"] = timeout
        return None

    monkeypatch.setattr("maverick.tools.agent_bus_tool.agent_bus.recv", fake_recv)
    tool = recv_from_agent("bob")

    assert tool.input_schema["properties"]["timeout"]["maximum"] == MAX_RECV_TIMEOUT_SECONDS
    assert "(no messages)" in asyncio.run(tool.fn({"timeout": 31_536_000}))
    assert observed == {"agent_id": "bob", "timeout": MAX_RECV_TIMEOUT_SECONDS}


def test_agent_bus_recv_tool_rejects_non_finite_timeout(monkeypatch):
    import asyncio

    from maverick.tools.agent_bus_tool import recv_from_agent

    recv = MagicMock(return_value=None)
    monkeypatch.setattr("maverick.tools.agent_bus_tool.agent_bus.recv", recv)

    assert "timeout must be a finite number" in asyncio.run(
        recv_from_agent("bob").fn({"timeout": "inf"})
    )
    recv.assert_not_called()


def test_agent_bus_recv_tool_does_not_block_event_loop():
    """A blocking recv must not stall other coroutines on the same loop.

    recv_from_agent offloads agent_bus.recv (a blocking threading.Queue wait)
    to a worker thread, so a concurrent task keeps making progress while a
    recv with a timeout is parked waiting for a message.
    """
    import asyncio
    import time

    from maverick import agent_bus
    from maverick.tools.agent_bus_tool import recv_from_agent

    agent_bus.clear()
    tool = recv_from_agent("bob")

    async def _drive():
        ticks = 0

        async def _ticker():
            nonlocal ticks
            for _ in range(20):
                ticks += 1
                await asyncio.sleep(0.01)

        ticker = asyncio.create_task(_ticker())
        # recv blocks ~0.3s waiting on an empty inbox; the ticker must keep
        # advancing during that wait if recv is truly off the event loop.
        start = time.monotonic()
        out = await tool.fn({"timeout": 0.3})
        elapsed = time.monotonic() - start
        await ticker
        return out, ticks, elapsed

    out, ticks, elapsed = asyncio.run(_drive())
    assert "(no messages)" in out
    assert elapsed >= 0.25  # actually waited (didn't return early)
    assert ticks >= 5       # the loop kept running concurrently during the wait
