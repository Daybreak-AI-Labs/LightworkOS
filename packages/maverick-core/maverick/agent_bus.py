"""Cross-agent message bus.

Lets agents in the same swarm communicate outside the parent/child
spawn relationship. Parent-child handoff is already covered by the
spawn tool's return value; this bus is for cousins / peers / debate
patterns where two agents at the same depth need to exchange info.

Storage: per-process in-memory queues, one per ``(namespace, agent_id)``.
The namespace is an opaque, per-swarm routing capability: agents in two
concurrent runs can use the same display id without sharing an inbox. Reads are
blocking with timeout. Writes never block. Audit-logged for the goal so the
trace shows who-told-what-to-whom.

This is intentionally tiny. Just enough plumbing to enable a few
coordination patterns (debate, supervisor-watch, cross-task negotiation)
without committing to a heavier message-passing framework.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class Message:
    sender: str
    recipient: str
    payload: Any
    ts: float = field(default_factory=time.time)
    correlation_id: str | None = None  # threads request/response
    namespace: str | None = None


class _Inbox(queue.Queue[Message]):
    """Queue plus a per-recipient audit/admission lock.

    Producers serialize only with other producers for this inbox. That lets a
    strict audit refusal happen before a message becomes visible without
    serializing unrelated recipients or holding Queue's internal mutex during
    filesystem I/O.
    """

    def __init__(self) -> None:
        super().__init__(maxsize=1000)
        self.send_lock = threading.Lock()


# Legacy callers that do not provide a namespace retain their historical string
# keys (some integration tests intentionally inspect ``_inboxes``). Hardened
# SwarmContext callers use ``(namespace, agent_id)`` keys.
_InboxKey = str | tuple[str, str]
_inboxes: dict[_InboxKey, _Inbox] = {}
_inboxes_lock = threading.Lock()

# An inbox is created lazily for any agent/recipient id that send/recv/peek
# touches and is never removed by the agents themselves. In a long-running
# process (e.g. `maverick serve`) every goal mints fresh per-run agent ids, and
# `send_to_agent` lets the model address arbitrary never-existing recipients,
# so without a bound `_inboxes` grows one Queue per distinct id for the whole
# process lifetime. Before admitting a new inbox, evict EMPTY inboxes
# (an empty queue holds no undelivered messages, so dropping it loses nothing —
# a later touch just re-creates it). If every inbox is non-empty, refuse the new
# recipient so pending messages are preserved and the cap is never exceeded.
try:
    _MAX_INBOXES = max(64, int(os.environ.get("MAVERICK_AGENT_BUS_MAX_INBOXES", "4096") or "4096"))
except ValueError:
    _MAX_INBOXES = 4096


def _inbox_key(agent_id: str, namespace: str | None) -> _InboxKey:
    return agent_id if namespace is None else (namespace, agent_id)


def _evict_empty_inboxes_locked(*, reserve: int = 0) -> None:
    """Make room under the hard cap. Caller holds ``_inboxes_lock``.

    ``reserve=1`` is used before creating a new queue, so at least one slot must
    be free. Non-empty queues are deliberately never evicted.
    """
    target = max(0, _MAX_INBOXES - max(0, reserve))
    if len(_inboxes) <= target:
        return
    for key in [key for key, q in _inboxes.items() if q.empty()]:
        del _inboxes[key]
        if len(_inboxes) <= target:
            break


def _get_inbox(
    agent_id: str,
    *,
    namespace: str | None = None,
) -> _Inbox | None:
    """Get-or-create an inbox, or return ``None`` when the registry is full."""
    key = _inbox_key(agent_id, namespace)
    with _inboxes_lock:
        q = _inboxes.get(key)
        if q is None:
            if len(_inboxes) >= _MAX_INBOXES:
                _evict_empty_inboxes_locked(reserve=1)
            if len(_inboxes) >= _MAX_INBOXES:
                return None
            q = _Inbox()
            _inboxes[key] = q
        return q


def send(
    sender: str,
    recipient: str,
    payload: Any,
    *,
    correlation_id: str | None = None,
    goal_id: int | None = None,
    namespace: str | None = None,
) -> bool:
    """Deliver a message to ``recipient``'s inbox. Non-blocking.

    Returns True on success. If the recipient's inbox is full, the
    message is dropped and a warning is logged.
    """
    msg = Message(
        sender=sender, recipient=recipient,
        payload=payload, correlation_id=correlation_id, namespace=namespace,
    )
    inbox = _get_inbox(recipient, namespace=namespace)
    if inbox is None:
        log.warning(
            "agent_bus: inbox registry full; refusing new recipient %s",
            recipient,
        )
        return False
    with inbox.send_lock:
        if inbox.full():
            log.warning("agent_bus: inbox full for %s; dropping message", recipient)
            return False
        # Audit before making the message visible. Ordinary writer outages
        # remain fail-soft; a configured compliance/custody refusal prevents
        # delivery instead of allowing an unrecorded action then raising.
        from .audit import audit_event

        audit_event(
            "agent_message",
            agent=sender, goal_id=goal_id,
            recipient=recipient,
            correlation_id=correlation_id,
        )
        try:
            # Every producer for this inbox holds send_lock, while consumers can
            # only free capacity, so this cannot become full after the check.
            inbox.put_nowait(msg)
        except queue.Full:  # pragma: no cover -- defensive Queue invariant
            log.error("agent_bus: inbox capacity changed under producer lock")
            return False
    return True


def recv(
    agent_id: str,
    *,
    timeout: float = 0.0,
    correlation_id: str | None = None,
    namespace: str | None = None,
) -> Message | None:
    """Pull one message from ``agent_id``'s inbox.

    ``timeout`` 0 = non-blocking. >0 = block up to that many seconds.
    If ``correlation_id`` is given, filters for that id; non-matching
    messages are re-queued.
    """
    inbox = _get_inbox(agent_id, namespace=namespace)
    if inbox is None:
        return None
    if correlation_id is None:
        try:
            return inbox.get(block=timeout > 0, timeout=max(0.0, timeout))
        except queue.Empty:
            return None

    # monotonic: this is an elapsed-time deadline, so a wall-clock NTP/DST jump
    # mustn't make recv block past (or return before) the requested timeout.
    deadline = time.monotonic() + max(0.0, timeout)

    # Scan the queue in place while holding Queue's mutex instead of pulling
    # non-matching messages into an unbounded side buffer. This preserves FIFO
    # for skipped messages, avoids temporary capacity expansion under producer
    # floods, and lets the explicit deadline check below cap total wait time
    # even when non-matching messages keep arriving.
    with inbox.not_empty:
        while True:
            for idx, msg in enumerate(inbox.queue):
                if msg.correlation_id == correlation_id:
                    del inbox.queue[idx]
                    inbox.not_full.notify()
                    return msg

            now = time.monotonic()
            if timeout <= 0 or now >= deadline:
                return None

            inbox.not_empty.wait(deadline - now)


def peek(agent_id: str, *, namespace: str | None = None) -> int:
    """Count messages waiting in ``agent_id``'s inbox."""
    inbox = _get_inbox(agent_id, namespace=namespace)
    return 0 if inbox is None else inbox.qsize()


def clear(agent_id: str | None = None, *, namespace: str | None = None) -> None:
    """Drop messages.

    With no arguments this clears the process registry (test/operator reset).
    With ``namespace`` it clears only that swarm, optionally narrowed to one
    agent. An ``agent_id`` without a namespace addresses the legacy namespace.
    """
    with _inboxes_lock:
        if agent_id is None and namespace is None:
            _inboxes.clear()
            return
        if namespace is None:
            _inboxes.pop(agent_id, None)
            return
        if agent_id is not None:
            _inboxes.pop(_inbox_key(agent_id, namespace), None)
            return
        for key in [
            key for key in _inboxes
            if isinstance(key, tuple) and key[0] == namespace
        ]:
            del _inboxes[key]


__all__ = ["Message", "send", "recv", "peek", "clear"]
