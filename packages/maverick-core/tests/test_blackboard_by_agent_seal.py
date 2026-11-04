"""by_agent() must withhold a sealed agent's posts atomically.

If by_agent() checked _is_sealed() OUTSIDE the lock and read the entries INSIDE
it, a concurrent seal() (e.g. from a FastAPI threadpool) could slip between the
check and the read and leak a just-sealed agent's posts. The check happens
under the same lock as the read.
"""
from __future__ import annotations

import threading

from maverick.blackboard import Blackboard
from maverick.quarantine import QuarantineRegistry


def test_by_agent_withholds_sealed_agent():
    bb = Blackboard()
    reg = QuarantineRegistry()
    bb.attach_quarantine(reg)
    bb.post("rogue", "observation", "secret finding")
    bb.post("good", "observation", "ok finding")
    assert bb.by_agent("rogue")  # visible before sealing
    reg.seal("rogue", "exfil attempt")
    assert bb.by_agent("rogue") == []          # sealed -> withheld wholesale
    assert len(bb.by_agent("good")) == 1       # other agents unaffected


def test_by_agent_withholds_during_concurrent_posts_after_seal():
    # Establish that seal() completed before any read, then hammer by_agent
    # while another thread keeps posting. A read that overlaps the initial seal
    # may legally linearize before it; comparing that result with a later,
    # separate is_sealed() call is a TOCTOU test bug rather than evidence of a
    # leak.
    bb = Blackboard()
    reg = QuarantineRegistry()
    bb.attach_quarantine(reg)
    stop = threading.Event()
    sealed = threading.Event()
    errors: list[Exception] = []

    def churn():
        i = 0
        try:
            bb.post("rogue", "observation", f"f{i}")
            reg.seal("rogue", "r")
            sealed.set()
            i += 1
        except Exception as e:  # pragma: no cover
            errors.append(e)
        while not stop.is_set():
            try:
                bb.post("rogue", "observation", f"f{i}")
                i += 1
            except Exception as e:  # pragma: no cover
                errors.append(e)

    writer = threading.Thread(target=churn, daemon=True)
    writer.start()
    try:
        assert sealed.wait(timeout=5), errors
        for _ in range(3000):
            assert bb.by_agent("rogue") == [], "sealed agent's posts leaked"
    finally:
        stop.set()
        writer.join(timeout=5)
    assert not writer.is_alive(), "concurrent poster did not stop"
    assert not errors, errors


def test_by_agent_checks_quarantine_while_holding_entry_lock():
    """Keep the seal check and entry snapshot in one blackboard critical section."""
    bb = Blackboard()
    lock_observations: list[bool] = []

    class ProbeRegistry:
        def is_sealed(self, _agent: str) -> bool:
            acquired = bb._lock.acquire(blocking=False)
            if acquired:
                bb._lock.release()
            lock_observations.append(not acquired)
            return False

    bb.attach_quarantine(ProbeRegistry())
    bb.post("rogue", "observation", "visible")

    assert len(bb.by_agent("rogue")) == 1
    assert lock_observations == [True]
