"""The run heartbeat carries tenant scope and stops with the run."""
from __future__ import annotations

import contextvars
import threading
import time

from maverick.goal_heartbeat import start_goal_heartbeat


def test_heartbeat_copies_tenant_context_and_stops():
    tenant = contextvars.ContextVar("heartbeat-test-tenant")
    seen = threading.Event()
    calls = []

    class World:
        def touch_goal(self, goal_id):
            calls.append((goal_id, tenant.get(None)))
            seen.set()
            return True

    token = tenant.set("client-a")
    try:
        stop = start_goal_heartbeat(World(), 42, interval=0.01)
    finally:
        tenant.reset(token)
    try:
        assert seen.wait(2.0)
        assert calls[0] == (42, "client-a")
    finally:
        stop()
    count = len(calls)
    time.sleep(0.05)
    assert len(calls) == count
