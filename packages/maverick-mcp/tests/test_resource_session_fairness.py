"""A caller's session churn must evict its own subscriptions first."""
from collections import OrderedDict

import pytest
from maverick_mcp.http_sessions import (
    _caller_scope,
    _MCPAuthorization,
    _mint_session_id,
    _resource_session_id,
    _store_session,
)


@pytest.mark.parametrize("capacity", [2, 64])
def test_caller_session_churn_preserves_other_callers_subscriptions(capacity):
    sessions = OrderedDict()
    victim = _caller_scope(_MCPAuthorization("alice", "alice", None, "agent", "a"))
    churner = _caller_scope(_MCPAuthorization("bob", "bob", None, "agent", "b"))
    victim_sid = _mint_session_id(victim)
    _store_session(sessions, victim_sid, victim, {"maverick://goals"}, max_sessions=capacity)
    issued = []
    for _ in range(2 * capacity):
        sid = _mint_session_id(churner)
        _store_session(sessions, sid, churner, {"maverick://skills"}, max_sessions=capacity)
        issued.append(sid)
    assert _resource_session_id(victim_sid, sessions, victim) == victim_sid
    assert sessions[victim_sid].subscriptions == {"maverick://goals"}
    assert len(sessions) <= capacity
    retained = [sid for sid, row in sessions.items() if row.caller_scope == churner]
    assert retained == issued[-min(32, capacity - 1):]
