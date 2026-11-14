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


@pytest.mark.parametrize("capacity", [64])
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
    assert retained == issued[-32:]


def _scope(name):
    return _caller_scope(_MCPAuthorization(name, name, None, "agent", name))


def test_full_store_leaves_overflow_to_global_lru_not_the_new_caller():
    sessions = OrderedDict()
    a, b, c = _scope("a"), _scope("b"), _scope("c")
    for _ in range(32):
        for caller in (a, b):
            _store_session(sessions, _mint_session_id(caller), caller, {"r"}, max_sessions=64)
    oldest_a = next(iter(sessions))
    c_sids = [_mint_session_id(c) for _ in range(3)]
    for sid in c_sids:
        _store_session(sessions, sid, c, {"r"}, max_sessions=64)
    assert [sid in sessions for sid in c_sids] == [True, True, True]
    assert oldest_a not in sessions
    assert len(sessions) == 64


def test_flooding_caller_cannot_push_other_callers_below_global_share():
    sessions = OrderedDict()
    holders = [_scope(f"holder{i}") for i in range(4)]
    held = {}
    for holder in holders:
        held[holder] = [_mint_session_id(holder) for _ in range(8)]
        for sid in held[holder]:
            _store_session(sessions, sid, holder, {"r"}, max_sessions=64)
    flooder = _scope("flooder")
    for _ in range(500):
        _store_session(sessions, _mint_session_id(flooder), flooder, {"r"}, max_sessions=64)
    for holder in holders:
        assert all(sid in sessions for sid in held[holder])
    assert sum(row.caller_scope == flooder for row in sessions.values()) == 32
    assert len(sessions) <= 64


def test_global_cap_still_enforced_across_many_callers():
    sessions = OrderedDict()
    for i in range(200):
        caller = _scope(f"caller{i}")
        _store_session(sessions, _mint_session_id(caller), caller, {"r"}, max_sessions=64)
    assert len(sessions) == 64
