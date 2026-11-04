"""HTTP sessions cannot transfer resource or task authority across callers."""
from collections import OrderedDict
from types import SimpleNamespace

from maverick_mcp.http_sessions import (
    _caller_scope,
    _MCPAuthorization,
    _mint_session_id,
    _quota_scope,
    _resource_session_id,
    _session_plan,
    _store_session,
    _supplied_session_id,
    _task_owner,
)


def _caller(name, credential):
    return _MCPAuthorization(name, name, None, "agent", credential)


def test_session_and_task_owner_are_bound_to_the_current_credential():
    alice = _caller("alice", "fingerprint-a")
    rotated = _caller("alice", "fingerprint-b")
    original_scope = _caller_scope(alice)
    rotated_scope = _caller_scope(rotated)
    sid = _mint_session_id(original_scope)
    request = SimpleNamespace(headers={"Mcp-Session-Id": sid}, cookies={})
    assert _supplied_session_id(request, original_scope) == sid
    assert _supplied_session_id(request, rotated_scope) is None
    assert _quota_scope(alice) == _quota_scope(rotated)
    assert _task_owner(sid, original_scope) != _task_owner(sid, rotated_scope)


def test_subscription_eviction_does_not_authorize_another_caller():
    sessions = OrderedDict()
    alice_scope = _caller_scope(_caller("alice", "a"))
    bob_scope = _caller_scope(_caller("bob", "b"))
    alice_sid = _mint_session_id(alice_scope)
    bob_sid = _mint_session_id(bob_scope)
    _store_session(sessions, alice_sid, alice_scope, {"maverick://goals"}, max_sessions=1)
    _store_session(sessions, alice_sid, bob_scope, {"maverick://skills"}, max_sessions=1)
    assert sessions[alice_sid].subscriptions == {"maverick://goals"}
    assert _resource_session_id(alice_sid, sessions, bob_scope) is None
    _store_session(sessions, bob_sid, bob_scope, {"maverick://skills"}, max_sessions=1)
    assert _resource_session_id(alice_sid, sessions, alice_scope) is None
    assert _resource_session_id(bob_sid, sessions, bob_scope) == bob_sid


def test_task_session_can_exist_without_persisting_subscriptions():
    scope = _caller_scope(_caller("alice", "a"))
    sid, resource_sid, persist, owner = _session_plan(
        supplied_sid=None, resource_sid=None, caller_scope=scope,
        method="tools/call", is_task_request=True,
    )
    assert sid is not None
    assert resource_sid is None
    assert persist is False
    assert owner == _task_owner(sid, scope)
