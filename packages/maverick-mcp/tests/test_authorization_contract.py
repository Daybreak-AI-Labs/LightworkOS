"""MCP policy decisions preserve caller identity and fail closed."""
from types import SimpleNamespace

import pytest
from maverick_mcp.authorization import (
    capability_permits,
    connector_principal,
    credential_fingerprint,
    principal_permits,
    refresh_task_capability,
    task_authorizer,
    task_execution_context,
)
from maverick_mcp.protocol import ProtocolError


def test_connector_transport_principal_cannot_alias_a_local_user():
    assert connector_principal("user:alice", None, None) == "agent:user:alice"
    assert connector_principal(None, None, SimpleNamespace(principal="user:alice")) == "user:alice"
    assert connector_principal(None, None, None) is None


def test_capability_and_principal_refuse_when_revocation_check_fails(monkeypatch):
    def unavailable(*args):
        raise RuntimeError("revocation unavailable")

    monkeypatch.setattr("maverick.revocation.revoked_principal", unavailable)
    capability = SimpleNamespace(principal="agent:alice", permits=lambda name: True)
    assert capability_permits(capability, "maverick_status") is False
    assert principal_permits("alice") is False


def test_task_creation_requires_refreshable_http_credential_identity():
    with pytest.raises(ProtocolError, match="incomplete task authorization context"):
        task_execution_context(caller_identity="alice", trust_principal="alice",
                               credential_kind="agent", credential_fingerprint=None,
                               capability=None)
    context = task_execution_context(caller_identity="alice", trust_principal="alice",
                                     credential_kind="agent", credential_fingerprint="fingerprint",
                                     capability=None)
    assert context.trust_principal == "alice"
    assert context.credential_fingerprint == "fingerprint"


def test_queued_task_rechecks_rotated_shared_credential(monkeypatch):
    from maverick import agent_trust

    denied = []
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (False, {}))
    monkeypatch.setattr(agent_trust, "decide_inbound", lambda *args, **kwargs:
                        SimpleNamespace(denied=False, capability=None))
    monkeypatch.setattr(agent_trust, "record_denied", lambda *args, **kwargs: denied.append(kwargs))
    context = task_execution_context(
        caller_identity="", trust_principal="mcp", credential_kind="shared",
        credential_fingerprint=credential_fingerprint("old"), capability=None,
    )
    with pytest.raises(PermissionError, match="no longer valid"):
        refresh_task_capability(context, setting=lambda *_args: "new", fingerprint=credential_fingerprint)
    assert denied[0]["rule"] == "credential_rotated"


def test_queued_task_cannot_gain_new_capabilities(monkeypatch):
    from maverick import agent_trust

    current = object()
    intersections = []
    frozen = SimpleNamespace(principal="agent:alice", intersect=lambda capability, **kwargs:
                             intersections.append((capability, kwargs)) or "narrowed")
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (
        True, {"alice": SimpleNamespace(mcp_token="secret")},
    ))
    monkeypatch.setattr(agent_trust, "decide_inbound", lambda *args, **kwargs:
                        SimpleNamespace(denied=False, capability=current))
    context = task_execution_context(
        caller_identity="alice", trust_principal="alice", credential_kind="agent",
        credential_fingerprint=credential_fingerprint("secret"), capability=frozen,
    )
    assert refresh_task_capability(context, setting=lambda *_args: "", fingerprint=credential_fingerprint) == "narrowed"
    assert intersections == [(current, {"principal": "agent:alice"})]


def test_waiting_task_is_reauthorized_and_denial_is_recorded():
    denied = []
    context = task_execution_context(
        caller_identity="alice", trust_principal="alice", credential_kind="agent",
        credential_fingerprint="fingerprint", capability="old",
    )
    current = ["narrowed"]
    authorize = task_authorizer(
        "old", "alice", "alice", audit_denial=True, refresh_context=context,
        refresh_capability=lambda _context: current[0],
        record_denial=lambda *args: denied.append(args),
        principal_check=lambda _principal: True,
        capability_check=lambda capability, _tool: capability == "narrowed",
    )
    assert authorize("maverick_status") is True
    current[0] = "revoked"
    assert authorize("maverick_status") is False
    assert denied == [("revoked", "alice", "maverick_status")]
