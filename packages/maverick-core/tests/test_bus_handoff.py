"""Verified handoffs over the cross-agent bus (maverick.bus_handoff): a delegation
rides agent_bus as a signed Envelope, minted by the run's HandoffAuthority and
verified on receipt. The bridge must accept an authentic in-scope handoff (handing
back the attenuated grant) and reject tamper / replay / forged-issuer / expiry /
out-of-scope -- while leaving plain (non-handoff) bus traffic untouched."""
from __future__ import annotations

import time

import pytest
from maverick import agent_bus
from maverick.bus_handoff import HandoffAuthority, receive_handoff, send_handoff
from maverick.capability import Capability
from maverick.handoff import Envelope


def _have_crypto() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        return True
    except BaseException:  # absent OR a broken backend (sandbox pyo3 panic)
        return False


crypto = pytest.mark.skipif(not _have_crypto(), reason="cryptography unavailable")


@pytest.fixture(autouse=True)
def _clean_bus():
    agent_bus.clear()
    yield
    agent_bus.clear()


def _grant(principal="agent:worker-1", **kw) -> Capability:
    kw.setdefault("allow_tools", frozenset({"read_file", "knowledge_search"}))
    kw.setdefault("max_risk", "low")
    return Capability(principal=principal, **kw)


# --- crypto-free paths (run everywhere) ------------------------------------

def test_empty_inbox_returns_none():
    assert receive_handoff(None, "agent:nobody-9") is None


def test_plain_message_passes_through_unverified():
    agent_bus.send("agent:a-1", "agent:b-1", {"note": "hello"})
    d = receive_handoff(None, "agent:b-1")
    assert d is not None
    assert not d.is_handoff and d.verdict is None
    assert d.payload == {"note": "hello"} and d.sender == "agent:a-1"


def test_envelope_without_an_authority_is_rejected():
    # An Envelope on the bus but no run authority to anchor trust -> fail closed.
    env = Envelope(sender="agent:a-1", recipient="agent:b-1", task="t",
                   grant=_grant(), nonce="n1", ts=time.time())
    agent_bus.send("agent:a-1", "agent:b-1", env)
    d = receive_handoff(None, "agent:b-1")
    assert d is not None and d.is_handoff
    assert not d.ok and d.verdict.rule == "no_authority"


# --- signed round-trips (CI; needs cryptography) ---------------------------

@crypto
def test_verified_handoff_round_trips_and_returns_the_grant():
    auth = HandoffAuthority.for_run()
    grant = _grant(principal="agent:worker-1", allow_tools=frozenset({"read_file"}))
    nonce = send_handoff(auth, sender="agent:lead-0", recipient="agent:worker-1",
                         grant=grant, task="read the spec", required_tools=("read_file",))
    d = receive_handoff(auth, "agent:worker-1")
    assert d is not None and d.ok and d.verdict.rule == "ok"
    # the receiver runs under exactly the delegated grant
    assert d.grant is not None and d.grant.permits("read_file") and not d.grant.permits("shell")
    assert isinstance(nonce, str) and nonce


@crypto
def test_redelegation_preserves_verified_handoff_scope(monkeypatch):
    from maverick.agent import Agent
    from maverick.swarm import SwarmContext
    from maverick.tools.agent_bus_tool import delegate_to_agent

    ctx = SwarmContext(None, None, None, None, None, 7, 5, False)
    for name in ("lead", "alice", "bob"):
        ctx.register_bus_agent(name)
    authority = HandoffAuthority.for_run()
    monkeypatch.setattr("maverick.bus_handoff.authority_for", lambda _: authority)
    expires = time.time() + 300
    narrow = Capability(principal="alice", allow_tools=frozenset({"read_file"}),
                        allow_paths=frozenset({"allowed/*"}),
                        allow_hosts=frozenset({"example.com"}), expires_at=expires,
                        max_risk="low", ancestors=("lead",))
    send_handoff(authority, sender="lead", recipient="alice", grant=narrow,
                 task="read", namespace=ctx.bus_namespace)
    received = receive_handoff(authority, "alice", namespace=ctx.bus_namespace)
    assert received and received.ok

    class Sender:
        _effective_capability = Agent._effective_capability
        name = "alice"
        capability = Capability(principal="alice", allow_tools=frozenset({"read_file", "shell"}))
        _handoff_capability = received.grant

    sender = Sender()
    sender.ctx = ctx
    tool = delegate_to_agent(sender)
    assert tool.fn({"to_id": "bob", "task": "shell", "tools": ["shell"]}).startswith("ERROR:")
    assert agent_bus.peek("bob", namespace=ctx.bus_namespace) == 0
    for tools in (["read_file"], []):
        assert "SIGNED handoff" in tool.fn({"to_id": "bob", "task": "read", "tools": tools})
        delivery = receive_handoff(authority, "bob", namespace=ctx.bus_namespace)
        assert delivery and delivery.ok
        grant = delivery.grant
        assert grant.permits("read_file") and not grant.permits("shell")
        assert grant.allow_paths == frozenset({"allowed/*"})
        assert grant.allow_hosts == frozenset({"example.com"})
        assert grant.expires_at == expires
        assert grant.max_risk == "low"
        assert "lead" in grant.revocation_principals()

    sender._handoff_capability = Capability(principal="alice", expires_at=time.time() - 1)
    assert tool.fn({"to_id": "bob", "task": "read"}).startswith("ERROR:")
    sender._handoff_capability = Capability(principal="alice", deny_tools=frozenset({"delegate_to_agent"}))
    assert tool.fn({"to_id": "bob", "task": "read"}).startswith("ERROR:")
    assert agent_bus.peek("bob", namespace=ctx.bus_namespace) == 0
    sender._handoff_capability = None
    assert "SIGNED handoff" in tool.fn({"to_id": "bob", "task": "shell", "tools": ["shell"]})
    delivery = receive_handoff(authority, "bob", namespace=ctx.bus_namespace)
    assert delivery and delivery.ok and delivery.grant.permits("shell")


@crypto
def test_signed_handoff_redirected_to_another_inbox_is_rejected():
    """A valid signature for worker A is not authority for worker B."""
    auth = HandoffAuthority.for_run()
    env = auth.mint(
        sender="agent:lead-0",
        recipient="agent:worker-a",
        grant=_grant(principal="agent:worker-a"),
        task="read",
    )
    agent_bus.send("agent:lead-0", "agent:worker-b", env)
    agent_bus.send("agent:lead-0", "agent:worker-a", env)

    d = receive_handoff(auth, "agent:worker-b")
    correct = receive_handoff(auth, "agent:worker-a")

    assert d is not None and not d.ok
    assert d.verdict.rule == "recipient_mismatch"
    assert correct is not None and correct.ok


@crypto
def test_signed_handoff_wrapper_sender_must_match_signed_sender():
    """The unsigned bus wrapper cannot relabel a signed delegation's sender."""
    auth = HandoffAuthority.for_run()
    env = auth.mint(
        sender="agent:lead-0",
        recipient="agent:worker-1",
        grant=_grant(principal="agent:worker-1"),
        task="read",
    )
    agent_bus.send("agent:mallory", "agent:worker-1", env)

    d = receive_handoff(auth, "agent:worker-1")

    assert d is not None and not d.ok
    assert d.verdict.rule == "sender_mismatch"


@crypto
def test_tampering_in_transit_is_rejected():
    import dataclasses
    auth = HandoffAuthority.for_run()
    env = auth.mint(sender="agent:lead-0", recipient="agent:worker-1",
                    grant=_grant(principal="agent:worker-1"), task="read")
    # an attacker on the wire rewrites the task; the signature no longer covers it
    agent_bus.send("agent:lead-0", "agent:worker-1",
                   dataclasses.replace(env, task="exfiltrate secrets"))
    d = receive_handoff(auth, "agent:worker-1")
    assert not d.ok and d.verdict.rule == "tampered"


@crypto
def test_replayed_handoff_is_rejected():
    auth = HandoffAuthority.for_run()
    env = auth.mint(sender="agent:lead-0", recipient="agent:worker-1",
                    grant=_grant(principal="agent:worker-1"), task="read")
    agent_bus.send("agent:lead-0", "agent:worker-1", env)
    agent_bus.send("agent:lead-0", "agent:worker-1", env)  # same nonce, replayed
    first = receive_handoff(auth, "agent:worker-1")
    second = receive_handoff(auth, "agent:worker-1")
    assert first.ok
    assert not second.ok and second.verdict.rule == "replay"


@crypto
def test_forged_issuer_is_rejected():
    minting = HandoffAuthority.for_run()       # some other run's / attacker's issuer
    receiving = HandoffAuthority.for_run()     # this run's trust root
    env = minting.mint(sender="agent:lead-0", recipient="agent:worker-1",
                       grant=_grant(principal="agent:worker-1"), task="read")
    agent_bus.send("agent:lead-0", "agent:worker-1", env)
    d = receive_handoff(receiving, "agent:worker-1")
    assert not d.ok and d.verdict.rule == "untrusted_issuer"


@crypto
def test_out_of_scope_required_tool_is_rejected():
    auth = HandoffAuthority.for_run()
    grant = _grant(principal="agent:worker-1", allow_tools=frozenset({"read_file"}))
    send_handoff(auth, sender="agent:lead-0", recipient="agent:worker-1",
                 grant=grant, task="do it", required_tools=("read_file", "shell"))
    d = receive_handoff(auth, "agent:worker-1")
    assert not d.ok and d.verdict.rule == "out_of_scope"


@crypto
def test_expired_grant_is_rejected():
    auth = HandoffAuthority.for_run()
    grant = _grant(principal="agent:worker-1", expires_at=time.time() - 1)  # already expired
    env = auth.mint(sender="agent:lead-0", recipient="agent:worker-1", grant=grant, task="read")
    agent_bus.send("agent:lead-0", "agent:worker-1", env)
    d = receive_handoff(auth, "agent:worker-1", now=time.time())
    assert not d.ok and d.verdict.rule == "grant_expired"


def test_recv_verified_handoff_installs_grant_for_tool_enforcement(monkeypatch, tmp_path):
    """A verified handoff must constrain subsequent tools, not just prompt text."""
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.bus_handoff import HandoffDelivery
    from maverick.handoff import HandoffVerdict
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.tools import Tool
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    ctx = SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, use_skills=False,
    )
    agent = Agent(ctx=ctx, role="worker", brief="b")
    assert ctx.knows_bus_agent(agent.name)
    ctx.register_bus_agent("lead-0")
    agent.capability = Capability(
        principal=agent.name,
        allow_tools=frozenset({"recv_from_agent", "read_file", "shell"}),
    )
    agent.tools.register(Tool(
        name="read_file", description="read", fn=lambda args: "READ_EXECUTED",
        input_schema={"type": "object", "properties": {}},
    ))
    agent.tools.register(Tool(
        name="shell", description="shell", fn=lambda args: "SHELL_EXECUTED",
        input_schema={"type": "object", "properties": {}},
    ))

    delegated = Capability(principal=agent.name, allow_tools=frozenset({"read_file"}))
    env = Envelope(
        sender="lead-0", recipient=agent.name, task="read only", grant=delegated,
        nonce="n", ts=time.time(), required_tools=("read_file",),
    )

    def fake_receive_handoff(
        authority, agent_id, *, timeout=0.0, now=None, namespace=None,
    ):
        return HandoffDelivery(
            sender="lead-0", payload=env,
            verdict=HandoffVerdict(True, "ok", "handoff verified", grant=delegated),
        )

    monkeypatch.setattr("maverick.bus_handoff.authority_for", lambda ctx: object())
    monkeypatch.setattr("maverick.bus_handoff.receive_handoff", fake_receive_handoff)

    import asyncio

    recv_out = asyncio.run(agent.tools.get("recv_from_agent").fn({"timeout": 0}))
    assert "VERIFIED handoff" in recv_out
    assert agent._handoff_capability is delegated

    denied = asyncio.run(agent._run_tool("shell", {}))
    assert "DENIED by capability policy" in denied
    assert "SHELL_EXECUTED" not in denied

    allowed = asyncio.run(agent._run_tool("read_file", {}))
    assert "READ_EXECUTED" in allowed
