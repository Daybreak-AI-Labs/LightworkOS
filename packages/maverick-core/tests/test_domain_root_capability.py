"""A domain-routed goal root runs under the REQUESTER's grant too.

``run_goal(domain=...)`` builds its root with ``agent_from_profile`` and no
parent, so without the requester's grant the pack's own tool envelope would
be the only grant the agent ran under, dropping the requesting user's RBAC
role, [security] risk ceiling and any regulatory attenuation. An explicit grant
may only ever NARROW the run's ambient grant.
"""
from __future__ import annotations

import pytest
from maverick.capability import Capability
from maverick.domain import DomainProfile, agent_from_profile


def _ctx(tmp_path, *, user_id="alice", capability=None):
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    return SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, use_skills=False, user_id=user_id,
        capability=capability,
    )


def _config(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


def _enforce(monkeypatch, on=True):
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", "1" if on else "0")


# A pack whose own envelope allows a read tool and two tools above "low" risk.
def _pack(**overrides):
    fields = {
        "name": "finance_controller", "compartment": "finance",
        "allow_tools": ["read_file", "write_file", "shell"], "max_risk": "high",
    }
    fields.update(overrides)
    return DomainProfile(**fields)


def test_pack_root_cannot_exceed_the_requesters_risk_ceiling(tmp_path, monkeypatch):
    _enforce(monkeypatch)
    _config(monkeypatch, {"security": {"max_risk": "low"}})

    agent = agent_from_profile(_pack(), _ctx(tmp_path), "close the books")

    assert agent.capability.permits("read_file") is True
    assert agent.capability.permits("shell") is False
    assert agent.capability.permits("write_file") is False
    assert agent.capability.max_risk == "low"


def test_pack_root_cannot_use_a_tool_the_requesters_role_lacks(tmp_path, monkeypatch):
    _enforce(monkeypatch)
    _config(monkeypatch, {
        "role_assignments": {"user:alice": "readonly"},
        "roles": {"readonly": {"allow_tools": ["read_file"]}},
    })

    agent = agent_from_profile(_pack(), _ctx(tmp_path, user_id="alice"), "close the books")

    assert agent.capability.permits("read_file") is True
    assert agent.capability.permits("write_file") is False
    assert agent.capability.permits("shell") is False


def test_pack_root_keeps_regulatory_outbound_denial(tmp_path, monkeypatch):
    # HIPAA / SOC 2 attenuate the grant with deny_tools=_OUTBOUND; a pack that
    # (e.g. with [workforce] levels on) is allowed email must not get it back.
    _enforce(monkeypatch)
    _config(monkeypatch, {"compliance": {"profiles": ["hipaa"]}})

    agent = agent_from_profile(
        _pack(allow_tools=["read_file", "email"], max_risk="high"),
        _ctx(tmp_path), "send the statement",
    )

    assert agent.capability.permits("read_file") is True
    assert agent.capability.permits("email") is False


def test_pack_root_is_revocable_through_the_requesters_principal(tmp_path, monkeypatch):
    _enforce(monkeypatch)
    _config(monkeypatch, {})

    agent = agent_from_profile(_pack(), _ctx(tmp_path, user_id="alice"), "close the books")

    assert agent.capability.principal == "agent:finance_controller-0"
    assert "user:alice" in agent.capability.revocation_principals()


def test_pack_root_children_inherit_the_narrowed_grant(tmp_path, monkeypatch):
    _enforce(monkeypatch)
    _config(monkeypatch, {"security": {"max_risk": "low"}})
    ctx = _ctx(tmp_path)
    root = agent_from_profile(_pack(), ctx, "close the books")

    child = agent_from_profile(_pack(name="ap_clerk"), ctx, "sub", parent=root, depth=1)

    assert child.capability.permits("shell") is False
    assert child.capability.permits("read_file") is True


def test_explicit_grant_is_narrowed_by_a_caller_supplied_run_grant(tmp_path, monkeypatch):
    # The run was started with an explicit capability (A2A / federation / queue
    # dispatch): the pack may not widen it, enforcement flag notwithstanding.
    _enforce(monkeypatch, on=False)
    _config(monkeypatch, {})
    run_grant = Capability(principal="a2a:peer", allow_tools=frozenset({"read_file"}))

    agent = agent_from_profile(_pack(), _ctx(tmp_path, capability=run_grant), "task")

    assert agent.capability.permits("read_file") is True
    assert agent.capability.permits("shell") is False


def test_unrestricted_requester_keeps_the_whole_pack_envelope(tmp_path, monkeypatch):
    # Enforcement on, but nothing restricts this person: the pack must still be
    # able to do everything its own envelope allows (no accidental narrowing).
    _enforce(monkeypatch)
    _config(monkeypatch, {})

    agent = agent_from_profile(_pack(), _ctx(tmp_path), "close the books")

    assert agent.capability.permits("read_file") is True
    assert agent.capability.permits("write_file") is True
    assert agent.capability.permits("shell") is True
    assert agent.capability.permits("web_search") is False  # outside the pack's list
    assert agent.capability.max_risk == "high"


def test_enforcement_off_leaves_the_pack_envelope_alone(tmp_path, monkeypatch):
    # Kernel default (kernel rule 1): no enforcement, no ambient grant -- the
    # pack's own envelope is the hard boundary, exactly as before.
    _enforce(monkeypatch, on=False)
    _config(monkeypatch, {"security": {"max_risk": "low"}})

    agent = agent_from_profile(_pack(), _ctx(tmp_path), "close the books")

    assert agent.capability.permits("shell") is True
    assert agent.capability.principal == "agent:finance_controller-0"


def test_unreadable_policy_denies_the_pack_root_everything(tmp_path, monkeypatch):
    # If the requester's grant cannot be resolved the pack must not fill the gap.
    _enforce(monkeypatch)

    def _boom(**_kwargs):
        raise RuntimeError("policy store down")

    monkeypatch.setattr("maverick.capability.capability_from_config", _boom)

    agent = agent_from_profile(_pack(), _ctx(tmp_path), "close the books")

    assert agent.capability.permits("read_file") is False
    assert agent.capability.permits("shell") is False


@pytest.mark.asyncio
async def test_pack_root_tool_call_is_refused_under_the_requesters_role(tmp_path, monkeypatch):
    # The refusal has to reach the tool boundary, not just the grant object: a
    # read-only user asks a pack that allows write_file; the call never runs.
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")
    _enforce(monkeypatch)
    _config(monkeypatch, {
        "role_assignments": {"user:alice": "readonly"},
        "roles": {"readonly": {"allow_tools": ["read_file"]}},
    })
    root = agent_from_profile(_pack(), _ctx(tmp_path, user_id="alice"), "close the books")

    refusal = await root._run_tool("write_file", {"path": "out.txt", "content": "hi"})

    assert "DENIED by capability policy" in refusal
    assert "The tool was not executed" in refusal
    assert not (tmp_path / "out.txt").exists()
