"""Identity layer: signed, attenuating capabilities + enforcement.

Capabilities gate the tool surface per-agent. Children inherit an
*attenuated* (never broadened) grant, so a sub-agent cannot escalate past
its parent. Default-open: no capability set == unrestricted, behaviour
unchanged. Opt in via [capabilities] enforce or MAVERICK_ENFORCE_CAPABILITIES.
"""

import pytest
from maverick.capability import (
    Capability,
    capability_enforced,
    capability_from_config,
    sign_capability,
    verify_capability,
)
from maverick.safety.tool_risk import tool_risk

# --- permits ---------------------------------------------------------------

def test_empty_allow_means_all():
    cap = Capability(principal="p")
    assert cap.permits("read_file") and cap.permits("shell")


def test_deny_beats_allow():
    cap = Capability(principal="p", allow_tools=frozenset({"shell"}),
                     deny_tools=frozenset({"shell"}))
    assert cap.permits("shell") is False


def test_allow_whitelist():
    cap = Capability(principal="p", allow_tools=frozenset({"read_file"}))
    assert cap.permits("read_file") is True
    assert cap.permits("shell") is False


def test_max_risk_ceiling():
    # shell is "high", read_file is "low" (see safety.tool_risk).
    cap = Capability(principal="p", max_risk="low")
    assert cap.permits("read_file") is True
    assert cap.permits("shell") is False


def test_knowledge_search_is_low_risk_lookup():
    cap = Capability(
        principal="p",
        allow_tools=frozenset({"knowledge_search"}),
        max_risk="low",
    )
    assert tool_risk("knowledge_search") == "low"
    assert cap.permits("knowledge_search") is True


def test_expiry():
    past = Capability(principal="p", expires_at=1000.0)
    assert past.permits("read_file", now=2000.0) is False
    assert past.permits("read_file", now=500.0) is True


# --- attenuation: can only narrow -----------------------------------------

def test_attenuate_rebinds_principal():
    child = Capability(principal="user:a").attenuate(principal="agent:coder-1")
    assert child.principal == "agent:coder-1"


def test_attenuate_records_revocation_lineage():
    root = Capability(principal="user:alice")
    child = root.attenuate(principal="agent:coder-1")
    grandchild = child.attenuate(principal="agent:reviewer-2")
    assert child.ancestors == ("user:alice",)
    assert grandchild.ancestors == ("user:alice", "agent:coder-1")
    assert grandchild.revocation_principals() == (
        "agent:reviewer-2", "agent:coder-1", "user:alice",
    )


def test_intersect_preserves_both_revocation_lineages():
    ambient = Capability(principal="agent:bob", ancestors=("user:bob",))
    handoff = Capability(principal="agent:bob", ancestors=("user:alice",))
    effective = ambient.intersect(handoff, principal="agent:bob")
    assert effective.ancestors == ("user:bob", "user:alice")
    assert effective.revocation_principals() == (
        "agent:bob", "user:alice", "user:bob",
    )


def test_child_signing_bytes_include_lineage():
    parent = Capability(principal="user:alice")
    child = parent.attenuate(principal="agent:coder-1")
    stripped = Capability(principal="agent:coder-1")
    assert b"ancestors" in child.signing_bytes()
    assert child.signing_bytes() != stripped.signing_bytes()


def test_attenuate_deny_grows():
    parent = Capability(principal="p", deny_tools=frozenset({"shell"}))
    child = parent.attenuate(deny={"computer"})
    assert {"shell", "computer"} <= set(child.deny_tools)
    assert not child.permits("shell") and not child.permits("computer")


def test_attenuate_allow_only_shrinks():
    # Parent allows all; child restricted to read_file.
    child = Capability(principal="p").attenuate(allow={"read_file"})
    assert child.allow_tools == frozenset({"read_file"})
    # Parent already restricted; child cannot ADD a tool back.
    parent = Capability(principal="p", allow_tools=frozenset({"read_file"}))
    child2 = parent.attenuate(allow={"read_file", "shell"})
    assert child2.allow_tools == frozenset({"read_file"})  # intersection only
    assert child2.permits("shell") is False


def test_attenuate_disjoint_tools_deny_all_not_allow_all():
    # Two restricted, non-overlapping tool allow-lists must NOT collapse to the
    # empty set (which would mean "all"); the child must permit no sampled tools.
    parent = Capability(principal="p", allow_tools=frozenset({"shell"}))
    child = parent.attenuate(allow={"read_file"})
    assert child.allow_tools != frozenset()  # not allow-all
    assert child.permits("shell") is False
    assert child.permits("read_file") is False
    assert child.permits("web_search") is False


def test_attenuate_max_risk_only_tightens():
    parent = Capability(principal="p", max_risk="high")
    assert parent.attenuate(max_risk="low").max_risk == "low"
    low = Capability(principal="p", max_risk="low")
    assert low.attenuate(max_risk="high").max_risk == "low"  # cannot loosen


def test_attenuation_is_subset_of_parent():
    # Every tool a child permits must also be permitted by the parent.
    parent = Capability(principal="p", deny_tools=frozenset({"computer"}),
                        max_risk="medium")
    child = parent.attenuate(principal="agent:x", deny={"write_file"}, max_risk="low")
    sample = ["read_file", "web_search", "shell", "computer", "write_file",
              "list_dir", "browser"]
    for t in sample:
        if child.permits(t):
            assert parent.permits(t), f"child escalated on {t}"


# --- resource scopes: paths + hosts ---------------------------------------

def test_empty_scopes_mean_all():
    cap = Capability(principal="p")
    assert cap.permits_path("/etc/passwd") and cap.permits_path("/repo/a.py")
    assert cap.permits_host("example.com") and cap.permits_host("10.0.0.1")


def test_permits_path_glob():
    cap = Capability(principal="p", allow_paths=frozenset({"/repo/*", "/tmp/*.log"}))
    assert cap.permits_path("/repo/src/main.py") is True
    assert cap.permits_path("/tmp/run.log") is True
    assert cap.permits_path("/etc/passwd") is False
    assert cap.permits_path("/tmp/run.txt") is False


def test_permits_host_glob():
    cap = Capability(principal="p", allow_hosts=frozenset({"*.example.com", "api.svc"}))
    assert cap.permits_host("a.example.com") is True
    assert cap.permits_host("api.svc") is True
    assert cap.permits_host("evil.com") is False
    assert cap.permits_host("example.com") is False  # no leading label


def test_attenuate_paths_restrict_from_all():
    # Parent unrestricted (all paths); child may be restricted to a subset.
    child = Capability(principal="p").attenuate(allow_paths={"/repo/*"})
    assert child.allow_paths == frozenset({"/repo/*"})
    assert child.permits_path("/repo/x") is True
    assert child.permits_path("/etc/x") is False


def test_attenuate_hosts_restrict_from_all():
    child = Capability(principal="p").attenuate(allow_hosts={"*.example.com"})
    assert child.allow_hosts == frozenset({"*.example.com"})
    assert child.permits_host("a.example.com") is True
    assert child.permits_host("evil.com") is False


def test_attenuate_paths_only_shrink():
    # Parent already restricted; child cannot add a path the parent lacked.
    parent = Capability(principal="p", allow_paths=frozenset({"/repo/*"}))
    child = parent.attenuate(allow_paths={"/repo/*", "/etc/*"})
    assert child.allow_paths == frozenset({"/repo/*"})  # intersection only
    assert child.permits_path("/etc/passwd") is False


def test_attenuate_hosts_only_shrink():
    parent = Capability(principal="p", allow_hosts=frozenset({"*.example.com"}))
    child = parent.attenuate(allow_hosts={"*.example.com", "evil.com"})
    assert child.allow_hosts == frozenset({"*.example.com"})
    assert child.permits_host("evil.com") is False


def test_attenuate_paths_inherited_when_unspecified():
    parent = Capability(principal="p", allow_paths=frozenset({"/repo/*"}),
                        allow_hosts=frozenset({"api.svc"}))
    child = parent.attenuate(principal="agent:x")
    assert child.allow_paths == frozenset({"/repo/*"})
    assert child.allow_hosts == frozenset({"api.svc"})


def test_attenuate_disjoint_scopes_deny_all_not_allow_all():
    # Two restricted, non-overlapping pattern sets must NOT collapse to the
    # empty set (which would mean "all"); the child must permit nothing.
    parent = Capability(principal="p", allow_paths=frozenset({"/repo/*"}))
    child = parent.attenuate(allow_paths={"/srv/*"})
    assert child.allow_paths != frozenset()  # not allow-all
    assert child.permits_path("/repo/x") is False
    assert child.permits_path("/srv/x") is False
    assert child.permits_path("/anything") is False


def test_attenuation_scopes_are_subset_of_parent():
    # Invariant: every path/host the child permits is also permitted by parent.
    parent = Capability(
        principal="p",
        allow_paths=frozenset({"/repo/*", "/tmp/*"}),
        allow_hosts=frozenset({"*.example.com", "api.svc"}),
    )
    child = parent.attenuate(
        principal="agent:x",
        allow_paths={"/repo/*"},
        allow_hosts={"*.example.com"},
    )
    paths = ["/repo/a", "/repo/b/c.py", "/tmp/x", "/etc/passwd", "/srv/y", "/"]
    for pth in paths:
        if child.permits_path(pth):
            assert parent.permits_path(pth), f"child escalated on path {pth}"
    hosts = ["a.example.com", "deep.sub.example.com", "api.svc", "evil.com",
             "example.com", "localhost"]
    for h in hosts:
        if child.permits_host(h):
            assert parent.permits_host(h), f"child escalated on host {h}"


def test_signing_bytes_includes_scopes():
    base = Capability(principal="p")
    scoped = Capability(principal="p", allow_paths=frozenset({"/repo/*"}),
                        allow_hosts=frozenset({"api.svc"}))
    # Distinct scopes must yield distinct signing payloads.
    assert base.signing_bytes() != scoped.signing_bytes()
    assert b"allow_paths" in scoped.signing_bytes()
    assert b"allow_hosts" in scoped.signing_bytes()
    # Stable + order-independent for the same logical grant.
    a = Capability(principal="p", allow_paths=frozenset({"/a", "/b"}))
    b = Capability(principal="p", allow_paths=frozenset({"/b", "/a"}))
    assert a.signing_bytes() == b.signing_bytes()


def test_from_config_scopes_default_unrestricted(monkeypatch):
    # New fields don't disturb capability_from_config: scopes stay all-permissive.
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"security": {"denied_tools": ["shell"]}},
    )
    cap = capability_from_config("user:local")
    assert cap.allow_paths == frozenset()
    assert cap.allow_hosts == frozenset()
    assert cap.permits_path("/anywhere") is True
    assert cap.permits_host("anyhost") is True


# --- signing (optional crypto) --------------------------------------------

def test_sign_verify_roundtrip():
    # Guard the whole crypto path: a half-installed cryptography (rust bindings
    # present, _cffi_backend missing) panics on import rather than raising
    # ImportError, so skip on any failure -- CI installs a working build.
    try:
        from maverick.audit.signing import _generate_keypair, _have_crypto
        if not _have_crypto():
            pytest.skip("cryptography not installed")
        priv, pub, _ = _generate_keypair()
    except BaseException:  # noqa: BLE001 -- pyo3 PanicException isn't an Exception
        pytest.skip("cryptography unavailable/broken in this environment")
    cap = Capability(principal="agent:coder-1", deny_tools=frozenset({"shell"}),
                     max_risk="medium")
    sig = sign_capability(cap, priv.hex())
    assert verify_capability(cap, sig, pub.hex()) is True
    # Tamper: a broadened grant must not verify against the original signature.
    tampered = Capability(principal="agent:coder-1", max_risk="high")
    assert verify_capability(tampered, sig, pub.hex()) is False


# --- enable flag -----------------------------------------------------------

def test_enforced_via_env(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", "1")
    assert capability_enforced() is True


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    assert capability_enforced() is False


def test_enforced_via_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"capabilities": {"enforce": True}})
    assert capability_enforced() is True


def test_enforcement_policy_load_error_fails_closed(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)

    def _boom():
        raise RuntimeError("config unavailable")

    monkeypatch.setattr("maverick.config.load_config", _boom)
    assert capability_enforced() is True


@pytest.mark.parametrize("value", ["sometimes", "2", "enabled"])
def test_invalid_enforcement_env_fails_closed(monkeypatch, value):
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", value)
    assert capability_enforced() is True


def test_malformed_capability_section_fails_closed(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    monkeypatch.setattr(
        "maverick.config.load_config", lambda: {"capabilities": ["not", "a", "table"]},
    )
    assert capability_enforced() is True


def test_from_config_reuses_acl(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"security": {"denied_tools": ["shell"], "max_risk": "medium"}},
    )
    cap = capability_from_config("user:local")
    assert "shell" in cap.deny_tools
    assert cap.max_risk == "medium"
    assert cap.permits("shell") is False


# --- propagation helper ----------------------------------------------------

def test_child_capability_attenuates():
    from maverick.tools.spawn import _child_capability

    class _Parent:
        capability = Capability(principal="user:local", deny_tools=frozenset({"shell"}))
        depth = 0

    child = _child_capability(_Parent(), "coder", 1)
    assert child.principal == "agent:coder-1"
    assert child.permits("shell") is False

    class _Unrestricted:
        capability = None
        depth = 0

    assert _child_capability(_Unrestricted(), "coder", 1) is None


# --- enforcement at the tool chokepoint ------------------------------------

def _agent(tmp_path):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    ctx = SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, use_skills=False,
    )
    return Agent(ctx=ctx, role="coder", brief="b")


@pytest.mark.parametrize("spawn_tool", ["spawn_subagent", "spawn_swarm"])
def test_child_capability_uses_active_handoff_grant(tmp_path, spawn_tool):
    from maverick.tools.spawn import _child_capability

    parent = _agent(tmp_path)
    parent.capability = Capability(
        principal="agent:parent",
        allow_tools=frozenset({"shell", "spawn_subagent", "spawn_swarm"}),
    )
    parent._handoff_capability = Capability(
        principal="agent:delegate",
        allow_tools=frozenset({"spawn_subagent", "spawn_swarm"}),
    )

    child = _child_capability(parent, "coder", 1, spawn_tool)

    assert child.principal == "agent:coder-1"
    assert child.permits(spawn_tool) is True
    assert child.permits("shell") is False


@pytest.mark.asyncio
async def test_run_tool_denies_uncapable(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  deny_tools=frozenset({"shell"}))
    out = await agent._run_tool("shell", {"cmd": "echo hi"})
    assert "DENIED by capability" in out
    assert "agent:coder-1" in out


@pytest.mark.asyncio
async def test_run_tool_noop_when_unrestricted(tmp_path):
    from maverick.tools import Tool
    agent = _agent(tmp_path)
    agent.capability = None  # default: enforcement is a no-op
    agent.tools.register(Tool(
        name="ping", description="ping", fn=lambda args: "pong",
        input_schema={"type": "object", "properties": {}},
    ))
    out = await agent._run_tool("ping", {})
    assert "pong" in out
    assert "DENIED" not in out


@pytest.mark.asyncio
async def test_run_tool_allows_permitted(tmp_path):
    from maverick.tools import Tool
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_tools=frozenset({"ping"}))
    agent.tools.register(Tool(
        name="ping", description="ping", fn=lambda args: "pong",
        input_schema={"type": "object", "properties": {}},
    ))
    assert "pong" in await agent._run_tool("ping", {})
    # A tool outside the whitelist is denied.
    assert "DENIED by capability" in await agent._run_tool("shell", {"cmd": "x"})


@pytest.mark.asyncio
async def test_capability_denial_is_audited(tmp_path, monkeypatch):
    import maverick.audit
    from maverick.audit import EventKind
    calls = []
    monkeypatch.setattr(maverick.audit, "record",
                        lambda kind, **kw: calls.append((kind, kw)) or True)
    agent = _agent(tmp_path)
    agent.ctx.channel = "sms"
    agent.ctx.user_id = "sms:+15551234567"
    agent.capability = Capability(principal="user:sms:+15551234567",
                                  deny_tools=frozenset({"shell"}))
    await agent._run_tool("shell", {"cmd": "x"})
    denied = [kw for k, kw in calls if k == EventKind.CAPABILITY_DENIED]
    assert denied, "capability denial was not written to the audit log"
    assert denied[0]["tool"] == "shell"
    assert denied[0]["principal"] == "user:sms:+15551234567"
    assert denied[0]["channel"] == "sms"
    assert denied[0]["user_id"] == "sms:+15551234567"


# --- RBAC: roles -> capability scopes --------------------------------------

def _cfg(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


def test_role_for_principal_explicit(monkeypatch):
    from maverick.capability import role_for_principal
    _cfg(monkeypatch, {"role_assignments": {"user:alice": "analyst"}})
    assert role_for_principal("user:alice") == "analyst"


def test_role_for_principal_default_fallback(monkeypatch):
    from maverick.capability import role_for_principal
    _cfg(monkeypatch, {"role_assignments": {"default": "readonly"}})
    assert role_for_principal("user:nobody") == "readonly"


def test_role_for_principal_none_without_config(monkeypatch):
    from maverick.capability import role_for_principal
    _cfg(monkeypatch, {})
    assert role_for_principal("user:alice") is None


def test_role_restricts_tools(monkeypatch):
    _cfg(monkeypatch, {
        "role_assignments": {"user:alice": "analyst"},
        "roles": {"analyst": {"allow_tools": ["read_file", "search"]}},
    })
    cap = capability_from_config("user:alice")
    assert cap.permits("read_file") is True
    assert cap.permits("shell") is False  # not in the role's allow-list


def test_role_cannot_escalate_past_acl_deny(monkeypatch):
    # [security] denies shell; a role that "allows" shell still can't grant it,
    # because attenuate unions deny -- the ceiling's deny persists.
    _cfg(monkeypatch, {
        "security": {"denied_tools": ["shell"]},
        "role_assignments": {"user:alice": "power"},
        "roles": {"power": {"allow_tools": ["shell", "read_file"]}},
    })
    cap = capability_from_config("user:alice")
    assert cap.permits("shell") is False
    assert cap.permits("read_file") is True


def test_role_disjoint_allow_tools_denies_all(monkeypatch):
    # Deployment ACL and role scopes are both ceilings. If their allow-lists are
    # disjoint, the narrowed role must not fail open to all deployment tools.
    _cfg(monkeypatch, {
        "security": {"allowed_tools": ["shell"]},
        "role_assignments": {"user:alice": "readonly"},
        "roles": {"readonly": {"allow_tools": ["read_file"]}},
    })
    cap = capability_from_config("user:alice")
    assert cap.allow_tools != frozenset()  # not allow-all
    assert cap.permits("shell") is False
    assert cap.permits("read_file") is False
    assert cap.permits("web_search") is False


def test_role_max_risk_only_tightens(monkeypatch):
    # ACL ceiling is low; a role asking for high cannot raise it.
    _cfg(monkeypatch, {
        "security": {"max_risk": "low"},
        "role_assignments": {"user:alice": "power"},
        "roles": {"power": {"max_risk": "high"}},
    })
    cap = capability_from_config("user:alice")
    assert cap.max_risk == "low"


def test_unknown_assigned_role_is_rejected(monkeypatch):
    from maverick.capability import UnknownRoleError

    _cfg(monkeypatch, {
        "role_assignments": {"user:alice": "ghost"},  # no [roles.ghost] defined
        "roles": {"analyst": {"allow_tools": ["read_file"]}},
    })
    with pytest.raises(UnknownRoleError, match="undefined RBAC role"):
        capability_from_config("user:alice")


def test_malformed_explicit_assignment_does_not_fall_back_to_default(monkeypatch):
    from maverick.capability import UnknownRoleError

    _cfg(monkeypatch, {
        "role_assignments": {"user:alice": "", "default": "readonly"},
        "roles": {"readonly": {"allow_tools": ["read_file"]}},
    })
    with pytest.raises(UnknownRoleError, match="invalid RBAC role assignment"):
        capability_from_config("user:alice")


def test_no_role_assignment_is_noop(monkeypatch):
    # ACL still applies; absent any role assignment the grant is ACL-only.
    _cfg(monkeypatch, {"security": {"denied_tools": ["shell"]}})
    cap = capability_from_config("user:alice")
    assert cap.permits("shell") is False
    assert cap.permits("read_file") is True


def test_capability_from_config_fails_closed_on_resolver_error(monkeypatch):
    """If the ACL resolver raises, the root grant must DENY every tool, not fall
    back to an all-permissive (empty allow_tools) grant -- an empty allow-list
    means 'all tools', so the error path must use the _DENY_ALL sentinel."""
    def _boom(**_kw):
        raise RuntimeError("resolver exploded")
    monkeypatch.setattr("maverick.safety.tool_acl.resolve_lists", _boom)
    monkeypatch.setattr("maverick.safety.tool_acl.resolve_max_risk", _boom)
    cap = capability_from_config("user:alice")
    assert cap.principal == "user:alice"
    assert cap.permits("read_file") is False
    assert cap.permits("shell") is False
    assert cap.permits("web_search") is False
    assert cap.permits("spawn_subagent") is False
    assert cap.permits_path("/tmp/anything") is False
    assert cap.permits_host("example.com") is False


def test_root_mint_failure_installs_deny_all_grant(monkeypatch):
    from types import SimpleNamespace

    from maverick.agent import Agent

    ctx = SimpleNamespace(
        capability=None,
        channel="slack",
        user_id="slack:UALICE",
    )
    agent = Agent.__new__(Agent)
    agent.ctx = ctx
    agent.depth = 0
    monkeypatch.setattr("maverick.capability.capability_enforced", lambda: True)

    def _boom(**_kwargs):
        raise RuntimeError("root mint failed")

    monkeypatch.setattr("maverick.capability.capability_from_config", _boom)
    cap = agent._resolve_capability(None)

    assert cap.principal == "user:slack:UALICE"
    assert cap.permits("read_file") is False
    assert cap.permits("spawn_subagent") is False
    assert cap.permits_path("/tmp/anything") is False
    assert cap.permits_host("example.com") is False
    assert ctx.capability is cap
