"""Agent identity and trust gating on the external surfaces.

Covers A2A per-caller bearer -> agent identity + admission + ceiling, the
gRPC, MCP and marketplace surfaces, and governance gating on federation
delegation (DENY + fail-closed REQUIRE_HUMAN)."""
from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from maverick import agent_trust
from maverick import federation_admission as admission
from maverick.agent_trust import TrustedAgent
from maverick.grpc_api.service import GoalService
from maverick.paths import data_dir
from maverick.world_model import WorldModel

# ---- per-caller A2A token resolution --------------------------------------


def test_agent_for_a2a_token_resolves():
    reg = {"vega": TrustedAgent(id="vega", a2a_token="s3cret"),
           "other": TrustedAgent(id="other", a2a_token="zzz")}
    assert agent_trust.agent_for_a2a_token("s3cret", registry=reg).id == "vega"
    assert agent_trust.agent_for_a2a_token("nope", registry=reg) is None
    assert agent_trust.agent_for_a2a_token("", registry=reg) is None
    # An entry with no a2a_token never matches the empty default.
    assert agent_trust.agent_for_a2a_token("", registry={"x": TrustedAgent(id="x")}) is None


def test_agent_for_a2a_token_rejects_inactive_or_outbound_only_entries():
    reg = {
        "revoked": TrustedAgent(id="revoked", a2a_token="revoked-token", revoked=True),
        "expired": TrustedAgent(id="expired", a2a_token="expired-token", expires_at=1),
        "future": TrustedAgent(id="future", a2a_token="future-token", not_before=9_999_999_999),
        "outbound": TrustedAgent(id="outbound", a2a_token="outbound-token", direction="outbound"),
    }
    for token in reg:
        assert agent_trust.agent_for_a2a_token(f"{token}-token", registry=reg) is None


def test_a2a_token_parses_from_config():
    reg = agent_trust.load_registry({"agent_trust": {"agents": [
        {"id": "vega", "a2a_token": "tok-123"},
    ]}})
    assert reg["vega"].a2a_token == "tok-123"


# ---- A2A auth + principal + admission + ceiling ---------------------------


def _patch(monkeypatch, registry, *, enforced=True):
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (enforced, registry))
    monkeypatch.setattr(agent_trust, "agent_trust_enforced", lambda cfg=None: enforced)
    monkeypatch.setattr(agent_trust, "load_registry", lambda cfg=None: registry)


def test_a2a_auth_accepts_per_caller_token(monkeypatch):
    from maverick.a2a_tasks import TaskEngine
    monkeypatch.delenv("MAVERICK_A2A_TOKEN", raising=False)
    reg = {"vega": TrustedAgent(id="vega", a2a_token="s3cret")}
    _patch(monkeypatch, reg)
    eng = TaskEngine()
    assert eng.auth_error("Bearer s3cret") is None          # valid per-caller token
    assert eng.auth_error("Bearer wrong") is not None       # unknown bearer
    assert eng.principal_for("Bearer s3cret") == "agent:vega"


def test_a2a_auth_rejects_revoked_per_caller_token(monkeypatch):
    from maverick.a2a_tasks import TaskEngine
    monkeypatch.delenv("MAVERICK_A2A_TOKEN", raising=False)
    reg = {"vega": TrustedAgent(id="vega", a2a_token="s3cret", revoked=True)}
    _patch(monkeypatch, reg)
    eng = TaskEngine()
    assert eng.auth_error("Bearer s3cret") is not None
    assert eng.principal_for("Bearer s3cret") != "agent:vega"


def test_a2a_trust_block_per_caller(monkeypatch):
    from maverick.a2a_tasks import _a2a_trust_block
    reg = {"vega": TrustedAgent(id="vega", direction="both"),
           "inbound_only": TrustedAgent(id="inbound_only", direction="outbound")}
    _patch(monkeypatch, reg)
    assert _a2a_trust_block("agent:vega") is None            # admitted
    assert _a2a_trust_block("agent:inbound_only") is not None  # outbound-only -> denied
    # An anon/shared caller with no surface-wide "a2a" entry is denied.
    assert _a2a_trust_block("anon") is not None


def test_a2a_trust_state_load_error_fails_closed(monkeypatch):
    from maverick.a2a_tasks import TaskEngine, _a2a_capability, _a2a_trust_block

    def _broken_state():
        raise OSError("trust registry unreadable")

    monkeypatch.setattr(agent_trust, "load_trust_state", _broken_state)
    assert "unavailable" in _a2a_trust_block("agent:vega")
    monkeypatch.setenv("MAVERICK_A2A_TOKEN", "shared")
    assert TaskEngine().auth_error("Bearer shared") is not None

    def _broken_enforcement(cfg=None):
        raise OSError("trust registry unreadable")

    monkeypatch.setattr(agent_trust, "agent_trust_enforced", _broken_enforcement)
    with pytest.raises(RuntimeError, match="policy unavailable"):
        _a2a_capability()


def test_a2a_capability_uses_caller_ceiling(monkeypatch):
    from maverick.a2a_tasks import _a2a_capability, _caller_agent
    reg = {"vega": TrustedAgent(id="vega", allow_tools=frozenset({"read_file"}))}
    _patch(monkeypatch, reg)
    cv = _caller_agent.set("vega")
    try:
        cap = _a2a_capability()
        assert cap.allow_tools == frozenset({"read_file"})
    finally:
        _caller_agent.reset(cv)


def test_queued_a2a_execution_reuses_admission_trust_snapshot(monkeypatch):
    from maverick import a2a_tasks as a2at
    from maverick import config

    registry = {
        "vega": TrustedAgent(id="vega", max_risk="low"),
    }
    loads = 0

    def _state():
        nonlocal loads
        loads += 1
        if loads > 1:
            raise OSError("policy changed after execution admission")
        return True, registry

    monkeypatch.setattr(agent_trust, "load_trust_state", _state)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **_k: {})
    observed = {}

    def _runner(_text, **_limits):
        observed["risk"] = a2at._a2a_capability().max_risk
        return "ok"

    engine = a2at.TaskEngine(runner=_runner)
    monkeypatch.setattr(engine, "_shield_block", lambda _text: None)
    params = {
        "message": {
            "role": "user",
            "parts": [{"kind": "text", "text": "run"}],
            "messageId": str(uuid.uuid4()),
        },
    }

    task = asyncio.run(engine.send(params, principal="agent:vega"))

    assert task["status"]["state"] == "completed"
    assert observed == {"risk": "low"}
    assert loads == 1


def test_external_agent_allowlist_does_not_implicitly_gain_coordination():
    from maverick.capability import COORDINATION_TOOLS

    entry = TrustedAgent(
        id="reader",
        allow_tools=frozenset({"read_file", "send_to_agent"}),
    )
    cap = entry.capability()

    assert cap.permits("read_file")
    assert cap.permits("send_to_agent")
    assert all(
        not cap.permits(tool)
        for tool in COORDINATION_TOOLS - {"send_to_agent"}
    )


# ---- governance gating on federation delegation ---------------------------


class _Goals(GoalService):
    def __init__(self):
        self.path = data_dir().parent / f"test-federation-{uuid.uuid4().hex}" / "world.db"
        super().__init__(world_factory=lambda: WorldModel(self.path),
                         dispatch=self._run, spawn=lambda fn: fn())

    def _run(self, goal_id, **kw):
        with WorldModel(self.path) as world:
            admission.require_execution(
                world, goal_id, capability=kw["capability"],
                max_dollars=kw["max_dollars"],
                max_wall_seconds=kw["max_wall_seconds"], consume=True,
            )
            world.set_goal_status(goal_id, "done", result="ok")


def _fed(monkeypatch, registry):
    from maverick import federation
    from maverick.federation import FederationService, Peer
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (True, registry))
    monkeypatch.setattr(agent_trust, "agent_trust_enforced", lambda cfg=None: True)
    monkeypatch.setattr(agent_trust, "load_registry", lambda cfg=None: registry)
    return federation, FederationService(
        node="b", peers=[Peer("a", "a:1", "tok")], local_grant=None,
        goal_service=_Goals(), record=lambda *a, **k: True,
    )


def _delegate(svc, **over):
    payload = {"auth_token": "tok", "correlation_id": "c1", "goal_title": "x",
               "requested_tools": ["read_file"]}
    payload.update(over)
    return svc.delegate_goal(payload)


def test_federation_governance_deny(monkeypatch):
    import maverick.governance as gov
    reg = {"a": TrustedAgent(id="a", allow_tools=frozenset({"read_file"}))}
    federation, svc = _fed(monkeypatch, reg)
    monkeypatch.setattr(gov, "evaluate", lambda *a, **k: gov.Verdict(
        gov.Decision.DENY, "blocked by policy", "deny_actions"))
    reply = _delegate(svc)
    assert reply["accepted"] is False and "governance" in reply["reason"]


def test_federation_governance_require_human_fail_closed(monkeypatch):
    import maverick.governance as gov
    reg = {"a": TrustedAgent(id="a", allow_tools=frozenset({"read_file"}))}
    federation, svc = _fed(monkeypatch, reg)
    monkeypatch.setattr(gov, "evaluate", lambda *a, **k: gov.Verdict(
        gov.Decision.REQUIRE_HUMAN, "needs sign-off", "require_human_actions"))
    reply = _delegate(svc)
    assert reply["accepted"] is False and "human approval" in reply["reason"].lower()


def test_federation_governance_allow_is_noop(monkeypatch):
    # No policy configured -> evaluate returns ALLOW -> delegation proceeds.
    reg = {"a": TrustedAgent(id="a", allow_tools=frozenset({"read_file"}))}
    _federation, svc = _fed(monkeypatch, reg)
    reply = _delegate(svc)
    assert reply["accepted"] is True


# ---- per-surface token isolation ------------------------------------------


def test_token_surface_isolation():
    # A token configured for one surface must not authenticate another.
    reg = {"vega": TrustedAgent(id="vega", grpc_token="g", mcp_token="m",
                                a2a_token="a")}
    assert agent_trust.agent_for_token("g", "grpc", registry=reg).id == "vega"
    assert agent_trust.agent_for_token("g", "mcp", registry=reg) is None
    assert agent_trust.agent_for_token("g", "a2a", registry=reg) is None
    assert agent_trust.agent_for_token("m", "mcp", registry=reg).id == "vega"


def test_duplicate_active_surface_token_is_not_an_identity():
    reg = {
        "vega": TrustedAgent(id="vega", mcp_token="duplicate"),
        "sirius": TrustedAgent(id="sirius", mcp_token="duplicate"),
    }

    assert agent_trust.agent_for_token("duplicate", "mcp", registry=reg) is None


def test_duplicate_token_ignores_inactive_entries():
    reg = {
        "vega": TrustedAgent(id="vega", grpc_token="duplicate"),
        "revoked": TrustedAgent(
            id="revoked", grpc_token="duplicate", revoked=True,
        ),
    }

    assert agent_trust.agent_for_token(
        "duplicate", "grpc", registry=reg,
    ).id == "vega"


# ---- gRPC goal API gating -------------------------------------------------


class _Ctx:
    def abort(self, code, details):
        raise PermissionError(details)


def _without_grpc_runtime(monkeypatch, server):
    codes = SimpleNamespace(
        UNAVAILABLE="UNAVAILABLE",
        PERMISSION_DENIED="PERMISSION_DENIED",
    )
    monkeypatch.setattr(server, "_grpc_code", lambda: codes)


def test_grpc_trust_capability_denies_unregistered(monkeypatch):
    pytest.importorskip("grpc")
    from maverick.grpc_api import server
    _patch(monkeypatch, {})  # engaged, no surface-wide "grpc" entry
    with pytest.raises(PermissionError):
        server._trust_capability(_Ctx(), None)


def test_grpc_trust_capability_allows_registered(monkeypatch):
    pytest.importorskip("grpc")
    from maverick.grpc_api import server
    reg = {"grpc": TrustedAgent(id="grpc", allow_tools=frozenset({"read_file"}))}
    _patch(monkeypatch, reg)
    cap = server._trust_capability(_Ctx(), None)
    assert cap is not None and cap.permits("read_file") and not cap.permits("shell")


def test_grpc_trust_capability_noop_when_disengaged(monkeypatch):
    pytest.importorskip("grpc")
    from maverick.grpc_api import server
    _patch(monkeypatch, {}, enforced=False)
    assert server._trust_capability(_Ctx(), None) is None


def test_grpc_trust_capability_load_error_fails_closed(monkeypatch):
    from maverick import agent_trust
    from maverick.grpc_api import server
    _without_grpc_runtime(monkeypatch, server)

    def _broken_state():
        raise OSError("trust registry unreadable")

    monkeypatch.setattr(agent_trust, "load_trust_state", _broken_state)
    with pytest.raises(PermissionError, match="policy unavailable"):
        server._trust_capability(_Ctx(), None)


@pytest.mark.parametrize(
    "state",
    [
        (None, {}),
        (False, []),
        ("false", {}),
    ],
)
def test_grpc_trust_capability_malformed_state_fails_closed(monkeypatch, state):
    from maverick.grpc_api import server
    _without_grpc_runtime(monkeypatch, server)

    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: state)
    with pytest.raises(PermissionError, match="policy unavailable"):
        server._trust_capability(_Ctx(), None)


def test_grpc_trust_capability_decision_error_fails_closed(monkeypatch):
    from maverick.grpc_api import server
    _without_grpc_runtime(monkeypatch, server)

    _patch(monkeypatch, {})

    def _broken_decision(*args, **kwargs):
        raise RuntimeError("decision engine unavailable")

    monkeypatch.setattr(agent_trust, "decide_inbound", _broken_decision)
    with pytest.raises(PermissionError, match="policy unavailable"):
        server._trust_capability(_Ctx(), None)


def test_grpc_denial_survives_audit_sink_failure(monkeypatch):
    from maverick.grpc_api import server
    _without_grpc_runtime(monkeypatch, server)

    _patch(monkeypatch, {})

    def _broken_audit(*args, **kwargs):
        raise OSError("audit sink unavailable")

    monkeypatch.setattr(agent_trust, "record_denied", _broken_audit)
    with pytest.raises(PermissionError, match="not in the trust registry"):
        server._trust_capability(_Ctx(), None)


# ---- MCP gating -----------------------------------------------------------


def test_mcp_admits_registered_shared_token(monkeypatch):
    from maverick_mcp import http_transport as ht
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "shared")
    _patch(monkeypatch, {"mcp": TrustedAgent(id="mcp", direction="both")})
    # Shared bearer -> authed with NO per-caller identity (empty string).
    assert ht._check_bearer("Bearer shared") == (True, "")


def test_mcp_denies_when_engaged_no_entry(monkeypatch):
    from maverick_mcp import http_transport as ht
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "shared")
    _patch(monkeypatch, {})  # engaged, no "mcp" surface entry
    assert ht._check_bearer("Bearer shared") == (False, "")


def test_mcp_per_caller_token(monkeypatch):
    from maverick_mcp import http_transport as ht
    monkeypatch.delenv("MAVERICK_MCP_TOKEN", raising=False)
    reg = {"vega": TrustedAgent(id="vega", mcp_token="v-tok", direction="both")}
    _patch(monkeypatch, reg)
    # Per-caller token -> authed AND carries the resolved agent identity.
    assert ht._check_bearer("Bearer v-tok") == (True, "vega")
    assert ht._check_bearer("Bearer nope") == (False, "")


def test_mcp_disengaged_auth_only(monkeypatch):
    from maverick_mcp import http_transport as ht
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "shared")
    _patch(monkeypatch, {}, enforced=False)
    assert ht._check_bearer("Bearer shared") == (True, "")
    assert ht._check_bearer("Bearer wrong") == (False, "")


def test_mcp_trust_state_load_error_fails_closed(monkeypatch):
    from maverick import agent_trust
    from maverick_mcp import http_transport as ht

    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "shared")

    def _broken_state():
        raise OSError("trust registry unreadable")

    monkeypatch.setattr(agent_trust, "load_trust_state", _broken_state)
    assert ht._check_bearer("Bearer shared") == (False, "")
