"""Agent Trust Plane: the single registry + decision point for external
agents. Covers registry parsing (fail-closed on junk), the engaged/disengaged
posture, inbound/outbound/direction/capability/budget decisions, pinned-key
identity verification, data-scope gating, and the federation + A2A wiring."""
from __future__ import annotations

from uuid import uuid4

import pytest
from maverick import agent_trust
from maverick import federation_admission as admission
from maverick.agent_trust import (
    TrustedAgent,
    clamp_budget,
    decide_inbound,
    decide_outbound,
    load_registry,
)
from maverick.grpc_api.service import GoalService
from maverick.paths import data_dir
from maverick.world_model import WorldModel

# ---- registry parsing -----------------------------------------------------


def test_load_registry_parses_entries():
    cfg = {"agent_trust": {"agents": [
        {"id": "vega", "pubkey": "ab" * 32, "direction": "both",
         "allow_tools": ["read_file", "http_fetch"], "max_risk": "medium",
         "max_dollars": 2.0, "max_wall_seconds": 600, "data_scopes": ["support"]},
        {"id": "copilot", "direction": "inbound", "allow_tools": ["research"]},
    ]}}
    reg = load_registry(cfg)
    assert set(reg) == {"vega", "copilot"}
    vega = reg["vega"]
    assert vega.pubkey == "ab" * 32
    assert vega.allow_tools == frozenset({"read_file", "http_fetch"})
    assert vega.max_dollars == 2.0
    assert vega.data_scopes == frozenset({"support"})
    assert reg["copilot"].pubkey == ""  # no pinned key is allowed (migration)


def test_load_registry_is_fail_closed_on_junk():
    cfg = {"agent_trust": {"agents": [
        "not-a-table",
        {"id": "BAD ID"},                      # invalid charset -> skipped
        {"id": "x", "pubkey": "nothex"},       # bad pubkey -> entry dropped
        {"id": "y", "direction": "sideways"},  # bad direction -> entry dropped
        {"id": "dup", "max_risk": "low"},
        {"id": "dup", "max_risk": "high"},     # duplicate -> first wins
    ]}}
    reg = load_registry(cfg)
    assert set(reg) == {"dup"}
    assert reg["dup"].max_risk == "low"


def test_load_registry_empty_when_absent_or_malformed():
    assert load_registry({}) == {}
    assert load_registry({"agent_trust": {"agents": "oops"}}) == {}


@pytest.mark.parametrize(("field", "bad"), [
    ("pubkey", ""),
    ("pubkey", 123),
    ("direction", "sideways"),
    ("direction", ["both"]),
    ("max_risk", "critical"),
    ("max_risk", None),
    ("max_dollars", 0),
    ("max_dollars", -1),
    ("max_dollars", float("nan")),
    ("max_dollars", float("inf")),
    ("max_dollars", "-inf"),
    ("max_wall_seconds", True),
    ("max_wall_seconds", "not-a-number"),
    ("allow_tools", 123),
    ("allow_tools", ["read_file", 123]),
    ("allow_tools", [""]),
    ("deny_tools", {"shell": True}),
    ("deny_tools", [None]),
    ("data_scopes", 123),
    ("data_scopes", ["support", ""]),
])
def test_present_malformed_security_field_drops_entry(field, bad):
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", field: bad},
    ]}})
    assert "v" not in reg


def test_absent_optional_security_fields_remain_valid():
    reg = load_registry({"agent_trust": {"agents": [{"id": "v"}]}})
    assert reg["v"] == TrustedAgent(id="v")


def test_load_trust_state_propagates_config_loader_failure(monkeypatch):
    from maverick import config

    def _broken_config():
        raise OSError("config unreadable")

    monkeypatch.setattr(config, "load_config", _broken_config)
    with pytest.raises(OSError, match="config unreadable"):
        agent_trust.load_trust_state()


def test_load_trust_state_fails_closed_on_corrupt_active_toml(tmp_path, monkeypatch):
    from maverick import config

    path = tmp_path / "config.toml"
    path.write_text("[agent_trust\nenforce = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    config.reset_config_cache()
    try:
        with pytest.raises(agent_trust.AgentTrustError, match="source is unreadable"):
            agent_trust.load_trust_state()
    finally:
        config.reset_config_cache()


def test_load_trust_state_rejects_non_table_config_root(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", list)
    with pytest.raises(agent_trust.AgentTrustError, match="root must be a table"):
        agent_trust.load_trust_state()


def test_load_trust_state_rejects_non_table_trust_section(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"agent_trust": []})
    with pytest.raises(agent_trust.AgentTrustError, match="section must be a table"):
        agent_trust.load_trust_state()


def test_load_registry_non_table_config_is_empty():
    assert load_registry([]) == {}
    assert load_registry({"agent_trust": []}) == {}


# ---- posture (engaged / disengaged) --------------------------------------


def test_enforced_env_overrides(monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "1")
    assert agent_trust.agent_trust_enforced() is True
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "0")
    assert agent_trust.agent_trust_enforced() is False


def test_enforced_rejects_malformed_env_and_config(monkeypatch):
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "definitely")
    with pytest.raises(agent_trust.AgentTrustError, match="recognized boolean"):
        agent_trust.agent_trust_enforced({})

    monkeypatch.delenv("MAVERICK_AGENT_TRUST")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    with pytest.raises(agent_trust.AgentTrustError, match="must be a boolean"):
        agent_trust.agent_trust_enforced({
            "agent_trust": {"enforce": "false"},
        })


def test_enforced_follows_enterprise_mode(monkeypatch):
    monkeypatch.delenv("MAVERICK_AGENT_TRUST", raising=False)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert agent_trust.agent_trust_enforced() is True


def test_disengaged_is_a_noop_allow():
    # No registry, no ceiling, always allowed -> existing deployments unchanged.
    d = decide_inbound("anybody", requested_tools=["shell"], enforced=False)
    assert d.allowed and d.rule == "disabled" and d.capability is None
    assert decide_outbound("anybody", enforced=False).allowed


# ---- inbound decisions ----------------------------------------------------


def _reg(*agents: TrustedAgent) -> dict[str, TrustedAgent]:
    return {a.id: a for a in agents}


def test_inbound_unknown_agent_denied_when_engaged():
    d = decide_inbound("ghost", registry={}, enforced=True)
    assert d.denied and d.rule == "not_in_registry"


def test_inbound_direction_enforced():
    reg = _reg(TrustedAgent(id="out", direction="outbound"))
    d = decide_inbound("out", registry=reg, enforced=True)
    assert d.denied and d.rule == "direction"


def test_inbound_capability_ceiling_blocks_unpermitted_tool():
    reg = _reg(TrustedAgent(id="vega", allow_tools=frozenset({"read_file"})))
    d = decide_inbound("vega", requested_tools=["shell"], registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


def test_inbound_allows_within_ceiling_and_returns_capability():
    reg = _reg(TrustedAgent(id="vega", allow_tools=frozenset({"read_file"}),
                            max_risk="medium"))
    d = decide_inbound("vega", requested_tools=["read_file"], registry=reg,
                       enforced=True)
    assert d.allowed and d.rule == "allow"
    assert d.capability is not None
    assert d.capability.permits("read_file")
    assert not d.capability.permits("shell")


def test_inbound_risk_above_ceiling_denied():
    reg = _reg(TrustedAgent(id="vega", max_risk="low"))
    d = decide_inbound("vega", max_risk="high", registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


# ---- outbound decisions ---------------------------------------------------


def test_outbound_unknown_denied_known_allowed():
    assert decide_outbound("ghost", registry={}, enforced=True).denied
    reg = _reg(TrustedAgent(id="vega", direction="both"))
    assert decide_outbound("vega", registry=reg, enforced=True).allowed
    reg2 = _reg(TrustedAgent(id="inb", direction="inbound"))
    assert decide_outbound("inb", registry=reg2, enforced=True).denied


# ---- budget clamp + scopes ------------------------------------------------


def test_clamp_budget_takes_the_tighter_bound():
    a = TrustedAgent(id="v", max_dollars=2.0, max_wall_seconds=600)
    assert clamp_budget(a, max_dollars=5.0, max_wall_seconds=300) == (2.0, 300)
    assert clamp_budget(a, max_dollars=1.0) == (1.0, 600)
    assert clamp_budget(None, max_dollars=5.0) == (5.0, None)


def test_permits_scope():
    a = TrustedAgent(id="v", data_scopes=frozenset({"support"}))
    assert a.permits_scope(None)        # unscoped query carries no department
    assert a.permits_scope("support")
    assert not a.permits_scope("finance")
    assert not TrustedAgent(id="w").permits_scope("support")  # empty == none


# ---- pinned-key identity --------------------------------------------------


def test_verify_identity_against_pinned_key():
    pytest.importorskip("cryptography")
    from maverick import federation_envelope as fe

    env = fe.sign_envelope({"schema": "maverick-test/1", "origin": "vega",
                            "created_at": 1.0, "payload": "hi"})
    pinned = env["pubkey"]
    reg = _reg(TrustedAgent(id="vega", pubkey=pinned))

    ok, _ = agent_trust.verify_identity(
        "vega", env, expected_schema="maverick-test/1", registry=reg)
    assert ok

    # Unknown agent and an agent without a pinned key both fail closed.
    ok2, reason2 = agent_trust.verify_identity(
        "ghost", env, expected_schema="maverick-test/1", registry={})
    assert not ok2 and "registry" in reason2
    ok3, reason3 = agent_trust.verify_identity(
        "nopub", env, expected_schema="maverick-test/1",
        registry=_reg(TrustedAgent(id="nopub")))
    assert not ok3 and "pinned" in reason3

    # Tampering with a signed field is rejected.
    tampered = dict(env, payload="changed")
    ok4, _ = agent_trust.verify_identity(
        "vega", tampered, expected_schema="maverick-test/1", registry=reg)
    assert not ok4


# ---- federation wiring ----------------------------------------------------


class _Goals(GoalService):
    def __init__(self):
        self.started = []
        self.path = data_dir().parent / f"test-federation-{uuid4().hex}" / "world.db"
        super().__init__(world_factory=lambda: WorldModel(self.path),
                         dispatch=self._run, spawn=lambda fn: fn())

    def _run(self, goal_id, **kw):
        with WorldModel(self.path) as world:
            admission.require_execution(
                world, goal_id, capability=kw["capability"],
                max_dollars=kw["max_dollars"],
                max_wall_seconds=kw["max_wall_seconds"], consume=True,
            )
            goal = world.get_goal(goal_id)
            self.started.append({"title": goal.title, "owner": goal.owner, **kw})
            world.set_goal_status(goal_id, "done", result="ok")


def _patch_trust(monkeypatch, *, registry, enforced=True):
    """Patch the single trust-state IO seam, then let the real decide_* /
    decide_memory_access logic run against the injected registry (no patching
    of lookup/decide so the parsing+decision paths are actually exercised)."""
    monkeypatch.setattr(agent_trust, "load_trust_state",
                        lambda: (enforced, registry))
    monkeypatch.setattr(agent_trust, "agent_trust_enforced",
                        lambda cfg=None: enforced)


def _fed_service(monkeypatch, *, registry, enforced=True):
    from maverick import federation
    from maverick.federation import FederationService, Peer

    _patch_trust(monkeypatch, registry=registry, enforced=enforced)
    rows: list[dict] = []

    def record(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    svc = FederationService(
        node="B", peers=[Peer("A", "a:1", "tok")], local_grant=None,
        goal_service=_Goals(), record=record,
    )
    return svc, rows, federation


def test_federation_inbound_denied_for_unregistered_peer(monkeypatch):
    # Authenticated by shared token, but absent from the trust registry ->
    # refused once the plane is engaged (the shared token is no longer enough).
    svc, rows, _ = _fed_service(monkeypatch, registry={})
    reply = svc.delegate_goal({"auth_token": "tok", "correlation_id": "c1",
                               "goal_title": "x"})
    assert reply["accepted"] is False
    assert "trust registry" in reply["reason"]
    # The federation seam records its "received" refusal half with the reason.
    assert any("trust registry" in str(r.get("reason", "")) for r in rows)


def test_federation_inbound_allowed_for_registered_peer(monkeypatch):
    reg = _reg(TrustedAgent(id="A", direction="both",
                            allow_tools=frozenset({"read_file"})))
    svc, _rows, _ = _fed_service(monkeypatch, registry=reg)
    reply = svc.delegate_goal({"auth_token": "tok", "correlation_id": "c2",
                               "goal_title": "do it",
                               "requested_tools": ["read_file"]})
    assert reply["accepted"] is True
    assert reply["goal_id"] >= 1


def test_federation_inbound_tool_outside_ceiling_refused(monkeypatch):
    reg = _reg(TrustedAgent(id="A", allow_tools=frozenset({"read_file"})))
    svc, _rows, _ = _fed_service(monkeypatch, registry=reg)
    reply = svc.delegate_goal({"auth_token": "tok", "correlation_id": "c3",
                               "goal_title": "do it", "requested_tools": ["shell"]})
    assert reply["accepted"] is False


def test_federation_outbound_blocked_for_unregistered_peer(monkeypatch):
    from maverick.federation import FederationNode, Peer

    _patch_trust(monkeypatch, registry={}, enforced=True)

    class _Boom:
        def call(self, *a, **k):  # must never be reached
            raise AssertionError("dialed a peer the trust plane forbade")

    node = FederationNode(node="A", peers=[Peer("B", "b:1", "tok")],
                          transport_factory=lambda peer: _Boom(),
                          record=lambda *a, **k: None)
    out = node.delegate("B", "title")
    assert out.accepted is False and "trust registry" in out.reason


def test_federation_disengaged_unchanged(monkeypatch):
    # The default posture: plane disengaged -> shared-token auth alone admits a
    # peer with no registry entry, exactly as before this feature.
    reg: dict = {}
    svc, _rows, _ = _fed_service(monkeypatch, registry=reg, enforced=False)
    reply = svc.delegate_goal({"auth_token": "tok", "correlation_id": "c4",
                               "goal_title": "legacy"})
    assert reply["accepted"] is True


# ---- A2A wiring -----------------------------------------------------------


def test_a2a_capability_tightened_by_registry(monkeypatch):
    from maverick.a2a_tasks import _a2a_capability

    registry = {
        "a2a": TrustedAgent(
            id="a2a", allow_tools=frozenset({"read_file"}),
        ),
    }
    monkeypatch.setattr(
        agent_trust, "load_trust_state", lambda: (True, registry),
    )
    cap = _a2a_capability()
    assert cap.allow_tools == frozenset({"read_file"})


def test_a2a_capability_unchanged_when_disengaged(monkeypatch):
    from maverick.a2a_tasks import _a2a_capability

    monkeypatch.setattr(
        agent_trust, "load_trust_state", lambda: (False, {}),
    )
    # Disengaged -> no [agent_trust] tightening; default ceiling (all tools,
    # medium risk) is preserved.
    cap = _a2a_capability()
    assert cap.allow_tools == frozenset()  # empty == all


# ---- fleet-memory data-scope gating ---------------------------------------


def _fleet(monkeypatch, *, registry, enforced=True):
    from maverick import fleet_memory
    monkeypatch.setattr(fleet_memory, "enabled", lambda: True)
    monkeypatch.setattr(
        fleet_memory,
        "roster",
        lambda: [{
            "source": "acme:bot", "vendor": "acme", "agent_id": "bot",
        }],
    )
    _patch_trust(monkeypatch, registry=registry, enforced=enforced)
    return fleet_memory


def test_fleet_recall_denied_outside_data_scope(monkeypatch):
    reg = _reg(TrustedAgent(id="bot", data_scopes=frozenset({"support"})))
    fleet_memory = _fleet(monkeypatch, registry=reg)
    ctx, reason = fleet_memory.recall("q", agent_id="bot", vendor="acme",
                                      domain="finance")
    assert ctx == "" and "finance" in reason


def test_fleet_recall_allowed_within_data_scope(monkeypatch):
    reg = _reg(TrustedAgent(id="bot", data_scopes=frozenset({"support"})))
    fleet_memory = _fleet(monkeypatch, registry=reg)
    _ctx, reason = fleet_memory.recall("q", agent_id="bot", vendor="acme",
                                       domain="support")
    assert reason == "ok"  # passed the scope gate


def test_fleet_recall_unregistered_agent_denied_when_engaged(monkeypatch):
    fleet_memory = _fleet(monkeypatch, registry={})
    ctx, reason = fleet_memory.recall("q", agent_id="bot", vendor="acme",
                                      domain="support")
    assert ctx == "" and "trust registry" in reason


def test_fleet_recall_unscoped_denied_when_engaged(monkeypatch):
    # domain=None must NOT read across all departments (the permits_scope(None)
    # bypass).
    reg = _reg(TrustedAgent(id="bot", data_scopes=frozenset({"support"})))
    fleet_memory = _fleet(monkeypatch, registry=reg)
    ctx, reason = fleet_memory.recall("q", agent_id="bot", vendor="acme",
                                      domain=None)
    assert ctx == "" and "scope" in reason.lower()


def test_fleet_recall_hard_filters_cross_department_content(monkeypatch):
    # Even within an allowed scope, content from OTHER departments must be
    # dropped (data_scopes is a hard filter, not just a ranking boost).
    from types import SimpleNamespace

    from maverick import reflexion
    reg = _reg(TrustedAgent(id="bot", data_scopes=frozenset({"support"})))
    fleet_memory = _fleet(monkeypatch, registry=reg)
    monkeypatch.setattr(reflexion, "recall", lambda *a, **k: [
        (0.9, SimpleNamespace(domain="support")),
        (0.8, SimpleNamespace(domain="finance")),  # must be filtered out
    ])
    monkeypatch.setattr(reflexion, "format_context",
                        lambda hits, shield=None: ",".join(h.domain for _, h in hits))
    ctx, reason = fleet_memory.recall("wire thresholds", agent_id="bot",
                                      vendor="acme", domain="support")
    assert reason == "ok"
    assert "support" in ctx and "finance" not in ctx


def test_fleet_ingest_denied_outside_scope_when_engaged(monkeypatch):
    # Memory-poisoning gate: an agent scoped to support cannot WRITE a finance
    # lesson once the plane is engaged (write path now gated like read).
    reg = _reg(TrustedAgent(id="bot", data_scopes=frozenset({"support"})))
    fleet_memory = _fleet(monkeypatch, registry=reg)
    ok, reason = fleet_memory.ingest({
        "agent_id": "bot", "vendor": "acme", "kind": "lesson",
        "goal_text": "x", "reflection": "y", "domain": "finance",
    })
    assert ok is False and "trust plane" in reason


def test_fleet_ingest_unregistered_in_trust_denied(monkeypatch):
    # On the roster but absent from the trust registry -> write refused.
    fleet_memory = _fleet(monkeypatch, registry={})
    ok, reason = fleet_memory.ingest({
        "agent_id": "bot", "vendor": "acme", "kind": "lesson",
        "goal_text": "x", "reflection": "y", "domain": "support",
    })
    assert ok is False


# ---- key lifecycle --------------------------------------------------------


def test_inbound_revoked_agent_denied():
    reg = _reg(TrustedAgent(id="v", revoked=True))
    d = decide_inbound("v", registry=reg, enforced=True)
    assert d.denied and d.rule == "revoked"


def test_inbound_expired_agent_denied():
    reg = _reg(TrustedAgent(id="v", expires_at=1.0))  # epoch 1970
    d = decide_inbound("v", registry=reg, enforced=True)
    assert d.denied and d.rule == "expired"


def test_inbound_not_yet_valid_denied():
    reg = _reg(TrustedAgent(id="v", not_before=4_102_444_800.0))  # year 2100
    d = decide_inbound("v", registry=reg, enforced=True)
    assert d.denied and d.rule == "not_yet_valid"


def test_outbound_revoked_denied():
    reg = _reg(TrustedAgent(id="v", revoked=True))
    assert decide_outbound("v", registry=reg, enforced=True).rule == "revoked"


def test_capability_inherits_entry_expiry():
    cap = TrustedAgent(id="v", expires_at=123.0).capability()
    assert cap.expires_at == 123.0


def test_lifecycle_fields_parse_from_config():
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", "expires_at": 999.0, "not_before": 1.0, "revoked": True},
    ]}})
    assert reg["v"].expires_at == 999.0
    assert reg["v"].not_before == 1.0
    assert reg["v"].revoked is True


def test_absent_lifecycle_fields_mean_no_bound():
    # Missing not_before/expires_at is legitimate (no bound) -> entry kept.
    reg = load_registry({"agent_trust": {"agents": [{"id": "v"}]}})
    assert reg["v"].expires_at is None
    assert reg["v"].not_before is None


@pytest.mark.parametrize("bad", ["not-a-date", 0, -5, "2026-13-99", ""])
def test_malformed_expiry_fails_closed(bad):
    # A present-but-malformed lifecycle bound must NOT coerce to "never expires"
    # (that would mint an immortal credential). Fail closed: drop the entry, so
    # the agent is simply untrusted rather than permanently valid.
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", "expires_at": bad},
    ]}})
    assert "v" not in reg


def test_malformed_not_before_fails_closed():
    reg = load_registry({"agent_trust": {"agents": [
        {"id": "v", "not_before": "garbage"},
    ]}})
    assert "v" not in reg


# ---- max_risk hardening ---------------------------------------------------


def test_inbound_max_risk_case_insensitive_ceiling():
    # "HIGH" must be normalised and caught against a "low" ceiling, not waved
    # through because the case didn't match the lowercase risk set.
    reg = _reg(TrustedAgent(id="v", max_risk="low"))
    d = decide_inbound("v", max_risk="HIGH", registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


def test_inbound_unrecognised_risk_refused():
    reg = _reg(TrustedAgent(id="v", max_risk="high"))
    d = decide_inbound("v", max_risk="bogus", registry=reg, enforced=True)
    assert d.denied and d.rule == "capability"


# ---- decide_memory_access -------------------------------------------------


def test_decide_memory_access_unscoped_denied():
    from maverick.agent_trust import decide_memory_access
    reg = _reg(TrustedAgent(id="v", data_scopes=frozenset({"support"})))
    assert decide_memory_access("v", None, registry=reg, enforced=True).denied
    assert decide_memory_access("v", "", registry=reg, enforced=True).denied


def test_decide_memory_access_scope_enforced():
    from maverick.agent_trust import decide_memory_access
    reg = _reg(TrustedAgent(id="v", data_scopes=frozenset({"support"})))
    assert decide_memory_access("v", "finance", registry=reg, enforced=True).denied
    assert decide_memory_access("v", "support", registry=reg, enforced=True).allowed
    # Disengaged is a no-op allow regardless of scope.
    assert decide_memory_access("v", None, registry=reg, enforced=False).allowed


# ---- identity binding -----------------------------------------------------


def test_verify_identity_rejects_origin_mismatch():
    pytest.importorskip("cryptography")
    from maverick import federation_envelope as fe

    # Signed with origin "other", but the registry entry is keyed "vega".
    env = fe.sign_envelope({"schema": "maverick-test/1", "origin": "other",
                            "created_at": 1.0})
    reg = _reg(TrustedAgent(id="vega", pubkey=env["pubkey"]))
    ok, reason = agent_trust.verify_identity(
        "vega", env, expected_schema="maverick-test/1", registry=reg)
    assert not ok and "origin" in reason.lower()


def test_verify_identity_rejects_revoked():
    reg = _reg(TrustedAgent(id="vega", pubkey="ab" * 32, revoked=True))
    ok, reason = agent_trust.verify_identity(
        "vega", {"origin": "vega", "schema": "maverick-test/1"},
        expected_schema="maverick-test/1", registry=reg)
    assert not ok and "revoked" in reason


# ---- A2A hard-deny --------------------------------------------------------


def test_a2a_trust_block_denies_when_engaged_and_no_entry(monkeypatch):
    from maverick.a2a_tasks import _a2a_trust_block
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (True, {}))
    reason = _a2a_trust_block()
    assert reason and "trust registry" in reason


def test_a2a_trust_block_admits_with_entry(monkeypatch):
    from maverick.a2a_tasks import _a2a_trust_block
    reg = _reg(TrustedAgent(id="a2a", direction="both"))
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (True, reg))
    assert _a2a_trust_block() is None


def test_a2a_trust_block_noop_when_disengaged(monkeypatch):
    from maverick.a2a_tasks import _a2a_trust_block
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (False, {}))
    assert _a2a_trust_block() is None
