"""Regulatory compiler: obligations become live gates, and the gate proves it."""
from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest
from maverick import regulatory_compiler as rc
from maverick.capability import Capability
from maverick.governance import Decision, Policy, evaluate
from maverick.tools import Tool

ALL = list(rc.shipped_profile_keys())


def _activate(monkeypatch, keys):
    monkeypatch.setattr(rc, "active_keys", lambda: list(keys))


# ---- the library ------------------------------------------------------------

def test_every_bound_tool_is_a_classified_tool():
    """A renamed tool must not silently turn an obligation into a no-op."""
    from maverick.safety.tool_risk import tool_risk_is_classified
    for obligations in rc.REGULATIONS.values():
        for ob in obligations:
            for name in ob.actions | ob.deny_tools:
                assert tool_risk_is_classified(name), f"{ob.id} binds unknown tool {name!r}"


def test_the_shipped_library_compiles_to_non_vacuous_gates():
    assert rc.verify(ALL) == []


@pytest.mark.parametrize("key", rc.SHIPPED_PROFILE_KEYS)
def test_each_shipped_profile_has_an_individually_non_vacuous_gate(key):
    """The CI registry is seven independently enforceable compiler profiles."""
    compiled = rc.compile_obligations([key])
    assert compiled.obligations
    assert rc.verify([key]) == []


def test_shipped_profile_registry_is_stable_and_matches_the_library():
    assert rc.SHIPPED_PROFILE_KEYS == (
        "gdpr", "eu_ai_act", "hipaa", "nist_ai_rmf", "iso_42001", "soc2", "sr_11_7",
    )
    assert rc.shipped_profile_keys() == rc.SHIPPED_PROFILE_KEYS
    assert set(rc.SHIPPED_PROFILE_KEYS) == set(rc.REGULATIONS)


def test_gdpr_compiles_into_the_chokepoint_policy():
    pol = rc.compile_obligations(["gdpr"]).policy
    assert {"sql_query", "email"} <= pol.require_human_actions
    assert pol.require_human_min_risk == "high"
    assert evaluate("email", policy=pol).decision == Decision.REQUIRE_HUMAN
    assert evaluate("shell", risk="high", policy=pol).decision == Decision.REQUIRE_HUMAN
    assert evaluate("read_file", risk="low", policy=pol).decision == Decision.ALLOW


def test_hipaa_is_an_attenuation_not_a_policy_rule():
    compiled = rc.compile_obligations(["hipaa"])
    assert compiled.policy.is_empty()
    assert "email" in compiled.deny_tools


def test_unknown_keys_are_ignored_and_deduplicated():
    compiled = rc.compile_obligations(["GDPR", "gdpr", "nope"])
    assert [o.regulation for o in compiled.obligations].count("GDPR") == 3


def test_deny_wins_over_require_human_for_the_same_action(monkeypatch):
    deny = rc.Obligation("t-deny", "T", "1", "", rc.EFFECT_DENY, actions=frozenset({"email"}))
    ask = rc.Obligation("t-ask", "T", "2", "", rc.EFFECT_REQUIRE_HUMAN,
                        actions=frozenset({"email"}))
    monkeypatch.setitem(rc.REGULATIONS, "t", (deny, ask))
    pol = rc.compile_obligations(["t"]).policy
    assert "email" in pol.deny_actions
    assert "email" not in pol.require_human_actions
    assert evaluate("email", policy=pol).decision == Decision.DENY


# ---- tagging: proof the gate was live ---------------------------------------

def test_audit_tags_trace_a_verdict_back_to_its_obligation(monkeypatch):
    _activate(monkeypatch, ["gdpr"])
    tags = rc.audit_tags("email", "require_human_actions")
    assert {key: tags[key] for key in ("obligation_id", "regulation", "article")} == {
        "obligation_id": "gdpr-art32-outbound-transfer",
        "regulation": "GDPR", "article": "Art. 32"}
    assert tags["obligations_enforced"] == [{
        "obligation_id": "gdpr-art32-outbound-transfer",
        "regulation": "GDPR", "article": "Art. 32"}, {
        "obligation_id": "gdpr-art22-automated-decision",
        "regulation": "GDPR", "article": "Art. 22"}]
    # A floor-level obligation tags a floor-level rule.
    assert rc.audit_tags("shell", "require_human_min_risk")["obligation_id"] \
        == "gdpr-art22-automated-decision"
    # The rule must belong to the obligation's effect: a capability denial of
    # an outbound tool is not GDPR Art. 32's doing.
    assert rc.audit_tags("email", "capability") == {}
    assert rc.audit_tags("read_file", "require_human_actions") == {}


def test_obligations_checked_lists_every_covering_obligation(monkeypatch):
    _activate(monkeypatch, ALL)
    checked = rc.obligations_checked("email")
    assert "gdpr-art32-outbound-transfer" in checked
    assert "hipaa-164-502b-minimum-necessary" in checked
    assert "gdpr-art17-erasure-governed-path" not in checked
    assert rc.checked_tags("email") == {"obligations_checked": checked}


def test_nothing_active_means_rows_are_untouched(monkeypatch):
    _activate(monkeypatch, [])
    assert rc.audit_tags("email", "require_human_actions") == {}
    assert rc.checked_tags("email") == {}


def test_tagging_never_raises(monkeypatch):
    monkeypatch.setattr(rc, "_active", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert "obligation_evidence_error" in rc.audit_tags("email", "deny_actions")
    assert "obligation_evidence_error" in rc.checked_tags("email")


def test_explicitly_unavailable_verdict_snapshot_never_reloads_active_profiles(
    monkeypatch,
):
    _activate(monkeypatch, ["gdpr"])
    assert "obligation_evidence_error" in rc.audit_tags(
        "email",
        "require_human_actions",
        keys=None,
    )
    assert "obligation_evidence_error" in rc.checked_tags("email", keys=None)


def test_denial_evidence_retains_all_applicable_citations_deterministically(monkeypatch):
    _activate(monkeypatch, ["eu_ai_act", "gdpr"])
    tags = rc.audit_tags("shell", "require_human_min_risk")
    assert [item["obligation_id"] for item in tags["obligations_enforced"]] == [
        "eu-aia-art14-human-oversight",
        "gdpr-art22-automated-decision",
    ]
    assert tags["obligations_enforced_count"] == 2
    assert tags["obligation_id"] == "eu-aia-art14-human-oversight"


def test_denial_evidence_is_bounded_and_reports_truncation():
    obligations = tuple(
        rc.Obligation(
            f"test-{index:02d}",
            "Test",
            str(index),
            "bounded evidence",
            rc.EFFECT_DENY,
            actions=frozenset({"email"}),
        )
        for index in range(20)
    )
    tags = rc.audit_tags_under("email", "deny_actions", obligations)
    assert len(tags["obligations_enforced"]) == 16
    assert tags["obligations_enforced_count"] == 20
    assert tags["obligations_enforced_truncated"] is True
    assert [item["obligation_id"] for item in tags["obligations_enforced"]] == [
        f"test-{index:02d}" for index in range(16)
    ]


def test_evidence_can_use_the_exact_verdict_profile_snapshot(monkeypatch):
    _activate(monkeypatch, ["gdpr"])
    tags = rc.audit_tags(
        "shell", "require_human_min_risk", keys=("eu_ai_act",)
    )
    assert [item["obligation_id"] for item in tags["obligations_enforced"]] == [
        "eu-aia-art14-human-oversight"
    ]


# ---- attenuation: never widens ----------------------------------------------

def test_attenuation_removes_the_tools_and_never_widens(monkeypatch):
    _activate(monkeypatch, ["hipaa"])
    cap = Capability(principal="p", allow_tools=frozenset({"email", "read_file"}),
                     max_risk="high")
    narrowed = rc.attenuate(cap)
    assert not narrowed.permits("email")
    assert narrowed.permits("read_file")
    assert narrowed.allow_tools <= cap.allow_tools
    assert narrowed.deny_tools >= cap.deny_tools
    # A child derived from the narrowed grant cannot get the tool back.
    child = narrowed.attenuate(principal="agent:child", allow={"email", "read_file"})
    assert not child.permits("email")


def test_attenuation_is_identity_when_nothing_is_active(monkeypatch):
    _activate(monkeypatch, [])
    cap = Capability(principal="p")
    assert rc.attenuate(cap) is cap


def test_capability_from_config_applies_the_attenuation(monkeypatch):
    _activate(monkeypatch, ["hipaa"])
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    from maverick.capability import capability_from_config
    cap = capability_from_config("user:local")
    assert not cap.permits("email")
    assert cap.permits("read_file")


# ---- anti-vacuity ------------------------------------------------------------

def test_verify_flags_an_obligation_bound_to_a_tool_that_does_not_exist(monkeypatch):
    """Fault injection: the clean library passes, a corrupted copy is caught."""
    good = rc.REGULATIONS["gdpr"]
    assert rc.verify(["gdpr"]) == []
    bad = tuple(dataclasses.replace(o, actions=frozenset({"tool_that_does_not_exist"}))
                if o.id.endswith("outbound-transfer") else o for o in good)
    monkeypatch.setitem(rc.REGULATIONS, "gdpr", bad)
    problems = rc.verify(["gdpr"])
    assert any("unknown tool 'tool_that_does_not_exist'" in p for p in problems)


def test_verify_flags_a_dead_overlay(monkeypatch):
    """If the chokepoint stopped honouring the compiled policy, the gate says so."""
    from maverick import governance
    from maverick.governance import Verdict
    monkeypatch.setattr(governance, "evaluate",
                        lambda action, **kw: Verdict(Decision.ALLOW, "open", "default"))
    problems = rc.verify(["gdpr"])
    assert any("dead overlay" in p for p in problems)


def test_verify_flags_an_attenuation_that_no_longer_bites(monkeypatch):
    monkeypatch.setattr(rc, "compile_obligations", lambda keys: rc.CompiledObligations(
        Policy(), frozenset(), rc.REGULATIONS["hipaa"]))
    problems = rc.verify(["hipaa"])
    assert any("dead attenuation" in p for p in problems)


def test_verify_flags_an_obligation_with_no_scope(monkeypatch):
    empty = rc.Obligation("t-empty", "T", "1", "", rc.EFFECT_DENY)
    monkeypatch.setitem(rc.REGULATIONS, "t", (empty,))
    assert any("no scope" in p for p in rc.verify(["t"]))


def test_main_exit_codes(monkeypatch, capsys):
    assert rc.main(["--ci", "--all"]) == 0
    assert "non-vacuous" in capsys.readouterr().out
    # Nothing active and nothing requested: a gate that inspected nothing.
    _activate(monkeypatch, [])
    assert rc.main(["--ci"]) == 2
    assert rc.main([]) == 2
    bad = rc.Obligation("t-bad", "T", "1", "", rc.EFFECT_DENY,
                        actions=frozenset({"tool_that_does_not_exist"}))
    monkeypatch.setitem(rc.REGULATIONS, "t", (bad,))
    assert rc.main(["--ci", "--profiles", "t"]) == 1
    capsys.readouterr()  # drain the human-readable output before the JSON run
    assert rc.main(["--json", "--profiles", "gdpr"]) == 0
    import json
    assert json.loads(capsys.readouterr().out)["problems"] == []


# ---- profiles: one activation switch ----------------------------------------

def test_the_profiles_expose_the_compiled_policies():
    from maverick.compliance_profiles import compile_policy, get_profile, list_profiles

    assert set(rc.SHIPPED_PROFILE_KEYS) == {profile.key for profile in list_profiles()}
    for key in rc.SHIPPED_PROFILE_KEYS:
        assert get_profile(key) is not None
        assert compile_policy([key]).compliance_profiles == (key,)
    assert get_profile("gdpr").policy == rc.compile_obligations(["gdpr"]).policy
    assert get_profile("eu_ai_act").policy.require_human_min_risk == "high"


def test_configured_profiles_reach_the_live_policy(monkeypatch):
    import maverick.compliance_profiles as cpmod
    monkeypatch.setattr(cpmod, "configured_profiles", lambda *_a, **_k: ["gdpr"])
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.config_source_errors", lambda *a, **k: {})
    pol = Policy.from_config()
    assert evaluate("email", policy=pol).decision == Decision.REQUIRE_HUMAN


def test_active_keys_reads_config_and_env(monkeypatch):
    import maverick.config as config_mod

    monkeypatch.setattr(config_mod, "load_config", lambda: {
        "compliance": {"profiles": ["gdpr"]}
    })
    monkeypatch.setattr(config_mod, "config_source_errors", dict)
    monkeypatch.setenv("MAVERICK_COMPLIANCE_PROFILES", "hipaa, eu_ai_act")
    assert rc.active_keys() == ["gdpr", "hipaa", "eu_ai_act"]


def test_environment_only_activation_reaches_every_live_enforcement_path(monkeypatch):
    import maverick.config as config_mod
    from maverick.capability import capability_from_config
    from maverick.compliance_profiles import FLOOR_EGRESS_LOCK, requires_floor

    monkeypatch.setattr(config_mod, "load_config", dict)
    monkeypatch.setattr(config_mod, "config_source_errors", dict)
    monkeypatch.setenv("MAVERICK_COMPLIANCE_PROFILES", "gdpr,hipaa")

    policy = Policy.from_config()
    assert policy.compliance_profiles == ("gdpr", "hipaa")
    assert evaluate("email", policy=policy).decision == Decision.REQUIRE_HUMAN
    assert not capability_from_config("user:local").permits("email")
    assert requires_floor(FLOOR_EGRESS_LOCK)
    assert "gdpr-art32-outbound-transfer" in rc.obligations_checked("email")
    assert "hipaa-164-502b-minimum-necessary" in rc.obligations_checked("email")


# ---- the chokepoint ---------------------------------------------------------

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
    agent = Agent(ctx=ctx, role="coder", brief="b")
    agent.capability = None
    agent.tools.register(Tool(
        name="ping", description="ping", fn=lambda args: "pong",
        input_schema={"type": "object", "properties": {}},
    ))
    return agent


def _gov(monkeypatch, policy: Policy):
    monkeypatch.setattr(
        Policy,
        "from_config",
        classmethod(lambda cls: policy),
    )


def _capture(monkeypatch):
    import maverick.audit as audit
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        audit,
        "record",
        lambda kind, **kw: seen.append((kind, kw)) or True,
    )
    return seen


@pytest.mark.asyncio
async def test_a_denial_at_the_chokepoint_names_the_obligation(monkeypatch, tmp_path):
    deny = rc.Obligation("t-deny-ping", "Test Reg", "s. 1", "", rc.EFFECT_DENY,
                         actions=frozenset({"ping"}))
    monkeypatch.setitem(rc.REGULATIONS, "t", (deny,))
    # The active resolver has changed by evidence time. The denial must retain
    # the profile snapshot that actually produced the verdict.
    _activate(monkeypatch, [])
    _gov(monkeypatch, Policy(
        deny_actions=frozenset({"ping"}),
        compliance_profiles=("t",),
    ))
    seen = _capture(monkeypatch)
    out = await _agent(tmp_path)._run_tool("ping", {})
    assert "DENIED" in out
    row = next(kw for kind, kw in seen if kind == "governance_denied")
    assert row["obligation_id"] == "t-deny-ping"
    assert row["regulation"] == "Test Reg" and row["article"] == "s. 1"


@pytest.mark.asyncio
async def test_a_call_that_ran_records_the_obligations_it_was_checked_against(
        monkeypatch, tmp_path):
    floor = rc.Obligation("t-floor", "Test Reg", "s. 2", "", rc.EFFECT_REQUIRE_HUMAN,
                          min_risk="low")
    monkeypatch.setitem(rc.REGULATIONS, "t", (floor,))
    _activate(monkeypatch, [])
    # A profile may enforce only through capability attenuation, so provenance
    # is retained even when its governance Policy is otherwise empty.
    _gov(monkeypatch, Policy(compliance_profiles=("t",)))
    seen = _capture(monkeypatch)
    out = await _agent(tmp_path)._run_tool("ping", {})
    assert "pong" in out
    row = next(kw for kind, kw in seen if kind == "tool_call")
    assert row["obligations_checked"] == ["t-floor"]


@pytest.mark.asyncio
async def test_no_obligations_leaves_the_rows_exactly_as_before(monkeypatch, tmp_path):
    floor = rc.Obligation("t-floor", "Test Reg", "s. 2", "", rc.EFFECT_REQUIRE_HUMAN,
                          min_risk="low")
    monkeypatch.setitem(rc.REGULATIONS, "t", (floor,))
    # A later activation must not relabel an already evaluated, trusted-empty
    # policy snapshot.
    _activate(monkeypatch, ["t"])
    _gov(monkeypatch, Policy())
    seen = _capture(monkeypatch)
    await _agent(tmp_path)._run_tool("ping", {})
    row = next(kw for kind, kw in seen if kind == "tool_call")
    assert "obligations_checked" not in row


def test_flow_dispatch_denials_are_tagged_too(monkeypatch):
    deny = rc.Obligation("t-deny-ping", "Test Reg", "s. 1", "", rc.EFFECT_DENY,
                         actions=frozenset({"ping"}))
    monkeypatch.setitem(rc.REGULATIONS, "t", (deny,))
    _activate(monkeypatch, [])
    _gov(monkeypatch, Policy(
        deny_actions=frozenset({"ping"}),
        compliance_profiles=("t",),
    ))
    # The flow gate classifies before governance; clear that (the real shield
    # allows this benign call) so the test isolates the obligation tag on the
    # governance denial.
    monkeypatch.setattr("maverick.flow.ir.action_tool_policy_error", lambda t: "")
    seen = _capture(monkeypatch)
    from maverick.tool_authz import authorize
    err = authorize("ping", {}, origin="flow")
    assert err and "DENIED" in err
    row = next(kw for kind, kw in seen if kind == "governance_denied")
    assert row["obligation_id"] == "t-deny-ping"


def test_flow_dispatch_success_uses_the_evaluated_profile_snapshot(monkeypatch):
    floor = rc.Obligation(
        "t-floor",
        "Test Reg",
        "s. 2",
        "",
        rc.EFFECT_REQUIRE_HUMAN,
        min_risk="low",
    )
    monkeypatch.setitem(rc.REGULATIONS, "t", (floor,))
    _activate(monkeypatch, [])
    _gov(monkeypatch, Policy(compliance_profiles=("t",)))
    monkeypatch.setattr("maverick.flow.ir.action_tool_policy_error", lambda t: "")
    seen = _capture(monkeypatch)

    from maverick.tool_authz import authorize

    assert authorize("ping", {}, origin="flow") is None
    row = next(kw for kind, kw in seen if kind == "tool_call")
    assert row["obligations_checked"] == ["t-floor"]


@pytest.mark.asyncio
async def test_autonomy_replacement_preserves_governance_profile_snapshot(
    monkeypatch,
    tmp_path,
):
    marker = rc.Obligation(
        "t-marker",
        "Test Reg",
        "s. 3",
        "",
        rc.EFFECT_DENY,
        actions=frozenset({"ping"}),
    )
    monkeypatch.setitem(rc.REGULATIONS, "t", (marker,))
    _activate(monkeypatch, [])
    _gov(monkeypatch, Policy(
        deny_actions=frozenset({"other"}),
        compliance_profiles=("t",),
    ))
    monkeypatch.setattr("maverick.agent_autonomy.levels_enabled", lambda: True)
    monkeypatch.setattr(
        "maverick.agent_autonomy.decide",
        lambda *args, **kwargs: SimpleNamespace(
            decision="deny",
            reason="restricted rung",
            level=SimpleNamespace(value="restricted"),
            execute_by="agent",
        ),
    )
    observed = []
    real_tags = rc.audit_tags

    def _tags(action, rule, *, keys=None):
        observed.append(keys)
        return real_tags(action, rule, keys=keys)

    monkeypatch.setattr(rc, "audit_tags", _tags)
    _capture(monkeypatch)

    refusal, profiles = await _agent(tmp_path)._governance_denial("ping", {}, None)

    assert refusal and "autonomy" in refusal
    assert profiles == ("t",)
    assert observed == [("t",)]


@pytest.mark.asyncio
async def test_governance_known_empty_profile_snapshot_returns_empty_tuple(
    monkeypatch,
    tmp_path,
):
    _gov(monkeypatch, Policy())
    monkeypatch.setattr("maverick.agent_autonomy.levels_enabled", lambda: False)

    refusal, profiles = await _agent(tmp_path)._governance_denial("ping", {}, None)

    assert refusal is None
    assert profiles == ()


@pytest.mark.asyncio
async def test_governance_policy_outage_returns_unavailable_profile_provenance(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        Policy,
        "from_config",
        classmethod(
            lambda cls: (_ for _ in ()).throw(RuntimeError("policy unavailable"))
        ),
    )
    monkeypatch.setattr("maverick.agent_autonomy.levels_enabled", lambda: False)
    observed = []
    monkeypatch.setattr(
        rc,
        "audit_tags",
        lambda action, rule, *, keys=None: observed.append(keys) or {},
    )
    _capture(monkeypatch)

    refusal, profiles = await _agent(tmp_path)._governance_denial("ping", {}, None)

    assert refusal and "DENIED" in refusal
    assert profiles is None
    assert observed == [None]
