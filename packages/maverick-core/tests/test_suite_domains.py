"""Built-in business-suite domain packs: load + safety invariants.

These packs are the agents the factory spawns for the business suites (Operations,
Legal, IT-GRC, Sales/GTM, HR, Strategy, and Product&Engineering). Almost every agent
*analyzes and drafts* but never acts on the world, so it must load, carry a persona +
a sealed compartment, and run under a read-only, low/medium-risk capability envelope
(deny wins; the whitelist excludes shell/write). The exception is the
Product&Engineering *builders* -- coding agents that need sandbox-mediated
shell/code_exec -- which instead carry the one hard floor that can never relax: an
agent may build, but never modify its own runtime/safety/controls (``self_edit``
denied). This test is the contract that keeps a new or edited pack from quietly
granting a dangerous tool.
"""
from __future__ import annotations

from maverick.domain import (
    builtin_dir,
    lint_profile,
    load_domains,
    render_workflow_prompt,
)

_BUILTIN = load_domains(builtin_dir())


def _by_prefix(pre: str) -> dict:
    return {k: v for k, v in _BUILTIN.items() if k.startswith(pre)}


_OPS = _by_prefix("ops_")
_LEGAL = _by_prefix("legal_")
_ITGRC = _by_prefix("itgrc_")
_GTM = _by_prefix("gtm_")
_HR = _by_prefix("hr_")
_STRAT = _by_prefix("strat_")
_PE = _by_prefix("pe_")
_COM = _by_prefix("com_")

# P&E splits into coding *builders* (sandbox shell/code_exec) and read-only seats.
_PE_BUILDERS = {k: v for k, v in _PE.items()
                if "code_exec" in v.allow_tools or "shell" in v.allow_tools}
_PE_READONLY = {k: v for k, v in _PE.items() if k not in _PE_BUILDERS}

# Every read-only/sealed pack across all suites obeys the same envelope.
_SUITE = {**_OPS, **_LEGAL, **_ITGRC, **_GTM, **_HR, **_STRAT, **_PE_READONLY}


def test_suites_present():
    # Each suite is fully built out as DomainProfile packs.
    assert len(_OPS) >= 39, f"expected >=39 Operations packs, found {len(_OPS)}"
    assert len(_LEGAL) >= 36, f"expected >=36 Legal packs, found {len(_LEGAL)}"
    assert len(_ITGRC) >= 55, f"expected >=55 IT-GRC packs, found {len(_ITGRC)}"
    assert len(_GTM) >= 50, f"expected >=50 Sales/GTM packs, found {len(_GTM)}"
    assert len(_HR) >= 46, f"expected >=46 HR packs, found {len(_HR)}"
    assert len(_STRAT) >= 31, f"expected >=31 Strategy packs, found {len(_STRAT)}"
    assert len(_PE) >= 46, f"expected >=46 Product&Eng packs, found {len(_PE)}"
    assert len(_PE_BUILDERS) >= 20, f"expected >=20 P&E builders, found {len(_PE_BUILDERS)}"
    assert len(_COM) >= 11, f"expected >=11 Commerce packs, found {len(_COM)}"


def test_every_suite_pack_loads_with_persona_and_compartment():
    assert _SUITE, "no suite packs discovered"
    for name, p in {**_SUITE, **_PE_BUILDERS}.items():
        assert p.name == name
        assert p.persona.strip(), f"{name}: empty persona"
        assert p.compartment, f"{name}: missing compartment"


def test_suite_packs_are_read_only_and_safe():
    for name, p in _SUITE.items():
        assert p.max_risk in ("low", "medium"), f"{name}: risk={p.max_risk!r}"
        cap = p.capability(f"agent:{name}")
        assert cap.permits("read_file") is True, f"{name}: cannot read"
        # Mutating / host-control tools must be unreachable (deny + whitelist + ceiling).
        for dangerous in ("shell", "write_file", "code_exec", "computer", "home_assistant"):
            assert cap.permits(dangerous) is False, f"{name}: {dangerous} reachable!"
        assert "shell" in p.deny_tools and "write_file" in p.deny_tools, (
            f"{name}: must explicitly deny shell + write_file"
        )


def test_legal_matter_packs_deny_external_web_search():
    # Legal packs bound to privileged matter data are sealed: they may search the
    # local knowledge base / CourtListener connectors, but must not send model-built
    # queries to external web-search providers.
    for name, p in _LEGAL.items():
        if "legal_matter" not in p.knowledge_sources:
            continue
        cap = p.capability(f"agent:{name}")
        assert "web_search" not in p.allow_tools, f"{name}: web_search allowed for legal matter"
        assert "web_search" in p.deny_tools, f"{name}: web_search must be denied"
        assert cap.permits("web_search") is False, f"{name}: web_search reachable!"


def test_strat_sealed_deal_execution_has_no_web_egress():
    # Deal-execution handles MNPI inside the sealed corp-dev compartment. Unlike
    # target sourcing, it only uses the deal compartment and legal/knowledge inputs,
    # so model-controlled web_search queries must be explicitly unreachable.
    p = _STRAT["strat_deal_execution"]
    cap = p.capability("agent:strat_deal_execution")
    assert "web_search" not in p.allow_tools
    assert "web_search" in p.deny_tools
    assert cap.permits("web_search") is False


def test_pe_builders_can_build_but_never_self_edit():
    # P&E coding agents legitimately need sandbox shell/code_exec; the floor that can
    # never relax is self-modification -- an agent never edits its own runtime/safety.
    assert _PE_BUILDERS, "no P&E builder packs discovered"
    for name, p in _PE_BUILDERS.items():
        cap = p.capability(f"agent:{name}")
        assert cap.permits("read_file") is True, f"{name}: cannot read"
        assert "self_edit" in p.deny_tools, f"{name}: builder must deny self_edit"
        assert cap.permits("self_edit") is False, f"{name}: self_edit reachable!"


def test_ops_compartments_are_sealed_by_tower():
    # Every Operations pack sits in an ops_* compartment (the Rung-2 seal boundary).
    for name, p in _OPS.items():
        assert p.compartment.startswith("ops_"), f"{name}: compartment={p.compartment!r}"


def test_suite_compartments_match_their_prefix():
    # A pack's compartment shares its suite prefix, so a Rung-2 seal quarantines the
    # whole suite/tower at once (the factory<->safety hinge).
    for pre, packs in (("itgrc_", _ITGRC), ("gtm_", _GTM), ("hr_", _HR),
                       ("strat_", _STRAT), ("pe_", _PE), ("com_", _COM)):
        for name, p in packs.items():
            assert p.compartment.startswith(pre), f"{name}: compartment={p.compartment!r}"


# Every built-in pack that is NOT a coding builder (no shell/code_exec in its
# allowlist) is read-only by design. The per-suite tests above cover seven
# suites by name; this covers the WHOLE roster -- finance and all the industry
# verticals (banking, healthcare, retail, tax, ...) included -- so a future
# edit anywhere that grants a drafting agent shell/write is caught.
_BUILDERS = {n: p for n, p in _BUILTIN.items()
             if "code_exec" in p.allow_tools or "shell" in p.allow_tools}
_NON_BUILDERS = {n: p for n, p in _BUILTIN.items() if n not in _BUILDERS}


def test_every_non_builder_pack_is_read_only_and_safe():
    assert len(_NON_BUILDERS) > 1000, f"only {len(_NON_BUILDERS)} non-builders?"
    for name, p in _NON_BUILDERS.items():
        # A high ceiling is legitimate only for a spawn-router (it holds the
        # privileged PARENT grant so children can attenuate down); everything
        # else stays low/medium. Either way the mutators must be unreachable.
        if p.max_risk == "high":
            assert {"spawn_subagent", "spawn_swarm"} & set(p.allow_tools), (
                f"{name}: high risk but not a spawn-router")
        else:
            assert p.max_risk in ("low", "medium"), f"{name}: risk={p.max_risk!r}"
        cap = p.capability(f"agent:{name}")
        # Mutating / host-control tools must be unreachable for a drafting agent.
        for dangerous in ("shell", "write_file", "code_exec", "computer"):
            assert cap.permits(dangerous) is False, f"{name}: {dangerous} reachable!"


def test_every_non_builder_pack_denies_the_readonly_floor():
    # Defense-in-depth: the allowlist already excludes shell/write_file, but an
    # explicit deny is what survives a later allowlist edit. The whole roster
    # carries it, not just the seven suites with bespoke tests.
    for name, p in _NON_BUILDERS.items():
        assert "shell" in p.deny_tools, f"{name}: must explicitly deny shell"
        assert "write_file" in p.deny_tools, f"{name}: must explicitly deny write_file"


def test_every_builder_denies_self_edit():
    # The one floor a coding agent can never relax, asserted across ALL builders
    # (not only the P&E suite): an agent may build, never edit its own runtime.
    assert _BUILDERS, "no builder packs discovered"
    for name, p in _BUILDERS.items():
        cap = p.capability(f"agent:{name}")
        assert "self_edit" in p.deny_tools, f"{name}: builder must deny self_edit"
        assert cap.permits("self_edit") is False, f"{name}: self_edit reachable!"


# --- Roster-wide quality harness (pure: render + lint, no spawn) -------------
# These run over EVERY built-in pack so a future edit anywhere that breaks the
# contract, the tool integrity, or the lint gate is caught immediately.

_GATE_RANK = {None: 0, "review": 1, "approval": 2}


def test_whole_roster_lints_error_free():
    # The 1,118-pack roster carries zero lint ERRORs at all times (empty
    # allowlist, bad max_risk, nameless/duplicate workflow steps would each fail).
    for name, p in _BUILTIN.items():
        errors, _ = lint_profile(p)
        assert errors == [], (name, errors)


def test_every_workflow_step_tool_is_in_allowlist():
    # A playbook may only hint tools the pack actually grants -- a step naming a
    # tool outside allow_tools is a dead reference (and a lint warning).
    for name, p in _BUILTIN.items():
        allow = set(p.allow_tools)
        for step in p.workflow:
            stray = [t for t in step.tools if t not in allow]
            assert not stray, f"{name}: step {step.name!r} names non-allowed {stray}"


def test_every_pack_renders_a_persona_and_playbook():
    # Every pack must produce a non-empty persona and, where it has a workflow,
    # render every step into the system prompt -- the spawn path depends on this.
    from maverick.domain_discipline import augment_persona
    for name, p in _BUILTIN.items():
        persona = augment_persona(p.name, p.persona)
        assert persona.strip(), f"{name}: empty persona after augmentation"
        wf = render_workflow_prompt(p.workflow)
        if p.workflow:
            assert "Workflow" in wf, f"{name}: workflow did not render"
            for step in p.workflow:
                assert step.name in wf, f"{name}: step {step.name!r} missing from render"


def test_deliverable_gate_not_lighter_than_playbook():
    # The deliverable's sign-off is never lighter than the human-handoff its own
    # playbook ends on (a 'review' deliverable from an 'approval' final step).
    for name, p in _BUILTIN.items():
        if p.output.deliverable and p.workflow:
            final = p.workflow[-1].gate
            assert _GATE_RANK.get(final, 0) <= _GATE_RANK.get(p.output.gate, 0), (
                f"{name}: output.gate={p.output.gate!r} < final step gate={final!r}")


def test_every_pack_declares_output_and_workflow():
    # Coverage guard: the consumption surface stays complete -- every pack keeps
    # a declared deliverable and a playbook (regression guard for the roster).
    for name, p in _BUILTIN.items():
        assert p.output.deliverable, f"{name}: missing [output] deliverable"
        assert p.workflow, f"{name}: missing [[workflow]] playbook"


_VALID_EFFORTS = {None, "low", "medium", "high", "xhigh", "max"}


def test_every_pack_effort_tier_is_valid():
    # A declared effort tier is always a real level (an invalid one is a lint
    # ERROR, but assert it across the roster too).
    for name, p in _BUILTIN.items():
        assert p.effort in _VALID_EFFORTS, f"{name}: effort={p.effort!r}"


def test_high_stakes_packs_carry_high_effort():
    # Right-sizing sentinels: severe-failure-cost judgment work runs deep.
    for name in ("finance_sox", "finance_revrec", "bank_aml_alerts",
                 "hc_prior_auth", "strat_valuation"):
        assert _BUILTIN[name].effort == "high", name


def test_high_volume_packs_carry_low_effort():
    # ...and clerical, high-throughput work runs light.
    for name in ("cx_status_page", "tax_efile_status", "proc_po_chaser"):
        assert _BUILTIN[name].effort == "low", name


# A pack that names a known SaaS-connector tool must scope the vendor's host in
# allow_hosts, so the egress lock (enterprise.py) lets the connector seat reach
# its system instead of blocking it. Guards the wired packs from drift.
_VENDOR_HOSTS = {
    "billdotcom": "*.bill.com", "coupa": "*.coupa.com", "tipalti": "*.tipalti.com",
    "adp": "*.adp.com", "gusto": "*.gusto.com", "netsuite": "*.netsuite.com",
    "workday": "*.workday.com",
}


def test_vendor_connector_packs_scope_their_egress_hosts():
    for name, p in _BUILTIN.items():
        hosts = set(p.allow_hosts)
        for tool in p.allow_tools:
            for vendor, host in _VENDOR_HOSTS.items():
                if vendor in tool.lower():
                    assert host in hosts, (
                        f"{name}: names {vendor} tool {tool!r} but {host} not in "
                        "allow_hosts -- the egress lock would block the connector")


def test_every_hr_pack_refuses_eu_ai_act_art5():
    # Every HR specialist carries the workplace emotion-inference + biometric
    # prohibitions (EU AI Act Art. 5) -- the suite with refused, not gated, uses.
    from maverick.domain_refusals import refusals_for
    hr = {n: p for n, p in _BUILTIN.items() if n.startswith("hr_")}
    assert hr
    for name in hr:
        items = refusals_for(name)
        assert any("emotion" in r for r in items), f"{name}: no Art-5 emotion refusal"
        assert any("biometric" in r for r in items), f"{name}: no biometric refusal"


def test_physical_world_packs_refuse_safety_actuation():
    from maverick.domain_refusals import refusals_for
    for pre in ("ops_", "mfg_", "util_"):
        packs = {n: p for n, p in _BUILTIN.items() if n.startswith(pre)}
        assert packs, pre
        for name in packs:
            items = refusals_for(name)
            assert any("interlock" in r or "safety-critical" in r for r in items), name
