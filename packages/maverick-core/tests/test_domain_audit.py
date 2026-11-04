"""Governance-posture audit of the specialist roster.

domains-lint answers "is each pack well-formed?"; domains-audit answers "what
can these agents do, and what stops them?" -- the inventory a GRC reviewer
needs. These tests pin the load-bearing invariant (no drafting agent reaches a
state-mutator) and the report shape.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.domain import DomainProfile, builtin_dir, load_domains
from maverick.domain_audit import (
    audit_profile,
    audit_roster,
    summarize,
    to_json,
)

_BUILTIN = load_domains(builtin_dir())


def test_audit_captures_governance_posture():
    p = _BUILTIN["finance_ap"]
    a = audit_profile(p)
    assert a.suite == "finance"
    assert a.compartment.startswith("finance")
    assert a.is_builder is False
    assert a.reachable_dangerous == []          # a drafting agent reaches no mutator
    assert "release_payment" in a.denied_irreversible
    assert a.human_gate in ("approval", "review")
    assert a.deliverable                        # declares a deliverable
    assert a.n_refusals >= 2                     # at least the universal refusals


def test_roster_has_no_drafting_agent_reaching_a_mutator():
    # The headline provable-governance number across all 1,118 packs.
    s = summarize(audit_roster(_BUILTIN))
    assert s["packs"] >= 1000
    assert s["drafting_agents_reaching_a_mutator"] == 0
    assert s["packs_with_deliverable"] == s["packs"]


def test_human_gate_prefers_approval_over_review():
    from maverick.domain import OutputContract, WorkflowStep
    p = DomainProfile(
        name="x", allow_tools=["read_file"], deny_tools=["shell", "write_file"],
        max_risk="low",
        output=OutputContract(deliverable="d", consumers=["o"], gate="review"),
        workflow=[WorkflowStep("commit", gate="approval")],
    )
    audit = audit_profile(p)
    assert audit.human_gate == "approval"
    assert audit.declared_prompt_gate == "approval"
    assert audit.enforced_gate == "approval"


def test_intermediate_prompt_gate_is_not_reported_as_enforced():
    from maverick.domain import WorkflowStep
    p = DomainProfile(
        name="x", allow_tools=["read_file"], deny_tools=["shell", "write_file"],
        max_risk="low",
        workflow=[
            WorkflowStep("approval", gate="approval"),
            WorkflowStep("finish"),
        ],
    )

    audit = audit_profile(p)

    assert audit.declared_prompt_gate == "approval"
    assert audit.enforced_gate is None
    assert audit.human_gate is None
    summary = summarize([audit])
    assert summary["packs_with_human_gate"] == 0
    assert summary["packs_with_unenforced_prompt_gate"] == 1


def test_builder_is_flagged_as_builder_not_dangerous():
    builders = [a for a in audit_roster(_BUILTIN) if a.is_builder]
    assert builders, "expected coding builders in the roster"
    for a in builders:
        # A builder legitimately reaches shell/code_exec; it is recorded as a
        # builder, and the summary excludes it from the drafting-agent invariant.
        assert "self_edit" not in a.reachable_dangerous  # the one floor never relaxes


def test_high_risk_mutators_are_reachable_dangerous():
    p = DomainProfile(
        name="finance_poc_apply_patch",
        allow_tools=["read_file", "apply_patch"],
        max_risk="high",
    )
    a = audit_profile(p)
    assert a.is_builder is False
    assert "apply_patch" in a.reachable_dangerous
    assert summarize([a])["drafting_agents_reaching_a_mutator"] == 1


def test_irreversible_business_actions_are_reachable_dangerous():
    p = DomainProfile(
        name="finance_poc_release_payment",
        allow_tools=["read_file", "release_payment"],
        max_risk="high",
    )
    a = audit_profile(p)
    assert a.is_builder is False
    assert "release_payment" in a.reachable_dangerous
    assert summarize([a])["drafting_agents_reaching_a_mutator"] == 1


def test_shell_does_not_make_drafting_pack_a_builder():
    p = DomainProfile(
        name="finance_poc_shell",
        allow_tools=["read_file", "shell"],
        max_risk="high",
    )
    a = audit_profile(p)
    assert a.is_builder is False
    assert "shell" in a.reachable_dangerous
    assert summarize([a])["drafting_agents_reaching_a_mutator"] == 1

def test_json_export_is_well_formed():
    doc = to_json(audit_roster(_BUILTIN))
    assert set(doc) == {"summary", "packs"}
    assert len(doc["packs"]) == len(_BUILTIN)
    row = doc["packs"][0]
    for key in ("name", "suite", "compartment", "max_risk", "reachable_dangerous",
                "n_refusals", "human_gate", "declared_prompt_gate",
                "enforced_gate", "deliverable"):
        assert key in row


def test_cli_reports_and_exits_clean():
    from maverick.cli import main
    res = CliRunner().invoke(main, ["domains-audit"])
    assert res.exit_code == 0, res.output
    assert "must be 0" in res.output
    assert "with a declared deliverable" in res.output


def test_cli_json_export(tmp_path):
    import json

    from maverick.cli import main
    out = tmp_path / "audit.json"
    res = CliRunner().invoke(main, ["domains-audit", "--json", str(out)])
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text())
    assert doc["summary"]["drafting_agents_reaching_a_mutator"] == 0


@pytest.mark.parametrize("levels", ["0", "1"])
@pytest.mark.parametrize("grounding", ["0", "1"])
def test_the_roster_audits_each_pack_as_it_audits_alone(monkeypatch, levels, grounding):
    # The roster reads a dial that is off once, not once per pack.
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", levels)
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", grounding)
    subset = {name: _BUILTIN[name] for name in sorted(_BUILTIN)[::25] + ["finance_ap"]}
    roster = audit_roster(subset)
    assert roster == [audit_profile(subset[name]) for name in sorted(subset)]
    granted = {tool for a in roster for tool in a.runtime_expansion}
    assert ({"email", "notify", "calendar"} <= granted) is (levels == "1")


def test_a_dial_that_is_off_is_read_once_per_roster(monkeypatch):
    from maverick import agent_autonomy, domain

    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "0")
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "0")
    reads = {"levels": 0, "grounding": 0}
    levels_enabled, data_grounding_enabled = agent_autonomy.levels_enabled, domain.data_grounding_enabled

    def counting_levels(*override):
        reads["levels"] += not override
        return levels_enabled(*override)

    def counting_grounding(*override):
        reads["grounding"] += not override
        return data_grounding_enabled(*override)

    monkeypatch.setattr(agent_autonomy, "levels_enabled", counting_levels)
    monkeypatch.setattr(domain, "data_grounding_enabled", counting_grounding)
    subset = {name: _BUILTIN[name] for name in sorted(_BUILTIN)[:40]}
    assert all(not a.runtime_expansion for a in audit_roster(subset))
    assert reads == {"levels": 1, "grounding": 1}


def test_posture_counts_equal_the_full_audit_including_overrides(tmp_path, monkeypatch):
    # The workforce posture call audited all 2,031 packs to count these two.
    from maverick.domain_audit import autonomy_posture

    names = sorted(_BUILTIN)
    (tmp_path / "config.toml").write_text(
        f'[[workforce.agents]]\nname = "{names[0]}"\ndefault = "auto"\nonboarding = false\n'
        f'[[workforce.agents]]\nname = "{names[3]}"\ndefault = "observe"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    subset = {name: _BUILTIN[name] for name in names[:60]}
    full = summarize(audit_roster(subset))
    posture = autonomy_posture(subset)
    assert posture == {"autonomy_posture": full["autonomy_posture"], "packs_onboarding": full["packs_onboarding"]}
    assert posture["autonomy_posture"]["auto"] >= 1 and posture["autonomy_posture"]["observe"] >= 1


def test_an_audit_without_runtime_differs_only_in_its_runtime_fields(monkeypatch):
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    subset = {name: _BUILTIN[name] for name in sorted(_BUILTIN)[::40]}
    with_runtime = audit_roster(subset)
    without = audit_roster(subset, runtime=False)
    assert any(a.runtime_expansion for a in with_runtime)
    assert all(not a.runtime_expansion and not a.runtime_reachable_dangerous for a in without)
    blank = {"runtime_expansion": [], "runtime_reachable_dangerous": []}
    from dataclasses import replace
    assert [replace(a, **blank) for a in with_runtime] == without
    assert summarize(with_runtime) == summarize(without)
