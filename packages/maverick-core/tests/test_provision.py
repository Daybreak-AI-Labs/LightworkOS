"""Tests for the agent factory's capability-provisioning step (maverick.provision).

Analysis is pure/read-only; application routes through the governed
self_learning paths. We inject fakes for the catalog search, skill install, and
tool-synthesis so these tests never touch the network, an LLM, or disk.
"""
from __future__ import annotations

import pytest
from maverick import provision
from maverick.domain import DomainProfile, WorkflowStep
from maverick.self_learning import Candidate


def _profile(**kw) -> DomainProfile:
    kw.setdefault("name", "acme_specialist")
    kw.setdefault("description", "Reconcile vendor invoices against POs.")
    kw.setdefault("workflow", [
        WorkflowStep("Pull invoices", "Fetch open invoices from the ledger."),
        WorkflowStep("Match to POs", "Three-way match invoice to PO and receipt."),
    ])
    return DomainProfile(**kw)


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------
def test_analyze_finds_skill_gap_per_phrase(monkeypatch):
    def fake_search(need, *, kinds=(), max_n=5, indexes=None):
        return [Candidate(kind="skill", name="invoice-recon", summary="3-way match",
                          source="builtin", score=0.8)]

    monkeypatch.setattr(provision, "_installed_skill_names", lambda: set())
    monkeypatch.setattr("maverick.self_learning.search_capabilities", fake_search)

    plan = provision.analyze_profile(_profile())
    assert not plan.is_empty()
    # One candidate, de-duplicated across the (description + 2 steps) phrases.
    assert [g.candidate for g in plan.skill_gaps] == ["invoice-recon"]
    assert plan.skill_gaps[0].resolution == "acquire_skill"


def test_analyze_skips_already_installed_skill(monkeypatch):
    def fake_search(need, *, kinds=(), max_n=5, indexes=None):
        return [Candidate(kind="skill", name="invoice-recon", summary="", source="x", score=0.9)]

    monkeypatch.setattr(provision, "_installed_skill_names", lambda: {"invoice-recon"})
    monkeypatch.setattr("maverick.self_learning.search_capabilities", fake_search)

    plan = provision.analyze_profile(_profile())
    assert plan.skill_gaps == []


def test_analyze_respects_min_score(monkeypatch):
    def fake_search(need, *, kinds=(), max_n=5, indexes=None):
        return [Candidate(kind="skill", name="weak", summary="", source="x", score=0.05)]

    monkeypatch.setattr(provision, "_installed_skill_names", lambda: set())
    monkeypatch.setattr("maverick.self_learning.search_capabilities", fake_search)

    plan = provision.analyze_profile(_profile(), min_score=0.2)
    assert plan.skill_gaps == []


def test_tool_gaps_only_when_known_tools_given(monkeypatch):
    monkeypatch.setattr(provision, "_installed_skill_names", lambda: set())
    monkeypatch.setattr("maverick.self_learning.search_capabilities",
                        lambda *a, **k: [])
    monkeypatch.setattr(provision, "_generated_tool_names", lambda: set())

    prof = _profile(allow_tools=["read_file", "frobnicate_widgets"])

    # No known_tools -> we can't tell missing from builtin, so no tool gaps.
    assert provision.analyze_profile(prof).tool_gaps == []

    # With the live tool set, the undeclared one is flagged for synthesis.
    plan = provision.analyze_profile(prof, known_tools={"read_file", "web_search"})
    needs = {g.need: g.resolution for g in plan.tool_gaps}
    assert needs == {"frobnicate_widgets": "generate_tool"}


def test_tool_gaps_dedupe_duplicate_allow_tools(monkeypatch):
    # A duplicated allow_tools entry must produce ONE gap, not N -- otherwise
    # apply_plan would redundantly synthesize the same tool repeatedly.
    monkeypatch.setattr(provision, "_installed_skill_names", lambda: set())
    monkeypatch.setattr("maverick.self_learning.search_capabilities", lambda *a, **k: [])
    monkeypatch.setattr(provision, "_generated_tool_names", lambda: set())
    prof = _profile(allow_tools=["frob", "frob", "frob", "read_file"])
    plan = provision.analyze_profile(prof, known_tools={"read_file"})
    assert [g.need for g in plan.tool_gaps] == ["frob"]


def test_missing_tool_resolved_by_strong_catalog_skill(monkeypatch):
    def fake_search(need, *, kinds=(), max_n=5, indexes=None):
        return [Candidate(kind="skill", name="send-sms", summary="Twilio SMS",
                          source="catalog", score=0.7)]

    monkeypatch.setattr("maverick.self_learning.search_capabilities", fake_search)
    gap = provision._classify_missing_tool("send_sms")
    assert gap.resolution == "acquire_skill"
    assert gap.candidate == "send-sms"


# --------------------------------------------------------------------------
# application gating
# --------------------------------------------------------------------------
def test_apply_skips_when_unapproved():
    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="skill", need="x", resolution="acquire_skill",
                                candidate="a"),
    ])
    res = provision.apply_plan(plan, approved=False)
    assert res.acquired == [] and res.skipped


def test_apply_skips_when_self_learning_off(monkeypatch):
    monkeypatch.setattr("maverick.self_learning.enabled", lambda: False)
    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="skill", need="x", resolution="acquire_skill",
                                candidate="a"),
    ])
    res = provision.apply_plan(plan, approved=True)
    assert res.acquired == []
    assert any("self-learning off" in s for s in res.skipped)


def test_apply_installs_skill(monkeypatch):
    calls = []
    monkeypatch.setattr("maverick.self_learning.enabled", lambda: True)
    monkeypatch.setattr("maverick.self_learning.settings",
                        lambda: {"max_acquisitions": 5, "create_tools": True})
    monkeypatch.setattr("maverick.self_learning.acquire_skill",
                        lambda name, need="": calls.append((name, need)) or "body")

    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="skill", need="three-way match",
                                resolution="acquire_skill", candidate="invoice-recon"),
    ])
    res = provision.apply_plan(plan, approved=True)
    assert res.acquired == ["invoice-recon"]
    assert calls == [("invoice-recon", "three-way match")]


def test_apply_records_skill_failure(monkeypatch):
    def boom(name, need=""):
        raise ValueError("no such catalog skill")

    monkeypatch.setattr("maverick.self_learning.enabled", lambda: True)
    monkeypatch.setattr("maverick.self_learning.settings",
                        lambda: {"max_acquisitions": 5, "create_tools": True})
    monkeypatch.setattr("maverick.self_learning.acquire_skill", boom)

    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="skill", need="x", resolution="acquire_skill",
                                candidate="missing"),
    ])
    res = provision.apply_plan(plan, approved=True)
    assert res.acquired == []
    assert res.failed and res.failed[0][0] == "missing"


def test_apply_generates_tool_and_registers(monkeypatch):
    registered = []

    class FakeTool:
        name = "frobnicate_widgets"

    monkeypatch.setattr("maverick.self_learning.enabled", lambda: True)
    monkeypatch.setattr("maverick.self_learning.settings",
                        lambda: {"max_acquisitions": 5, "create_tools": True})
    monkeypatch.setattr(provision, "_generate_tool",
                        lambda need, llm=None, sandbox=None: FakeTool())

    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="tool", need="frobnicate_widgets",
                                resolution="generate_tool"),
    ])
    res = provision.apply_plan(plan, approved=True, llm=object(),
                               register=registered.append)
    assert res.generated == ["frobnicate_widgets"]
    assert registered and registered[0].name == "frobnicate_widgets"


def test_apply_generate_tool_needs_llm(monkeypatch):
    monkeypatch.setattr("maverick.self_learning.enabled", lambda: True)
    monkeypatch.setattr("maverick.self_learning.settings",
                        lambda: {"max_acquisitions": 5, "create_tools": True})
    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="tool", need="x", resolution="generate_tool"),
    ])
    res = provision.apply_plan(plan, approved=True, llm=None)
    assert res.generated == []
    assert any("no LLM" in s for s in res.skipped)


def test_apply_zero_budget_acquires_nothing(monkeypatch):
    monkeypatch.setattr("maverick.self_learning.enabled", lambda: True)
    monkeypatch.setattr("maverick.self_learning.settings",
                        lambda: {"max_acquisitions": 5, "create_tools": True})
    monkeypatch.setattr("maverick.self_learning.acquire_skill",
                        lambda name, need="": "body")
    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="skill", need="a", resolution="acquire_skill",
                                candidate="one"),
    ])
    # cap==0 must mean none -- not floored to one.
    res = provision.apply_plan(plan, approved=True, max_acquisitions=0)
    assert res.acquired == []


def test_apply_respects_acquisition_budget(monkeypatch):
    monkeypatch.setattr("maverick.self_learning.enabled", lambda: True)
    monkeypatch.setattr("maverick.self_learning.settings",
                        lambda: {"max_acquisitions": 1, "create_tools": True})
    monkeypatch.setattr("maverick.self_learning.acquire_skill",
                        lambda name, need="": "body")

    plan = provision.ProvisioningPlan("p", [
        provision.CapabilityGap(kind="skill", need="a", resolution="acquire_skill",
                                candidate="one"),
        provision.CapabilityGap(kind="skill", need="b", resolution="acquire_skill",
                                candidate="two"),
    ])
    res = provision.apply_plan(plan, approved=True)
    assert res.acquired == ["one"]
    assert any("budget reached" in s for s in res.skipped)


# --------------------------------------------------------------------------
# tool-name sanitation + plan rendering
# --------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("send_sms", "send_sms"),
    ("Send-SMS!", "send_sms"),
    ("3way_match", "t_3way_match"),
    ("  Weird  Name  ", "weird_name"),
])
def test_sanitize_tool_name(raw, expected):
    assert provision._sanitize_tool_name(raw) == expected


def test_plan_summary_lists_gaps():
    plan = provision.ProvisioningPlan("acme", [
        provision.CapabilityGap(kind="skill", need="x", resolution="acquire_skill",
                                candidate="a", summary="does a"),
        provision.CapabilityGap(kind="tool", need="y", resolution="generate_tool"),
    ])
    text = plan.summary()
    assert "acme" in text and "install skill 'a'" in text and "synthesize tool" in text


def test_empty_plan_summary():
    plan = provision.ProvisioningPlan("acme", [])
    assert "no capability gaps" in plan.summary()
    assert plan.is_empty()
