"""The Finance Operating Profile: each [finance] key changes what the kernel does.

framework selects a policy pack, materiality raises review scope, the
automation ladder gates finance actions with hard floors that config cannot
lower, the separation-of-duties mode blocks or records at action time, and the
approval timeout never lets an unanswered finance approval through. With the
finance layer off, or a key unset, nothing changes.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal

import pytest
from maverick.finance import profile as fin
from maverick.governance import Decision, GovernancePolicyError, Policy, evaluate
from maverick.tools import Tool

_ON = "[finance_operations]\nenable = true\n"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _config(tmp_path, text: str) -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def _decision(action: str, **kw):
    return evaluate(action, policy=Policy.from_config(), **kw)


# ------------------------------------------------------------ layer off / unset

def test_unset_keys_and_a_disabled_layer_change_nothing(tmp_path):
    _config(tmp_path, _ON)
    assert fin.configured_profile() is None
    assert Policy.from_config().is_empty()
    # Profile keys without the finance layer are ignored entirely.
    _config(tmp_path, '[finance]\nframework = "us_gaap"\nmateriality = 100\n'
                      '[finance.automation]\ndefault = "draft"\n'
                      '[finance.sod]\nmode = "enforce"\n')
    assert fin.configured_profile() is None
    assert Policy.from_config().is_empty()
    assert _decision("release_payment").decision is Decision.ALLOW
    assert fin.check_action_sod("release_payment") is None


def test_malformed_profile_fails_closed(tmp_path):
    _config(tmp_path, _ON + '[finance]\nframework = "local_gaap"\n')
    with pytest.raises(GovernancePolicyError):
        Policy.from_config()


# ------------------------------------------------------------ automation ladder

def test_draft_level_denies_and_approve_level_needs_a_person(tmp_path):
    _config(tmp_path, _ON + '[finance.automation]\ndefault = "draft"\n')
    verdict = _decision("approve_expense")
    assert verdict.decision is Decision.DENY
    assert verdict.rule == "finance_automation:draft"
    # A tool that is not a finance action is untouched.
    assert _decision("read_file").decision is Decision.ALLOW
    _config(tmp_path, _ON + '[finance.automation]\ndefault = "approve"\n')
    verdict = _decision("approve_expense")
    assert verdict.decision is Decision.REQUIRE_HUMAN
    assert verdict.rule == "finance_automation:approve"


def test_auto_threshold_runs_only_under_a_threshold_with_an_amount(tmp_path):
    _config(tmp_path, _ON + '[finance.automation]\ndefault = "auto_threshold"\n')
    # No threshold anywhere: every call waits for a person.
    assert _decision("approve_expense", amount=10.0).decision is Decision.REQUIRE_HUMAN
    _config(tmp_path, _ON + '[governance.require_human_above]\n"*" = 1000\n'
                      '[finance.automation]\ndefault = "auto_threshold"\n')
    assert _decision("approve_expense", amount=500.0).decision is Decision.ALLOW
    assert _decision("approve_expense", amount=5000.0).decision is Decision.REQUIRE_HUMAN
    missing = _decision("approve_expense")
    assert missing.decision is Decision.REQUIRE_HUMAN
    assert missing.rule == "require_human_above"


def test_hard_floors_hold_whatever_the_default(tmp_path):
    _config(tmp_path, _ON + '[governance.require_human_above]\n"*" = 1000\n'
                      '[finance.automation]\ndefault = "straight_through"\n')
    for action in ("release_payment", "post_journal_entry", "wire_transfer",
                   "run_payroll", "file_with_sec", "close_period"):
        verdict = _decision(action, amount=1.0)
        assert verdict.decision is Decision.REQUIRE_HUMAN, action
        assert verdict.rule == "finance_automation:approve", action
    # A non-floored finance action really runs straight through.
    assert _decision("send_invoice", amount=1.0).decision is Decision.ALLOW
    _config(tmp_path, _ON + '[governance.require_human_above]\n"*" = 1000\n'
                      '[finance.automation]\ndefault = "auto_threshold"\n')
    assert _decision("release_payment", amount=1.0).decision is Decision.REQUIRE_HUMAN
    assert _decision("approve_expense", amount=1.0).decision is Decision.ALLOW


def test_an_entry_lowering_a_hard_floor_is_refused(tmp_path):
    _config(tmp_path, _ON + '[finance.automation]\n"ap.release_payment" = "straight_through"\n')
    with pytest.raises(GovernancePolicyError):
        Policy.from_config()
    with pytest.raises(ValueError, match="hard-floored"):
        fin.parse_profile({"finance": {"automation": {"post_journal_entry": "auto_threshold"}}})
    # Raising a floor, or leaving it at approve, is fine.
    parsed = fin.parse_profile({"finance": {"automation": {"release_payment": "draft"}}})
    assert fin.automation_levels(parsed)["release_payment"] == "draft"


def test_per_class_entries_override_the_default(tmp_path):
    _config(tmp_path, _ON + '[finance.automation]\ndefault = "draft"\n'
                      '"ar.send_invoice" = "straight_through"\n'
                      'approve_po = "approve"\n')
    assert _decision("send_invoice").decision is Decision.ALLOW
    assert _decision("approve_po").decision is Decision.REQUIRE_HUMAN
    assert _decision("approve_expense").decision is Decision.DENY


def test_levels_never_loosen_regimes(tmp_path):
    _config(tmp_path, _ON + '[finance]\nregimes = ["aml"]\n'
                      '[finance.automation]\ndefault = "straight_through"\n'
                      '"treasury.ach_send" = "approve"\n')
    verdict = _decision("approve_vendor")
    assert verdict.decision is Decision.REQUIRE_HUMAN  # the AML pack still gates it
    assert verdict.rule == "require_human_actions"


# ------------------------------------------------------------------ framework

def test_framework_selects_its_policy_pack(tmp_path):
    _config(tmp_path, _ON + '[finance]\nframework = "us_gaap"\n')
    assert _decision("reverse_impairment_loss").decision is Decision.DENY
    assert _decision("apply_lifo_inventory").decision is Decision.ALLOW
    assert _decision("post_journal_entry").decision is Decision.REQUIRE_HUMAN
    _config(tmp_path, _ON + '[finance]\nframework = "ifrs"\n')
    assert _decision("reverse_impairment_loss").decision is Decision.REQUIRE_HUMAN
    assert _decision("apply_lifo_inventory").decision is Decision.DENY


def test_framework_unions_strictest_wins_with_regimes(tmp_path):
    _config(tmp_path, _ON + '[finance]\nframework = "ifrs"\nregimes = ["sec"]\n')
    assert _decision("file_with_sec").decision is Decision.REQUIRE_HUMAN
    assert _decision("apply_lifo_inventory").decision is Decision.DENY


# ---------------------------------------------------------------- materiality

def _payment(txid: str, amount: str, when: str):
    from maverick.finance.anomaly_engine import FinanceTransaction

    return FinanceTransaction(
        transaction_id=txid, amount=Decimal(amount), currency="USD", posted_at=when,
        source_system="erp-ap", source_record_id=f"ap/{txid}", counterparty_id="v-1",
        source_uri=f"erp://payments/{txid}",
        source_sha256=hashlib.sha256(txid.encode()).hexdigest(),
    )


def _duplicate_severity(config) -> tuple[str, dict]:
    from maverick.finance.anomaly_engine import DUPLICATE_RULE_ID, scan_transactions

    rows = [_payment("t1", "30000", "2026-01-05T10:00:00+00:00"),
            _payment("t2", "30000", "2026-01-05T11:00:00+00:00")]
    report = scan_transactions(rows, config=config)
    finding = next(f for f in report.findings if f.rule_id == DUPLICATE_RULE_ID)
    return finding.severity, report.config


def test_materiality_raises_review_scope(tmp_path):
    from maverick.finance.anomaly_engine import (
        FinanceAnomalyConfig,
        with_configured_materiality,
    )

    _config(tmp_path, _ON)
    unset = with_configured_materiality(FinanceAnomalyConfig())
    severity, bound = _duplicate_severity(unset)
    assert severity == "medium" and "materiality" not in bound
    _config(tmp_path, _ON + "[finance]\nmateriality = 50000\n")
    configured = with_configured_materiality(FinanceAnomalyConfig())
    assert configured.materiality == Decimal("50000.0")
    severity, bound = _duplicate_severity(configured)
    # 60,000 of duplicated payments is at or above materiality: a second,
    # independent reviewer is now required to close it.
    assert severity == "high" and bound["materiality"] == "50000"
    _config(tmp_path, _ON + "[finance]\nmateriality = 100000\n")
    severity, _ = _duplicate_severity(with_configured_materiality(FinanceAnomalyConfig()))
    assert severity == "medium"


def test_materiality_caps_what_runs_automatically(tmp_path):
    _config(tmp_path, _ON + '[finance]\nmateriality = 2000\n'
                      '[governance.require_human_above]\n"*" = 10000\n'
                      '[finance.automation]\ndefault = "auto_threshold"\n')
    assert _decision("approve_expense", amount=1500.0).decision is Decision.ALLOW
    assert _decision("approve_expense", amount=5000.0).decision is Decision.REQUIRE_HUMAN


# ----------------------------------------------------- separation of duties

def test_sod_modes_decide_block_or_review(tmp_path):
    _config(tmp_path, _ON + '[finance.sod]\nmode = "enforce"\n')
    check = fin.check_action_sod("approve_expense")  # unrestricted grant
    assert check is not None and check.blocks and check.rule == "finance_sod:enforce"
    # A grant that holds one duty only is clean.
    assert fin.check_action_sod("stage_payment_batch",
                                allow_tools=["stage_payment_batch", "read_file"]) is None
    held = fin.check_action_sod("release_payment",
                                allow_tools=["stage_payment_batch", "release_payment"])
    assert held is not None and {held.conflicts[0].duty_a, held.conflicts[0].duty_b} == {
        "custody", "record"}
    _config(tmp_path, _ON + '[finance.sod]\nmode = "warn"\n')
    warn = fin.check_action_sod("approve_expense")
    assert warn is not None and not warn.blocks
    # A conflict on a hard-floored action is refused even under warn.
    assert fin.check_action_sod("release_payment").blocks


def _agent(tmp_path, tool_name: str, ran: list):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=world.create_goal("g", ""), use_skills=False,
    )
    agent = Agent(ctx=ctx, role="coder", brief="b")
    agent.capability = None
    agent.tools.register(Tool(
        name=tool_name, description=tool_name,
        fn=lambda args: ran.append(tool_name) or "done",
        input_schema={"type": "object", "properties": {}},
    ))
    return agent


def _audit(monkeypatch) -> list:
    import maverick.audit as audit

    rows: list = []
    monkeypatch.setattr(audit, "record", lambda kind, **kw: rows.append((kind, kw)) or True)
    return rows


@pytest.mark.asyncio
async def test_enforce_blocks_the_action_at_run_time(tmp_path, monkeypatch):
    _config(tmp_path, _ON + '[finance.sod]\nmode = "enforce"\n')
    rows = _audit(monkeypatch)
    ran: list = []
    out = await _agent(tmp_path, "approve_expense", ran)._run_tool("approve_expense", {})
    assert "DENIED" in out and "finance_sod:enforce" in out
    assert ran == []
    finding = next(kw for kind, kw in rows if kind == "finance_sod_finding")
    assert finding["outcome"] == "blocked" and finding["mode"] == "enforce"


@pytest.mark.asyncio
async def test_warn_records_a_finding_and_needs_a_person(tmp_path, monkeypatch):
    from contextlib import nullcontext

    import maverick.safety.consent as consent

    _config(tmp_path, _ON + '[finance.sod]\nmode = "warn"\n')
    rows = _audit(monkeypatch)
    asked: list = []
    monkeypatch.setattr(consent, "require_operation_consent", lambda *a, **k: asked.append(k) or object())
    monkeypatch.setattr(consent, "consume_operation_consent", lambda permit: nullcontext())
    ran: list = []
    out = await _agent(tmp_path, "approve_expense", ran)._run_tool("approve_expense", {})
    assert ran == ["approve_expense"], out
    assert asked and "separation-of-duties conflict" in asked[0]["detail"]
    assert asked[0]["require_fresh_person"] is True
    finding = next(kw for kind, kw in rows if kind == "finance_sod_finding")
    assert finding["outcome"] == "human_review" and finding["conflicts"]


@pytest.mark.asyncio
async def test_warn_without_a_person_does_not_run(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    monkeypatch.setattr("maverick.safety.consent._decide_via_dashboard", lambda *a, **k: None)
    _config(tmp_path, _ON + '[finance.sod]\nmode = "warn"\n')
    _audit(monkeypatch)
    ran: list = []
    out = await _agent(tmp_path, "approve_expense", ran)._run_tool("approve_expense", {})
    assert ran == [] and "requires human approval" in out


def test_flow_dispatch_refuses_a_duty_conflict(tmp_path, monkeypatch):
    from maverick import tool_authz

    _config(tmp_path, _ON + '[finance.sod]\nmode = "warn"\n')
    monkeypatch.setattr("maverick.flow.ir.action_tool_policy_error", lambda t: "")
    rows = _audit(monkeypatch)
    denial = tool_authz.authorize("approve_expense", {}, origin="flow")
    assert denial and "separation of duties" in denial
    assert any(kind == "finance_sod_finding" for kind, _ in rows)


# ---------------------------------------------------------- approval timeout

@pytest.mark.asyncio
async def test_unanswered_finance_approval_is_refused_and_withdrawn(tmp_path, monkeypatch):
    import maverick.safety.consent as consent

    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    _config(tmp_path, _ON + '[finance.automation]\ndefault = "approve"\n'
                      '[finance.approvals]\ntimeout = "fail_closed"\n')
    _audit(monkeypatch)
    # A standing "remember this" grant exists; fail_closed must not use it.
    monkeypatch.setattr(consent, "_check_ledger", lambda *a, **k: True)
    waited: list = []
    monkeypatch.setattr(consent, "_decide_via_dashboard",
                        lambda *a, **k: waited.append(k) or None)  # nobody answered
    ran: list = []
    out = await _agent(tmp_path, "approve_expense", ran)._run_tool("approve_expense", {})
    assert ran == [] and "requires human approval" in out
    assert waited == [{"withdraw_on_timeout": True}]


@pytest.mark.asyncio
async def test_standing_grant_does_not_replace_human_approval(tmp_path, monkeypatch):
    import maverick.safety.consent as consent

    _config(tmp_path, _ON + '[finance.automation]\ndefault = "approve"\n')
    _audit(monkeypatch)
    monkeypatch.setattr(consent, "_check_ledger", lambda *a, **k: True)
    monkeypatch.setattr(consent, "_decide_via_dashboard", lambda *a, **k: None)
    ran: list = []
    result = await _agent(tmp_path, "approve_expense", ran)._run_tool("approve_expense", {})
    assert ran == []
    assert "requires human approval" in result


def test_fail_closed_applies_only_to_finance_actions(tmp_path):
    _config(tmp_path, _ON + '[finance.approvals]\ntimeout = "fail_closed"\n')
    assert fin.approval_fail_closed("release_payment")
    assert fin.approval_fail_closed("reverse_impairment_loss")
    assert not fin.approval_fail_closed("send_email")
    with pytest.raises(ValueError):
        fin.parse_profile({"finance": {"approvals": {"timeout": "fail_open"}}})
