"""Segregation-of-duties conflict linter (finance-agent-suite §2.1)."""
from __future__ import annotations

import pytest
from maverick.domain import DomainProfile
from maverick.finance.sod_linter import (
    SoDViolation,
    assert_no_conflicts,
    classify_duty,
    lint_compartment,
    lint_finance_roster,
    lint_roster,
)


def test_classify_duty():
    assert classify_duty("stage_journal_entry") == "record"
    assert classify_duty("stage_payment_batch") == "record"
    assert classify_duty("release_payment") == "custody"
    assert classify_duty("wire_transfer") == "custody"
    assert classify_duty("run_payroll") == "custody"
    assert classify_duty("approve_expense") == "authorize"
    assert classify_duty("post_journal_entry") == "authorize"
    assert classify_duty("reconcile_accounts") == "reconcile"
    assert classify_duty("read_file") is None
    assert classify_duty("propose_transfer") is None  # proposing is not custody


def test_classify_duty_is_case_insensitive():
    # A control linter must never let a mis-cased tool name silently escape
    # classification and hide a real SoD conflict.
    assert classify_duty("Release_Payment") == "custody"
    assert classify_duty("RELEASE_PAYMENT") == "custody"
    assert classify_duty("  approve_expense  ") == "authorize"
    # the conflict is now caught even with mixed-case tool names
    conflicts = lint_compartment("ap", ["Stage_Payment_Batch", "RELEASE_PAYMENT"])
    assert len(conflicts) == 1
    assert {conflicts[0].duty_a, conflicts[0].duty_b} == {"record", "custody"}


def test_record_plus_custody_is_conflict():
    conflicts = lint_compartment("ap", ["stage_payment_batch", "release_payment"])
    assert len(conflicts) == 1
    assert {conflicts[0].duty_a, conflicts[0].duty_b} == {"record", "custody"}


def test_record_plus_reconcile_is_allowed():
    # one accountant records AND reconciles in the close — not a conflict
    assert lint_compartment("gl", ["stage_journal_entry", "reconcile_accounts"]) == []


def test_authorize_plus_record_is_conflict():
    conflicts = lint_compartment("x", ["stage_journal_entry", "post_journal_entry"])
    assert len(conflicts) == 1
    assert {conflicts[0].duty_a, conflicts[0].duty_b} == {"authorize", "record"}


def test_clean_readonly_compartment():
    assert lint_compartment("fpa", ["gl_read_actuals", "build_variance_report"]) == []


def test_lint_roster_unions_packs_in_a_compartment():
    # two packs share a compartment; together they break SoD
    recorder = DomainProfile(name="rec", compartment="shared",
                             allow_tools=["stage_payment_batch"])
    payer = DomainProfile(name="pay", compartment="shared",
                          allow_tools=["release_payment"])
    conflicts = lint_roster([recorder, payer])
    assert len(conflicts) == 1
    assert conflicts[0].compartment == "shared"


def test_assert_no_conflicts():
    clean = [DomainProfile(name="a", compartment="a", allow_tools=["gl_read_journal"])]
    assert_no_conflicts(clean)  # no raise
    bad = [DomainProfile(name="b", compartment="b",
                         allow_tools=["stage_journal_entry", "wire_transfer"])]
    with pytest.raises(SoDViolation):
        assert_no_conflicts(bad)


def test_lint_finance_roster_checks_builtin_and_workspace_finance_packs(tmp_path, monkeypatch):
    # The shared check behind `maverick finance lint-sod` and the dashboard
    # button: shipped finance packs are clean; a workspace pack is included,
    # and packs outside finance are not.
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    packs, conflicts = lint_finance_roster()
    assert packs and all(name.startswith("finance_") for name in packs)
    assert conflicts == []
    (tmp_path / "finance_desk.toml").write_text(
        'name = "finance_desk"\nallow_tools = ["stage_payment_batch", "release_payment"]\n',
        encoding="utf-8")
    (tmp_path / "ops_desk.toml").write_text(
        'name = "ops_desk"\nallow_tools = ["stage_payment_batch", "release_payment"]\n',
        encoding="utf-8")
    packs2, conflicts2 = lint_finance_roster()
    assert len(packs2) == len(packs) + 1 and "ops_desk" not in packs2
    assert [c.compartment for c in conflicts2] == ["finance_desk"]
