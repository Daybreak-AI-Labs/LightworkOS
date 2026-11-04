"""Finance roster: the ~31 domain packs load and obey the suite's invariants.

This is the finance analogue of the capability tests (finance-agent-suite §2.1,
§2.5): it proves the shipped packs are segregation-of-duties-clean, read-only by
construction (no allowed tool exceeds the pack's risk ceiling; money/posting tools
are denied), and carry the cardinal "never move money without a human" guardrail.
"""
from __future__ import annotations

import pytest
from maverick.domain import builtin_dir, load_domains
from maverick.finance.sod_linter import lint_roster
from maverick.safety.tool_risk import tools_exceeding

_EXPECTED = {
    # Tower 1 — Controllership
    "finance_gl_close", "finance_ap", "finance_ar", "finance_payroll",
    "finance_fa", "finance_revrec", "finance_intercompany", "finance_expense",
    # Tower 2 — FP&A
    "finance_fpa", "finance_forecasting", "finance_cashflow",
    # Tower 3 — Treasury
    "finance_treasury", "finance_investments", "finance_fx", "finance_capmarkets",
    # Tower 4 — Tax
    "finance_tax_provision", "finance_tax_compliance", "finance_transfer_pricing",
    # Tower 5 — Risk, Controls & Assurance
    "finance_sox", "finance_internal_audit", "finance_external_audit",
    "finance_fraud", "finance_anomaly", "finance_erm", "finance_credit",
    # Tower 6 — Procurement & Vendor
    "finance_procurement", "finance_vendor",
    # Tower 7 — External & Investor Reporting
    "finance_sec_reporting", "finance_ir", "finance_equity_sbc",
    # Supervisor
    "finance_controller",
}

# Money-movement / posting / filing tools no pack may *allow* (only deny / draft).
_FORBIDDEN_IN_ALLOW = {
    "post_journal_entry", "close_period", "release_payment",
    "release_payroll_payment", "run_payroll", "wire_transfer", "ach_send",
    "send_payment", "place_trade", "create_order_instruction", "execute_fx_trade",
    "file_return", "file_tax_return", "remit_tax", "file_with_sec",
    "vendor_master_change", "edit_employee_bank_details", "set_credit_limit",
    "dispose_asset", "approve_expense", "approve_po", "approve_vendor",
    "write_off_balance", "send_invoice",
}


@pytest.fixture(scope="module")
def packs():
    all_domains = load_domains(builtin_dir())
    return {n: p for n, p in all_domains.items() if n.startswith("finance_")}


def test_all_roster_packs_present(packs):
    missing = _EXPECTED - set(packs)
    assert not missing, f"missing finance packs: {sorted(missing)}"


def test_roster_is_sod_clean(packs):
    conflicts = lint_roster(packs)
    assert conflicts == [], "SoD conflicts:\n" + "\n".join(str(c) for c in conflicts)


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_pack_is_coherent_and_governed(name, packs):
    p = packs[name]
    # 1. Read-only by default: no allowed tool is a money/posting/filing tool.
    leaked = set(p.allow_tools) & _FORBIDDEN_IN_ALLOW
    assert not leaked, f"{name} allows forbidden mutating tools: {sorted(leaked)}"
    # 2. Coherent envelope: every allowed tool fits under the pack's risk ceiling.
    exceeding = tools_exceeding(p.allow_tools, p.max_risk)
    assert not exceeding, f"{name} allows tools above its max_risk: {sorted(exceeding)}"
    # 3. Compartment seal set.
    assert p.compartment, f"{name} has no compartment seal"


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_pack_has_never_guardrail(name, packs):
    persona = (packs[name].persona or "").lower()
    assert persona, f"{name} has no persona"
    assert "never" in persona, f"{name} persona lacks the 'never' guardrail"


def test_controller_denies_money_movement(packs):
    ctrl = packs["finance_controller"]
    for tool in ("post_journal_entry", "release_payment", "run_payroll",
                 "wire_transfer", "file_with_sec"):
        assert tool in ctrl.deny_tools, f"controller must deny {tool}"
    # It may spawn (the privileged parent) but never move money itself.
    assert "spawn_subagent" in ctrl.allow_tools


def test_custody_isolated_from_controllership(packs):
    # Treasury (custody) and Controllership (record) are distinct seal boundaries.
    assert packs["finance_treasury"].compartment != packs["finance_gl_close"].compartment
    assert packs["finance_payroll"].compartment == "finance_payroll"  # PII isolation
