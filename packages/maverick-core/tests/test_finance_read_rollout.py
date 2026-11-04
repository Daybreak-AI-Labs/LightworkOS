"""Finance read-seat rollout: every read/draft tower now has an executable,
LOW-risk vendor read connector wired into its allow_tools (extending the
treasury reference across the suite), so the whole CFO office can pull its own
data -- while each tower's money seal stays intact. This closes, for finance, the
domain-action gap that test_fleet_spine documented as "wired on paper"."""
from __future__ import annotations

from maverick.capability import Capability
from maverick.domain import builtin_dir, domain_capability, load_domains
from maverick.safety.tool_risk import tool_risk

# tower -> a read seat (GET-only connector) it must be able to reach
_WIRED = {
    "finance_treasury": "modern_treasury_read",
    "finance_cashflow": "modern_treasury_read",
    "finance_ap": "billdotcom_read",
    "finance_procurement": "ariba_read",
    "finance_ar": "netsuite_read",
    "finance_revrec": "chargebee_read",
    "finance_fa": "netsuite_read",
    "finance_gl_close": "netsuite_read",
    "finance_equity_sbc": "carta_read",
    "finance_expense": "ramp_read",
    "finance_payroll": "adp_read",
    "finance_sec_reporting": "workiva_read",
    "finance_tax_compliance": "avalara_read",
}
_MONEY = ("wire_transfer", "release_payment", "post_journal_entry", "run_payroll", "ach_send")


def _parent() -> Capability:
    return Capability(principal="agent:finance_controller-0", max_risk="high")


def test_every_wired_tower_reaches_a_read_seat_and_still_denies_money():
    d = load_domains(builtin_dir())
    parent = _parent()
    for pack, seat in _WIRED.items():
        cap = domain_capability(d[pack], parent, f"agent:{pack}-1")
        assert cap.permits(seat), f"{pack} cannot reach its read seat {seat}"
        assert tool_risk(seat) == "low", f"{seat} must be low to pass a read-only ceiling"
        for money in _MONEY:
            assert not cap.permits(money), f"{pack} permits money tool {money!r}"


def test_read_seats_are_low_while_their_write_connectors_stay_high():
    for seat in set(_WIRED.values()):
        assert tool_risk(seat) == "low"
        write = seat[: -len("_read")]
        assert tool_risk(write) == "high", f"{write} (write seat) must stay high-risk"
