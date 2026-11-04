"""End-to-end proof of the fleet spine on the *real* roster.

The session built three layers -- identity (capability), delegation
(spawn_specialist / verified bus handoffs), and verification (handoff verifier).
This exercises them together against the actual finance packs, locking the
guarantees that hold so a refactor can't silently regress them:

  * a specialist deployed from a pack runs under an **attenuated, sealed**
    capability (the pack's allow/deny/max_risk/host envelope), never the parent's;
  * the suite's cardinal rule -- *never move money without a human* -- is enforced
    at the capability layer across EVERY finance pack, however each is configured;
  * a child grant can never exceed its parent (confused-deputy safe);
  * a peer-to-peer handoff is signed and verified, handing back the attenuated
    grant the receiver runs under.

What this test deliberately does NOT assert (the honest gap, see the PR notes):
the packs' *domain* ops (`bank_read_balance`, `propose_transfer`, ...) are not yet
registered tools, so a specialist can reason/research but can't yet act on a
finance system -- the domain-action bridge (connector-backed read ops) is the
next build. This file proves the trust/fleet layer, which is real today.
"""
from __future__ import annotations

import pytest
from maverick.bus_handoff import HandoffAuthority
from maverick.capability import Capability
from maverick.domain import builtin_dir, domain_capability, load_domains

# Money-movement / system-of-record tools the finance suite gates on a human.
_MONEY_TOOLS = (
    "wire_transfer", "ach_send", "release_payment", "release_payroll_payment",
    "run_payroll", "send_payment", "post_journal_entry", "place_trade",
    "execute_fx_trade", "file_return", "file_with_sec", "file_tax_return",
    "remit_tax", "vendor_master_change", "edit_employee_bank_details",
)


def _have_crypto() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        return True
    except BaseException:  # absent OR a broken backend (sandbox pyo3 panic)
        return False


crypto = pytest.mark.skipif(not _have_crypto(), reason="cryptography unavailable")


def _finance_packs() -> dict:
    return {k: v for k, v in load_domains(builtin_dir()).items() if k.startswith("finance_")}


def _broad_parent() -> Capability:
    # The controller's privileged parent grant (unrestricted up to high risk);
    # every tower attenuates down from it.
    return Capability(principal="agent:finance_controller-0", max_risk="high")


def test_no_finance_pack_can_move_money_without_a_human():
    # The suite's cardinal rule, proven at the capability layer across the WHOLE
    # finance roster -- whether a pack drops money tools via a read-only ceiling
    # (towers) or denies them explicitly behind a high ceiling (the controller),
    # no attenuated grant in the suite permits moving money or posting.
    parent = _broad_parent()
    packs = _finance_packs()
    assert len(packs) >= 20, f"expected the finance roster, got {len(packs)}"
    for name, prof in packs.items():
        cap = domain_capability(prof, parent, f"agent:{name}-1")
        for tool in _MONEY_TOOLS:
            assert not cap.permits(tool), f"{name} permits money tool {tool!r}"


def test_treasury_specialist_runs_under_a_sealed_attenuated_capability():
    prof = load_domains(builtin_dir())["finance_treasury"]
    cap = domain_capability(prof, _broad_parent(), "agent:finance_treasury-1")
    # least privilege: it runs at the pack's read/propose ceiling, not the parent's
    assert cap.max_risk == "medium"
    # permits its domain read/propose ops
    for tool in ("read_file", "bank_read_balance", "bank_read_transactions", "propose_transfer"):
        assert cap.permits(tool), tool
    # the custody seal: money movement denied even in the treasury compartment
    for money in ("wire_transfer", "ach_send", "release_payment"):
        assert not cap.permits(money), money
    # a high-risk vendor connector is dropped by the medium ceiling -- the read-
    # only seal holds even where the vendor host is allowed
    assert not cap.permits("modern_treasury")
    # host scope comes from the pack
    assert cap.permits_host("api.moderntreasury.com")
    assert not cap.permits_host("paste.evil.example")


def test_specialist_grant_never_exceeds_its_parent():
    # Confused-deputy safety: a constrained parent narrows the pack further --
    # never broadens it. The pack's own ceiling is medium, but a low parent
    # propagates down (min by rank), so the child can't use the pack's headroom.
    prof = load_domains(builtin_dir())["finance_treasury"]
    low_parent = Capability(principal="agent:finance_controller-0", max_risk="low")
    cap = domain_capability(prof, low_parent, "agent:finance_treasury-1")
    assert cap.max_risk == "low"             # min(parent low, pack medium)
    assert cap.permits("read_file")          # a low op still runs
    assert not cap.permits("wire_transfer")  # the money seal holds


@crypto
def test_specialist_to_peer_handoff_is_verified():
    # A treasury specialist delegates a scoped read to an FP&A peer over the bus;
    # the run authority signs it and the peer verifies it, receiving exactly the
    # attenuated grant to run under -- nothing more.
    auth = HandoffAuthority.for_run()
    grant = Capability(
        principal="agent:finance_fpa-1",
        allow_tools=frozenset({"bank_read_balance", "build_forecast_scenario"}),
        max_risk="low",
    )
    env = auth.mint(
        sender="agent:finance_treasury-1", recipient="agent:finance_fpa-1",
        grant=grant, task="pull the cash position for the forecast",
        required_tools=("bank_read_balance",),
    )
    v = auth.verify(env)
    assert v.ok and v.rule == "ok"
    assert v.grant.permits("bank_read_balance")
    assert not v.grant.permits("wire_transfer")
