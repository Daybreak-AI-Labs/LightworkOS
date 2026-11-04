"""`maverick billing invoice` must not mint a misleading $0 invoice for a typo.

Invoicing a tenant id that does not exist would read an absent ledger and rate
to an empty ``TOTAL: $0.00`` invoice at exit 0 -- indistinguishable from a real
"this customer owes nothing" statement, so a typo'd tenant id would pass
silently. The guard errors (exit 2) only in the genuinely suspect case -- an
empty invoice for a tenant a provisioned roster has never heard of -- while
leaving every legitimate flow unchanged:

  * a tenant with usage always invoices (so a deleted-but-unpurged tenant whose
    ledger survives can still be billed a final time);
  * a known tenant with no usage in the period is a real $0 invoice, not an error;
  * with no roster provisioned at all (single-tenant / opt-in registry absent)
    nothing errors, because a bare id cannot be validated against a roster.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)


def _provision(tenant_id: str, **kw) -> None:
    from maverick.tenant import registry as tr
    tr.create_tenant(tenant_id, **kw)


def _record_usage(tenant_id: str, day: str = "2026-06-01") -> None:
    from maverick.billing import ledger_for_tenant
    ledger_for_tenant(tenant_id).record("user:alice", 1.25, 10_000, 2_000, day=day)


def _invoice(*args: str):
    return CliRunner().invoke(main, ["billing", "invoice", *args])


def test_unknown_tenant_with_roster_errors_instead_of_zero_invoice():
    # A roster exists (one real tenant); invoicing a typo'd id must error, not
    # print a $0.00 statement that looks like a settled account.
    _provision("acme", plan="pro")
    res = _invoice("acme-crop")
    assert res.exit_code == 2, res.output
    assert "no such tenant 'acme-crop'" in res.output
    assert "$0.00" not in res.output


def test_known_tenant_with_usage_invoices():
    _provision("acme", plan="pro")
    _record_usage("acme")
    res = _invoice("acme")
    assert res.exit_code == 0, res.output
    assert "user:alice" in res.output
    assert "TOTAL: $1.25" in res.output


def test_known_tenant_quiet_period_is_zero_invoice_not_error():
    # A real tenant with no usage in the requested window is a legitimate $0
    # invoice -- exit 0, with a note explaining the emptiness (not an error).
    _provision("acme", plan="pro")
    _record_usage("acme", day="2026-06-01")
    res = _invoice("acme", "--since", "2099-01-01")
    assert res.exit_code == 0, res.output
    assert "no metered usage" in res.output
    assert "TOTAL: $0.00" in res.output


def test_no_roster_never_errors():
    # Opt-in registry absent (single-tenant deployment): a bare id cannot be
    # validated, so invoicing must stay non-breaking (exit 0), empty or not.
    res = _invoice("whoever")
    assert res.exit_code == 0, res.output
    assert "TOTAL: $0.00" in res.output


def test_invoice_rejects_malformed_since_until():
    # A typo'd period bound used to compare lexically out of range and mint a
    # misleading empty invoice at exit 0; it must error instead.
    _provision("acme", plan="pro")
    for args in (["acme", "--since", "not-a-date"],
                 ["acme", "--until", "2026-13-99"],   # impossible calendar date
                 ["acme", "--since", "2026-6-1"]):     # not zero-padded YYYY-MM-DD
        res = _invoice(*args)
        assert res.exit_code == 2, (args, res.output)
        assert "YYYY-MM-DD" in res.output


def test_deleted_but_unpurged_tenant_still_invoices_final():
    # Deleting a tenant without --purge drops the roster row but keeps its
    # ledger; that surviving usage must still bill a final time (line items
    # present => never the typo branch), even though it is no longer in the
    # roster (a sibling tenant keeps the roster non-empty).
    from maverick.tenant import registry as tr
    _provision("acme", plan="pro")
    _provision("beta", plan="free")
    _record_usage("acme", day="2026-05-15")
    assert tr.delete_tenant("acme", purge=False) is True
    assert tr.get_tenant("acme") is None
    res = _invoice("acme")
    assert res.exit_code == 0, res.output
    assert "user:alice" in res.output
    assert "TOTAL: $1.25" in res.output
