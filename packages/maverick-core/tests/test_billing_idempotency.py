"""Invoice idempotency key: re-running billing for a tenant-period must yield a
stable id so a downstream payment/AR step can dedup and never double-charge."""
from __future__ import annotations

from maverick.billing import RateCard, generate_invoice, rate_ledger
from maverick.quotas import UsageLedger


def _ledger(tmp_path):
    led = UsageLedger(path=tmp_path / "ledger.json")
    led.record("user:alice", 1.00, 10_000, 2_000, day="2026-06-01")
    led.record("user:bob", 2.00, 20_000, 4_000, day="2026-06-02")
    return led


def test_invoice_id_is_stable_across_runs(tmp_path):
    led = _ledger(tmp_path)
    a = rate_ledger(led, RateCard(markup_pct=20.0), tenant="acme",
                    since="2026-06-01", until="2026-06-30")
    b = rate_ledger(led, RateCard(markup_pct=20.0), tenant="acme",
                    since="2026-06-01", until="2026-06-30")
    assert a.invoice_id and a.invoice_id == b.invoice_id
    assert a.invoice_id.startswith("inv_")
    assert a.to_dict()["invoice_id"] == a.invoice_id


def test_invoice_id_differs_by_tenant_and_period(tmp_path):
    led = _ledger(tmp_path)
    base = rate_ledger(led, RateCard(), tenant="acme",
                       since="2026-06-01", until="2026-06-30")
    other_tenant = rate_ledger(led, RateCard(), tenant="beta",
                               since="2026-06-01", until="2026-06-30")
    other_period = rate_ledger(led, RateCard(), tenant="acme",
                               since="2026-07-01", until="2026-07-31")
    assert base.invoice_id != other_tenant.invoice_id
    assert base.invoice_id != other_period.invoice_id


def test_invoice_id_independent_of_amount(tmp_path):
    """Same tenant+period under different rate cards keeps the same idempotency
    key -- the period is the dedup unit, not the dollar amount."""
    led = _ledger(tmp_path)
    cheap = rate_ledger(led, RateCard(markup_pct=0.0), tenant="acme",
                        since="2026-06-01", until="2026-06-30")
    pricey = rate_ledger(led, RateCard(markup_pct=50.0), tenant="acme",
                         since="2026-06-01", until="2026-06-30")
    assert cheap.total != pricey.total
    assert cheap.invoice_id == pricey.invoice_id


def test_generate_invoice_sets_id(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    inv = generate_invoice("acme", RateCard(), since="2026-06-01", until="2026-06-30")
    assert inv.invoice_id.startswith("inv_")


def test_open_ended_invoice_has_no_idempotency_key(tmp_path, monkeypatch):
    """An open-ended invoice ('all usage so far') has a growing total, so it must
    NOT get a stable dedup key -- otherwise a deduping processor under-bills as
    usage accrues. Both fully-open and one-sided periods are open-ended."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert generate_invoice("acme", RateCard()).invoice_id == ""
    assert generate_invoice("acme", RateCard(), since="2026-06-01").invoice_id == ""
    assert generate_invoice("acme", RateCard(), until="2026-06-30").invoice_id == ""
    # closing the period (both bounds) restores a stable key
    assert generate_invoice(
        "acme", RateCard(), since="2026-06-01", until="2026-06-30"
    ).invoice_id.startswith("inv_")
