"""A rate card or matching total can never upgrade an estimate to an invoice."""
from types import SimpleNamespace

from maverick.cost_provenance import receipt_row, runtime_basis


def receipt(**changes):
    fields = dict(reference='receipt-a', provider='example', period='2026-09', projected=4,
                  state='settled', actual=2, currency='USD', cost_basis='estimated',
                  pricing_evidence={'verified': False, 'rate_card_version': 'legacy'}, reconciliation=None)
    fields.update(changes)
    return SimpleNamespace(**fields)


def test_strict_pricing_off_receipt_keeps_estimate_and_never_invoice_claim():
    row = receipt_row(receipt())
    assert row['basis'] == 'estimated'
    assert row['invoice_verified'] is False
    assert row['rate_card_version'] == 'legacy'


def test_verified_rate_is_recorded_but_not_invoice_verified():
    row = receipt_row(receipt(cost_basis='observed', pricing_evidence={'verified': True}))
    assert row['basis'] == 'recorded'
    assert row['invoice_verified'] is False


def test_interrupted_reservation_stays_unknown_not_free():
    row = receipt_row(receipt(state='unknown', actual=None))
    assert row['basis'] == 'unknown'
    assert row['actual'] is None
    assert row['projected'] == 4
    assert runtime_basis(None).startswith('Unknown')


def test_reconciled_ledger_keeps_review_reference_separate_from_invoice():
    row = receipt_row(receipt(reconciliation='PAR-reviewed'))
    assert row['basis'] == 'reconciled'
    assert row['reconciliation_review'] == 'PAR-reviewed'
    assert row['invoice_verified'] is False
