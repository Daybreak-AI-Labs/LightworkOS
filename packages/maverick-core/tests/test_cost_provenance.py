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


def test_for_goals_matches_for_goal_with_one_ledger_read(tmp_path, monkeypatch):
    # Spend and the cost export read one row per task; batching must not change
    # any row, including an unlinked episode and a task with no receipts.
    from maverick import cost_provenance
    from maverick import provider_cost_cap as cap
    from maverick import provider_spend_sqlite as indexed

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    config = tmp_path / "config.toml"
    config.write_text("[budget.provider_caps]\nopenai = 20.0\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config))
    monkeypatch.setattr(cap, "_INDEXED_MIGRATION_BYTES", 1)
    cap._save_json(cap._ledger_path(), {cap.period_key(): {"openai": 1.0}})
    for goal in (7, 8):
        hold = cap.reserve("openai", 0.5, operation_id=f"g{goal}", category="inference",
                           attempt_no=1, work_item_id=f"goal:{goal}")
        cap.settle(hold, 0.25)
    assert indexed.is_active(cap._ledger_path())
    ids = [7, None, 8, 9]
    singles = {goal: cost_provenance.for_goal(goal) for goal in ids}
    digests = []
    original = indexed._digest_file
    monkeypatch.setattr(indexed, "_digest_file", lambda path: digests.append(path) or original(path))
    together = cost_provenance.for_goals(ids)
    assert together == singles
    assert [together[goal]["state"] for goal in ids] == ["available", "unlinked", "available", "no_linked_receipts"]
    assert len(digests) == 1
