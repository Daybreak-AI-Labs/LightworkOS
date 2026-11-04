"""Audit result paging and exact displayed invoice allocation; unrun regression cases."""
from decimal import Decimal

import pytest
from maverick.billing import Invoice, LineItem
from maverick_dashboard.audit_search import search_events
from maverick_dashboard.billing_invoice_api import _display_amounts


def event(n, kind="task_done"):
    return {"ts": n, "kind": kind, "event_id": str(n),
            "payload": {"actor": "alice", "content": "private-needle"}}


def search(events, **kwargs):
    return search_events(events, person_for=lambda e: e["payload"]["actor"], limit=2, **kwargs)


def test_matching_happens_before_result_limit_and_pages_do_not_repeat():
    rows = [event(n, "match" if n % 1000 == 0 else "other") for n in range(1, 5001)]
    first = search(iter(rows), matches=lambda e: e["kind"] == "match")
    second = search(iter(rows), matches=lambda e: e["kind"] == "match", before=first["next_cursor"])
    third = search(iter(rows), matches=lambda e: e["kind"] == "match", before=second["next_cursor"])
    assert [[e["ts"] for e in r["events"]] for r in (first, second, third)] == [[4000, 5000], [2000, 3000], [1000]]
    assert third["next_cursor"] is None


def test_private_text_is_removed_before_search_and_cursoring():
    result = search([event(1)], matches=lambda e: "private-needle" in str(e))
    assert result["matched"] == 0
    assert not result["events"]


def test_expired_cursor_and_scan_limit_are_explicit():
    stale = search([event(1)], matches=lambda e: True, before="f" * 64)
    assert not stale["cursor_found"]
    partial = search_events([event(n) for n in range(5)], matches=lambda e: True,
                            person_for=lambda e: "alice", limit=2, scan_limit=3)
    assert partial["cut"] is True


@pytest.mark.parametrize("currency, charge, expected", [("USD", .005, Decimal(".02")),
                         ("JPY", .5, Decimal("2")), ("ISK", .5, Decimal("2")),
                         ("UGX", .5, Decimal("2"))])
def test_visible_lines_reconcile_to_currency_total_without_mutating_invoice(currency, charge, expected):
    invoice = Invoice("tenant", "2026-09-01", "2026-09-29",
        [LineItem(str(n), "2026-09-01", charge, 1, 1, charge) for n in range(3)],
        subtotal=charge * 3, total=charge * 3, currency=currency)
    before = invoice.to_dict()
    _, amounts, total, _ = _display_amounts(invoice)
    assert sum(amounts) == total == expected
    assert invoice.to_dict() == before
