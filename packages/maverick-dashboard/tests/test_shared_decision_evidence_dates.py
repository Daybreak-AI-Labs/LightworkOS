"""Decision reviews show readable dates, never raw ISO timestamps."""
from __future__ import annotations

from maverick_dashboard import shared_decision_evidence_store as store


def test_review_dates_read_as_dates():
    text = store._date(1795101845.026)
    assert text == "19 Nov 2026, 15:24 UTC"
    assert "+00:00" not in text and "2026-11-19" not in text
