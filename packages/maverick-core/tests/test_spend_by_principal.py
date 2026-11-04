"""Per-principal spend enumeration: answers "which user is burning budget?",
which the point-lookup usage() couldn't."""
from __future__ import annotations

from maverick.quotas import UsageLedger


def test_spend_by_principal(tmp_path):
    led = UsageLedger(path=tmp_path / "ledger.json")
    led.record("user:alice", 1.50, 100, 50)
    led.record("user:alice", 0.50, 10, 5)
    led.record("user:bob", 9.00, 900, 450)
    led.record("user:carol", 0.0, 0, 0)  # zero spend -> omitted

    by = led.spend_by_principal()
    assert by["user:alice"] == 2.00
    assert by["user:bob"] == 9.00
    assert "user:carol" not in by


def test_spend_by_principal_empty(tmp_path):
    assert UsageLedger(path=tmp_path / "ledger.json").spend_by_principal() == {}
