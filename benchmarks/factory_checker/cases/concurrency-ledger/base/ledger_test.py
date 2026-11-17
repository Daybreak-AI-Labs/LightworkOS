from ledger import Ledger


def test_adds():
    ledger = Ledger()
    ledger.add(2)
    ledger.add(3)
    assert ledger.balance == 5
