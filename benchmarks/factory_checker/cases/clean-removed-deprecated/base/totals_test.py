from totals import legacy_total, total


def test_total():
    assert total([(2, 3), (5, 1)]) == 11


def test_legacy_total():
    assert legacy_total([1, 2]) == 3
