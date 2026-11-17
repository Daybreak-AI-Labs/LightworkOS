from series import increases


def test_counts_increases():
    assert increases([1, 2, 2, 5, 3]) == 2


def test_short_series():
    assert increases([]) == 0
    assert increases([4]) == 0
