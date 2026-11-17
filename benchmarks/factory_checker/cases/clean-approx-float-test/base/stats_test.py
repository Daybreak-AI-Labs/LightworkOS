from stats import mean


def test_mean():
    assert mean([1, 2, 3, 4]) == 2.5


def test_float_mean():
    assert mean([0.1, 0.2]) == 0.15000000000000002
