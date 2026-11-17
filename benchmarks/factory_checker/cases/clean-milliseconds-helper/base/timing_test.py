from timing import elapsed


def test_seconds():
    assert elapsed(1.0, 3.5) == 2.5
