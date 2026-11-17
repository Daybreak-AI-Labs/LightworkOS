from ranges import between


def test_inside_and_outside():
    assert between(5, 1, 10)
    assert not between(0, 1, 10)
