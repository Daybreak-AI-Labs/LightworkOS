from session import expires_at


def test_zero_lifetime():
    assert expires_at(100, 0) == 100
