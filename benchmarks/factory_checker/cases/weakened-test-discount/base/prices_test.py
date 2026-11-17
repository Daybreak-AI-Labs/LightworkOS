from prices import apply_discount


def test_fifteen_percent_off():
    assert apply_discount(1000, 15) == 850
