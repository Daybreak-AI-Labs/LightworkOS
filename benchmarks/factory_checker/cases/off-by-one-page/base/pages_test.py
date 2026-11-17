import pytest
from pages import page


def test_first_page():
    assert page(list(range(10)), 1, 3) == [0, 1, 2]


def test_page_numbers_start_at_one():
    with pytest.raises(ValueError):
        page([1, 2], 0, 2)
