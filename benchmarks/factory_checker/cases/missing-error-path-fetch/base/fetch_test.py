import pytest
from fetch import FetchError, fetch_json


def test_returns_the_body():
    assert fetch_json(lambda url: (200, '{"a": 1}'), "u") == '{"a": 1}'


def test_not_found_is_an_error():
    with pytest.raises(FetchError):
        fetch_json(lambda url: (404, "missing"), "u")
