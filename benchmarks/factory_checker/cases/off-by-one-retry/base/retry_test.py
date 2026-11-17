import pytest
from retry import retry


def test_returns_first_success():
    assert retry(lambda: 5) == 5


def test_raises_when_every_attempt_fails():
    def boom():
        raise OSError("down")
    with pytest.raises(OSError):
        retry(boom, attempts=2)
