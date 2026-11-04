import hmac

import pytest
from maverick.constant_time import text_equals


def test_non_ascii_text_is_a_mismatch_not_an_error():
    with pytest.raises(TypeError):
        hmac.compare_digest("é" * 4, "abcd")
    assert text_equals("é" * 4, "abcd") is False
    assert text_equals("abcd", "\u2028abc") is False


def test_equal_text_matches_whatever_it_holds():
    assert text_equals("abcd", "abcd") is True
    assert text_equals("räksmörgås", "räksmörgås") is True
    assert text_equals("", "") is True


def test_a_lone_surrogate_never_matches_a_real_character():
    assert text_equals("\ud800", "\ud800") is True
    assert text_equals("\ud800", "\U00010000") is False
    assert text_equals("\ud800", "?") is False
