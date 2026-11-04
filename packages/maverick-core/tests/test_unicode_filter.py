"""Tests for the Unicode filter (maverick.safety.unicode_filter)."""
from __future__ import annotations

# ---------- unicode filter ----------

def test_unicode_strips_zero_width():
    from maverick.safety.unicode_filter import normalize
    text = "hello​world‍!"
    r = normalize(text)
    assert r.cleaned == "helloworld!"
    assert "zero_width" in r.categories
    assert r.had_dangerous is True


def test_unicode_strips_bidi_overrides():
    from maverick.safety.unicode_filter import normalize
    # The Trojan Source RLO attack
    r = normalize("safe‮text")
    assert "‮" not in r.cleaned
    assert "bidi_override" in r.categories


def test_unicode_strips_tag_block():
    from maverick.safety.unicode_filter import normalize
    # E0041 = TAG LATIN CAPITAL LETTER A — invisible
    r = normalize("a\U000E0041b")
    assert r.cleaned == "ab"
    assert "tag_block" in r.categories


def test_unicode_nfkc_normalizes_lookalikes():
    from maverick.safety.unicode_filter import normalize
    # 'ﬁ' (U+FB01, FI ligature) -> 'fi' after NFKC.
    r = normalize("oﬁce")
    assert r.cleaned == "ofice"


def test_unicode_clean_text_is_untouched():
    from maverick.safety.unicode_filter import normalize
    r = normalize("plain ascii hello")
    assert r.cleaned == "plain ascii hello"
    assert r.had_dangerous is False
    assert r.categories == []


def test_has_dangerous_unicode_quick_check():
    from maverick.safety.unicode_filter import has_dangerous_unicode
    assert has_dangerous_unicode("ok​nope") is True
    assert has_dangerous_unicode("plain text") is False
    assert has_dangerous_unicode("") is False


class TestUnicodeImplicitBidiMarks:
    def test_implicit_marks_flagged(self):
        from maverick.safety.unicode_filter import has_dangerous_unicode
        for cp in (0x200E, 0x200F, 0x061C):
            assert has_dangerous_unicode("ok" + chr(cp) + "text"), hex(cp)

    def test_implicit_marks_stripped(self):
        from maverick.safety.unicode_filter import normalize
        res = normalize("a" + chr(0x200E) + "b" + chr(0x061C))
        assert res.cleaned == "ab"
        assert 0x200E in res.removed_codepoints
        assert 0x061C in res.removed_codepoints
