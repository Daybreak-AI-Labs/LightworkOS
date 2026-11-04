"""watermark_detector: detect hidden text watermarks / steganography."""
from __future__ import annotations

from maverick.tools.watermark_detector import watermark_detector


def _scan(text):
    return watermark_detector().fn({"op": "scan", "text": text})


def test_clean_text():
    assert _scan("The quick brown fox.").startswith("CLEAN")


def test_zero_width_detected():
    out = _scan("hel​lo wor‍ld")  # ZWSP + ZWJ
    assert out.startswith("LIKELY WATERMARKED")
    assert "zero-width: 2" in out


def test_tag_chars_and_variation_selectors():
    out = _scan("hi\U000e0041️")  # tag char + variation selector
    assert out.startswith("LIKELY WATERMARKED")
    assert "tag-chars: 1" in out and "variation-selector: 1" in out


def test_homoglyph_only_is_suspicious():
    # Cyrillic 'а' (U+0430) inside an otherwise-Latin word
    out = _scan("pаssword")
    assert out.startswith("SUSPICIOUS")
    assert "homoglyph: 1" in out


def test_positions_reported():
    out = _scan("a​b​c")
    assert "zero-width: 2 at [1, 3]" in out


def test_errors():
    t = watermark_detector()
    assert t.fn({"op": "scan", "text": ""}).startswith("ERROR")
    assert t.fn({"op": "scan"}).startswith("ERROR")
    assert t.fn({"op": "nope", "text": "x"}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "watermark_detector" in names
