"""payload_compress: world_model compression helper (stdlib zlib)."""
from __future__ import annotations

import zlib

from maverick.tools.payload_compress import payload_compress


def _stats(text, **kw):
    return payload_compress().fn({"op": "stats", "text": text, **kw})


def _roundtrip(text):
    return payload_compress().fn({"op": "roundtrip", "text": text})


def test_stats_reports_sizes_and_shrinks():
    text = "ab" * 1000  # 2000 bytes, highly compressible
    out = _stats(text)
    expected_c = len(zlib.compress(text.encode("utf-8"), 6))
    assert out.startswith("OK level=6")
    assert "original=2000" in out
    assert f"compressed={expected_c}" in out
    assert expected_c < 2000  # actually compressed


def test_stats_custom_level():
    out = _stats("hello world " * 50, level=9)
    assert out.startswith("OK level=9")
    expected_c = len(zlib.compress(("hello world " * 50).encode("utf-8"), 9))
    assert f"compressed={expected_c}" in out


def test_stats_empty_text():
    out = _stats("")
    assert "original=0" in out
    assert "ratio=0.0000" in out
    assert "(0.0%)" in out


def test_roundtrip_lossless():
    out = _roundtrip("world model state: éà你好 \n\t binary-ish")
    assert out.startswith("OK lossless")


def test_roundtrip_empty():
    out = _roundtrip("")
    assert out.startswith("OK lossless")
    assert "0 bytes" in out


def test_errors():
    t = payload_compress()
    assert t.fn({"op": "stats"}).startswith("ERROR")                       # no text
    assert t.fn({"op": "stats", "text": "x", "level": 99}).startswith("ERROR")
    assert t.fn({"op": "roundtrip"}).startswith("ERROR")                   # no text
    assert t.fn({"op": "nope", "text": "x"}).startswith("ERROR")
