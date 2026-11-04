"""compaction_classifier: compaction v6 hybrid strategy picker."""
from __future__ import annotations

from maverick.tools.compaction_classifier import compaction_classifier


def _pick(**features):
    return compaction_classifier().fn({"op": "pick", "features": features})


def test_small_tokens_truncate():
    out = _pick(turns=3, tokens=500, has_code=True, pinned_ratio=0.9)
    # tokens < 4000 wins first, even with code + pins present
    assert out.startswith("STRATEGY truncate")
    assert "< 4000" in out


def test_high_pinned_ratio_structural():
    out = _pick(turns=10, tokens=10000, has_code=False, pinned_ratio=0.6)
    assert out.startswith("STRATEGY structural")
    assert "pinned_ratio" in out


def test_code_or_tool_output_structural():
    out = _pick(turns=10, tokens=10000, has_tool_output=True, pinned_ratio=0.1)
    assert out.startswith("STRATEGY structural")
    assert "tool_output" in out


def test_large_long_retrieval():
    out = _pick(turns=80, tokens=40000, has_code=False,
                has_tool_output=False, pinned_ratio=0.0)
    assert out.startswith("STRATEGY retrieval")
    assert "index and fetch" in out


def test_default_summarize():
    out = _pick(turns=10, tokens=10000, has_code=False,
                has_tool_output=False, pinned_ratio=0.0)
    assert out.startswith("STRATEGY summarize")


def test_errors():
    t = compaction_classifier()
    assert t.fn({"op": "pick"}).startswith("ERROR")  # no features
    assert _pick(turns="x", tokens=10).startswith("ERROR")
    assert _pick(turns=1, tokens=10000, pinned_ratio=1.5).startswith("ERROR")
    assert t.fn({"op": "nope", "features": {}}).startswith("ERROR")
