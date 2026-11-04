"""Tests for the citation_verifier tool (maverick.tools.citation_verifier)."""
from __future__ import annotations

from maverick.tools.citation_verifier import citation_verifier

# ---- citation_verifier ----

def test_citation_supported_partial_unsupported():
    t = citation_verifier()
    src = "The quick brown fox jumps over the lazy dog near the river."
    out = t.fn({"items": [
        {"quote": "quick brown fox", "source": src},          # exact -> SUPPORTED
        {"quote": "the lazy dog jumps quick", "source": src},  # high overlap -> PARTIAL
        {"quote": "a spaceship landed", "source": src},        # -> UNSUPPORTED
    ]})
    lines = out.splitlines()
    assert lines[1].startswith("[0] SUPPORTED")
    assert lines[2].startswith("[1] PARTIAL")
    assert lines[3].startswith("[2] UNSUPPORTED")
    assert "1 supported, 1 partial, 1 unsupported of 3" in out


def test_citation_normalises_whitespace_and_case():
    t = citation_verifier()
    out = t.fn({"items": [{"quote": "QUICK   brown\nfox", "source": "the quick brown fox"}]})
    assert "[0] SUPPORTED" in out
