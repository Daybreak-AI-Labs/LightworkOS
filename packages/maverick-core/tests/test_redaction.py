"""Deterministic redaction: exact spans out, invalid look-alikes kept.

The assertions that matter: validated findings are replaced with typed
placeholders while near-misses survive untouched; a second pass over
redacted output is a no-op; the category filter narrows what is removed.
"""
from __future__ import annotations

import pytest
from maverick.redaction import redact_text

_TEXT = (
    "Write to alice@example.com or +1 415-555-2671. "
    "Valid card 4111 1111 1111 1111; invalid card 4111 1111 1111 1112."
)


def test_redacts_validated_findings_and_keeps_near_misses():
    result = redact_text(_TEXT)
    assert "alice@example.com" not in result["text"]
    assert "[REDACTED:email]" in result["text"]
    assert "4111 1111 1111 1112" in result["text"]
    assert result["counts"]["email"] == 1
    assert result["counts"]["financial"] == 1


def test_second_pass_is_a_noop():
    once = redact_text(_TEXT)["text"]
    again = redact_text(once)
    assert again["redactions"] == 0 and again["text"] == once


def test_category_filter():
    result = redact_text(_TEXT, categories=["email"])
    assert result["counts"] == {"email": 1}
    assert "415-555-2671" in result["text"]


def test_nested_findings_redact_the_whole_outer_span():
    # The nested roster name used to win and leave the rest of the e-mail visible.
    result = redact_text("contact john.smith@example.com now", roster=["john"])
    assert result["text"] == "contact [REDACTED:email] now"
    assert result["redactions"] == 1


def test_findings_beyond_the_classifier_cap_refuse_instead_of_leaking():
    from maverick.content_classifier import MAX_FINDINGS
    text = " ".join(f"u{i}@example.com" for i in range(MAX_FINDINGS + 5))
    with pytest.raises(ValueError, match="too many findings"):
        redact_text(text)


def test_bounds():
    with pytest.raises(ValueError, match="characters"):
        redact_text("x" * 2_000_001)


def test_structured_redaction_walks_fields_not_blobs():
    from maverick.redaction import redact_structured

    payload = {
        "subject": "alice@example.com",
        "meta": {"count": 3, "flag": True},
        "notes": ["call +1 415-555-2671.", "clean line"],
    }
    result = redact_structured(payload)
    assert result["value"]["subject"] == "[REDACTED:email]"
    assert result["value"]["meta"] == {"count": 3, "flag": True}
    assert result["value"]["notes"][0] == "call [REDACTED:phone]."
    assert result["value"]["notes"][1] == "clean line"
    assert result["counts"] == {"email": 1, "phone": 1}
    with pytest.raises(ValueError, match="nodes"):
        redact_structured([["x"] * 1000] * 300)
