"""Content classifier: every finding must be recomputable, never a guess.

The assertions that matter: identifiers with integrity math are validated
against it (Luhn, mod-97, SSA structure, octet ranges) and near-misses
stay clean; context-gated detectors (DOB, ICD-10) fire only in context;
card-shaped digit runs never double-report as phone numbers; samples in
reports are masked; bounds hold.
"""
from __future__ import annotations

import pytest
from maverick.content_classifier import MAX_TEXT_CHARS, classify_text


def _counts(text: str) -> dict:
    return classify_text(text)["counts"]


def test_luhn_separates_real_cards_from_near_misses():
    assert _counts("card 4111 1111 1111 1111") == {"financial": 1}
    assert _counts("card 4111 1111 1111 1112") == {}


def test_iban_mod97_validates():
    assert _counts("IBAN DE89370400440532013000") == {"financial": 1}
    assert _counts("IBAN DE89370400440532013001") == {}


def test_ssn_structural_rules():
    assert _counts("ssn 219-09-9999") == {"national_id": 1}
    for bad in ("000-12-3456", "666-12-3456", "900-12-3456",
                "219-00-3456", "219-09-0000"):
        assert _counts(f"ssn {bad}") == {}, bad


def test_ipv4_octets_must_parse():
    assert _counts("host 10.0.0.7") == {"ip_address": 1}
    assert _counts("host 999.1.1.1") == {}


def test_dob_and_icd10_need_context():
    assert _counts("released 2020-01-15") == {}
    assert "date_of_birth" in _counts("born 1990-04-12")
    assert _counts("error code E11.9 in module") == {}
    assert "health" in _counts("diagnosis code E11.9")


def test_card_shaped_runs_never_report_as_phones():
    report = classify_text("bad card 4111 1111 1111 1112 here")
    assert report["counts"] == {}
    assert "phone" in _counts("call +1 415-555-2671.")


def test_gps_pairs_detect_with_trailing_punctuation():
    assert _counts("meet at 37.774929, -122.419416.") == {"location": 1}
    # A money pair is not a coordinate (no decimal-run shape).
    assert _counts("totals 12, 14") == {}


def test_samples_are_masked_and_positions_exact():
    text = "mail alice@example.com end"
    report = classify_text(text)
    finding = report["findings"][0]
    assert "alice@example.com" not in finding["sample"]
    assert text[finding["start"]:finding["end"]] == "alice@example.com"


def test_bounds():
    with pytest.raises(ValueError, match="characters"):
        classify_text("x" * (MAX_TEXT_CHARS + 1))
    empty = classify_text("")
    assert empty["categories"] == [] and empty["findings"] == []


def test_aadhaar_verhoeff_and_nhs_mod11_validate_in_context():
    from maverick.content_classifier import _nhs_ok, _verhoeff_ok

    # Published Verhoeff example: check digit for 236 is 3.
    assert _verhoeff_ok("2363") is True
    assert _verhoeff_ok("2364") is False
    # Published NHS test number 943 476 5919.
    assert _nhs_ok("9434765919") is True
    assert _nhs_ok("9434765918") is False
    ok = classify_text("NHS number 943 476 5919 on file")
    assert ok["counts"] == {"national_id": 1}
    assert ok["findings"][0]["kind"] == "nhs_number_mod11"
    # Without the context word the digits read as phone-shaped, not as a
    # national id — the validated finding only outranks phone when the
    # context justifies running the validator at all.
    assert classify_text("ref 943 476 5919")["counts"] == {"phone": 1}
    # In context but failing mod-11: no national id, and the id-shaped
    # digits still fall back to the phone shape.
    bad = classify_text("NHS number 943 476 5918")
    assert bad["counts"] == {"phone": 1}


def test_roster_names_match_whole_word_case_insensitive():
    text = "Escalated by Carol Danvers; carbon copy to CAROL DANVERS. Caroline stays."
    report = classify_text(text, roster=["Carol Danvers"])
    assert report["counts"] == {"name": 2}
    assert all(f["kind"] == "roster_match" for f in report["findings"])
    # Whole-word: 'Caroline' never matches a roster entry 'Carol'.
    assert classify_text("Caroline stays", roster=["Carol"])["counts"] == {}
    from maverick.redaction import redact_text

    red = redact_text(text, roster=["Carol Danvers"])
    assert "Carol Danvers" not in red["text"]
    assert "Caroline" in red["text"]
    assert red["counts"]["name"] == 2
    import pytest as pytest_module
    with pytest_module.raises(ValueError, match="roster"):
        classify_text("x", roster=["n"] * 5_001)
