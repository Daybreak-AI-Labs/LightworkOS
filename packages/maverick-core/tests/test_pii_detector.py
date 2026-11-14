"""Tests for the PII detector (maverick.safety.pii_detector)."""
from __future__ import annotations

import pytest

# ---------- PII detector ----------

@pytest.mark.parametrize("name,sample", [
    ("email", "Contact me at alice@example.com please."),
    ("ssn", "SSN: 123-45-6789"),
    ("phone_us", "Call me at (415) 555-2671."),
    ("ipv4", "Server at 192.168.1.100."),
    ("street_address", "Mail to 123 Main Street."),
])
def test_pii_detector_finds(name, sample):
    from maverick.safety.pii_detector import scan
    found = [m.kind for m in scan(sample)]
    assert name in found, f"expected {name} in {found}"


@pytest.mark.parametrize("compressed", [
    "2001:db8::1",
    "fe80::1",
    "2001:db8::dead:beef",
    "2001::dead:beef:cafe",
    "fe80::dead:beef:1234:5678",
    "::1",
])
def test_pii_detector_redacts_compressed_ipv6_in_full(compressed):
    # The IPV6 alternation must redact the WHOLE address; a leftmost-match
    # ordering bug left the final hextet(s) in cleartext (2001:db8::1 ->
    # "[REDACTED:ipv6]1"). No hex fragment of the address may survive.
    from maverick.safety.pii_detector import redact
    out, matches = redact(f"addr={compressed} end")
    assert matches and "[REDACTED:ipv6]" in out
    for hextet in compressed.replace("::", ":").split(":"):
        if hextet:  # no fragment of the address leaks
            assert hextet not in out, (compressed, out)
    assert out.startswith("addr=") and out.endswith(" end")


def test_pii_detector_luhn_validates_credit_cards():
    from maverick.safety.pii_detector import scan
    # Real Luhn-valid Visa test number.
    valid = "Card: 4532-0151-1283-0366"
    matches = [m.kind for m in scan(valid)]
    assert "credit_card" in matches
    # Random 16-digit string that fails Luhn -> not flagged.
    invalid = "Order #: 1234-5678-9012-3456"
    matches2 = [m.kind for m in scan(invalid)]
    assert "credit_card" not in matches2


def test_pii_detector_redact_replaces():
    from maverick.safety.pii_detector import redact
    text = "Hello alice@example.com, your SSN 123-45-6789 is on file."
    out, matches = redact(text)
    assert "alice@example.com" not in out
    assert "123-45-6789" not in out
    assert "[REDACTED:email]" in out
    assert "[REDACTED:ssn]" in out
    assert len(matches) == 2


def test_pii_detector_empty():
    from maverick.safety.pii_detector import redact, scan
    assert scan("") == []
    assert redact("") == ("", [])


def test_pii_value_preview_never_embeds_raw_pii():
    # Previews are persisted to the audit log, so they must not leak raw PII
    # (even the first 4 chars would leak an SSN area number or partial phone).
    from maverick.safety.pii_detector import scan
    matches = scan("SSN 123-45-6789, phone (415) 555-2671, ip 192.168.1.100")
    assert matches
    for m in matches:
        assert "123" not in m.value_preview
        assert "415" not in m.value_preview
        assert "192" not in m.value_preview


def test_pii_long_card_redacts_cleanly_without_phone_subrun():
    # A 16-digit card must not also match a 10-digit phone sub-run: overlapping
    # spans produced corrupt redactions ([REDACTED:credit_card]hone_us]) and
    # leaked leading digits. Coalescing + the phone anchor keep it one clean span.
    from maverick.safety.pii_detector import redact
    out, matches = redact("pay 4532015112830366 now")
    assert {m.kind for m in matches} == {"credit_card"}
    assert "[REDACTED:credit_card]" in out
    assert "phone" not in out  # no overlap-corruption fragment
    assert "4532" not in out and "0366" not in out  # no raw digits leak


def test_pii_long_nonluhn_number_not_partially_redacted():
    # A 13-digit non-card, non-phone run must not be PARTIALLY redacted (which
    # leaked its leading digits). It is left intact rather than half-masked.
    from maverick.safety.pii_detector import redact
    out, _ = redact("ref 4111111111111 end")
    assert "[REDACTED" not in out


def test_pii_overlap_cluster_redacts_later_tail():
    # The Luhn-valid prefix overlaps a standalone phone beginning after a hyphen;
    # coalescing must redact the whole overlap cluster, not drop the phone tail.
    from maverick.safety.pii_detector import redact

    out, matches = redact("9444260960-415-555-2671")

    assert len(matches) == 1
    assert matches[0].span == (0, 23)
    assert out == "[REDACTED:credit_card]"
    assert "555-2671" not in out


def test_pii_email_scan_is_linear_on_runs_without_at_sign():
    # Every word boundary in a long ``a.a.a.`` run used to start a scan to the
    # end of the run (quadratic: about 50 s for this input). The local part
    # is now bounded at 64 characters, its RFC 5321 limit.
    from maverick.safety.pii_detector import scan

    assert scan("a." * 100_000) == []
    found = [m.kind for m in scan("mail first.last+tag@example.co.uk now")]
    assert found == ["email"]
