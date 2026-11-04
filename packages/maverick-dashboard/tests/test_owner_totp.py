"""Authenticator-app codes (RFC 6238) and recovery codes for the local owner."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from maverick_dashboard import owner_totp

# ASCII "12345678901234567890": the shared secret of RFC 4226 Appendix D and
# RFC 6238 Appendix B.
RFC_SECRET = b"12345678901234567890"

# RFC 4226 Appendix D, counters 0 to 9.
RFC4226_CODES = ["755224", "287082", "359152", "969429", "338314",
                 "254676", "287922", "162583", "399871", "520489"]

# RFC 6238 Appendix B, HMAC-SHA1 rows (eight digits). Six digits are the last six.
RFC6238_SHA1 = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]


def test_hotp_matches_rfc4226_appendix_d():
    assert [owner_totp.hotp(RFC_SECRET, counter) for counter in range(10)] == RFC4226_CODES


@pytest.mark.parametrize("when, eight_digits", RFC6238_SHA1)
def test_totp_matches_rfc6238_appendix_b_sha1(when, eight_digits):
    assert owner_totp.totp(RFC_SECRET, when) == eight_digits[-6:]


def test_current_step_and_one_either_side_are_accepted():
    now = 1111111111.0
    step = owner_totp.step_at(now)
    for candidate in (step - 1, step, step + 1):
        assert owner_totp.verify(RFC_SECRET, owner_totp.hotp(RFC_SECRET, candidate), now=now) == candidate
    for outside in (step - 2, step + 2):
        assert owner_totp.verify(RFC_SECRET, owner_totp.hotp(RFC_SECRET, outside), now=now) is None


def test_a_code_opens_one_sign_in_and_earlier_steps_are_refused_after_a_later_one():
    now = 1111111111.0
    step = owner_totp.step_at(now)
    code = owner_totp.hotp(RFC_SECRET, step)
    assert owner_totp.verify(RFC_SECRET, code, now=now) == step
    # The same code is refused once its step has been accepted.
    assert owner_totp.verify(RFC_SECRET, code, now=now, last_step=step) is None
    # A step older than the last accepted one is refused as well.
    assert owner_totp.verify(RFC_SECRET, owner_totp.hotp(RFC_SECRET, step - 1), now=now, last_step=step) is None
    # The next step is still accepted.
    assert owner_totp.verify(RFC_SECRET, owner_totp.hotp(RFC_SECRET, step + 1), now=now, last_step=step) == step + 1


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "12345a", "١٢٣٤٥٦", None, 123456])
def test_malformed_codes_are_refused_without_comparing(bad):
    assert owner_totp.verify(RFC_SECRET, bad, now=1111111111.0) is None


def test_secret_text_round_trips_and_is_twenty_bytes():
    raw = owner_totp.new_secret()
    assert len(raw) == 20
    text = owner_totp.encode_secret(raw)
    assert set(text) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") and "=" not in text
    assert owner_totp.decode_secret(text) == raw
    spaced = " ".join(text[i:i + 4] for i in range(0, len(text), 4)).lower()
    assert owner_totp.decode_secret(spaced) == raw
    with pytest.raises(ValueError):
        owner_totp.decode_secret("not base32!")


def test_otpauth_uri_carries_the_manual_entry_values():
    text = owner_totp.encode_secret(RFC_SECRET)
    uri = owner_totp.otpauth_uri(text, "owner@example.com")
    parts = urlsplit(uri)
    assert parts.scheme == "otpauth" and parts.netloc == "totp"
    assert parts.path == "/Lightwork:owner@example.com"
    query = {key: values[0] for key, values in parse_qs(parts.query).items()}
    assert query == {"secret": text, "issuer": "Lightwork", "algorithm": "SHA1",
                     "digits": "6", "period": "30"}


def test_recovery_codes_are_ten_unique_codes_from_an_unambiguous_alphabet():
    codes = owner_totp.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    for code in codes:
        assert len(code) == 9 and code[4] == "-"
        assert set(code.replace("-", "")) <= set(owner_totp.RECOVERY_ALPHABET)
    assert not set("01IOL") & set("".join(codes))


def test_recovery_codes_are_stored_only_as_salted_digests():
    code = owner_totp.new_recovery_codes()[0]
    entry = owner_totp.new_recovery_entry(code)
    assert set(entry) == {"salt", "hash"}
    assert code.replace("-", "") not in str(entry)
    assert len(bytes.fromhex(entry["salt"])) == 16 and len(bytes.fromhex(entry["hash"])) == 32
    # The same code under another salt gives another digest.
    assert owner_totp.hash_recovery(code.replace("-", ""), b"x" * 16) != entry["hash"]


def test_typed_recovery_codes_are_normalized_and_matched_once_per_entry():
    codes = owner_totp.new_recovery_codes()
    entries = [owner_totp.new_recovery_entry(code) for code in codes]
    typed = codes[3].lower().replace("-", " ")
    assert owner_totp.normalize_recovery(typed) == codes[3].replace("-", "")
    assert owner_totp.recovery_index(entries, typed) == 3
    assert owner_totp.recovery_index(entries, "ABCD-EFGH") is None
    # Characters outside the alphabet are never a code, so nothing is hashed.
    assert owner_totp.normalize_recovery("ABCD-0EFG") is None
    assert owner_totp.normalize_recovery(None) is None


def test_a_non_ascii_lookalike_is_never_a_recovery_code():
    """R9: text outside ASCII is refused before any case folding (a long s uppercases to S)."""
    from maverick_dashboard import owner_totp
    assert "ſ".upper() == "S"
    assert owner_totp.normalize_recovery("ABCD-EFGſ") is None
    assert owner_totp.normalize_recovery("ABCD-EFG ") is None
    assert owner_totp.normalize_recovery("abcd efgh") == "ABCDEFGH"
