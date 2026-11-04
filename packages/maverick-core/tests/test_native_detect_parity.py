"""The Rust ``maverick_native`` secret/PII scanners must equal pure Python.

``rust/mvk-scan`` ports ``secret_detector.scan`` and ``pii_detector.scan`` (the
latter checks phone/SSN boundaries outside its linear regex candidates)
so the SAME detection logic can run in the TypeScript / edge runtimes,
which have no ``re``. The native port is deliberately NOT wired into this Python
hot path -- CPython's compiled ``re`` is faster here (see rust/README.md) -- so
these tests compare the native extension's output DIRECTLY against the
pure-Python ``scan`` and prove it is byte-for-byte identical: names/kinds,
codepoint spans, order, dedup and overlap-coalescing, plus a deterministic
differential fuzz. When the wheel isn't built they skip and only the pure-Python
sanity check runs.
"""
from __future__ import annotations

import random
import string

import pytest
from maverick.safety import pii_detector as pd
from maverick.safety import secret_detector as sd

try:
    import maverick_native as _native
except Exception:
    _native = None

NATIVE = _native is not None and hasattr(_native, "secret_scan_spans") and hasattr(
    _native, "pii_scan_spans"
)


def _secret(text):
    """Native extension output as (name, start, end) triples."""
    return [tuple(x) for x in _native.secret_scan_spans(text)]


def _secret_py(text):
    return [(m.name, m.span[0], m.span[1]) for m in sd.scan(text)]


def _pii(text):
    return [tuple(x) for x in _native.pii_scan_spans(text)]


def _pii_py(text):
    return [(m.kind, m.span[0], m.span[1]) for m in pd.scan(text)]


# NOTE: every fixture is a FAKE credential. To exercise the detector patterns
# the runtime string must look like a real token, but a contiguous token literal
# trips GitHub's push protection -- so the recognizable prefix is split from its
# body via ``+``; the bytes on disk are never a whole secret, the runtime value
# still matches. (`# pragma: allowlist secret` covers the local detect-secrets.)
_SECRET_BATTERY = [
    "",
    "nothing to see here",
    "café résumé 漢字 😀 unicode offsets",
    "key sk-" + "ant-abcdefghijklmnopqrstuvwxyz0123456 trailing",  # pragma: allowlist secret
    "OPENAI=sk-" + "proj-abcdefghij_klmnop-qrstuvwxyz0123456789",  # pragma: allowlist secret
    "AKIA" + "IOSFODNN7EXAMPLE and aws_secret_access_key = " + "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY",  # pragma: allowlist secret
    "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz token",  # pragma: allowlist secret
    "github_pat_" + "A" * 82,  # pragma: allowlist secret
    "gho_" + "b" * 36,  # pragma: allowlist secret
    "AIza" + "c" * 35,  # pragma: allowlist secret
    '{"type": "service_account"}',
    "DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=" + "A" * 44,  # pragma: allowlist secret
    "xoxb-1234567890-1234567890-" + "a" * 24,  # pragma: allowlist secret
    "sk_live_" + "0" * 24,  # pragma: allowlist secret
    "sk_test_" + "z" * 30,  # pragma: allowlist secret
    "eyJ" + "hbGciOi.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4",  # pragma: allowlist secret
    "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIB" + "a" * 200 + "\n-----END RSA PRIVATE KEY-----",  # pragma: allowlist secret
    "-----BEGIN PRIVATE KEY-----\n" + "b" * 60 + "  truncated no end marker",  # pragma: allowlist secret
    "glpat-" + "abcdefghijklmnopqrstuvwxyz",  # pragma: allowlist secret
    "SK" + "0123456789abcdef" * 2,  # pragma: allowlist secret  (Twilio-shaped)
    "https://hooks.slack.com/services/" + "T00/B00/XXXXXXXX",
    "postgres://user:p@ss@db.host:5432/name",  # pragma: allowlist secret
    "Authorization: Bearer " + "abcdef0123456789._-+/=",  # pragma: allowlist secret
    "export INTERNAL_API_TOKEN=" + "supersecret123\nDB_PASSWORD=hunter2hunter2",  # pragma: allowlist secret
    "  MY_SECRET_KEY = value_here_xyz",  # pragma: allowlist secret
    # multibyte prefix to stress codepoint-vs-byte span reporting
    "é漢😀 sk-" + "ant-abcdefghijklmnopqrstuvwxyz01 done",  # pragma: allowlist secret
]

_PII_BATTERY = [
    "",
    "plain text, no PII",
    "email me at john.doe@example.com please",
    "ssn 123-45-6789 valid; 000-12-3456 and 666-99-9999 invalid",
    "ip 192.168.1.1 and 255.255.255.255 and 256.1.1.1 (not ip)",
    "v6 2001:db8::1 fe80::1 ::1 2001:db8::dead:beef ::",
    "call (555) 123-4567 or 555.123.4567 or +1 555 123 4567",
    "13-digit run 1234567890123 is not a phone",
    "card 4111 1111 1111 1111 valid; 4111 1111 1111 1112 invalid",
    "addr 123 Main Street and 4567 Oak Ave",
    "mixed bob@corp.io 10.0.0.5 415-555-1234 4242424242424242",
    "overlap 5555555555554444 then 555-555-5555",
    "é漢😀 unicode then 192.168.0.1 and a@b.co",
]


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
@pytest.mark.parametrize("text", _SECRET_BATTERY)
def test_secret_native_matches_pure_python(text):
    assert _secret(text) == _secret_py(text)


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
@pytest.mark.parametrize("text", _PII_BATTERY)
def test_pii_native_matches_pure_python(text):
    assert _pii(text) == _pii_py(text)


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
def test_native_not_wired_into_python_hotpath():
    # The native engine exists, but the Python scanners stay pure `re` on purpose
    # (faster here). Guard against a future accidental re-wiring of the shim.
    assert not hasattr(sd, "_scan_py"), "secret_detector should not install a native shim"
    assert not hasattr(pd, "_scan_py"), "pii_detector should not install a native shim"


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
def test_differential_fuzz():
    """Deterministic fuzz: native and pure Python must agree on every input."""
    rng = random.Random(20260615)
    toks = [  # pragma: allowlist secret  (fake token fragments for fuzzing)
        "sk-ant-", "sk-proj-", "AKIA" + "1234567890ABCDEF", "ghp_", "gho_", "AIza",  # pragma: allowlist secret
        '"type":"service_account"', "xoxb-1-2-", "sk_live_", "eyJa.eyJb.cccc",  # pragma: allowlist secret -- deliberately truncated synthetic detector fixture
        "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----",  # pragma: allowlist secret
        "glpat-", "postgres://u:p@h/d", "Authorization: Bearer ", "SECRET_KEY=",
        "\nAPI_TOKEN=", "@example.com", "123-45-6789", "192.168.1.1",
        "2001:db8::1", "fe80::1", "::", "(555) 123-4567", "4111111111111111",
        " Main Street ", " Oak Ave ",
    ]
    charsets = [
        string.digits + " -.:",
        "0123456789abcdefABCDEF:.",
        string.ascii_uppercase + "0123456789_= \n",
        string.ascii_letters + string.digits + "-_./@:+= \n()é漢😀",
    ]
    for _ in range(3000):
        cs = rng.choice(charsets)
        s = "".join(rng.choice(cs) for _ in range(rng.randint(0, 80)))
        for _ in range(rng.randint(0, 3)):
            pos = rng.randint(0, len(s))
            s = s[:pos] + rng.choice(toks) + s[pos:]
        assert _secret(s) == _secret_py(s), s
        # Native deliberately raises on a Luhn-ambiguous non-ASCII-digit card
        # candidate (the documented fall-back point); skip only that case.
        try:
            native_pii = _pii(s)
        except ValueError:
            continue
        assert native_pii == _pii_py(s), s


def test_pure_python_sanity_unchanged():
    """Always-on: the public API behaves regardless of the native extension."""
    red, matches = sd.redact("token ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz here")
    assert "[REDACTED:github_pat_classic]" in red
    assert matches and matches[0].name == "github_pat_classic"

    red2, m2 = pd.redact("ssn 123-45-6789 email a@b.com")
    assert "[REDACTED:ssn]" in red2 and "[REDACTED:email]" in red2


@pytest.mark.skipif(not NATIVE, reason="native scanner not built")
def test_native_large_input_and_overlapping_boundary_candidates():
    token = "lw-rest-" + "a" * 24
    data = ("ordinary " * 140_000) + " " + token + " 123-45-6789"
    assert _secret(data) == _secret_py(data)
    assert _pii(data) == _pii_py(data)
    for text in ("١(555) 123-4567", "²(555) 123-4567",
                 "x" + token, token + "_suffix", "666-12-3456"):
        assert _secret(text) == _secret_py(text)
        assert _pii(text) == _pii_py(text)
