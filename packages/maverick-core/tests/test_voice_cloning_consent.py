"""voice_cloning_consent: deny-by-default voice-clone consent gate."""
from __future__ import annotations

from maverick.tools.voice_cloning_consent import voice_cloning_consent


def _check(**kw):
    return voice_cloning_consent().fn({"op": "check", **kw})


def test_allow_granted_in_scope_not_expired():
    out = _check(
        consent={"subject": "alice", "granted": True, "scope": ["ads", "narration"],
                 "expires_iso": "2030-01-01"},
        requested_scope="ads",
        today_iso="2026-06-09",
    )
    assert out.startswith("ALLOW") and "alice" in out


def test_deny_not_granted():
    out = _check(
        consent={"subject": "bob", "granted": False, "scope": ["ads"]},
        requested_scope="ads",
        today_iso="2026-06-09",
    )
    assert out.startswith("DENY") and "not granted" in out


def test_deny_by_default_non_bool_granted():
    # A stringy "true" is truthy in Python but must fail closed.
    out = _check(
        consent={"subject": "c", "granted": "true", "scope": ["ads"]},
        requested_scope="ads",
        today_iso="2026-06-09",
    )
    assert out.startswith("DENY")


def test_deny_scope_mismatch_and_wildcard_allows():
    miss = _check(
        consent={"subject": "d", "granted": True, "scope": ["narration"]},
        requested_scope="ads",
        today_iso="2026-06-09",
    )
    assert miss.startswith("DENY") and "scope" in miss
    star = _check(
        consent={"subject": "d", "granted": True, "scope": "*"},
        requested_scope="anything",
        today_iso="2026-06-09",
    )
    assert star.startswith("ALLOW")


def test_deny_expired():
    out = _check(
        consent={"subject": "e", "granted": True, "scope": ["ads"],
                 "expires_iso": "2026-01-01"},
        requested_scope="ads",
        today_iso="2026-06-09",
    )
    assert out.startswith("DENY") and "expired" in out


def test_errors_and_factory_shape():
    t = voice_cloning_consent()
    assert t.fn({"op": "check", "requested_scope": "x", "today_iso": "2026-01-01"}).startswith("ERROR")
    assert t.fn({"op": "nope", "consent": {}, "requested_scope": "x", "today_iso": "2026-01-01"}).startswith("ERROR")
    assert t.name == "voice_cloning_consent"
    assert t.parallel_safe is True
    assert t.input_schema["required"] == ["consent", "requested_scope", "today_iso"]
