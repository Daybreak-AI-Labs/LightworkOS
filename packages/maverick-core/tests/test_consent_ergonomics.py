"""consent_ergonomics: plain-language consent prompt + risk badge."""
from __future__ import annotations

from maverick.tools.consent_ergonomics import consent_ergonomics


def _run(request):
    return consent_ergonomics().fn({"op": "summarize", "request": request})


def test_low_risk_read_only():
    out = _run({"action": "read your notes", "scopes": ["read_notes"],
                "duration": "1 hour"})
    assert out.startswith("CONSENT [LOW]")
    assert "Allow read your notes?" in out
    assert "Duration: 1 hour." in out


def test_high_risk_scope_badge():
    out = _run({"action": "manage account", "scopes": ["delete_all"],
                "duration": "1 day"})
    assert out.startswith("CONSENT [HIGH]")


def test_med_risk_scope_badge():
    out = _run({"action": "post update", "scopes": ["send_messages"],
                "duration": "1 day"})
    assert out.startswith("CONSENT [MED]")


def test_flags_wildcard_overbroad():
    out = _run({"action": "do everything", "scopes": ["*"], "duration": "1d"})
    assert "flags:" in out
    assert "over-broad" in out


def test_flags_missing_duration_and_too_many_scopes():
    out = _run({"action": "sync", "scopes": [f"read_{i}" for i in range(6)]})
    assert "no duration set" in out
    assert "6 scopes" in out


def test_lists_data_accessed():
    out = _run({"action": "back up", "scopes": ["read_files"],
                "data": ["photos", "contacts"], "duration": "always"})
    assert "photos" in out and "contacts" in out


def test_errors_and_contract():
    assert consent_ergonomics().fn(
        {"op": "summarize", "request": "nope"}).startswith("ERROR")
    assert _run({"scopes": ["x"]}).startswith("ERROR")  # missing action
    assert consent_ergonomics().fn(
        {"op": "bad", "request": {"action": "a"}}).startswith("ERROR")
    t = consent_ergonomics()
    assert t.name == "consent_ergonomics" and t.parallel_safe is True
