"""`maverick doctor` surfaces the active deployment profile + posture."""
from __future__ import annotations

import maverick.health as h


def test_profile_row_standard_by_default(monkeypatch, capsys):
    monkeypatch.delenv("MAVERICK_PROFILE", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    h._check_profile()
    out = capsys.readouterr().out
    assert "deployment profile = standard" in out
    assert "egress lock off" in out


def test_profile_row_enterprise(monkeypatch, capsys):
    monkeypatch.setenv("MAVERICK_PROFILE", "enterprise")
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    h._check_profile()
    out = capsys.readouterr().out
    assert "deployment profile = enterprise" in out
    assert "egress lock ON" in out


def test_profile_row_never_emits_a_failure(monkeypatch):
    """The posture row is informational — it must never count as a ✗ failure."""
    monkeypatch.delenv("MAVERICK_PROFILE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    h._FAILURES.clear()
    h._check_profile()
    assert h._FAILURES == []
