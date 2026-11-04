"""Tests for consent gating (maverick.safety.consent)."""
from __future__ import annotations

import pytest

# ---------- consent ----------

def test_consent_auto_approve_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    from maverick.safety.consent import require_consent
    d = require_consent("test-action", risk="high")
    assert d.granted is True
    assert d.source == "auto"


def test_consent_auto_deny_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    from maverick.safety.consent import require_consent
    d = require_consent("test-action")
    assert d.granted is False
    assert d.source == "auto"


def test_consent_ask_mode_non_tty_denies(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # 'ask' mode in a non-tty context (pytest captures stdin) denies.
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "ask")
    from maverick.safety.consent import require_consent
    d = require_consent("test-action")
    assert d.granted is False
    assert d.source == "non-tty-deny"


def test_consent_default_is_opt_in_auto_approve(tmp_path, monkeypatch):
    # With no MAVERICK_CONSENT_MODE set, gating is OFF (auto-approve) so wiring
    # require_consent into tools doesn't change out-of-the-box behavior.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    from maverick.safety.consent import require_consent
    d = require_consent("test-action")
    assert d.granted is True
    assert d.source == "auto"


def test_consent_raise_on_deny(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    from maverick.safety.consent import ConsentDenied, require_consent
    with pytest.raises(ConsentDenied):
        require_consent("rm-rf", raise_on_deny=True)


def test_consent_ledger_grant_then_check(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    from maverick.safety.consent import grant_persistent, list_grants, require_consent
    grant_persistent("force-push", scope="main")
    grants = list_grants()
    assert ("force-push", "main") in grants
    d = require_consent("force-push", scope="main")
    assert d.granted is True
    assert d.source == "ledger"


def test_consent_revoke(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.safety.consent import grant_persistent, list_grants, revoke
    grant_persistent("rm-rf", scope="/tmp/test")
    assert ("rm-rf", "/tmp/test") in list_grants()
    assert revoke("rm-rf", scope="/tmp/test") is True
    assert ("rm-rf", "/tmp/test") not in list_grants()
    # Idempotent: revoking again returns False.
    assert revoke("rm-rf", scope="/tmp/test") is False
