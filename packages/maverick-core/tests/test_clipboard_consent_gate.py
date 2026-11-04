"""The clipboard tool gates read AND write through the consent path.

The clipboard holds passwords / 2FA codes / tokens, and it's host-bound so it
can't be sandbox-mediated. Both read and write therefore require a fresh human
decision; silent auto-approval and explicit denial both block the effect with a
clear error (not a crash).
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.tools.clipboard import clipboard


@pytest.fixture
def _fake_backends(monkeypatch):
    """Stub the actual clipboard backends so the test never touches a real
    desktop clipboard; we only care about the consent gate around them."""
    monkeypatch.setattr("maverick.tools.clipboard._read_clipboard", lambda: "SECRET")
    monkeypatch.setattr("maverick.tools.clipboard._write_clipboard", lambda text: True)


def test_clipboard_read_blocked_under_auto_deny(tmp_path: Path, monkeypatch, _fake_backends):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    out = clipboard().fn({"op": "read"})
    assert out == "ERROR: clipboard access was not approved; no clipboard action was sent"
    # The secret must NOT have been returned.
    assert "SECRET" not in out


def test_clipboard_write_blocked_under_auto_deny(tmp_path: Path, monkeypatch, _fake_backends):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    out = clipboard().fn({"op": "write", "text": "planted"})
    assert out == "ERROR: clipboard access was not approved; no clipboard action was sent"


@pytest.mark.parametrize(
    "args",
    [{"op": "read"}, {"op": "write", "text": "hello"}],
)
def test_clipboard_silent_auto_approve_is_not_human_consent(
    args, tmp_path: Path, monkeypatch, _fake_backends,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    assert clipboard().fn(args) == (
        "ERROR: clipboard access was not approved; no clipboard action was sent"
    )


def _approve_as_human(monkeypatch):
    import maverick.safety.consent as consent

    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        ),
    )


def test_clipboard_read_allowed_after_human_approval(
    tmp_path: Path, monkeypatch, _fake_backends,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    _approve_as_human(monkeypatch)
    out = clipboard().fn({"op": "read"})
    assert out == "SECRET"


def test_clipboard_write_allowed_after_human_approval(
    tmp_path: Path, monkeypatch, _fake_backends,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    _approve_as_human(monkeypatch)
    out = clipboard().fn({"op": "write", "text": "hello"})
    assert "wrote 5 chars" in out


def test_clipboard_env_disable_still_wins(tmp_path: Path, monkeypatch, _fake_backends):
    """The pre-existing global env disable is preserved and short-circuits
    before the consent gate."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIPBOARD_DISABLE", "1")
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    out = clipboard().fn({"op": "read"})
    assert "disabled by MAVERICK_CLIPBOARD_DISABLE" in out


def test_clipboard_target_drift_after_approval_never_reads(tmp_path: Path, monkeypatch):
    import maverick.safety.consent as consent

    calls = []

    def approve(*_args, **_kwargs):
        monkeypatch.setenv("MAVERICK_CLIPBOARD_DISABLE", "1")
        return SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        )

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CLIPBOARD_DISABLE", raising=False)
    monkeypatch.setattr(consent, "require_consent", approve)
    monkeypatch.setattr(
        "maverick.tools.clipboard._read_clipboard",
        lambda: calls.append(True) or "SECRET",
    )

    out = clipboard().fn({"op": "read"})

    assert "target or approval authority changed" in out
    assert calls == []
