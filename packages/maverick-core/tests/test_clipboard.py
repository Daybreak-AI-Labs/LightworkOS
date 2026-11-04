"""Tests for the clipboard tool (maverick.tools.clipboard)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

# ---------- clipboard ----------

def test_clipboard_kill_switch(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIPBOARD_DISABLE", "1")
    from maverick.tools.clipboard import clipboard
    assert "disabled" in clipboard().fn({"op": "read"}).lower()


def test_clipboard_read_via_pyperclip(monkeypatch, fresh_human_decision):
    monkeypatch.delenv("MAVERICK_CLIPBOARD_DISABLE", raising=False)
    # Subject is the pyperclip transport, not the consent gate (covered in
    # test_clipboard_consent_gate); the shared fixture supplies the fresh
    # human decision the clipboard permit requires.
    fake_pyperclip = MagicMock()
    fake_pyperclip.paste.return_value = "from clipboard"
    with patch.dict("sys.modules", {"pyperclip": fake_pyperclip}):
        # Force reload to pick up the mock.
        import importlib

        import maverick.tools.clipboard as _clip_mod
        importlib.reload(_clip_mod)
        out = _clip_mod.clipboard().fn({"op": "read"})
    assert out == "from clipboard"


def test_clipboard_unknown_op():
    from maverick.tools.clipboard import clipboard
    assert "unknown op" in clipboard().fn({"op": "explode"}).lower()
