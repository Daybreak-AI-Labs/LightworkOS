"""Tests for the maverick CLI: command registration and progress-line sanitizing."""
from __future__ import annotations

from maverick.cli import _sanitize_progress_content

# ---------- CLI surface (smoke import) ----------

def test_cli_imports_with_new_commands():
    """Ensure the new commands attached to main don't break import."""
    from maverick.cli import main
    cmds = main.commands.keys()
    assert "audit" in cmds
    assert "halt" in cmds
    assert "unhalt" in cmds
    assert "cost" in cmds
    assert "export" in cmds
    assert "logs" in cmds


def test_cli_audit_subgroup_has_tail_grep():
    from maverick.cli import main
    audit = main.commands["audit"]
    assert "tail" in audit.commands
    assert "grep" in audit.commands


class TestProgressSanitization:
    def test_strips_terminal_control_sequences(self):
        text = "ok\r\n\x1b[2Kforged\x1b]52;c;QUJD\x07tail"
        out = _sanitize_progress_content(text, limit=200)
        assert "\x1b" not in out
        assert "\r" not in out and "\n" not in out
        assert "forged" in out

    def test_scrubs_secrets_before_display(self):
        text = "Authorization: Bearer abc123secrettokenvalue4567890"
        out = _sanitize_progress_content(text, limit=200)
        assert "abc123secrettokenvalue4567890" not in out
        assert "[REDACTED:bearer]" in out
