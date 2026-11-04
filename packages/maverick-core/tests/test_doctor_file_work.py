"""Doctor and task start describe the effective first-run file-work limit."""
from __future__ import annotations

import maverick.health as health


def test_doctor_names_limited_file_work_and_product_recovery(monkeypatch, capsys):
    monkeypatch.setattr("maverick.runtime_overrides.denied_tools", lambda: set())
    config = {
        "sandbox": {"backend": "local"},
        "security": {"denied_tools": ["shell", "write_file", "apply_patch",
                                      "str_replace_editor", "ast_edit"]},
    }
    health._FAILURES.clear()
    health._check_file_work(config)
    output = capsys.readouterr().out
    assert "file work" in output
    assert "File changes or program execution are off" in output
    assert "Permissions > Where work runs" in output
    assert "Allow file work" in output
    assert health._FAILURES == []  # answer-only operation still works


def test_file_work_notice_does_not_promise_policy_override(monkeypatch):
    monkeypatch.setattr("maverick.runtime_overrides.denied_tools", lambda: {"ast_edit"})
    config = {"sandbox": {"backend": "docker"}, "security": {"denied_tools": []}}
    notice = health.file_work_notice(config)
    assert "organization rule" in notice
    assert "Allow file work" not in notice


def test_file_work_notice_clears_after_container_permission(monkeypatch):
    monkeypatch.setattr("maverick.runtime_overrides.denied_tools", lambda: set())
    config = {"sandbox": {"backend": "docker"}, "security": {"denied_tools": []}}
    assert health.file_work_notice(config) == ""
