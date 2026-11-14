"""`maverick doctor` schema-lints the config so a mistyped key (e.g. a budget
cap typo that would otherwise run UNCAPPED) surfaces, not only in the dedicated
`maverick config-lint`. Advisory: findings are warnings, never failures."""
from __future__ import annotations

import maverick.health as h


def test_doctor_config_lint_flags_budget_typo(capsys):
    h._FAILURES.clear()
    h._check_config_lint({"budget": {"max_dollarss": 5.0}})
    out = capsys.readouterr().out
    assert "config-lint" in out
    assert "max_dollarss" in out          # the typo is named
    assert "✗" not in out                 # advisory (!), not a red failure
    assert h._FAILURES == []              # does not count toward the exit code


def test_doctor_config_lint_clean_config(capsys):
    h._FAILURES.clear()
    h._check_config_lint({"budget": {"max_dollars": 5.0}})
    out = capsys.readouterr().out
    assert "config-lint" in out and "no unknown" in out
    assert h._FAILURES == []


def test_doctor_config_lint_noop_on_empty_config(capsys):
    # corrupt / missing config -> _check_config already reported it; stay quiet
    h._FAILURES.clear()
    h._check_config_lint({})
    assert capsys.readouterr().out == ""
    assert h._FAILURES == []


def test_diagnose_wires_in_config_lint():
    import inspect
    assert "_check_config_lint" in inspect.getsource(h.diagnose)


def test_governance_tool_names_are_a_doctor_notice_that_never_blocks_a_strict_start(monkeypatch, capsys):
    from maverick import config_lint

    cfg = {"governance": {"deny_actions": ["browser_navigate", "mcp_github__delete_repo", "Computer",
                                           "shel"]}}
    pre_installed = {"governance": {"deny_actions": ["browser_navigate", "mcp_github__delete_repo"]}}
    with monkeypatch.context() as startup:
        startup.setattr("maverick.config.config_path", lambda: type("P", (), {"exists": lambda self: True})())
        startup.setattr("maverick.config._read_toml_raw", lambda p: pre_installed)
        config_lint.warn_config_at_startup(strict=True)  # no SystemExit
    h._FAILURES.clear()
    h._check_governance_tool_names(cfg)
    out = capsys.readouterr().out
    assert "shel" in out and h._FAILURES == []          # a misspelled built-in is shown
    assert "mcp_github__delete_repo" not in out          # MCP tools are not in the catalog
    assert "Computer" not in out                         # optional built-ins count, case-insensitively
