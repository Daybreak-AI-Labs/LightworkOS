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
