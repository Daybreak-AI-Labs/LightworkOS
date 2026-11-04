"""A consumer should never see a Python traceback for an expected failure.

`maverick start/chat/resume/watch` must not let operational errors (no Docker
daemon, a rejected API key, a dropped connection) escape as a raw traceback
or exit 0. These tests pin the friendly-message + non-zero-exit behavior and
the MAVERICK_DEBUG escape hatch.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import _humane_errors, _humanize_run_error, main


def test_sandbox_choice_lists_every_real_backend():
    # An invalid --sandbox value makes click print the valid choices; all of
    # the backends build_sandbox() actually supports must be offered.
    result = CliRunner().invoke(main, ["start", "--sandbox", "nope", "x"])
    assert result.exit_code != 0
    from maverick.sandbox_names import BUILTIN_SANDBOX_BACKENDS

    for backend in BUILTIN_SANDBOX_BACKENDS:
        assert backend in result.output


def test_humanize_sandbox_error_is_actionable():
    msg = _humanize_run_error(RuntimeError(
        "Docker not available. ... change [sandbox] backend to 'local'."
    ))
    assert "sandbox" in msg.lower()
    assert "Traceback" not in msg


def test_humanize_auth_error():
    class AuthenticationError(Exception):
        pass

    msg = _humanize_run_error(
        AuthenticationError("Error code: 401 - invalid x-api-key")
    )
    assert "401" in msg
    assert "rejected" in msg.lower()


def test_humanize_generic_points_to_debug_flag():
    msg = _humanize_run_error(ValueError("something weird"))
    assert "MAVERICK_DEBUG" in msg


def test_humanize_operator_policy_error_is_actionable_and_path_safe():
    from maverick.runtime_overrides import RuntimeOverridesSecurityError

    msg = _humanize_run_error(
        RuntimeOverridesSecurityError("C:/private/runtime-overrides.toml")
    )
    assert "operator policy is unavailable" in msg
    assert "maverick doctor" in msg
    assert "C:/private" not in msg


def test_humane_errors_prints_message_and_exits_nonzero(capsys):
    @_humane_errors
    def boom():
        raise RuntimeError("Docker not available")

    with pytest.raises(SystemExit) as exc:
        boom()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "sandbox" in err.lower()
    assert "Traceback" not in err


def test_humane_errors_debug_reraises(monkeypatch):
    monkeypatch.setenv("MAVERICK_DEBUG", "1")

    @_humane_errors
    def boom():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        boom()


def test_humane_errors_passes_through_success():
    @_humane_errors
    def ok():
        return 42

    assert ok() == 42
