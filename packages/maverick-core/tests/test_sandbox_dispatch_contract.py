"""A sandbox failure must never act as a probe that replays its side effects."""
from __future__ import annotations

import os
import shlex

import pytest
from maverick.sandbox import LocalBackend
from maverick.sandbox.local import ExecResult
from maverick.tools import sandbox_run


def test_internal_typeerror_after_effect_is_not_replayed():
    effects = []

    class Backend:
        def exec(self, cmd, timeout=None):
            effects.append((cmd, timeout))
            raise TypeError("result decoding failed after effect")

    with pytest.raises(TypeError, match="after effect"):
        sandbox_run(Backend(), ["synthetic", "operation"], timeout=3)
    assert effects == [("synthetic operation", 3)]


def test_nonconforming_backend_is_not_dispatched_without_deadline():
    effects = []

    class Backend:
        def exec(self, cmd):
            effects.append(cmd)

    with pytest.raises(TypeError, match="timeout"):
        sandbox_run(Backend(), ["synthetic"], timeout=3)
    assert not effects


def test_missing_exec_never_falls_back_to_host(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid sandbox fell back to host execution")

    monkeypatch.setattr("subprocess.run", unexpected)
    with pytest.raises(TypeError, match="configured sandbox"):
        sandbox_run(object(), ["synthetic"], timeout=3)


def test_declared_exec_preserves_timeout_quoting_and_input():
    calls = []

    class Backend:
        def exec(self, cmd, *, timeout):
            calls.append((cmd, timeout))
            return ExecResult(stdout="ok", stderr="", exit_code=0)

    assert sandbox_run(Backend(), ["synthetic", "argument with spaces"], timeout=2) == (0, "ok", "")
    assert shlex.split(calls[0][0]) == ["synthetic", "argument with spaces"]
    sandbox_run(Backend(), ["synthetic"], timeout=4, stdin="untrusted $() input")
    assert calls[1][1] == 4
    assert "untrusted $() input" not in calls[1][0]
    assert "base64 -d" in calls[1][0]


def test_windows_local_backend_passes_argv_without_shell_interpolation(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows LocalBackend argv dispatch")
    value = "& echo injected %PATH%"

    code, out, err = sandbox_run(
        LocalBackend(workdir=tmp_path),
        ["python", "-c", "import sys; print(sys.argv[1])", value],
        timeout=10,
    )

    assert code == 0, err
    assert out.strip() == value
