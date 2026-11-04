"""Explicit finite legacy backend admission; no timeout-emulation threads."""
from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from maverick.sandbox import sdk
from maverick.sandbox.local import ExecResult
from maverick.tools import sandbox_run


class FixedBackend:
    def __init__(self, workdir=None, timeout=None, **options):
        self.workdir = workdir
        self.legacy_execution_policy = sdk.LegacyExecutionPolicy(.1)
        self.calls = []

    def exec(self, command):
        self.calls.append(command)
        return ExecResult(stdout="ok", stderr="", exit_code=0)


def test_declared_legacy_shape_adapts_before_one_effect():
    backend = FixedBackend()
    assert sandbox_run(backend, ["fixture", "value with spaces"], timeout=.1) == (0, "ok", "")
    assert backend.calls == ["fixture 'value with spaces'"]


def test_shorter_requested_deadline_never_dispatches():
    backend = FixedBackend()
    with pytest.raises(ValueError, match="shorter requested timeout"):
        sandbox_run(backend, ["fixture"], timeout=.05)
    assert backend.calls == []


@pytest.mark.parametrize("limit", [0, -1, float("inf"), float("nan"), True, "1"])
def test_declaration_must_be_positive_finite_numeric(limit):
    with pytest.raises(ValueError, match="finite and positive"):
        sdk.LegacyExecutionPolicy(limit)


@pytest.mark.parametrize("limit", [0, float("inf"), float("nan"), True])
def test_invalid_caller_limit_never_dispatches(limit):
    backend = FixedBackend()
    with pytest.raises(ValueError, match="finite and positive"):
        sandbox_run(backend, ["fixture"], timeout=limit)
    assert not backend.calls


@pytest.mark.parametrize("change", ["policy", "method"])
def test_changed_admitted_owner_requires_readmission(change):
    backend = FixedBackend()
    adapter = sdk.LegacySandboxAdapter(backend)
    if change == "policy":
        backend.legacy_execution_policy = sdk.LegacyExecutionPolicy(.05)
    else:
        backend.exec = lambda cmd: pytest.fail("changed executor invoked")
    with pytest.raises(RuntimeError, match="policy changed"):
        adapter.exec("fixture", timeout=1)
    assert not backend.calls


@pytest.mark.parametrize("error", [TypeError("after effect"), asyncio.CancelledError(), KeyboardInterrupt()])
def test_legacy_effect_error_or_stop_is_never_replayed(error):
    class Backend(FixedBackend):
        def exec(self, command):
            self.calls.append(command)
            raise error

    backend = Backend()
    with pytest.raises(type(error)):
        sandbox_run(backend, ["fixture"], timeout=1)
    assert backend.calls == ["fixture"]


def test_legacy_entry_point_is_admitted_before_effect(monkeypatch, tmp_path):
    monkeypatch.setattr(sdk, "_sandbox_entry_points", lambda: [SimpleNamespace(name="fixed", load=lambda: FixedBackend)])
    backend = sdk.load_entry_point_backend("fixed", workdir=tmp_path, timeout=.2)
    assert isinstance(backend, sdk.LegacySandboxAdapter)
    assert sdk.conformance(backend) == []
    assert backend.workdir == tmp_path
    assert backend.calls == []
    assert backend.exec("fixture", timeout=.1).stdout == "ok"
    with pytest.raises(ValueError, match="shorter requested timeout"):
        sdk.load_entry_point_backend("fixed", workdir=tmp_path, timeout=.05)


def test_backend_owned_fixed_cap_reaps_actual_controlled_child():
    class BoundedBackend(FixedBackend):
        def exec(self, command):
            self.calls.append(command)
            self.process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            try:
                self.process.wait(timeout=self.legacy_execution_policy.max_seconds)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
                return ExecResult(stdout="", stderr="fixed backend timeout", exit_code=124)
            finally:
                if self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=2)
            raise AssertionError("controlled child should exceed the backend-owned cap")

    backend = BoundedBackend()
    started = time.monotonic()
    assert sandbox_run(backend, ["fixture"], timeout=1)[0] == 124
    assert time.monotonic() - started < 3
    assert backend.process.poll() is not None
    assert backend.calls == ["fixture"]
