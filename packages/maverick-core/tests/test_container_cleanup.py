"""Cleanup must prove removal, retain uncertainty and bound the total wait."""
from __future__ import annotations

import subprocess

import pytest
import pytest as _workspace_guard_pytest
from maverick.sandbox import container_cleanup as cleanup
from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.podman import PodmanBackend

NAME = "maverick-sandbox-cleanup-fixture"


def _result(args, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, code, stdout=stdout, stderr=stderr)


@pytest.mark.parametrize("engine", ["docker", "podman"])
def test_nonzero_cleanup_is_not_success(monkeypatch, engine):
    calls = []

    def unavailable(args, **kwargs):
        calls.append(args)
        return _result(args, 1, stderr="sensitive daemon response")

    monkeypatch.setattr(cleanup.subprocess, "run", unavailable)
    outcome = cleanup.cleanup_container(NAME, engine)
    assert not outcome.removed
    assert outcome.attempts == 2
    assert "cleanup failed" in outcome.note
    assert "sensitive daemon" not in outcome.note
    assert all(call[0] == engine for call in calls)
    assert len([call for call in calls if call[1] == "rm"]) == 2


def test_force_remove_still_runs_after_kill_error(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args[1])
        if args[1] == "kill":
            raise OSError("no process")
        return _result(args)

    monkeypatch.setattr(cleanup.subprocess, "run", run)
    assert cleanup.cleanup_container(NAME).removed
    assert calls == ["kill", "rm"]


@pytest.mark.parametrize("listed,expected", [("", True), (NAME + "\n", False)])
def test_already_absent_requires_successful_engine_listing(monkeypatch, listed, expected):
    def run(args, **kwargs):
        return _result(args, 0 if args[1] == "ps" else 1, stdout=listed)

    monkeypatch.setattr(cleanup.subprocess, "run", run)
    outcome = cleanup.cleanup_container(NAME)
    assert outcome.removed is expected


def test_retry_can_confirm_removal(monkeypatch):
    removals = 0

    def run(args, **kwargs):
        nonlocal removals
        if args[1] == "rm":
            removals += 1
            return _result(args, 0 if removals == 2 else 1)
        return _result(args, stdout=NAME)

    monkeypatch.setattr(cleanup.subprocess, "run", run)
    outcome = cleanup.cleanup_container(NAME)
    assert outcome.removed and outcome.attempts == 2


def test_all_commands_share_one_deadline(monkeypatch):
    elapsed = 0.0
    timeouts = []

    def run(args, **kwargs):
        nonlocal elapsed
        seconds = kwargs["timeout"]
        timeouts.append(seconds)
        elapsed += seconds
        raise subprocess.TimeoutExpired(args, seconds)

    monkeypatch.setattr(cleanup.time, "monotonic", lambda: elapsed)
    monkeypatch.setattr(cleanup.subprocess, "run", run)
    outcome = cleanup.cleanup_container(NAME, timeout=7)
    assert not outcome.removed
    assert elapsed == 7
    assert timeouts == [5, 2]


@pytest.mark.parametrize("name,engine", [("unowned-service", "docker"), (NAME, "shell")])
def test_rejects_unowned_namespace_or_unknown_engine_before_command(monkeypatch, name, engine):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid cleanup identity reached a process")

    monkeypatch.setattr(cleanup.subprocess, "run", unexpected)
    with pytest.raises(ValueError, match="owned container"):
        cleanup.cleanup_container(name, engine)


@pytest.mark.parametrize("backend_type,engine", [(DockerBackend, "docker"), (PodmanBackend, "podman")])
def test_backend_retains_failed_cleanup_and_reconciles_on_close(monkeypatch, tmp_path, backend_type, engine):
    monkeypatch.setattr(backend_type, "_verify_" + engine, lambda self: None)
    available = False
    executions = 0

    def run(args, **kwargs):
        nonlocal executions
        if args[1] == "run":
            executions += 1
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return _result(args, 0 if available else 1)

    monkeypatch.setattr(cleanup.subprocess, "run", run)
    backend = backend_type(workdir=tmp_path)
    result = backend.exec("synthetic operation", timeout=1)
    assert result.exit_code == 124 and "cleanup failed" in result.stderr
    assert len(backend.pending_cleanup) == 1
    with pytest.raises(RuntimeError, match="cleanup is unresolved"):
        backend.exec("second synthetic operation")
    assert executions == 1
    available = True
    backend.close()
    assert backend.pending_cleanup == {}


def test_warm_timeout_is_not_reused_after_failed_cleanup(monkeypatch, tmp_path):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)

    def run(args, **kwargs):
        if args[1] == "run":
            return _result(args)
        if args[1] == "exec":
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return _result(args, 1)

    monkeypatch.setattr(cleanup.subprocess, "run", run)
    backend = DockerBackend(workdir=tmp_path, reuse_container=True)
    result = backend.exec("synthetic operation", timeout=1)
    assert "cleanup failed" in result.stderr
    assert backend._warm_name is None
    assert len(backend.pending_cleanup) == 1


def test_warm_start_timeout_retains_uncertain_container_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)

    def run(args, **kwargs):
        if args[1] == "run":
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return _result(args, 1)

    monkeypatch.setattr(cleanup.subprocess, "run", run)
    backend = DockerBackend(workdir=tmp_path, reuse_container=True)
    with pytest.raises(RuntimeError, match="start timed out.*cleanup failed"):
        backend.exec("synthetic operation")
    assert backend._warm_name is None and len(backend.pending_cleanup) == 1


# Container argv tests use a workspace separate from the operator's state.
@_workspace_guard_pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))
