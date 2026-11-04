"""Tests for the Podman sandbox backend (maverick.sandbox.podman)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest as _workspace_guard_pytest

# ---------- sandbox: timeout cleanup never masks the TIMEOUT result ----

def test_podman_timeout_cleanup_swallows_cleanup_error(monkeypatch, tmp_path):
    import subprocess

    from maverick.sandbox.podman import PodmanBackend

    def _run(args, *a, **k):
        if args[:2] == ["podman", "version"]:
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        if args[:2] == ["podman", "rm"]:
            # Cleanup itself blows up — must be swallowed.
            raise subprocess.TimeoutExpired(cmd="podman rm", timeout=10)
        # The actual `podman run` times out.
        raise subprocess.TimeoutExpired(cmd="podman run", timeout=5)

    monkeypatch.setattr("subprocess.run", _run)
    backend = PodmanBackend(workdir=tmp_path, image="alpine")
    result = backend.exec("sleep 999")
    assert result.exit_code == 124
    assert "TIMEOUT" in result.stderr


# Container argv tests use a workspace separate from the operator's state.
@_workspace_guard_pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))


# ---------- Podman sandbox ----------

def test_podman_verify_missing(tmp_path, monkeypatch):
    """No podman binary on PATH -> RuntimeError with actionable msg."""
    from maverick.sandbox.podman import PodmanBackend

    def _no_podman(args, *a, **k):
        if args and args[0] == "podman":
            raise FileNotFoundError("podman")
        raise AssertionError(f"unexpected: {args}")

    monkeypatch.setattr("subprocess.run", _no_podman)
    try:
        PodmanBackend(workdir=tmp_path)
    except RuntimeError as e:
        assert "podman" in str(e).lower()
        return
    raise AssertionError("expected RuntimeError")


def test_podman_exec_runs_container(tmp_path, monkeypatch):
    from maverick.sandbox.podman import PodmanBackend

    calls = {"n": 0, "args": []}

    def _fake_run(args, *a, **k):
        calls["n"] += 1
        calls["args"].append(args)
        if args[:2] == ["podman", "version"]:
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        # Match the second `podman run` call.
        return MagicMock(returncode=0, stdout="hello\n", stderr="")

    monkeypatch.setattr("subprocess.run", _fake_run)
    backend = PodmanBackend(workdir=tmp_path, image="alpine")
    result = backend.exec("echo hello")
    assert result.exit_code == 0
    assert "hello" in result.stdout

    run_args = calls["args"][1]
    assert run_args[0] == "podman"
    assert "--rm" in run_args
    assert "--network" in run_args  # default allow_network=False
    assert "alpine" in run_args


def test_podman_allows_network_when_flag_set(tmp_path, monkeypatch):
    from maverick.sandbox.podman import PodmanBackend

    captured = {"args": None}

    def _fake_run(args, *a, **k):
        if args[:2] == ["podman", "version"]:
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        captured["args"] = args
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", _fake_run)
    backend = PodmanBackend(workdir=tmp_path, allow_network=True)
    backend.exec("true")
    assert "--network" not in captured["args"]


def test_build_sandbox_constructs_podman(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "subprocess.run",
        lambda args, *a, **k: MagicMock(returncode=0, stdout=b"", stderr=b""),
    )
    # Monkeypatch config so backend = "podman" without writing a real file.
    import maverick.config as cfg
    from maverick.sandbox import build_sandbox

    def _fake_cfg():
        return {"sandbox": {"backend": "podman", "workdir": str(tmp_path),
                            "timeout": 30}}

    monkeypatch.setattr(cfg, "load_config", _fake_cfg)
    monkeypatch.setattr(cfg, "get_sandbox", lambda: _fake_cfg()["sandbox"])
    sb = build_sandbox()
    assert sb.__class__.__name__ == "PodmanBackend"
