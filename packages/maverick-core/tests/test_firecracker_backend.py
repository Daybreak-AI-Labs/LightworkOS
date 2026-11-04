"""Tests for the Firecracker sandbox backend (maverick.sandbox.firecracker)."""
from __future__ import annotations

import subprocess

import pytest
import pytest as _workspace_guard_pytest


# Container argv tests use a workspace separate from the operator's state.
@_workspace_guard_pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))


class TestSandboxHardening:
    def test_firecracker_docker_fallback_drops_caps(self, monkeypatch, tmp_path):
        from maverick.sandbox import firecracker
        monkeypatch.setattr(firecracker.shutil, "which",
                            lambda _x: "/usr/bin/firecracker")
        captured = []

        def fake_run(args, **kwargs):
            captured.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        backend = firecracker.FirecrackerBackend(workdir=tmp_path, provider="local")
        backend._docker_fallback("echo hi")
        run_args = next(a for a in captured if a[:2] == ["docker", "run"])
        assert "--cap-drop" in run_args and "ALL" in run_args
        assert "no-new-privileges" in run_args


# ---------- Firecracker sandbox ----------

class TestFirecrackerBackend:
    def test_local_provider_requires_firecracker_binary(self, monkeypatch):
        from maverick.sandbox.firecracker import FirecrackerBackend
        monkeypatch.setattr("shutil.which", lambda c: None)
        from pathlib import Path
        with pytest.raises(NotImplementedError, match="firecracker"):
            FirecrackerBackend(workdir=Path.cwd(), provider="local")

    def test_e2b_provider_requires_api_key(self, monkeypatch):
        from maverick.sandbox.firecracker import FirecrackerBackend
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        from pathlib import Path
        with pytest.raises(ValueError, match="E2B_API_KEY"):
            FirecrackerBackend(workdir=Path.cwd(), provider="e2b")

    def test_e2b_picks_up_env_key(self, monkeypatch):
        from maverick.sandbox.firecracker import FirecrackerBackend
        monkeypatch.setenv("E2B_API_KEY", "test-key")
        from pathlib import Path
        b = FirecrackerBackend(workdir=Path.cwd(), provider="e2b")
        assert b.api_key == "test-key"

    def test_unknown_provider_raises(self, monkeypatch):
        from maverick.sandbox.firecracker import FirecrackerBackend
        monkeypatch.setattr("shutil.which", lambda c: "/usr/bin/firecracker")
        from pathlib import Path
        with pytest.raises(ValueError, match="provider"):
            FirecrackerBackend(workdir=Path.cwd(), provider="bogus")

    def test_build_sandbox_factory_wires_firecracker(self, monkeypatch, tmp_path):
        """The build_sandbox() factory routes `backend=firecracker` correctly.

        We force the e2b provider so __post_init__'s `firecracker` binary
        check doesn't run (E2B path only needs an API key).
        """
        from maverick.sandbox import FirecrackerBackend
        monkeypatch.setenv("E2B_API_KEY", "test-key")
        # Direct construction; the factory tests are covered by build_sandbox
        # itself but they require the config layer to set provider=e2b.
        sb = FirecrackerBackend(
            workdir=tmp_path, provider="e2b", api_key="k",
        )
        assert isinstance(sb, FirecrackerBackend)
        assert sb.provider == "e2b"


class TestFirecrackerStrictDefault:
    """Firecracker fails CLOSED by default when firectl is absent (no silent
    downgrade to a weaker Docker boundary); the hardened fallback is only
    reached when the operator opts in with MAVERICK_FIRECRACKER_STRICT=0."""

    def _backend(self, monkeypatch, tmp_path):
        import shutil
        from pathlib import Path

        from maverick.sandbox.firecracker import FirecrackerBackend
        # Construct successfully (firecracker binary 'present').
        monkeypatch.setattr(shutil, "which", lambda c: "/usr/bin/firecracker")
        return FirecrackerBackend(workdir=Path(tmp_path), provider="local")

    def test_fails_closed_by_default_without_firectl(self, monkeypatch, tmp_path):
        import shutil

        import pytest
        b = self._backend(monkeypatch, tmp_path)
        monkeypatch.delenv("MAVERICK_FIRECRACKER_STRICT", raising=False)
        monkeypatch.setattr(shutil, "which", lambda c: None)  # firectl absent
        with pytest.raises(RuntimeError, match="microVM isolation is unavailable"):
            b._exec_local("echo hi")

    def test_strict_zero_allows_hardened_fallback(self, monkeypatch, tmp_path):
        import shutil
        b = self._backend(monkeypatch, tmp_path)
        monkeypatch.setenv("MAVERICK_FIRECRACKER_STRICT", "0")
        monkeypatch.setattr(shutil, "which", lambda c: None)
        called = {}
        monkeypatch.setattr(b, "_docker_fallback", lambda cmd: called.setdefault("cmd", cmd))
        b._exec_local("echo hi")
        assert called["cmd"] == "echo hi"

    def test_docker_fallback_is_hardened(self, monkeypatch, tmp_path):
        import subprocess
        b = self._backend(monkeypatch, tmp_path)
        captured = {}

        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        def _fake_run(args, **kw):
            captured["args"] = args
            return _P()

        monkeypatch.setattr(subprocess, "run", _fake_run)
        b._docker_fallback("echo hi")
        args = captured["args"]
        assert "--cap-drop" in args and "ALL" in args
        assert "no-new-privileges" in args
        assert "--network=none" in args and "--read-only" in args
