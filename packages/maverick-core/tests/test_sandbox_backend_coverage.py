"""`maverick health` / `diagnose` recognize every backend build_sandbox supports.

Previously `_check_sandbox` only knew local/docker/ssh, so a valid podman /
devcontainer / kubernetes / firecracker config was reported as "unsupported"
even though build_sandbox runs it. These pin the expanded coverage.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import pytest as _workspace_guard_pytest
from maverick import config, health
from maverick.tools import diagnose as d


def _health_details(cfg, monkeypatch, *, which=True, run_ok=True) -> str:
    rows: list[str] = []
    monkeypatch.setattr(
        health, "_row",
        lambda marker, label, detail="", fix="": rows.append(f"{detail} || {fix}"),
    )
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}" if which else None)
    if run_ok:
        monkeypatch.setattr("subprocess.run", lambda *a, **k: MagicMock(returncode=0))
    health._check_sandbox(cfg)
    return "\n".join(rows)


class TestHealthBackendCoverage:
    @pytest.mark.parametrize("backend,needle", [
        ("podman", "podman responding"),
        ("kubernetes", "kubectl present"),
        ("devcontainer", "devcontainer"),
    ])
    def test_backend_recognized(self, backend, needle, monkeypatch):
        out = _health_details({"sandbox": {"backend": backend}}, monkeypatch)
        assert needle in out
        assert "not recognized" not in out

    def test_firecracker_local_binary_present(self, monkeypatch):
        out = _health_details(
            {"sandbox": {"backend": "firecracker", "provider": "local"}}, monkeypatch,
        )
        assert "firecracker binary present" in out

    def test_firecracker_e2b_requires_key(self, monkeypatch):
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        cfg = {"sandbox": {"backend": "firecracker", "provider": "e2b"}}
        assert "E2B_API_KEY unset" in _health_details(cfg, monkeypatch, which=False)
        monkeypatch.setenv("E2B_API_KEY", "x")
        assert "via E2B" in _health_details(cfg, monkeypatch, which=False)

    def test_podman_missing_binary_is_red(self, monkeypatch):
        out = _health_details({"sandbox": {"backend": "podman"}}, monkeypatch, which=False)
        assert "podman not on PATH" in out

    def test_truly_unknown_backend_still_flagged(self, monkeypatch):
        out = _health_details({"sandbox": {"backend": "frobnicator"}}, monkeypatch)
        assert "not recognized" in out

    def test_gvisor_requires_registered_docker_runtime(self, monkeypatch):
        class _Result:
            stdout = '{"io.containerd.runc.v2": {}}'

        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr("subprocess.run", lambda *a, **k: _Result())
        missing = _health_details(
            {"sandbox": {"backend": "gvisor"}}, monkeypatch, run_ok=False,
        )
        assert "not registered" in missing

        _Result.stdout = '{"runsc": {"path": "runsc"}}'
        ready = _health_details(
            {"sandbox": {"backend": "gvisor"}}, monkeypatch, run_ok=False,
        )
        assert "registration metadata validated; Docker responding" in ready

        exact = _health_details(
            {"sandbox": {"backend": "gvisor", "runtime": "run"}},
            monkeypatch,
            run_ok=False,
        )
        assert "not an approved gVisor runtime" in exact

        _Result.stdout = "not-json"
        malformed = _health_details(
            {"sandbox": {"backend": "gvisor"}}, monkeypatch, run_ok=False,
        )
        assert "malformed Docker runtime metadata" in malformed

    def test_modal_is_recognized_and_requires_network_acknowledgement(
        self, monkeypatch,
    ):
        blocked = _health_details(
            {"sandbox": {"backend": "modal", "allow_network": False}},
            monkeypatch,
        )
        assert "execution will fail closed" in blocked
        assert "not recognized" not in blocked

    def test_external_entry_point_is_recognized(self, monkeypatch):
        monkeypatch.setattr(
            "maverick.sandbox.sdk.installed_entry_point_names",
            lambda: ("vendor",),
        )
        ready = _health_details(
            {"sandbox": {"backend": "ep:vendor"}}, monkeypatch,
        )
        assert "is installed" in ready
        assert "not recognized" not in ready


class TestDiagnoseBackendCoverage:
    @pytest.mark.parametrize("backend", ["devcontainer", "kubernetes"])
    def test_missing_binary_flagged(self, backend, monkeypatch):
        monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": backend})
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert "not on PATH" in "\n".join(d._check_sandbox())

    def test_firecracker_e2b_missing_key_flagged(self, monkeypatch):
        monkeypatch.setattr(
            config, "get_sandbox",
            lambda: {"backend": "firecracker", "provider": "e2b"},
        )
        monkeypatch.setattr("shutil.which", lambda name: None)
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        assert "E2B_API_KEY unset" in "\n".join(d._check_sandbox())

    def test_gvisor_missing_runtime_flagged(self, monkeypatch):
        class _Result:
            stdout = '{"runc": {}}'

        monkeypatch.setattr(
            config, "get_sandbox", lambda: {"backend": "gvisor"}
        )
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr("subprocess.run", lambda *a, **k: _Result())
        assert "not registered" in "\n".join(d._check_sandbox())

    def test_external_entry_point_missing_is_flagged(self, monkeypatch):
        monkeypatch.setattr(
            config, "get_sandbox", lambda: {"backend": "ep:missing"}
        )
        monkeypatch.setattr(
            "maverick.sandbox.sdk.installed_entry_point_names", tuple
        )
        assert "is not installed" in "\n".join(d._check_sandbox())


class TestE2BSandboxTeardown:
    """The hosted E2B microVM must be torn down even when the process call
    raises, or a transient network error orphans a *billable* sandbox until
    E2B's idle TTL reaps it."""

    def test_sandbox_deleted_even_when_process_raises(self, tmp_path, monkeypatch):
        httpx = pytest.importorskip("httpx")
        from maverick.sandbox.firecracker import FirecrackerBackend

        created = []

        class _FakeClient:
            def __init__(self, *a, **k):
                self.deleted = []
                created.append(self)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def delete(self, url, headers=None):
                self.deleted.append(url)

        monkeypatch.setattr(httpx, "Client", _FakeClient)

        be = FirecrackerBackend(workdir=tmp_path, provider="e2b", api_key="k")
        monkeypatch.setattr(be, "_e2b_create", lambda client: ("sb-leak", 200))

        def _boom(client, sb_id, cmd):
            raise RuntimeError("transient network blip mid-exec")

        monkeypatch.setattr(be, "_e2b_process", _boom)

        res = be._exec_e2b("echo hi")
        # The transient error surfaces as an e2b error result...
        assert res.exit_code == 125
        # ...but the microVM was still deleted (no billable leak).
        assert created
        assert created[0].deleted == ["https://api.e2b.dev/sandboxes/sb-leak"]


class TestContainerResourceCaps:
    """Docker/Podman must bound host RAM by default (OOM is the catastrophic,
    non-recoverable host-DoS); CPU is opt-in since the per-exec timeout already
    bounds a busy-loop."""

    @staticmethod
    def _argv(monkeypatch, Backend, verify_attr, tmp_path, **kw):
        monkeypatch.setattr(Backend, verify_attr, lambda self: None)
        cap: dict = {}

        class _R:
            stdout = ""
            stderr = ""
            returncode = 0

        monkeypatch.setattr("subprocess.run",
                            lambda args, **k: cap.update(args=args) or _R())
        Backend(workdir=tmp_path, **kw).exec("echo hi")
        return cap["args"]

    def test_docker_memory_capped_by_default_cpu_optin(self, tmp_path, monkeypatch):
        from maverick.sandbox.docker import DockerBackend
        args = self._argv(monkeypatch, DockerBackend, "_verify_docker", tmp_path)
        assert args[args.index("--memory") + 1] == "4g"
        assert "--cpus" not in args  # opt-in
        # existing containment must remain intact
        assert "--cap-drop" in args and "no-new-privileges" in args

    def test_docker_cpu_cap_applied_when_configured(self, tmp_path, monkeypatch):
        from maverick.sandbox.docker import DockerBackend
        args = self._argv(monkeypatch, DockerBackend, "_verify_docker", tmp_path,
                          cpus="2", memory="1g")
        assert args[args.index("--cpus") + 1] == "2"
        assert args[args.index("--memory") + 1] == "1g"

    def test_memory_cap_disengageable_with_falsy(self, tmp_path, monkeypatch):
        from maverick.sandbox.docker import DockerBackend
        args = self._argv(monkeypatch, DockerBackend, "_verify_docker", tmp_path,
                          memory="")
        assert "--memory" not in args

    def test_podman_memory_capped_by_default(self, tmp_path, monkeypatch):
        from maverick.sandbox.podman import PodmanBackend
        args = self._argv(monkeypatch, PodmanBackend, "_verify_podman", tmp_path)
        assert args[args.index("--memory") + 1] == "4g"

    def test_build_sandbox_passes_memory_from_config(self, tmp_path, monkeypatch):
        # The [sandbox] memory/cpus knobs reach the backend.
        from maverick import sandbox
        monkeypatch.setattr(sandbox.DockerBackend, "_verify_docker", lambda self: None)
        monkeypatch.setattr(config, "get_sandbox",
                            lambda: {"backend": "docker", "workdir": str(tmp_path)})
        monkeypatch.setattr(
            "maverick.config.load_config",
            lambda: {"sandbox": {"backend": "docker", "memory": "8g", "cpus": "4"}},
        )
        be = sandbox.build_sandbox()
        assert be.memory == "8g" and be.cpus == "4"

    @pytest.mark.parametrize(
        "backend",
        ["local", "podman", "devcontainer", "kubernetes", "firecracker", "ssh"],
    )
    def test_read_only_paths_fail_closed_on_non_enforcing_backends(
        self,
        backend,
        tmp_path,
    ):
        from maverick import sandbox

        with pytest.raises(ValueError, match="read_only_paths requires"):
            sandbox.build_sandbox(
                workdir=tmp_path,
                backend=backend,
                sandbox_config={
                    "backend": backend,
                    "read_only_paths": ["evidence"],
                },
            )


# Container argv tests use a workspace separate from the operator's state.
@_workspace_guard_pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))
