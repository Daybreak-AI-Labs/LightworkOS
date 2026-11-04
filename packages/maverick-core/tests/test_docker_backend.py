
import os
import pathlib
import subprocess

import pytest
import pytest as _workspace_guard_pytest
from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.podman import PodmanBackend


def _capture_run_argv(monkeypatch, Backend, verify_attr, tmp_path, **kw):
    """Run exec() once with subprocess.run mocked; return the run/exec argv."""
    monkeypatch.setattr(Backend, verify_attr, lambda self: None)
    cap: dict = {}

    class _R:
        stdout = ""
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda args, **k: cap.update(args=args) or _R())
    Backend(workdir=tmp_path, **kw).exec("echo hi")
    return cap["args"]


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX-only uid/gid")
@pytest.mark.parametrize("Backend,verify", [
    (DockerBackend, "_verify_docker"),
    (PodmanBackend, "_verify_podman"),
])
def test_runs_non_root_by_default(monkeypatch, tmp_path, Backend, verify):
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)
    args = _capture_run_argv(monkeypatch, Backend, verify, tmp_path)
    assert "--user" in args
    assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"


@pytest.mark.parametrize("Backend,verify", [
    (DockerBackend, "_verify_docker"),
    (PodmanBackend, "_verify_podman"),
])
def test_allow_root_field_drops_user_flag(monkeypatch, tmp_path, Backend, verify):
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)
    args = _capture_run_argv(monkeypatch, Backend, verify, tmp_path, allow_root=True)
    assert "--user" not in args


def test_allow_root_env_var_drops_user_flag(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_SANDBOX_ALLOW_ROOT", "1")
    args = _capture_run_argv(monkeypatch, DockerBackend, "_verify_docker", tmp_path)
    assert "--user" not in args


def test_memory_swap_pinned_to_memory(monkeypatch, tmp_path):
    args = _capture_run_argv(monkeypatch, DockerBackend, "_verify_docker", tmp_path,
                             memory="2g")
    assert args[args.index("--memory") + 1] == "2g"
    assert args[args.index("--memory-swap") + 1] == "2g"


def test_read_only_paths_are_overlay_mounted(monkeypatch, tmp_path):
    evidence = tmp_path / "context"
    evidence.mkdir()
    (evidence / "PR_DIFF.patch").write_text("trusted", encoding="utf-8")

    args = _capture_run_argv(
        monkeypatch,
        DockerBackend,
        "_verify_docker",
        tmp_path,
        read_only_paths=["context"],
    )

    expected = f"{evidence.resolve()}:/workspace/context:ro"
    assert expected in args
    assert args.index(expected) < args.index("python:3.12-slim")


@pytest.mark.parametrize("configured", ["../outside", "/absolute", "missing"])
def test_read_only_paths_fail_closed_on_unsafe_or_missing_entries(
    monkeypatch, tmp_path, configured
):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    with pytest.raises(ValueError, match="read_only_paths"):
        DockerBackend(workdir=tmp_path, read_only_paths=[configured])


def test_timeout_cleanup_failure_surfaced(monkeypatch, tmp_path):
    """If reaping the orphaned container fails, the leak is reported in stderr
    rather than swallowed under a bare except."""
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)

    def _fake_run(args, **kwargs):
        if args[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 0), output=b"x")
        if args[0] == "docker" and args[1] in {"kill", "rm", "ps"}:
            raise OSError("daemon wedged")
        raise AssertionError(f"unexpected: {args}")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = DockerBackend(workdir=tmp_path).exec("sleep 30", timeout=1)
    assert result.exit_code == 124
    assert result.stderr.startswith("TIMEOUT after 1s")
    assert "cleanup failed" in result.stderr


def test_timeout_forces_container_cleanup(monkeypatch, tmp_path):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["docker", "version"]:
            return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")
        if args[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 0), output=b"partial")
        if args[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected docker call: {args}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    backend = DockerBackend(workdir=tmp_path)
    result = backend.exec("sleep 30", timeout=1)

    assert result.exit_code == 124
    assert result.stderr == "TIMEOUT after 1s"
    assert result.stdout == "partial"

    run_args = next(args for args in calls if args[:2] == ["docker", "run"])
    rm_args = next(args for args in calls if args[:3] == ["docker", "rm", "-f"])
    assert "--name" in run_args
    container_name = run_args[run_args.index("--name") + 1]
    assert rm_args[3] == container_name


def test_build_sandbox_parses_string_false_docker_controls(monkeypatch, tmp_path):
    """Quoted/interpolated false must not enable Docker network or root."""
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "\n".join([
            "[sandbox]",
            'backend = "docker"',
            f'workdir = "{tmp_path}"',
            'allow_network = "${MAV_ALLOW_NETWORK}"',
            'allow_root = "false"',
        ])
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAV_ALLOW_NETWORK", "false")
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)

    from maverick.sandbox import DockerBackend, build_sandbox

    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)

    backend = build_sandbox()
    assert backend.allow_network is False
    assert backend.allow_root is False

    captured: dict = {}

    class _R:
        stdout = ""
        stderr = ""
        returncode = 0

    monkeypatch.setattr(
        subprocess, "run", lambda args, **kwargs: captured.update(args=args) or _R()
    )
    backend.exec("echo hi")

    assert "--network" in captured["args"]
    assert captured["args"][captured["args"].index("--network") + 1] == "none"
    if hasattr(os, "getuid"):
        assert "--user" in captured["args"]
        assert captured["args"][captured["args"].index("--user") + 1] == (
            f"{os.getuid()}:{os.getgid()}"
        )


# ---- gVisor runtime (docker --runtime=runsc) ----

def test_no_runtime_flag_by_default(monkeypatch, tmp_path):
    args = _capture_run_argv(monkeypatch, DockerBackend, "_verify_docker", tmp_path)
    assert "--runtime" not in args


def test_runtime_field_injects_runsc(monkeypatch, tmp_path):
    args = _capture_run_argv(monkeypatch, DockerBackend, "_verify_docker", tmp_path,
                             runtime="runsc")
    assert "--runtime" in args
    assert args[args.index("--runtime") + 1] == "runsc"
    # must precede the image (the positional that ends the docker-run flags)
    assert args.index("--runtime") < args.index("python:3.12-slim")


def test_build_sandbox_gvisor_uses_runsc(monkeypatch, tmp_path):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    monkeypatch.setattr(
        "maverick.sandbox.validate_docker_gvisor_runtime",
        lambda runtime: str(runtime or "runsc"),
    )
    from maverick.sandbox import build_sandbox
    sb = build_sandbox(workdir=tmp_path, backend="gvisor")
    assert isinstance(sb, DockerBackend)
    assert sb.runtime == "runsc"


@pytest.mark.parametrize("runtime", ["runc", "not-runsc", "gvisorless-runc"])
def test_build_sandbox_gvisor_refuses_untrusted_runtime_alias(
    monkeypatch, tmp_path, runtime
):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    from maverick.sandbox import SandboxPolicyError, build_sandbox

    with pytest.raises(SandboxPolicyError, match="not an approved gVisor runtime"):
        build_sandbox(
            workdir=tmp_path,
            backend="gvisor",
            sandbox_config={"runtime": runtime},
        )


def test_build_sandbox_docker_has_no_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    from maverick.sandbox import build_sandbox
    sb = build_sandbox(workdir=tmp_path, backend="docker")
    assert isinstance(sb, DockerBackend)
    assert sb.runtime is None


# ---- warm-container reuse ("sandbox pool") ----

def _record_all_runs(monkeypatch):
    """Capture every subprocess.run argv; return the list."""
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    runs: list = []

    class _R:
        stdout = ""
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run",
                        lambda args, **k: runs.append(args) or _R())
    return runs


def test_warm_first_exec_starts_then_execs(monkeypatch, tmp_path):
    runs = _record_all_runs(monkeypatch)
    be = DockerBackend(workdir=tmp_path, reuse_container=True)
    be.exec("echo hi")
    # first call: docker run -d (sleep infinity) to start the warm container
    assert runs[0][:3] == ["docker", "run", "-d"]
    assert runs[0][-2:] == ["sleep", "infinity"]
    # second call: docker exec into it (NOT another run); the command is
    # wrapped so background jobs are reaped before the exec returns.
    assert runs[1][:2] == ["docker", "exec"]
    assert runs[1][3:5] == ["sh", "-c"]
    assert "sh -c 'echo hi' &" in runs[1][5]
    assert "kill -KILL" in runs[1][5]


def test_warm_reuses_container_across_execs(monkeypatch, tmp_path):
    runs = _record_all_runs(monkeypatch)
    be = DockerBackend(workdir=tmp_path, reuse_container=True)
    be.exec("one")
    be.exec("two")
    be.exec("three")
    # exactly one `docker run -d` (the warm start); the rest are `docker exec`
    starts = [r for r in runs if r[:3] == ["docker", "run", "-d"]]
    execs = [r for r in runs if r[:2] == ["docker", "exec"]]
    assert len(starts) == 1
    assert len(execs) == 3
    # all execs target the same container name
    assert len({r[2] for r in execs}) == 1


def test_warm_timeout_removes_container(monkeypatch, tmp_path):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["docker", "version"]:
            return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")
        if args[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(args, 0, stdout="warm", stderr="")
        if args[:2] == ["docker", "exec"]:
            raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 0), output=b"partial")
        if args[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected docker call: {args}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    be = DockerBackend(workdir=tmp_path, reuse_container=True)
    result = be.exec("while true; do :; done", timeout=1)

    assert result.exit_code == 124
    assert result.stdout == "partial"
    assert result.stderr == "TIMEOUT after 1s"
    start = next(r for r in calls if r[:3] == ["docker", "run", "-d"])
    cname = start[start.index("--name") + 1]
    assert ["docker", "rm", "-f", cname] in calls
    assert be._warm_name is None


def test_warm_close_removes_container(monkeypatch, tmp_path):
    runs = _record_all_runs(monkeypatch)
    be = DockerBackend(workdir=tmp_path, reuse_container=True)
    be.exec("x")
    name = [r for r in runs if r[:3] == ["docker", "run", "-d"]][0]
    cname = name[name.index("--name") + 1]
    be.close()
    assert ["docker", "rm", "-f", cname] in runs


def test_close_noop_when_unused(monkeypatch, tmp_path):
    runs = _record_all_runs(monkeypatch)
    be = DockerBackend(workdir=tmp_path, reuse_container=True)
    be.close()  # never exec'd -> nothing to remove
    assert not any(r[:3] == ["docker", "rm", "-f"] for r in runs)


def test_warm_container_has_security_flags(monkeypatch, tmp_path):
    runs = _record_all_runs(monkeypatch)
    DockerBackend(workdir=tmp_path, reuse_container=True).exec("x")
    start = [r for r in runs if r[:3] == ["docker", "run", "-d"]][0]
    assert "--cap-drop" in start and "--security-opt" in start
    assert start[start.index("--network") + 1] == "none"


def test_build_sandbox_reuse_container(monkeypatch, tmp_path):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    from maverick.sandbox import build_sandbox
    sb = build_sandbox(workdir=tmp_path, backend="docker")
    assert sb.reuse_container is False  # default off


# Container argv tests use a workspace separate from the operator's state.
@_workspace_guard_pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))


# --- docker timeout cleanup must not mask the TIMEOUT result ---

def test_docker_timeout_cleanup_is_guarded(monkeypatch):
    from maverick.sandbox.docker import DockerBackend

    b = DockerBackend.__new__(DockerBackend)
    b.workdir = pathlib.Path(".")
    b.image = "python:3.12-slim"
    b.timeout = 1.0
    b.allow_network = False

    calls = {"n": 0}

    def fake_run(args, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise subprocess.TimeoutExpired(cmd=args, timeout=1.0)
        # The cleanup `docker rm -f` also hangs (wedged daemon).
        raise subprocess.TimeoutExpired(cmd=args, timeout=10)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = b.exec("sleep 100")
    assert res.exit_code == 124
    assert "TIMEOUT" in res.stderr
