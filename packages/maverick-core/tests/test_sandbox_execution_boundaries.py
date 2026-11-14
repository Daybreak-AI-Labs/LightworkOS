"""Deadlines and operation ownership survive overlapping sandbox calls."""
from __future__ import annotations

import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.firecracker import FirecrackerBackend
from maverick.sandbox.podman import PodmanBackend
from maverick.sandbox.ssh import SSHBackend


@pytest.fixture(autouse=True)
def separate_operator_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home / ".maverick"))


@pytest.mark.parametrize("backend_type,verify", [
    (DockerBackend, "_verify_docker"), (PodmanBackend, "_verify_podman"),
])
def test_cold_container_has_its_own_deadline(monkeypatch, tmp_path, backend_type, verify):
    monkeypatch.setattr(backend_type, verify, lambda self: None)
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    backend = backend_type(workdir=tmp_path, timeout=12)
    for override, effective in ((None, 12), (0.125, 0.125)):
        assert backend.exec("echo 'hello; world'", timeout=override).stdout == "ok"
        args, options = calls[-1]
        command = args[args.index(backend.image) + 1:]
        assert command[:3] == ["timeout", "-s", "KILL"]
        assert float(command[3].removesuffix("s")) == effective
        assert command[4:] == ["sh", "-c", "echo 'hello; world'"]
        assert options["timeout"] == effective
    for invalid in (0, -1, float("nan"), float("inf")):
        result = backend.exec("echo unsafe", timeout=invalid)
        assert result.exit_code != 0 and "timeout" in result.stderr.lower()
    assert len(calls) == 2


def test_warm_container_start_and_execution_are_serialized(monkeypatch, tmp_path):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    backend = DockerBackend(workdir=tmp_path, reuse_container=True)
    first_start, overlapping_start, overlapping_exec = (
        threading.Event(), threading.Event(), threading.Event()
    )
    lock = threading.Lock()
    starts, active, peak = [], 0, 0

    def run(args, **kwargs):
        nonlocal active, peak
        if args[:3] == ["docker", "run", "-d"]:
            with lock:
                starts.append(args[args.index("--name") + 1])
                initial = len(starts) == 1
            if initial:
                first_start.set()
                overlapping_start.wait(0.1)
            else:
                overlapping_start.set()
        elif args[:2] == ["docker", "exec"]:
            with lock:
                active += 1
                peak = max(peak, active)
                if active > 1:
                    overlapping_exec.set()
            overlapping_exec.wait(0.1)
            with lock:
                active -= 1
        return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(backend.exec, "first")
        assert first_start.wait(2)
        second = executor.submit(backend.exec, "second")
        assert first.result(timeout=2).exit_code == second.result(timeout=2).exit_code == 0
    assert len(starts) == 1
    assert peak == 1
    assert backend._warm_name == starts[0]


@pytest.mark.parametrize("provider", ["local", "fallback", "e2b"])
def test_firecracker_override_never_mutates_the_default(monkeypatch, tmp_path, provider):
    first_entered, second_entered, release_second = (
        threading.Event(), threading.Event(), threading.Event()
    )
    observed = []
    monkeypatch.setattr("shutil.which", lambda name: None if provider == "fallback" and name == "firectl" else "/bin/available")
    monkeypatch.setenv("MAVERICK_FIRECRACKER_STRICT", "0")
    image = tmp_path / "image"
    image.touch()
    monkeypatch.setattr("maverick.sandbox.firecracker.data_dir", lambda *parts: image)
    backend = FirecrackerBackend(workdir=tmp_path, provider="e2b" if provider == "e2b" else "local", api_key="synthetic")

    def observe(timeout):
        observed.append((timeout, backend.timeout))
        if len(observed) == 1:
            first_entered.set()
            assert second_entered.wait(2)
        else:
            second_entered.set()
            assert release_second.wait(2)

    if provider == "e2b":
        class Client:
            def __init__(self, timeout):
                observe(timeout)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def delete(self, *args, **kwargs):
                pass

        monkeypatch.setattr("httpx.Client", Client)
        monkeypatch.setattr(backend, "_e2b_create", lambda client: ("synthetic", 200))
        monkeypatch.setattr(backend, "_e2b_process", lambda *args: SimpleNamespace(status_code=200, json=lambda: {"exitCode": 0}))
    else:
        def run(args, **kwargs):
            observe(kwargs["timeout"])
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", run)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(backend.exec, "first", timeout=600)
        assert first_entered.wait(2)
        second = executor.submit(backend.exec, "second")
        try:
            assert first.result(timeout=2).exit_code == 0
        finally:
            release_second.set()
        assert second.result(timeout=2).exit_code == 0
    assert observed == [(600, 60), (60, 60)]
    assert backend.timeout == 60


def test_ssh_readiness_requires_remote_gnu_timeout(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/ssh")
    missing = True
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        code = 127 if "timeout --version" in args[-1] and missing else 0
        return subprocess.CompletedProcess(args, code, stdout=b"", stderr=b"timeout: not found" if code else b"")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="GNU timeout"):
        SSHBackend(host="synthetic.example", ssh_args=["-p", "2222"])
    missing = False
    assert SSHBackend(host="synthetic.example").host == "synthetic.example"
    assert any("timeout --version" in args[-1] for args in calls)
