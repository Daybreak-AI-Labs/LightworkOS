"""A missing container image is downloaded before the command's time limit starts.

`podman run` / `docker run` pulled a missing image inside the command's 60 s
limit, so the first approved command after choosing a container timed out on a
fresh computer and a person had to approve it again.
"""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def _forget_ready_images():
    from maverick.sandbox import image_pull
    image_pull._READY.clear()
    yield
    image_pull._READY.clear()


@pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))


def _engine(monkeypatch, engine, *, present=False, pull_code=0):
    calls = []

    def fake(args, *a, **kw):
        calls.append((list(args), kw.get("timeout")))
        if args[1:2] == ["version"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[1:3] in (["image", "exists"], ["image", "inspect"]):
            return SimpleNamespace(returncode=0 if present or any(c[0][1:2] == ["pull"] for c in calls) else 1,
                                   stdout="", stderr="")
        if args[1:2] == ["pull"]:
            return SimpleNamespace(returncode=pull_code, stdout="", stderr="" if pull_code == 0 else "denied: no access\n")
        return SimpleNamespace(returncode=0, stdout="42\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    import maverick.sandbox.local as local
    monkeypatch.setattr(local, "run_capped", lambda args, **kw: fake(args, **kw))
    for mod in ("maverick.sandbox.podman", "maverick.sandbox.docker"):
        monkeypatch.setattr(f"{mod}.run_capped", lambda args, **kw: fake(args, **kw))
    return calls


def _backend(engine, tmp_path):
    if engine == "podman":
        from maverick.sandbox.podman import PodmanBackend
        return PodmanBackend(workdir=tmp_path / "ws", image="python:3.12-slim")
    from maverick.sandbox.docker import DockerBackend
    return DockerBackend(workdir=tmp_path / "ws", image="python:3.12-slim")


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_a_missing_image_is_pulled_outside_the_command_limit(monkeypatch, tmp_path, engine):
    calls = _engine(monkeypatch, engine)
    result = _backend(engine, tmp_path).exec("python3 -c 'print(6*7)'", timeout=60)
    assert result.exit_code == 0 and "42" in result.stdout
    pulls = [c for c in calls if c[0][1:2] == ["pull"]]
    runs = [c for c in calls if c[0][1:2] == ["run"]]
    assert pulls == [([engine, "pull", "python:3.12-slim"], pulls[0][1])]
    assert pulls[0][1] >= 300  # its own generous limit
    assert runs and runs[0][1] == 60  # the command keeps exactly its own limit
    assert calls.index(pulls[0]) < calls.index(runs[0])


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_a_present_image_is_not_pulled_and_is_checked_once(monkeypatch, tmp_path, engine):
    calls = _engine(monkeypatch, engine, present=True)
    backend = _backend(engine, tmp_path)
    backend.exec("true")
    backend.exec("true")
    assert not [c for c in calls if c[0][1:2] == ["pull"]]
    assert len([c for c in calls if c[0][1:3] in (["image", "exists"], ["image", "inspect"])]) == 1


def test_a_failed_download_says_the_command_did_not_run(monkeypatch, tmp_path):
    calls = _engine(monkeypatch, "podman", pull_code=125)
    result = _backend("podman", tmp_path).exec("true")
    assert result.exit_code != 0
    assert "did not run" in result.stderr and "denied: no access" in result.stderr
    assert not [c for c in calls if c[0][1:2] == ["run"]]
