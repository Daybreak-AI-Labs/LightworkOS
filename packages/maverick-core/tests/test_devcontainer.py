"""Regression tests for devcontainer spec parsing security.

The `image` field is read from a repo-supplied devcontainer.json and placed
as the IMAGE positional in `docker run`. A leading-dash value is parsed by
docker's CLI as a flag (e.g. `--privileged`), which would negate the
--cap-drop ALL / no-new-privileges hardening. `_parse_devcontainer` must
reject option-like image values.
"""
from __future__ import annotations

import json
import os
import subprocess
from unittest.mock import MagicMock

import pytest
import pytest as _workspace_guard_pytest
from maverick.sandbox.devcontainer import (
    DevcontainerBackend,
    DevcontainerSpec,
    _parse_devcontainer,
)


def _write_devcontainer(tmp_path, image):
    p = tmp_path / "devcontainer.json"
    p.write_text(json.dumps({"image": image}), encoding="utf-8")
    return p


def test_parse_rejects_option_like_image(tmp_path):
    # `"image": "--privileged"` would inject a docker run flag that defeats the
    # sandbox's --cap-drop ALL / no-new-privileges hardening.
    p = _write_devcontainer(tmp_path, "--privileged")
    with pytest.raises(RuntimeError, match="option-like"):
        _parse_devcontainer(p)


@pytest.mark.parametrize(
    "bad",
    ["-v/etc:/host", "--mount=type=bind,src=/,dst=/host", "--network=host"],
)
def test_parse_rejects_other_flag_shapes(tmp_path, bad):
    p = _write_devcontainer(tmp_path, bad)
    with pytest.raises(RuntimeError, match="option-like"):
        _parse_devcontainer(p)


@pytest.mark.parametrize("folder", ["/w:Z", "relative", "/w/../etc", "/a,b"])
def test_parse_rejects_mount_option_workspace_folder(tmp_path, folder):
    p = tmp_path / "devcontainer.json"
    p.write_text(json.dumps({"image": "alpine", "workspaceFolder": folder}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="workspaceFolder"):
        _parse_devcontainer(p)


@pytest.mark.parametrize(
    "good",
    [
        "python:3.12-slim",
        "ubuntu:22.04",
        "ghcr.io/org/repo:tag",
        "registry.example.com:5000/team/img@sha256:" + "a" * 64,
    ],
)
def test_parse_accepts_normal_image(tmp_path, good):
    p = _write_devcontainer(tmp_path, good)
    spec = _parse_devcontainer(p)
    assert spec.image == good


# ---- isolation parity with DockerBackend -----------------------------------
#
# The devcontainer backend claims parity with DockerBackend, so it must not ship
# WEAKER defaults: network ON (every other container backend defaults
# --network none), or, with the spec-default remoteUser="root", an agent
# running as root against the writable {project_dir}:{workspace} host
# bind-mount. These pin the defaults: network off, and the container user
# pinned to the invoking uid:gid unless there is an explicit allow_root opt-in.


@pytest.fixture(autouse=True)
def _nonroot_invoking_identity(monkeypatch):
    if hasattr(os, "getuid"):
        monkeypatch.setattr(os, "getuid", lambda: 1234)
        monkeypatch.setattr(os, "getgid", lambda: 1234)


def _devc_args(monkeypatch, tmp_path, *, spec, **kw):
    """Capture the ``docker run`` argv one exec would produce, with the docker
    daemon check and the actual subprocess stubbed out."""
    monkeypatch.setattr(DevcontainerBackend, "_verify_docker", lambda self: None)
    cap: dict = {}

    class _R:
        stdout = ""
        stderr = ""
        returncode = 0

    monkeypatch.setattr(
        "subprocess.run", lambda args, **k: cap.update(args=args) or _R(),
    )
    be = DevcontainerBackend(project_dir=tmp_path, spec_override=spec, **kw)
    be.exec("echo hi")
    return cap["args"]


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX uid/gid only")
def test_default_network_off_and_user_pinned_for_root_remoteuser(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)
    # Spec default remoteUser is "root"; default allow_network is now False.
    spec = DevcontainerSpec(image="python:3.12-slim")
    args = _devc_args(monkeypatch, tmp_path, spec=spec)
    # Network disabled by default -- parity with docker/podman/kubernetes.
    assert "--network" in args and args[args.index("--network") + 1] == "none"
    # A `remoteUser: root` spec is NOT silently honored against the writable
    # host mount: the container user is pinned to the invoking uid:gid.
    assert "--user" in args
    assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    # The DockerBackend-parity hardening stays intact.
    assert "--cap-drop" in args and "no-new-privileges" in args


def test_allow_network_true_omits_network_none(tmp_path, monkeypatch):
    spec = DevcontainerSpec(image="python:3.12-slim")
    args = _devc_args(monkeypatch, tmp_path, spec=spec, allow_network=True)
    assert "--network" not in args


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX uid/gid only")
@pytest.mark.parametrize("remote_user", ["vscode", "0", "000", "0:0", "root:root", "1001"])
def test_repo_remoteuser_cannot_override_invoking_identity(tmp_path, monkeypatch, remote_user):
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)
    spec = DevcontainerSpec(image="python:3.12-slim", remote_user=remote_user)
    args = _devc_args(monkeypatch, tmp_path, spec=spec)
    assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"


def test_devcontainer_fails_closed_without_nonroot_host_identity(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)
    monkeypatch.setattr("maverick.sandbox.devcontainer.container_user_args", lambda _: ["--user", "0:0"])
    spec = DevcontainerSpec(image="python:3.12-slim")
    with pytest.raises(RuntimeError, match="non-root invoking user"):
        _devc_args(monkeypatch, tmp_path, spec=spec)
    monkeypatch.setattr("maverick.sandbox.devcontainer.container_user_args", lambda _: ["--user", "1000:0"])
    with pytest.raises(RuntimeError, match="non-root invoking user"):
        _devc_args(monkeypatch, tmp_path, spec=spec)
    monkeypatch.setattr("maverick.sandbox.devcontainer.container_user_args", lambda _: [])
    with pytest.raises(RuntimeError, match="non-root invoking user"):
        _devc_args(monkeypatch, tmp_path, spec=spec)


def test_allow_root_opts_back_into_root(tmp_path, monkeypatch):
    # Explicit opt-in: no --user pinning, so the container runs as root.
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)
    spec = DevcontainerSpec(image="python:3.12-slim")  # remoteUser root
    args = _devc_args(monkeypatch, tmp_path, spec=spec, allow_root=True)
    assert "--user" not in args


@pytest.mark.parametrize("use_env", [False, True])
@pytest.mark.parametrize("remote_user", ["0:0", "vscode"])
def test_explicit_root_opt_in_allows_repo_user(tmp_path, monkeypatch, use_env, remote_user):
    monkeypatch.setenv("MAVERICK_SANDBOX_ALLOW_ROOT", "1" if use_env else "0")
    spec = DevcontainerSpec(image="python:3.12-slim", remote_user=remote_user)
    args = _devc_args(monkeypatch, tmp_path, spec=spec, allow_root=not use_env)
    assert args[args.index("--user") + 1] == remote_user


def test_build_sandbox_devcontainer_defaults_isolated(tmp_path, monkeypatch):
    # The build_sandbox default (not just the class field) defaults network OFF
    # and root OFF -- matching docker/podman.
    from maverick import config, sandbox

    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(
        json.dumps({"image": "python:3.12-slim"}), encoding="utf-8",
    )
    monkeypatch.setattr(
        sandbox.DevcontainerBackend, "_verify_docker", lambda self: None,
    )
    monkeypatch.setattr(
        config, "get_sandbox",
        lambda: {"backend": "devcontainer", "workdir": str(tmp_path)},
    )
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"sandbox": {"backend": "devcontainer", "project_dir": str(tmp_path)}},
    )
    be = sandbox.build_sandbox()
    assert be.allow_network is False
    assert be.allow_root is False


# Container argv tests use a workspace separate from the operator's state.
@_workspace_guard_pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))


# ---------- devcontainer sandbox ----------

def _stub_subprocess_ok(monkeypatch):
    monkeypatch.setattr(
        "subprocess.run",
        lambda args, *a, **k: MagicMock(returncode=0, stdout=b"", stderr=b""),
    )


def test_devcontainer_strip_jsonc():
    from maverick.sandbox.devcontainer import _strip_jsonc
    text = """
{
  // a line comment
  "image": "python:3.12", /* block comment */
  "runArgs": ["--cap-add=NET_ADMIN",],
}
"""
    cleaned = _strip_jsonc(text)
    data = json.loads(cleaned)
    assert data["image"] == "python:3.12"
    assert data["runArgs"] == ["--cap-add=NET_ADMIN"]


def test_devcontainer_requires_spec(tmp_path, monkeypatch):
    _stub_subprocess_ok(monkeypatch)
    from maverick.sandbox.devcontainer import DevcontainerBackend
    try:
        DevcontainerBackend(project_dir=tmp_path)
    except RuntimeError as e:
        assert "devcontainer.json" in str(e)
        return
    raise AssertionError("expected RuntimeError")


def test_devcontainer_rejects_build_only_spec(tmp_path, monkeypatch):
    _stub_subprocess_ok(monkeypatch)
    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(
        json.dumps({"dockerFile": "Dockerfile"}),
    )
    from maverick.sandbox.devcontainer import DevcontainerBackend
    try:
        DevcontainerBackend(project_dir=tmp_path)
    except RuntimeError as e:
        assert "image" in str(e) and "dockerFile" in str(e)
        return
    raise AssertionError("expected RuntimeError")


def test_devcontainer_parses_image(tmp_path, monkeypatch):
    _stub_subprocess_ok(monkeypatch)
    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(
        json.dumps({
            "image": "mcr.microsoft.com/devcontainers/python:3.12",
            "remoteUser": "vscode",
            "workspaceFolder": "/workspaces/myrepo",
            "containerEnv": {"FOO": "bar"},
        }),
    )
    from maverick.sandbox.devcontainer import DevcontainerBackend
    backend = DevcontainerBackend(project_dir=tmp_path)
    assert backend.spec.image.endswith(":3.12")
    assert backend.spec.remote_user == "vscode"
    assert backend.spec.workspace_folder == "/workspaces/myrepo"
    assert backend.spec.container_env == {"FOO": "bar"}


def test_devcontainer_rejects_run_args(tmp_path, monkeypatch):
    _stub_subprocess_ok(monkeypatch)
    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(
        json.dumps({"image": "alpine", "runArgs": ["--privileged"]}),
    )
    from maverick.sandbox.devcontainer import DevcontainerBackend
    try:
        DevcontainerBackend(project_dir=tmp_path)
    except RuntimeError as e:
        assert "runArgs" in str(e)
        return
    raise AssertionError("expected RuntimeError")


def test_devcontainer_exec_builds_docker_run(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SANDBOX_ALLOW_ROOT", raising=False)
    monkeypatch.setattr("maverick.sandbox.devcontainer.container_user_args", lambda _allow_root: ["--user", "1000:1000"])
    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(
        json.dumps({
            "image": "alpine", "remoteUser": "node",
            "containerEnv": {"NODE_ENV": "test"},
        }),
    )

    captured = {"args": None}

    def _fake_run(args, *a, **k):
        if args[:2] == ["docker", "version"]:
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        captured["args"] = args
        return MagicMock(returncode=0, stdout="ran\n", stderr="")

    monkeypatch.setattr("subprocess.run", _fake_run)
    from maverick.sandbox.devcontainer import DevcontainerBackend
    backend = DevcontainerBackend(project_dir=tmp_path)
    result = backend.exec("echo hi")
    assert result.ok
    args = captured["args"]
    assert args[args.index("--user"):args.index("--user") + 2] == ["--user", "1000:1000"]
    assert "node" not in args
    assert "-e" in args and any("NODE_ENV=test" in s for s in args)
    assert "alpine" in args
    # DoS parity with DockerBackend: RAM is capped and swap pinned to it so the
    # cap can't be sidestepped via swap.
    assert "--memory" in args and "--memory-swap" in args


def test_build_sandbox_constructs_devcontainer(monkeypatch, tmp_path):
    _stub_subprocess_ok(monkeypatch)
    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(
        json.dumps({"image": "alpine"}),
    )
    import maverick.config as cfg

    def _fake_cfg():
        return {"sandbox": {
            "backend": "devcontainer",
            "project_dir": str(tmp_path),
            "timeout": 30,
        }}

    monkeypatch.setattr(cfg, "load_config", _fake_cfg)
    monkeypatch.setattr(cfg, "get_sandbox", lambda: _fake_cfg()["sandbox"])
    from maverick.sandbox import build_sandbox
    sb = build_sandbox()
    assert sb.__class__.__name__ == "DevcontainerBackend"


def _docker_ok(args, **kwargs):
    if args[:2] == ["docker", "version"]:
        return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")
    return subprocess.CompletedProcess(args, 0, stdout="done", stderr="")


class TestSandboxHardening:
    def test_devcontainer_drops_caps_and_privilege_escalation(self, monkeypatch, tmp_path):
        from maverick.sandbox.devcontainer import DevcontainerBackend, DevcontainerSpec
        captured = []

        def fake_run(args, **kwargs):
            captured.append(args)
            return _docker_ok(args, **kwargs)

        monkeypatch.setattr(subprocess, "run", fake_run)
        backend = DevcontainerBackend(
            project_dir=tmp_path,
            spec_override=DevcontainerSpec(image="python:3.12-slim"),
        )
        backend.exec("echo hi")
        run_args = next(a for a in captured if a[:2] == ["docker", "run"])
        assert "--cap-drop" in run_args and "ALL" in run_args
        assert "no-new-privileges" in run_args
