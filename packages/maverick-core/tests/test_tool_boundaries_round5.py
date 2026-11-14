"""Regression coverage for tool boundary admission."""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("kind", ["python", "ts", "grpc"])
def test_plugins_cannot_claim_disabled_builtin_names(monkeypatch, kind):
    from maverick import tools
    from maverick.safety.tool_risk import _DEFAULT_RISK

    names = sorted(set(_DEFAULT_RISK) | tools.CORE_TOOL_NAMES) + ["boundary_custom"]
    candidates = [tools.Tool(name=n, description="", input_schema={}, fn=lambda _: "") for n in names]
    if kind == "python":
        monkeypatch.setattr("maverick.plugins.discover_tools", lambda: [(t.name, lambda t=t: t) for t in candidates])
    else:
        monkeypatch.setattr(f"maverick.{kind}_plugin_host.load_configured_{kind}_plugins", lambda: candidates)
    reg = tools.ToolRegistry()
    getattr(tools, f"_apply_{kind}_plugins")(reg)
    assert set(reg._tools) == {"boundary_custom"}


def test_tenant_ip_policy_applies_to_equivalent_literals():
    from maverick.tenant.egress import host_allowed

    aliases = ["93.184.216.34", "1572395042", "0x5db8d822", "0135.0270.0330.042", "::ffff:93.184.216.34"]
    for host in aliases:
        for pattern in aliases:
            assert not host_allowed(host, policy={"deny": [pattern]})
            assert host_allowed(host, policy={"allow": [pattern]})
        assert not host_allowed(host, policy={"deny": "*", "allow": [host]})
    assert not host_allowed("93.184.216.34", policy={"deny": ["93.184.*"]})
    assert not host_allowed("api.example.com", policy={"deny": ["*.example.com"]})


def test_large_local_stdin_reaches_backend_without_command_size_limit(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import sandbox_run

    payload = "a" * (256 * 1024)
    backend = LocalBackend(workdir=tmp_path)
    result = sandbox_run(backend, [sys.executable, "-c", "import sys; print(len(sys.stdin.read()))"], stdin=payload, timeout=5)
    assert result == (0, f"{len(payload)}\n", "")
    assert list(tmp_path.iterdir()) == []


def test_android_screenshot_refuses_git_metadata(tmp_path, monkeypatch):
    from maverick.tools.android import _op_screenshot

    monkeypatch.setattr("maverick.tools.host_exec", lambda *a, **k: pytest.fail("adb must not run"))
    assert "ERROR" in _op_screenshot("", ".git/config", SimpleNamespace(workdir=tmp_path))


def test_mobile_tools_require_local_workspace(tmp_path):
    from maverick.tools import base_registry

    backend = SimpleNamespace(workdir=tmp_path, workdir_is_local=False)
    reg = base_registry(SimpleNamespace(), backend, enable_mobile_tools=True)
    assert not {"android", "ios_sim"} & {t.name for t in reg.all()}


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory descriptors and FIFOs")
def test_write_walk_rejects_real_parent_swap_before_creation(tmp_path, monkeypatch):
    from maverick.tools import fs

    workdir = tmp_path / "workspace"
    workdir.mkdir()
    parent = workdir / "parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    original = fs._safe_resolve

    def swap(sandbox, path):
        resolved = original(sandbox, path)
        parent.rename(workdir / "original-parent")
        parent.symlink_to(outside, target_is_directory=True)
        return resolved

    monkeypatch.setattr(fs, "_safe_resolve", swap)
    out = fs.write_file(SimpleNamespace(workdir=workdir)).fn({"path": "parent/new/file.txt", "content": "private"})
    assert out.startswith("ERROR")
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(not os.path.exists("/proc/self/fd"), reason="descriptor path containment")
@pytest.mark.parametrize("replace_created", [False, True])
def test_failed_walk_cleans_only_its_created_inodes(tmp_path, monkeypatch, replace_created):
    from maverick.tools import fs

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    parent = workspace / "parent"
    parent.mkdir()
    moved = tmp_path / "moved-parent"
    verify = fs._verify_write_fd

    def move_after_create(root, fd):
        path = fs._fd_real_path(fd)
        if path.name == "file.txt" and not moved.exists():
            parent.rename(moved)
            if replace_created:
                replacement = moved / "new" / "file.txt"
                replacement.unlink()
                replacement.write_text("another writer")
        verify(root, fd)

    monkeypatch.setattr(fs, "_verify_write_fd", move_after_create)
    result = fs.write_file(SimpleNamespace(workdir=workspace)).fn({"path": "parent/new/file.txt", "content": "private"})
    assert result.startswith("ERROR")
    if replace_created:
        assert (moved / "new" / "file.txt").read_text() == "another writer"
    else:
        assert list(moved.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO")
def test_file_write_refuses_fifo_without_waiting(tmp_path):
    import subprocess

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    # A subprocess makes a regression fail promptly instead of hanging pytest.
    script = "from types import SimpleNamespace; from maverick.tools.fs import write_file; import sys; print(write_file(SimpleNamespace(workdir=sys.argv[1])).fn({'path':'fifo','content':'x'}))"
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("ERROR")


@pytest.mark.parametrize("attack", ["symlink", "replacement"])
def test_large_stdin_does_not_stage_in_untrusted_workspace(tmp_path, monkeypatch, attack):
    import tempfile

    from maverick.sandbox.local import ExecResult
    from maverick.tools import sandbox_run

    workdir = tmp_path / "workspace"
    workdir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    valuable = workdir / "user-data"
    valuable.mkdir()
    (valuable / "valuable.txt").write_text("keep me")
    temporary_directory = tempfile.TemporaryDirectory

    class RacingDirectory(temporary_directory):
        def __enter__(self):
            from pathlib import Path

            created = super().__enter__()
            path = Path(created)
            path.rename(workdir / "original-stage")
            path.symlink_to(outside, target_is_directory=True)
            return created

    class Backend:
        def __init__(self):
            self.workdir = workdir

        def exec(self, cmd, *, timeout):
            stage = next(workdir.glob(".maverick-stdin-*"))
            stage.rename(workdir / "saved-input")
            valuable.rename(stage)
            return ExecResult(stdout="completed", stderr="", exit_code=0)

    if attack == "symlink":
        monkeypatch.setattr(tempfile, "TemporaryDirectory", RacingDirectory)
    try:
        result = sandbox_run(Backend(), ["unused"], stdin="PRIVATE" * 10000)
    except OSError:
        result = None
    assert list(outside.iterdir()) == []
    assert (valuable / "valuable.txt").read_text() == "keep me"
    assert sorted(path.name for path in workdir.iterdir()) == ["user-data"]
    assert result[0] != 0
    assert "stdin" in result[2]
    assert "PRIVATE" not in result[2]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission modes")
@pytest.mark.parametrize(("mask", "expected"), [(0o022, 0o644), (0o077, 0o600)])
def test_new_text_file_mode_respects_umask_without_execute_bits(tmp_path, mask, expected):
    import stat

    from maverick.tools import fs

    previous = os.umask(mask)
    try:
        result = fs.write_file(SimpleNamespace(workdir=tmp_path)).fn({"path": "plain.txt", "content": "data"})
    finally:
        os.umask(previous)
    assert result.startswith("wrote")
    assert stat.S_IMODE((tmp_path / "plain.txt").stat().st_mode) == expected
