"""Real shell/temp behavior and publication through synthetic kubectl transport.

These tests do not emulate Linux read-only mounts. Actual EROFS enforcement
still needs qualification on the target cluster.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.sandbox import workspace_transfer as transfer
from maverick.sandbox.kubernetes import KubernetesBackend


@pytest.fixture
def posix_shell():
    shell = shutil.which("sh")
    if not shell and os.name == "nt":
        git = shutil.which("git")
        candidate = Path(git).parent.parent / "bin" / "sh.exe" if git else None
        if candidate and candidate.is_file():
            shell = str(candidate)
    if not shell:
        pytest.skip("a local POSIX shell is required; no shell will be installed")
    return shell


def _python_command(source):
    return f"{shlex.quote(Path(sys.executable).as_posix())} -c {shlex.quote(source)}"


def _backend(monkeypatch, tmp_path, shell):
    """Run the exact native shell wrapper against a local workspace mapping."""
    real_run = subprocess.run
    local, remote = tmp_path / "workspace", tmp_path / "remote"
    local.mkdir()
    calls, container_environment = [], {}

    def run(args, **kwargs):
        calls.append(args)
        if "run" in args:
            remote.mkdir()
            pod = json.loads(args[args.index("--overrides") + 1])["spec"]
            container = pod["containers"][0]
            assert container["securityContext"]["readOnlyRootFilesystem"] is True
            assert container["volumeMounts"] == [{"name": "workspace", "mountPath": "/workspace"}]
            assert len(pod["volumes"]) == 1
            container_environment.update({item["name"]: item["value"] for item in container.get("env", [])})
        elif "cp" in args:
            shutil.copytree(kwargs["cwd"], remote, dirs_exist_ok=True)
        elif "exec" in args:
            if "tar" in args:
                with tarfile.open(fileobj=kwargs["stdout"], mode="w") as archive:
                    archive.add(remote, arcname=".")
            else:
                command = args[args.index("--") + 1:]
                assert command[:2] == ["sh", "-c"]
                # Only the sandbox's positional workspace arguments represent
                # pod paths. The command itself may legitimately contain a
                # host interpreter under /workspace (for example a venv).
                mapped = command[1:]
                assert mapped[3].startswith("/workspace/") and mapped[4] == "/workspace"
                mapped[3] = remote.as_posix() + mapped[3][len("/workspace"):]
                mapped[4] = remote.as_posix()
                environment = {**os.environ, **container_environment}
                if "TMPDIR" in environment:
                    environment["TMPDIR"] = environment["TMPDIR"].replace("/workspace", remote.as_posix())
                return real_run([shell, *mapped], capture_output=True, text=True,
                                env=environment, cwd=remote, timeout=kwargs["timeout"])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def capture(args, archive, timeout):
        with archive.open("xb") as destination:
            return run(args, stdout=destination, timeout=timeout).returncode

    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr(transfer, "capture_archive", capture)
    return KubernetesBackend(workdir=local, allow_network=True), local, calls


def test_emptying_temp_directory_preserves_customer_workspace(monkeypatch, tmp_path, posix_shell):
    backend, local, _ = _backend(monkeypatch, tmp_path, posix_shell)
    (local / "customer.txt").write_text("keep")
    (local / ".hidden-customer.txt").write_text("keep hidden")
    (local / "reports").mkdir()
    (local / "reports" / "previous.txt").write_text("keep nested")
    result = backend.exec(_python_command("""
import os
from pathlib import Path
import shutil

temporary = Path(os.environ['TMPDIR'])
(temporary / 'disposable.txt').write_text('scratch')
for path in temporary.iterdir():
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
Path('result.txt').write_text('finished')
"""))
    assert result.exit_code == 0, result.stderr
    assert (local / "customer.txt").read_text() == "keep"
    assert (local / ".hidden-customer.txt").read_text() == "keep hidden"
    assert (local / "reports" / "previous.txt").read_text() == "keep nested"
    assert {path.name for path in local.iterdir()} == {
        "customer.txt", ".hidden-customer.txt", "reports", "result.txt",
    }


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_temp_name_collision_refuses_command_without_touching_input(monkeypatch, tmp_path, posix_shell, kind):
    monkeypatch.setattr("maverick.sandbox.kubernetes.uuid.uuid4", lambda: SimpleNamespace(hex="a" * 32))
    backend, local, _ = _backend(monkeypatch, tmp_path, posix_shell)
    collision = local / (".maverick-tmp-" + "a" * 32)
    if kind == "directory":
        collision.mkdir()
        original = collision / "customer.txt"
    else:
        original = collision
    original.write_text("customer data")
    result = backend.exec(_python_command("from pathlib import Path; Path('executed.txt').touch()"))
    assert result.exit_code == 74
    assert original.read_text() == "customer data"
    assert not (local / "executed.txt").exists()


def test_managed_temporary_files_do_not_pollute_published_workspace(monkeypatch, tmp_path, posix_shell):
    backend, local, _ = _backend(monkeypatch, tmp_path, posix_shell)
    for name in ("tmp", ".tmp", ".cache", ".maverick-tmp"):
        (local / name).write_text("customer data")
    result = backend.exec(_python_command("""
import os
from contextlib import closing
from pathlib import Path
import sqlite3
import tarfile
import tempfile

workspace = Path.cwd()
temporary = Path(tempfile.gettempdir())
assert temporary != workspace and temporary.parent == workspace
if os.name != 'nt':
    assert temporary.stat().st_mode & 0o777 == 0o700
with tempfile.TemporaryDirectory() as child:
    scratch = Path(child)
    assert scratch.parent == temporary
    with closing(sqlite3.connect(scratch / 'working.sqlite')) as database:
        database.execute('CREATE TABLE result (value TEXT)')
        database.execute('INSERT INTO result VALUES (?)', ('finished',))
        value = database.execute('SELECT value FROM result').fetchone()[0]
    (scratch / 'report.txt').write_text(value)
    with tarfile.open('deliverable.tar', 'w') as archive:
        archive.add(scratch / 'report.txt', arcname='report.txt')
    os.replace(scratch / 'report.txt', workspace / 'result.txt')
assert not scratch.exists()
"""))
    assert result.exit_code == 0, result.stderr
    assert {path.name for path in local.iterdir()} == {
        "tmp", ".tmp", ".cache", ".maverick-tmp", "result.txt", "deliverable.tar",
    }
    assert (local / "result.txt").read_text() == "finished"
    for name in ("tmp", ".tmp", ".cache", ".maverick-tmp"):
        assert (local / name).read_text() == "customer data"


def test_nonempty_scratch_and_command_status_survive_copyout(monkeypatch, tmp_path, posix_shell):
    backend, local, _ = _backend(monkeypatch, tmp_path, posix_shell)
    (local / "customer.txt").write_text("keep")
    result = backend.exec(_python_command("""
import os
from pathlib import Path
import sys

temporary = Path(os.environ['TMPDIR'])
(temporary / 'recover.txt').write_text('recover this interrupted work')
print('command output')
print('command diagnostic', file=sys.stderr)
sys.exit(7)
"""))
    assert result.exit_code == 7
    assert result.stdout == "command output\n"
    assert result.stderr == "command diagnostic\n"
    [scratch] = list(local.glob(".maverick-tmp-*"))
    assert (scratch / "recover.txt").read_text() == "recover this interrupted work"
    assert (local / "customer.txt").read_text() == "keep"
