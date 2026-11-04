"""Tests for the git_advanced tool (maverick.tools.git_advanced)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _make_git_repo(p: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=p, check=True)
    subprocess.run(["git", "-C", str(p), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(p), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(p), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(p), "config", "tag.gpgsign", "false"], check=True)


# ---------- git_advanced ----------

def test_git_advanced_requires_repo(tmp_path):
    from maverick.tools.git_advanced import git_advanced

    class _Sandbox:
        workdir = str(tmp_path)

    out = git_advanced(_Sandbox()).fn({"op": "bisect_start"})
    assert "not a git repo" in out


def test_git_advanced_log_oneline(tmp_path):
    if not _git_available():
        pytest.skip("git not installed")
    _make_git_repo(tmp_path)
    (tmp_path / "a.txt").write_text("v1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "first"], check=True)
    (tmp_path / "a.txt").write_text("v2\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "second"], check=True)

    from maverick.tools.git_advanced import git_advanced

    class _Sandbox:
        workdir = str(tmp_path)

    out = git_advanced(_Sandbox()).fn({"op": "log_oneline", "limit": 5})
    assert "[log] OK" in out
    assert "first" in out and "second" in out


def test_git_advanced_cherry_pick_requires_commit(tmp_path):
    if not _git_available():
        pytest.skip("git not installed")
    _make_git_repo(tmp_path)
    (tmp_path / "a").write_text("x")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    from maverick.tools.git_advanced import git_advanced

    class _Sandbox:
        workdir = str(tmp_path)

    out = git_advanced(_Sandbox()).fn({"op": "cherry_pick"})
    assert "requires commit" in out


def test_git_mutation_denial_never_reaches_backend(tmp_path, monkeypatch):
    from maverick.safety import ConsentDenied
    from maverick.tools import git_advanced as git_module

    (tmp_path / ".git").mkdir()
    commands = []

    class _Sandbox:
        workdir = str(tmp_path)

        def exec(self, cmd, timeout=None):
            commands.append(cmd)

    def deny(*args, **kwargs):
        raise ConsentDenied("git_advanced")

    monkeypatch.setattr(git_module, "request_execution_consent", deny)
    out = git_module.git_advanced(_Sandbox()).fn({"op": "bisect_start"})
    assert "not approved" in out
    assert commands == []


def test_git_advanced_unknown_op(tmp_path):
    if not _git_available():
        pytest.skip("git not installed")
    _make_git_repo(tmp_path)
    (tmp_path / "a").write_text("x")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    from maverick.tools.git_advanced import git_advanced

    class _Sandbox:
        workdir = str(tmp_path)

    out = git_advanced(_Sandbox()).fn({"op": "garbage"})
    assert "unknown op" in out


# ---------- git option injection ----------

class _FakeSandbox:
    def __init__(self, workdir):
        self.workdir = workdir

    def exec(self, cmd, timeout=None):
        class _R:
            exit_code = 0
            stdout = cmd
            stderr = ""
        return _R()


@pytest.fixture
def _git_run(tmp_path):
    (tmp_path / ".git").mkdir()
    from maverick.tools.git_advanced import _make_run
    return _make_run(_FakeSandbox(tmp_path))


@pytest.mark.parametrize("args", [
    {"op": "show_commit", "commit": "--output=/tmp/pwn"},
    {"op": "cherry_pick", "commit": "-x"},
    {"op": "rebase_onto", "onto": "--exec=touch /tmp/x", "upstream": "main"},
    {"op": "worktree_add", "path": "--foo"},
    {"op": "log_oneline", "since_ref": "--all"},
    {"op": "bisect_good", "ref": "-x"},
])
def test_git_advanced_rejects_option_like_args(_git_run, args):
    out = _git_run(args)
    assert out.startswith("ERROR: refusing option-like argument")


def test_git_advanced_accepts_normal_ref(_git_run):
    out = _git_run({"op": "show_commit", "commit": "HEAD"})
    assert "show HEAD" in out and "OK" in out
