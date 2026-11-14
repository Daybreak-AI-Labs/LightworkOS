"""Tests for the preview_diff tool (maverick.tools.preview_diff)."""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# ---------- preview_diff ----------

def test_preview_diff_not_a_git_repo(tmp_path):
    from maverick.tools.preview_diff import preview_diff

    class _Sandbox:
        workdir = str(tmp_path)

    out = preview_diff(_Sandbox()).fn({})
    assert "not a git repo" in out


def test_preview_diff_no_changes(tmp_path):
    # Init a git repo with one committed file, no changes.
    if not _git_available():
        pytest.skip("git not installed")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    # Test env may force commit signing; disable it for the throwaway repo.
    subprocess.run(["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "tag.gpgsign", "false"], check=True)
    (tmp_path / "a.txt").write_text("hi\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"],
        check=True,
    )

    from maverick.tools.preview_diff import preview_diff

    class _Sandbox:
        workdir = str(tmp_path)

    out = preview_diff(_Sandbox()).fn({})
    assert "(no changes)" in out


def test_preview_diff_shows_unstaged_changes(tmp_path):
    if not _git_available():
        pytest.skip("git not installed")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    # Test env may force commit signing; disable it for the throwaway repo.
    subprocess.run(["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "tag.gpgsign", "false"], check=True)
    (tmp_path / "a.txt").write_text("line1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"],
        check=True,
    )
    # Modify file in worktree (unstaged).
    (tmp_path / "a.txt").write_text("line1\nline2\n")
    from maverick.tools.preview_diff import preview_diff

    class _Sandbox:
        workdir = str(tmp_path)

    out = preview_diff(_Sandbox()).fn({})
    assert "+line2" in out


def test_preview_diff_disables_ext_diff_and_textconv(tmp_path):
    from maverick.tools.preview_diff import preview_diff

    class _Sandbox:
        workdir = str(tmp_path)

    (tmp_path / ".git").mkdir()
    with patch("subprocess.run") as run_mock:
        run_mock.return_value = subprocess.CompletedProcess(
            args=["git", "diff"], returncode=0, stdout=b"", stderr=b""
        )
        preview_diff(_Sandbox()).fn({})
    cmd = run_mock.call_args.args[0]
    assert "--no-ext-diff" in cmd
    assert "--no-textconv" in cmd


def test_preview_diff_ignores_repo_fsmonitor_and_keeps_the_head_through_a_sandbox(tmp_path):
    """A workspace .git/config could name a core.fsmonitor command that git
    diff ran; and a sandbox (which keeps only the stdout tail) used to hand
    back the end of a long diff with no marker."""
    if not _git_available():
        pytest.skip("git not installed")
    from maverick.sandbox import LocalBackend
    from maverick.tools.preview_diff import preview_diff

    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@t.t")
    git("config", "user.name", "t")
    git("config", "commit.gpgsign", "false")
    (tmp_path / "a.txt").write_text("".join(f"old {i}\n" for i in range(3000)))
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    marker = tmp_path / "fsmonitor-ran"
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    git("config", "core.fsmonitor", str(hook))
    (tmp_path / "a.txt").write_text("".join(f"new {i}\n" for i in range(3000)))

    out = preview_diff(LocalBackend(workdir=tmp_path)).fn({})
    assert out.startswith("diff --git")
    assert "[... truncated" in out
    assert not marker.exists()
