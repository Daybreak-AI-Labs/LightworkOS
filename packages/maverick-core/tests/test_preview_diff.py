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
