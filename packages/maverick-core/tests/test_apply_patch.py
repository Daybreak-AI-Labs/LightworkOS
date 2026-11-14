"""Tests for the apply_patch tool (maverick.tools.apply_patch)."""
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


# ---------- apply_patch ----------

def test_apply_patch_requires_patch():
    from maverick.tools.apply_patch import apply_patch

    class _Sandbox:
        workdir = "."

    out = apply_patch(_Sandbox()).fn({"patch": ""})
    assert "patch is required" in out


def test_apply_patch_rejects_path_traversal(tmp_path):
    if not _git_available():
        pytest.skip("git not installed")
    _make_git_repo(tmp_path)
    (tmp_path / "a").write_text("x")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    from maverick.tools.apply_patch import apply_patch

    class _Sandbox:
        workdir = str(tmp_path)

    bad_patch = (
        "diff --git a/../etc/passwd b/../etc/passwd\n"
        "--- a/../etc/passwd\n"
        "+++ b/../etc/passwd\n"
        "@@ -1 +1 @@\n"
        "-hi\n+pwned\n"
    )
    out = apply_patch(_Sandbox()).fn({"patch": bad_patch})
    assert "path-traversal" in out


def test_apply_patch_dry_run_lists_files(tmp_path):
    if not _git_available():
        pytest.skip("git not installed")
    _make_git_repo(tmp_path)
    (tmp_path / "a.txt").write_text("line1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    (tmp_path / "a.txt").write_text("line1\nline2\n")
    proc = subprocess.run(
        ["git", "-C", str(tmp_path), "diff"], capture_output=True, check=True,
    )
    patch_text = proc.stdout.decode()
    # Reset so the patch applies cleanly against the worktree.
    subprocess.run(
        ["git", "-C", str(tmp_path), "checkout", "--", "a.txt"], check=True,
    )

    from maverick.tools.apply_patch import apply_patch

    class _Sandbox:
        workdir = str(tmp_path)

    out = apply_patch(_Sandbox()).fn({"patch": patch_text, "dry_run": True})
    assert "DRY RUN" in out
    assert "a.txt" in out


def test_apply_patch_applies_real_patch(tmp_path):
    if not _git_available():
        pytest.skip("git not installed")
    _make_git_repo(tmp_path)
    (tmp_path / "a.txt").write_text("line1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    (tmp_path / "a.txt").write_text("line1\nline2\n")
    proc = subprocess.run(
        ["git", "-C", str(tmp_path), "diff"], capture_output=True, check=True,
    )
    patch_text = proc.stdout.decode()
    subprocess.run(
        ["git", "-C", str(tmp_path), "checkout", "--", "a.txt"], check=True,
    )
    assert (tmp_path / "a.txt").read_text() == "line1\n"

    from maverick.tools.apply_patch import apply_patch

    class _Sandbox:
        workdir = str(tmp_path)

    out = apply_patch(_Sandbox()).fn({"patch": patch_text})
    assert "applied to 1 file" in out
    assert (tmp_path / "a.txt").read_text() == "line1\nline2\n"


class TestApplyPatchPathExtraction:
    def test_deletion_and_rename_paths_extracted(self):
        from maverick.tools.apply_patch import _files_in_patch
        # Deletion: target lives on `--- a/...`, `+++ /dev/null`.
        deletion = "--- a/secret.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
        assert "secret.py" in _files_in_patch(deletion)
        assert "/dev/null" not in _files_in_patch(deletion)
        # Rename with a traversal target must be surfaced (so it gets checked).
        rename = (
            "diff --git a/a.py b/a.py\nrename from a.py\n"
            "rename to ../../etc/evil.py\n"
        )
        files = _files_in_patch(rename)
        assert "../../etc/evil.py" in files

    def test_modify_patch_not_double_counted(self):
        from maverick.tools.apply_patch import _files_in_patch
        modify = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
        assert _files_in_patch(modify) == ["x.py"]


def test_hunk_lines_that_look_like_headers_are_not_paths():
    from maverick.tools.apply_patch import _files_in_patch

    patch = (
        "diff --git a/q.sql b/q.sql\n"
        "--- a/q.sql\n"
        "+++ b/q.sql\n"
        "@@ -1,3 +1,2 @@\n"
        " select 1;\n"
        "-- /usr/share/doc notes\n"
        "+++ added line\n"
        "-old\n"
        "diff --git a/../x b/../x\n"
        "--- a/../x\n"
        "+++ b/../x\n"
    )
    assert _files_in_patch(patch) == ["q.sql", "../x"]
