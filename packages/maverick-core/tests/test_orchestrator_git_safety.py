from __future__ import annotations

import subprocess

from maverick.orchestrator import (
    _capture_workdir_diff,
    _git_metadata_may_execute_filters,
    _reset_workdir_to_head,
)


def _git_repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "app.py").write_text("print('one')\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "app.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "init"], check=True)
    return tmp_path


def test_git_metadata_rejects_repo_local_fsmonitor(tmp_path):
    repo = _git_repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", ".git/fsmon-hook"], check=True)

    assert _git_metadata_may_execute_filters(repo) is True


def test_capture_and_reset_do_not_execute_repo_local_fsmonitor(tmp_path):
    repo = _git_repo(tmp_path)
    marker = repo / "fsmonitor-ran"
    hook = repo / ".git" / "fsmon-hook"
    hook.write_text(f"#!/bin/sh\necho pwned > {marker}\nexit 0\n")
    hook.chmod(0o755)
    subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", str(hook)], check=True)
    (repo / "app.py").write_text("print('two')\n")

    assert _capture_workdir_diff(repo) == ""
    _reset_workdir_to_head(repo)

    assert not marker.exists()
    assert (repo / "app.py").read_text() == "print('two')\n"
