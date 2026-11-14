"""The agent's own patch plumbing must not run a repo-local git filter
on the host.

``Agent._extract_and_apply_patch`` (SEARCH/REPLACE in coding mode) creates a
disposable ``git worktree`` on the HOST from the agent's workdir, and the
no-``exec`` fallbacks of ``_reset_workdir`` / ``_git_apply`` run ``git`` on the
host too. Anything that can write the workdir's ``.git/config`` (inside a
container sandbox, e.g. a notebook cell) can plant ``filter.<x>.smudge``/
``clean``; git runs it during checkout / ``reset --hard`` / ``apply`` as the
service user, outside the sandbox. ``core.hooksPath`` does not stop filters.
Same guard ``coding_mode.evaluate_candidate`` already uses
(``git_safety.git_metadata_may_execute_filters``).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.sandbox.local import ExecResult
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel

_GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

_SR_FINAL = (
    "FINAL:\n"
    "f.txt\n"
    "<<<<<<< SEARCH\n"
    "base\n"
    "=======\n"
    "changed\n"
    ">>>>>>> REPLACE\n"
)


class _ExecSandbox:
    """An exec-backed sandbox (docker/ssh/k8s stand-in): git it is asked to
    run happens "inside" it, so the stub just records and succeeds."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.commands: list[str] = []

    def exec(self, cmd: str, timeout=None) -> ExecResult:
        self.commands.append(cmd)
        return ExecResult(stdout="", stderr="", exit_code=0)


class _NoExecSandbox:
    def __init__(self, workdir: Path):
        self.workdir = workdir


def _agent(tmp_path: Path, sandbox, fake_llm) -> Agent:
    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=sandbox,
        goal_id=world.create_goal("g", ""), use_skills=False,
    )
    return Agent(ctx=ctx, role="coder", brief="...")


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> None:
    subprocess.run(["git", "-C", str(repo), *args], input=stdin, check=True,
                   capture_output=True, env={**_GIT_ENV, "PATH": os.environ.get("PATH", "")})


# Where the compromised sandbox plants the filter. "config" is the plain
# `.git/config` + committed `.gitattributes`; the other two are placements the
# first version of the guard never looked at.
LAYOUTS = ["config", "pointer", "worktree_config"]


def _repo_with_planted_filter(root: Path, kind: str, layout: str = "config") -> tuple[Path, Path]:
    """A committed repo that was then given a ``kind`` ("smudge" or "clean")
    filter writing a marker file if git ever runs it, planted as ``layout``."""
    repo = root / "repo"
    repo.mkdir()
    marker = root / "filter-ran"
    _git(repo, "init", "-q")
    (repo / "f.txt").write_bytes(b"base\n")
    if layout == "config":
        (repo / ".gitattributes").write_text("* filter=pwn\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    # Planted AFTER the commit, as the compromised sandbox would.
    command = f"sh -c 'id > {marker.as_posix()}; cat'"
    if layout == "config":
        _git(repo, "config", f"filter.pwn.{kind}", command)
    elif layout == "pointer":
        # The git directory is moved inside the workspace and `.git` becomes a
        # pointer file, with the attributes in the moved directory.
        shutil.move(str(repo / ".git"), str(repo / "gd"))
        (repo / ".git").write_text("gitdir: gd\n")
        (repo / "gd" / "info").mkdir(exist_ok=True)
        (repo / "gd" / "info" / "attributes").write_text("* filter=pwn\n")
        _git(repo, "config", f"filter.pwn.{kind}", command)
    elif layout == "worktree_config":
        # `extensions.worktreeConfig` makes git read `.git/config.worktree`,
        # which carries both the attributes file and the filter.
        config = repo / ".git" / "config"
        config.write_text(
            config.read_text().replace("repositoryformatversion = 0", "repositoryformatversion = 1")
            + "[extensions]\n\tworktreeConfig = true\n")
        attrs = repo / ".git" / "evil-attributes"
        attrs.write_text("* filter=pwn\n")
        (repo / ".git" / "config.worktree").write_text(
            f'[core]\n\tattributesFile = {attrs.as_posix()}\n[filter "pwn"]\n\t{kind} = "{command}"\n')
    else:  # pragma: no cover - a typo in a test
        raise AssertionError(layout)
    return repo, marker


@pytest.mark.parametrize("layout", LAYOUTS)
def test_search_replace_does_not_run_a_planted_smudge_filter_on_the_host(tmp_path, fake_llm, layout):
    repo, marker = _repo_with_planted_filter(tmp_path, "smudge", layout)
    agent = _agent(tmp_path, _ExecSandbox(repo), fake_llm)

    patch, summary = agent._extract_and_apply_patch(_SR_FINAL)

    assert not marker.exists(), "git ran the repo-local filter on the host"
    assert patch is None
    assert summary is not None and not summary.ok
    assert "git" in summary.results[-1].reason.lower()
    # The model is not told its edits were wrong when they were never tried.
    assert "not a problem with the edits" in summary.results[-1].reason
    assert (repo / "f.txt").read_text() == "base\n"
    # No disposable worktree left registered in the agent's repository.
    worktrees = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout
    assert worktrees.count("worktree ") == 1


@pytest.mark.parametrize("layout", LAYOUTS)
def test_reset_without_exec_does_not_run_a_planted_filter_on_the_host(tmp_path, fake_llm, layout):
    repo, marker = _repo_with_planted_filter(tmp_path, "smudge", layout)
    (repo / "f.txt").write_bytes(b"edited\n")  # so `reset --hard` rewrites the file
    agent = _agent(tmp_path, _NoExecSandbox(repo), fake_llm)

    agent._reset_workdir()

    assert not marker.exists(), "git ran the repo-local filter on the host"


def test_reset_without_exec_does_not_run_a_planted_hook_on_the_host(tmp_path, fake_llm):
    # `git reset --hard` runs `.git/hooks/reference-transaction` and
    # `post-index-change`; hooks written into `.git` by the compromised sandbox
    # must not run on the host either. The filter guard cannot see them, so the
    # host git environment has to switch hooks off.
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "hook-ran"
    _git(repo, "init", "-q")
    (repo / "f.txt").write_bytes(b"base\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    for name in ("reference-transaction", "post-index-change"):
        hook = repo / ".git" / "hooks" / name
        hook.write_text(f"#!/bin/sh\necho {name} >> {marker}\nexit 0\n")
        hook.chmod(0o755)
    (repo / "f.txt").write_bytes(b"edited\n")
    agent = _agent(tmp_path, _NoExecSandbox(repo), fake_llm)

    agent._reset_workdir()

    assert not marker.exists(), "a repo-local git hook ran on the host"
    assert (repo / "f.txt").read_text() == "base\n"  # the reset itself still happened


@pytest.mark.parametrize("layout", LAYOUTS)
def test_git_apply_without_exec_does_not_run_a_planted_filter_on_the_host(tmp_path, fake_llm, layout):
    repo, marker = _repo_with_planted_filter(tmp_path, "clean", layout)
    agent = _agent(tmp_path, _NoExecSandbox(repo), fake_llm)
    patch = (
        "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n"
        "@@ -1 +1 @@\n-base\n+changed\n"
    )

    applied = agent._git_apply(patch)

    assert not marker.exists(), "git ran the repo-local filter on the host"
    assert applied is False
    assert (repo / "f.txt").read_text() == "base\n"


@pytest.mark.parametrize("layout", LAYOUTS)
def test_patch_check_does_not_run_a_planted_clean_filter_on_the_host(tmp_path, layout):
    # `git apply --check` reads the files it would patch through the repo's
    # `clean` filter. The agent loop runs it on the host for every unified-diff
    # FINAL, so it is the same hole as the SEARCH/REPLACE worktree.
    from maverick.coding_mode import validate_patch

    repo, marker = _repo_with_planted_filter(tmp_path, "clean", layout)
    patch = (
        "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n"
        "@@ -1 +1 @@\n-base\n+changed\n"
    )

    verdict = validate_patch(patch, repo)

    assert not marker.exists(), "git ran the repo-local filter on the host"
    assert verdict.valid is False
    assert "git" in verdict.reason.lower()
    assert "not a problem with the patch" in verdict.reason
    assert "git-lfs, or another command" not in verdict.reason  # names the finding


def test_patch_check_still_accepts_a_good_patch_on_a_clean_repo(tmp_path):
    from maverick.coding_mode import validate_patch

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "f.txt").write_bytes(b"base\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    patch = (
        "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n"
        "@@ -1 +1 @@\n-base\n+changed\n"
    )

    assert validate_patch(patch, repo).valid is True


def test_host_git_fallbacks_still_work_on_a_clean_repo(tmp_path, fake_llm):
    # The guard must not turn the normal path off.
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "f.txt").write_bytes(b"base\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    agent = _agent(tmp_path, _NoExecSandbox(repo), fake_llm)
    patch = (
        "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n"
        "@@ -1 +1 @@\n-base\n+changed\n"
    )

    assert agent._git_apply(patch) is True
    assert (repo / "f.txt").read_text() == "changed\n"
    agent._reset_workdir()
    assert (repo / "f.txt").read_text() == "base\n"


def test_search_replace_still_applies_in_a_disposable_worktree_on_a_clean_repo(tmp_path, fake_llm):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "f.txt").write_bytes(b"base\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    agent = _agent(tmp_path, _ExecSandbox(repo), fake_llm)

    patch, summary = agent._extract_and_apply_patch(_SR_FINAL)

    assert summary is not None and summary.ok
    assert patch is not None and "+changed" in patch
    assert (repo / "f.txt").read_text() == "base\n"
