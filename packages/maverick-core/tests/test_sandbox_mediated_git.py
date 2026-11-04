"""CLAUDE.md rule 4: the agent's git plumbing must go through
``sandbox.exec`` so it runs on the configured backend's filesystem
(ssh/k8s/firecracker), not the host.

These tests pin two guarantees:

(a) ``Agent._reset_workdir`` / ``Agent._git_apply`` CALL ``sandbox.exec``
    when the backend exposes it, and fall back to a direct host
    ``subprocess`` only when it doesn't (sandbox None / no ``exec``).
(b) The parallel-coder apply/test/reset critical section is guarded:
    ``SwarmContext.workdir_lock`` is an asyncio.Lock-like object, and the
    coding-mode verifier branch wraps the section in
    ``async with self.ctx.workdir_lock:`` so concurrent coder children
    (spawned via ``asyncio.gather``) can't stomp the shared git tree.
"""
from __future__ import annotations

import asyncio
import inspect
import subprocess
from pathlib import Path

import pytest
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.sandbox import LocalBackend
from maverick.sandbox.local import ExecResult
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


class RecordingSandbox:
    """Sandbox stub that records every ``exec`` shell string.

    ``exit_code`` is configurable so ``_git_apply`` can be exercised on
    both the apply-succeeded and apply-failed paths.
    """

    def __init__(self, workdir: Path, exit_code: int = 0):
        self.workdir = workdir
        self._exit_code = exit_code
        self.commands: list[str] = []

    def exec(self, cmd: str, timeout=None) -> ExecResult:
        self.commands.append(cmd)
        return ExecResult(stdout="", stderr="", exit_code=self._exit_code)


def _ctx(tmp_path: Path, sandbox, fake_llm) -> SwarmContext:
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    return SwarmContext(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(),
        sandbox=sandbox,
        goal_id=goal_id,
        use_skills=False,
    )


def _agent(ctx) -> Agent:
    return Agent(ctx=ctx, role="coder", brief="...")


# --- (a) helpers route through sandbox.exec when present ----------------


def test_reset_workdir_calls_sandbox_exec(tmp_path, fake_llm):
    sandbox = RecordingSandbox(tmp_path)
    agent = _agent(_ctx(tmp_path, sandbox, fake_llm))

    agent._reset_workdir()

    assert sandbox.commands == ["git reset --hard HEAD && git clean -fd"]


def test_git_apply_calls_sandbox_exec_and_reports_success(tmp_path, fake_llm):
    sandbox = RecordingSandbox(tmp_path, exit_code=0)
    agent = _agent(_ctx(tmp_path, sandbox, fake_llm))

    ok = agent._git_apply("diff --git a/x b/x\n")

    assert ok is True
    assert any(c.startswith("git apply ") for c in sandbox.commands)
    # The patch is written to a tempfile INSIDE the workdir and referenced
    # by basename (sandbox.exec can't pipe stdin); it must be cleaned up.
    assert list(tmp_path.glob("*.patch")) == []


def test_git_apply_reports_failure_from_exit_code(tmp_path, fake_llm):
    sandbox = RecordingSandbox(tmp_path, exit_code=1)
    agent = _agent(_ctx(tmp_path, sandbox, fake_llm))

    ok = agent._git_apply("not a real patch")

    assert ok is False
    assert any(c.startswith("git apply ") for c in sandbox.commands)


# --- (a') fallback path when the backend lacks exec ---------------------


class _NoExecSandbox:
    """A 'backend' with a workdir but no ``exec`` (forces host fallback)."""

    def __init__(self, workdir: Path):
        self.workdir = workdir


def _init_git_repo(path: Path) -> None:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@t"],
        ["git", "config", "user.name", "t"],
    ):
        subprocess.run(cmd, cwd=path, check=True, capture_output=True, env={**env})
    # Keep the patch fixture's LF hunk byte-for-byte on Windows too.
    (path / "f.txt").write_bytes(b"base\n")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=path, check=True,
                   capture_output=True, env=env)


def test_local_fallback_apply_and_reset_are_correct(tmp_path, fake_llm):
    """LocalBackend path stays functionally correct: a real git apply +
    reset round-trips against an on-disk repo when there's no ``exec``."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    sandbox = _NoExecSandbox(repo)
    assert not hasattr(sandbox, "exec")
    agent = _agent(_ctx(tmp_path, sandbox, fake_llm))

    patch = (
        "diff --git a/f.txt b/f.txt\n"
        "--- a/f.txt\n"
        "+++ b/f.txt\n"
        "@@ -1 +1 @@\n"
        "-base\n"
        "+changed\n"
    )
    assert agent._git_apply(patch) is True
    assert (repo / "f.txt").read_text() == "changed\n"

    # _reset_workdir restores HEAD via the host subprocess fallback.
    agent._reset_workdir()
    assert (repo / "f.txt").read_text() == "base\n"


# --- (b) the parallel-coder critical section is guarded -----------------


def test_workdir_lock_is_asyncio_lock_like(tmp_path, fake_llm):
    ctx = _ctx(tmp_path, LocalBackend(workdir=tmp_path), fake_llm)
    lock = ctx.workdir_lock
    assert isinstance(lock, asyncio.Lock)
    # Same instance on repeat access (lazily created once).
    assert ctx.workdir_lock is lock


@pytest.mark.asyncio
async def test_workdir_lock_serializes_holders(tmp_path, fake_llm):
    ctx = _ctx(tmp_path, LocalBackend(workdir=tmp_path), fake_llm)
    async with ctx.workdir_lock:
        assert ctx.workdir_lock.locked()


def test_coding_branch_wraps_critical_section_in_lock():
    """The apply/test/reset sections of the coding-mode loop must run under
    ``async with self.ctx.workdir_lock`` -- otherwise two coder children
    sharing one workdir race on the git tree."""
    # The two loop phases that touch the workdir: the apply check
    # (_validate_final_patch) and the test-driven verifier
    # (_verify_against_tests); _run_inner delegates to them.
    validate_src = inspect.getsource(Agent._validate_final_patch)
    verify_src = inspect.getsource(Agent._verify_against_tests)
    assert validate_src.count("async with self.ctx.workdir_lock:") == 1
    assert verify_src.count("async with self.ctx.workdir_lock:") == 1
    # The apply-check lock must enclose the extract/reset calls, not sit
    # beside them. (Those calls are off-loaded via asyncio.to_thread, so they
    # read `to_thread(self._extract_and_apply_patch,` -- match the method
    # name without "(".)
    lock_at = validate_src.index("async with self.ctx.workdir_lock:")
    extract_at = validate_src.index("self._extract_and_apply_patch", lock_at)
    reset_at = validate_src.index("self._reset_workdir", lock_at)
    assert lock_at < extract_at < reset_at
    # The verifier's lock encloses its own extract, apply, test run and reset.
    lock_at = verify_src.index("async with self.ctx.workdir_lock:")
    assert lock_at < verify_src.index("self._extract_and_apply_patch", lock_at)
    assert lock_at < verify_src.index("self._git_apply", lock_at)
    assert lock_at < verify_src.rindex("self._reset_workdir")
    # The blocking git/pytest work must be off-loaded with asyncio.to_thread so
    # it doesn't freeze the event loop (and every other concurrent agent, the
    # channel server, and the dashboard) while the lock is held.
    assert "asyncio.to_thread(self._extract_and_apply_patch" in validate_src
    assert "asyncio.to_thread(self._reset_workdir)" in validate_src
    assert "asyncio.to_thread(self._git_apply" in verify_src
    assert "asyncio.to_thread(self._reset_workdir)" in verify_src
    assert "run_failing_tests," in verify_src and "asyncio.to_thread(" in verify_src


def test_search_replace_exec_sandbox_uses_disposable_worktree(tmp_path, fake_llm):
    """SEARCH/REPLACE extraction must not write to the host checkout when
    reset/apply are mediated through an exec-backed sandbox."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    sandbox = RecordingSandbox(repo)
    agent = _agent(_ctx(tmp_path, sandbox, fake_llm))
    final = (
        "FINAL:\n"
        "f.txt\n"
        "<<<<<<< SEARCH\n"
        "base\n"
        "=======\n"
        "changed\n"
        ">>>>>>> REPLACE\n"
    )

    patch, summary = agent._extract_and_apply_patch(final)

    assert summary is not None and summary.ok
    assert patch is not None
    assert "-base" in patch
    assert "+changed" in patch
    assert (repo / "f.txt").read_text() == "base\n"
    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--short"],
        check=True, capture_output=True, text=True,
    )
    assert status.stdout == ""


def test_search_replace_exec_sandbox_disables_worktree_hooks(tmp_path, fake_llm):
    """Host-side disposable worktree creation must not run repo hooks."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    marker = tmp_path / "hook-ran"
    hook = repo / ".git" / "hooks" / "post-checkout"
    hook.write_text(f"#!/bin/sh\necho exploited > {marker}\n", encoding="utf-8")
    hook.chmod(0o755)

    sandbox = RecordingSandbox(repo)
    agent = _agent(_ctx(tmp_path, sandbox, fake_llm))
    final = (
        "FINAL:\n"
        "f.txt\n"
        "<<<<<<< SEARCH\n"
        "base\n"
        "=======\n"
        "changed\n"
        ">>>>>>> REPLACE\n"
    )

    patch, summary = agent._extract_and_apply_patch(final)

    assert summary is not None and summary.ok
    assert patch is not None
    assert "-base" in patch
    assert "+changed" in patch
    assert not marker.exists()
