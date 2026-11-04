"""Trace pinning to commit.

A replayed trace is only meaningful against the code it ran on. This stamps
each run with the workspace's git state — commit, branch, and whether the
tree was dirty — as a ``trace_meta`` event at run start, so a trace, its
annotations, and a replay all tie back to an exact commit ("this run was
HEAD=abc123, dirty"). Reading it back is one helper.

Best-effort by design: a workspace that isn't a git repo (or has no git)
stamps nothing and the run proceeds — provenance must never block execution.
The git calls are argv-list subprocess with the secret-scrubbed env (no
shell), per the tools/host-exec doctrine.
"""
from __future__ import annotations

import json
import logging
import subprocess

log = logging.getLogger(__name__)

TRACE_META_KIND = "trace_meta"


def _git(args: list[str], cwd: str | None) -> str | None:
    from .tools import scrub_child_env

    # Git reads repository-local config even when invoked without a shell.
    # Disable optional helpers that may execute workspace-controlled programs
    # (notably core.fsmonitor during `git status`) before inspecting the repo.
    safe_args = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"]
    try:
        r = subprocess.run(
            ["git", *safe_args, *args], capture_output=True, text=True, timeout=5,
            env=scrub_child_env(), cwd=cwd or None,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip()


def workspace_git_state(cwd: str | None = None) -> dict | None:
    """``{commit, branch, dirty}`` for the workspace, or None when not a repo."""
    commit = _git(["rev-parse", "HEAD"], cwd)
    if not commit:
        return None
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd) or ""
    status = _git(["status", "--porcelain"], cwd)
    return {
        "commit": commit,
        "branch": branch,
        "dirty": bool(status),
    }


def pin_trace(world, goal_id: int, *, cwd: str | None = None) -> dict | None:
    """Stamp the goal's trace with the workspace git state. Never raises."""
    try:
        state = workspace_git_state(cwd)
        if state is None:
            return None
        world.append_event(goal_id, "system", TRACE_META_KIND,
                           json.dumps(state, sort_keys=True))
        return state
    except Exception:  # provenance must never block the run
        log.debug("trace pin failed for goal %s", goal_id, exc_info=True)
        return None


def trace_commit(world, goal_id: int) -> dict | None:
    """The pinned git state for a run (first trace_meta event), or None."""
    try:
        for e in world.goal_events(goal_id, limit=50):
            if e.kind == TRACE_META_KIND:
                try:
                    return json.loads(e.content)
                except ValueError:
                    return None
    except Exception:
        pass
    return None


__all__ = ["pin_trace", "trace_commit", "workspace_git_state", "TRACE_META_KIND"]
