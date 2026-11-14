"""File-diff preview tool.

Lets the agent see a unified diff of the workspace BEFORE committing
or applying further changes. Wraps ``git diff`` (the most reliable
source of truth) with a clean schema; the workdir must be a git
repository.

Common use: after a series of str_replace_editor / write_file calls,
the agent calls preview_diff to verify its work matches intent.
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_DIFF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific paths to diff. Default: all changed.",
        },
        "staged": {
            "type": "boolean",
            "description": "Diff staged (--cached) changes instead of unstaged.",
        },
        "max_bytes": {
            "type": "integer",
            "description": "Truncate output (default 50_000).",
        },
        "stat_only": {
            "type": "boolean",
            "description": "Show --stat summary instead of full diff.",
        },
    },
    "required": [],
}


_MAX_BYTES_CEILING = 1_000_000
# Sandbox backends return at most the last 8000 characters of stdout.
_SANDBOX_STDOUT_BYTES = 7_900


def _git_env() -> dict[str, str]:
    from ..git_safety import git_env_without_user_config
    return git_env_without_user_config()


def _sandbox_diff(sandbox, git_args: list[str], max_bytes: int) -> str:
    # exec keeps only the last 8000 characters of stdout, so on a POSIX
    # shell the diff is cut to its head first; otherwise the agent would get
    # an unmarked tail. cmd.exe (Windows LocalBackend) has no such pipeline,
    # so there the plain command runs and a possibly clipped result is marked.
    cap = min(max_bytes, _SANDBOX_STDOUT_BYTES)
    git_cmd = "git " + " ".join(shlex.quote(a) for a in git_args)
    if os.name == "nt":
        shell_cmd = "git " + subprocess.list2cmdline(git_args)
    else:
        env = " ".join(f"{k}={shlex.quote(v)}" for k, v in _git_env().items()
                       if k.startswith("GIT_"))
        shell_cmd = f'out=$({env} {git_cmd}); rc=$?; printf "%s" "$out" | head -c {cap}; exit $rc'
    try:
        res = sandbox.exec(shell_cmd, timeout=15)
    except Exception as e:
        return f"ERROR: cannot run git: {e}"
    if getattr(res, "exit_code", 1) != 0:
        return f"ERROR: git diff exited {getattr(res, 'exit_code', '?')}: {(res.stderr or '')[:500]}"
    out = res.stdout or ""
    if not out.strip():
        return "(no changes)"
    if len(out.encode("utf-8", errors="replace")) >= cap:
        where = "the beginning may be missing" if os.name == "nt" else f"truncated at {cap} bytes"
        out += f"\n\n[... {where}; narrow it with paths=[...] or stat_only=true]"
    return out


def _host_diff(cwd: str, git_args: list[str], max_bytes: int) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", cwd, *git_args], capture_output=True, timeout=15,
            env=_git_env(),
        )
    except subprocess.TimeoutExpired:
        return "ERROR: git diff timed out (15s)"
    except OSError as e:
        return f"ERROR: cannot run git: {e}"
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        return f"ERROR: git diff exited {proc.returncode}: {err[:500]}"
    out = (proc.stdout or b"").decode("utf-8", errors="replace")
    if not out.strip():
        return "(no changes)"
    if len(out) > max_bytes:
        out = out[:max_bytes] + f"\n\n[... truncated at {max_bytes} bytes]"
    return out


def _run_factory(sandbox):
    def _run(args: dict[str, Any]) -> str:
        cwd = str(Path(getattr(sandbox, "workdir", ".")).resolve())
        if not Path(cwd).is_dir():
            return f"ERROR: workdir {cwd!r} not found"
        if not (Path(cwd) / ".git").exists():
            return (
                "ERROR: not a git repo. preview_diff currently requires "
                "a git repository at the sandbox workdir."
            )
        try:
            max_bytes = int(args.get("max_bytes") or 50_000)
        except (TypeError, ValueError):
            return "ERROR: max_bytes must be an integer"
        max_bytes = max(1, min(max_bytes, _MAX_BYTES_CEILING))
        # Repository config and attributes are workspace content: a filter's
        # clean/smudge/process command, a config include or core.fsmonitor
        # would make git run a workspace-chosen program during diff. Refuse
        # those repositories, as the other host-side git helpers do, and run
        # without user/system config, fsmonitor or hooks.
        from ..git_safety import git_metadata_may_execute_filters
        if git_metadata_may_execute_filters(Path(cwd)):
            return ("ERROR: this repository's git config or attributes define a "
                    "filter, include or fsmonitor that git would run during a "
                    "diff (git-lfs counts); preview_diff refuses to run it.")
        git_args = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
                    "diff", "--no-ext-diff", "--no-textconv"]
        if as_bool(args.get("staged")):
            git_args.append("--cached")
        if as_bool(args.get("stat_only")):
            git_args.append("--stat")
        for p in (args.get("paths") or []):
            git_args.append("--")
            git_args.append(str(p))
        # CLAUDE.md rule 4: route git through sandbox.exec so the diff
        # reflects the configured backend's filesystem (ssh/k8s/fc), not
        # the host. Fall back to host subprocess (env-scrubbed) when there's
        # no exec.
        if hasattr(sandbox, "exec"):
            return _sandbox_diff(sandbox, git_args, max_bytes)
        return _host_diff(cwd, git_args, max_bytes)
    return _run


def preview_diff(sandbox) -> Tool:
    return Tool(
        name="preview_diff",
        description=(
            "Show a unified diff of pending changes in the sandbox workdir "
            "(via `git diff`). Use after str_replace_editor/write_file to "
            "review your work before continuing. Args: staged=true for "
            "staged changes, stat_only=true for a summary, paths=[...] to "
            "limit to specific files. Output truncated at max_bytes "
            "(default 50000)."
        ),
        input_schema=_DIFF_SCHEMA,
        fn=_run_factory(sandbox),
    )
