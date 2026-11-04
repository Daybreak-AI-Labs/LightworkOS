"""File-diff preview tool.

Lets the agent see a unified diff of the workspace BEFORE committing
or applying further changes. Wraps ``git diff`` (the most reliable
source of truth) with a clean schema; falls back to ``difflib`` against
HEAD blobs when git isn't a repo.

Common use: after a series of str_replace_editor / write_file calls,
the agent calls preview_diff to verify its work matches intent.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
from pathlib import Path
from typing import Any

from . import Tool

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
        max_bytes = int(args.get("max_bytes") or 50_000)
        git_args = ["diff", "--no-ext-diff", "--no-textconv"]
        if args.get("staged"):
            git_args.append("--cached")
        if args.get("stat_only"):
            git_args.append("--stat")
        for p in (args.get("paths") or []):
            git_args.append("--")
            git_args.append(str(p))
        # CLAUDE.md rule 4: route git through sandbox.exec so the diff
        # reflects the configured backend's filesystem (ssh/k8s/fc), not
        # the host. exec runs a shell string at workdir and truncates
        # stdout to 8000 chars -- acceptable for a diff preview. Fall
        # back to host subprocess (env-scrubbed) when there's no exec.
        if hasattr(sandbox, "exec"):
            shell_cmd = "git " + " ".join(shlex.quote(a) for a in git_args)
            try:
                res = sandbox.exec(shell_cmd, timeout=15)
            except Exception as e:
                return f"ERROR: cannot run git: {e}"
            if getattr(res, "exit_code", 1) not in (0, 1):
                return f"ERROR: git diff exited {res.exit_code}: {(res.stderr or '')[:500]}"
            out = res.stdout or ""
            if not out.strip():
                return "(no changes)"
            if len(out) > max_bytes:
                out = out[:max_bytes] + f"\n\n[... truncated at {max_bytes} bytes]"
            return out

        cmd = ["git", "-C", cwd, *git_args]
        from ..sandbox.local import scrub_env
        child_env = scrub_env()
        child_env["GIT_PAGER"] = ""
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=15,
                env=child_env,
            )
        except subprocess.TimeoutExpired:
            return "ERROR: git diff timed out (15s)"
        except OSError as e:
            return f"ERROR: cannot run git: {e}"
        if proc.returncode not in (0, 1):
            err = (proc.stderr or b"").decode("utf-8", errors="replace")
            return f"ERROR: git diff exited {proc.returncode}: {err[:500]}"
        out = (proc.stdout or b"").decode("utf-8", errors="replace")
        if not out.strip():
            return "(no changes)"
        if len(out) > max_bytes:
            out = out[:max_bytes] + f"\n\n[... truncated at {max_bytes} bytes]"
        return out
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
