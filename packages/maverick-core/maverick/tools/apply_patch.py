"""Multi-file atomic apply_patch tool.

Apply a unified diff via ``git apply``. Either every hunk applies
cleanly OR the entire patch is rejected and the workspace is
untouched. No half-applied state.

``git apply --check`` validates first; on success, ``git apply``
writes. On any failure we report the stderr without writing.

Works inside any directory that has a ``.git`` (or is a git
worktree). Falls back to an actionable error otherwise — without a
git index there's no reliable way to apply a unified diff atomically.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from . import Tool


def _scrub() -> dict:
    """Child env with secrets stripped (shared tools.scrub_child_env)."""
    from . import scrub_child_env
    return scrub_child_env()
log = logging.getLogger(__name__)


_APPLY_PATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "patch": {
            "type": "string",
            "description": "Unified diff text (output of `git diff` or hand-authored).",
        },
        "dry_run": {
            "type": "boolean",
            "description": "Run --check only; report what would happen, don't write.",
        },
    },
    "required": ["patch"],
}


# Extract paths from BOTH sides plus rename/copy headers. The old `+++ [ab]/`
# only regex extracted nothing from deletions (target on `--- a/...`, with
# `+++ /dev/null`), renames/copies (paths on `rename to`/`copy to`), or
# `--no-prefix` diffs -- so for those shapes _files_in_patch returned [] and the
# traversal check was skipped entirely.
# Header lines are only matched outside hunk bodies: inside a hunk, a removed
# line "-- comment" or an added line "++ x" is file content, not a path.
_PATH_RE = re.compile(r"^(?:\+\+\+|---) (?:[ab]/)?(.+)$")
_RENAME_RE = re.compile(r"^(?:rename|copy) (?:from|to) (.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def _header_paths(text: str) -> list[str]:
    """Paths named by file-header lines, skipping hunk bodies by their counts
    (as ``git apply`` does)."""
    found: list[str] = []
    old = new = 0
    for line in text.splitlines():
        if old > 0 or new > 0:
            if line.startswith("\\"):  # "\ No newline at end of file"
                continue
            tag = line[:1]
            if tag in ("-", " ", ""):
                old -= 1
            if tag in ("+", " ", ""):
                new -= 1
            continue
        if hunk := _HUNK_RE.match(line):
            old = int(hunk.group(1) or 1)
            new = int(hunk.group(2) or 1)
        elif m := _PATH_RE.match(line) or _RENAME_RE.match(line):
            found.append(m.group(1))
    return found


def _files_in_patch(text: str) -> list[str]:
    """Pull out every referenced path so we can traversal-check + report them."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _header_paths(text):
        # Strip a trailing tab+timestamp (`--- a/x.py\t2024-...`) and skip the
        # /dev/null sentinel used for add/delete; dedupe (--- and +++ name the
        # same file on a modify).
        p = m.strip().split("\t", 1)[0].strip()
        if p and p != "/dev/null" and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _is_safe_path(rel: str, workdir: Path) -> bool:
    try:
        target = (workdir / rel).resolve()
        rel_to_workdir = target.relative_to(workdir)
    except ValueError:
        return False
    # Host-git hardening (see git_safety.py): a patch
    # targeting `.git/config` (or any path under `.git/`) can plant a
    # core.fsmonitor hook or filter smudge/clean command that a later
    # host-side git call would execute. `write_file` and friends already
    # refuse this (fs.py); apply_patch's own path check must too.
    if any(part.rstrip(" .").casefold() == ".git" for part in rel_to_workdir.parts):
        return False
    return True


def _make_run(sandbox):
    def _run(args: dict[str, Any]) -> str:
        patch_text = str(args.get("patch") or "")
        if not patch_text.strip():
            return "ERROR: patch is required"
        dry_run = bool(args.get("dry_run"))
        workdir = Path(getattr(sandbox, "workdir", ".")).resolve()
        if not workdir.is_dir():
            return f"ERROR: workdir {workdir} not found"
        if not (workdir / ".git").exists():
            return (
                "ERROR: apply_patch requires a git repo at the sandbox "
                "workdir (we use `git apply` for atomic patch application)."
            )

        files = _files_in_patch(patch_text)
        bad = [rel for rel in files if not _is_safe_path(rel, workdir)]
        if bad:
            return f"ERROR: refusing path-traversal in patch: {bad}"

        # Write the patch to a tempfile so we can `git apply` it. The whole
        # create+use is bracketed by the try/finally below so an interruption
        # after creation can't leak a stray .patch into the repo workdir (which
        # would pollute `git status`).
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".patch", dir=str(workdir),
                delete=False, encoding="utf-8",
            ) as tmp:
                tmp.write(patch_text)
                tmp_path = tmp.name
            # CLAUDE.md rule 4: route git through sandbox.exec so the patch
            # applies on the configured backend's filesystem (ssh/k8s/fc),
            # not the host. exec runs a shell string at workdir and returns
            # exit_code/stderr, which is all `git apply` needs. The tempfile
            # was written into workdir, so we reference it by basename. Fall
            # back to host subprocess (env-scrubbed) when there's no exec.
            # Tempfile names are generated alphanumerics, but exec runs a shell
            # string -- quote anyway so a different tempdir/suffix can never
            # smuggle shell metacharacters (same pattern as preview_diff).
            rel = shlex.quote(os.path.basename(tmp_path))
            use_exec = hasattr(sandbox, "exec")
            if use_exec:
                try:
                    res = sandbox.exec(f"git apply --check {rel}", timeout=30)
                except Exception as e:
                    return f"ERROR: cannot run git: {e}"
                if getattr(res, "exit_code", 1) != 0:
                    return (
                        "ERROR: patch rejected by git apply --check:\n"
                        f"{(res.stderr or '')[:1000]}"
                    )
                if dry_run:
                    return (
                        f"DRY RUN: would touch {len(files)} file(s):\n  "
                        + "\n  ".join(files)
                    )
                res2 = sandbox.exec(f"git apply {rel}", timeout=60)
                if getattr(res2, "exit_code", 1) != 0:
                    return f"ERROR: git apply failed:\n{(res2.stderr or '')[:1000]}"
                return (
                    f"applied to {len(files)} file(s):\n  "
                    + "\n  ".join(files)
                )

            check_cmd = ["git", "-C", str(workdir), "apply", "--check", tmp_path]
            try:
                proc = subprocess.run(check_cmd, capture_output=True, timeout=30, env=_scrub())
            except subprocess.TimeoutExpired:
                return "ERROR: git apply --check timed out (30s)"
            except OSError as e:
                return f"ERROR: cannot run git: {e}"
            if proc.returncode != 0:
                err = (proc.stderr or b"").decode("utf-8", errors="replace")
                return f"ERROR: patch rejected by git apply --check:\n{err[:1000]}"

            if dry_run:
                return (
                    f"DRY RUN: would touch {len(files)} file(s):\n  "
                    + "\n  ".join(files)
                )

            apply_cmd = ["git", "-C", str(workdir), "apply", tmp_path]
            try:
                proc2 = subprocess.run(apply_cmd, capture_output=True, timeout=60, env=_scrub())
            except subprocess.TimeoutExpired:
                return "ERROR: git apply timed out (60s)"
            if proc2.returncode != 0:
                err = (proc2.stderr or b"").decode("utf-8", errors="replace")
                return f"ERROR: git apply failed:\n{err[:1000]}"
            return (
                f"applied to {len(files)} file(s):\n  "
                + "\n  ".join(files)
            )
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    return _run


def apply_patch(sandbox) -> Tool:
    return Tool(
        name="apply_patch",
        description=(
            "Apply a multi-file unified diff via `git apply`. Atomic: "
            "either every hunk applies cleanly OR the workspace is "
            "untouched. Set dry_run=true to run `git apply --check` "
            "without writing. Requires a git repo at the sandbox "
            "workdir. Refuses any path that traverses outside it."
        ),
        input_schema=_APPLY_PATCH_SCHEMA,
        fn=_make_run(sandbox),
    )
