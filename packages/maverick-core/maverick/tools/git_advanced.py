"""Git advanced ops tool.

Surfaces high-leverage git verbs the agent commonly fumbles when
using the raw shell tool: bisect, rebase --onto, cherry-pick,
worktree. Structured args + sandbox-mediated execution.

Each op is a typed verb. The tool returns a short result summary
plus the relevant output; on failure, the full stderr is included.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
from pathlib import Path
from typing import Any

from ..approval_cards import ApprovalCardError
from ..safety import ConsentDenied, consume_operation_consent
from ..safety.secret_detector import redact
from . import Tool
from .execution_consent import execution_target, file_version, request_execution_consent

log = logging.getLogger(__name__)


_GIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": [
                "bisect_start", "bisect_good", "bisect_bad",
                "bisect_skip", "bisect_reset",
                "rebase_onto",
                "cherry_pick",
                "worktree_add", "worktree_remove", "worktree_list",
                "log_oneline", "blame_line", "show_commit",
            ],
            "description": "git operation.",
        },
        "ref": {"type": "string", "description": "git ref (sha, branch, tag)."},
        "upstream": {"type": "string", "description": "Upstream ref (rebase_onto)."},
        "onto": {"type": "string", "description": "New base (rebase_onto)."},
        "branch": {"type": "string", "description": "Branch name (rebase_onto, worktree_add)."},
        "commit": {"type": "string", "description": "Commit sha (cherry_pick, show_commit, blame_line)."},
        "path": {"type": "string", "description": "Worktree path (worktree_add/remove) or file path (blame_line)."},
        "line": {"type": "integer", "description": "Line number (blame_line)."},
        "limit": {"type": "integer", "description": "Log entry cap (log_oneline)."},
        "since_ref": {"type": "string", "description": "Range start ref (log_oneline)."},
    },
    "required": ["op"],
}


def _run_git(sandbox, workdir: Path, args: list[str], *, timeout: int = 30) -> tuple[int, str, str]:
    # CLAUDE.md rule 4: route git through sandbox.exec so ops run on the
    # configured backend's filesystem (ssh/k8s/fc), not the host. exec
    # runs a shell string at workdir and truncates stdout to 8000 chars
    # -- acceptable for these summaries. Fall back to host subprocess
    # (env-scrubbed) when the backend has no exec.
    if hasattr(sandbox, "exec"):
        shell_cmd = "git " + " ".join(shlex.quote(a) for a in args)
        try:
            res = sandbox.exec(shell_cmd, timeout=timeout)
        except Exception as e:
            return 127, "", f"cannot run git: {e}"
        return getattr(res, "exit_code", 1), res.stdout or "", res.stderr or ""
    cmd = ["git", "-C", str(workdir), *args]
    # Scrub secrets from the child env: git plumbing has no need for provider
    # keys / tokens, and inheriting full os.environ would let a hostile repo
    # config (e.g. a malicious `core.pager`/`gpg.program`) read them.
    from ..sandbox.local import scrub_env
    child_env = scrub_env()
    child_env["GIT_PAGER"] = ""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            env=child_env,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {shlex.join(cmd)}"
    except OSError as e:
        return 127, "", f"cannot run git: {e}"
    return (
        proc.returncode,
        (proc.stdout or b"").decode("utf-8", errors="replace"),
        (proc.stderr or b"").decode("utf-8", errors="replace"),
    )


def _reject_option_like(*values: str) -> str | None:
    """Return an error string if any value begins with ``-``.

    ``shlex.quote`` (in ``_run_git``) blocks shell metacharacters but the
    quoted token is still delivered to ``git`` as a single argument, and git
    treats any arg starting with ``-`` as an option. Without this guard an
    LLM-controlled ref/path like ``--output=/home/user/.ssh/authorized_keys``
    smuggles a git option (e.g. ``git show --output=...`` writes an arbitrary
    file). Legitimate refs/paths never start with ``-`` (a file named ``-x``
    is addressable as ``./-x``), so reject leading-dash values outright.
    """
    for v in values:
        if v.startswith("-"):
            return f"ERROR: refusing option-like argument {v!r} (must not start with '-')"
    return None


def _shape(code: int, out: str, err: str, *, label: str) -> str:
    if code == 0:
        return f"[{label}] OK\n{out}".rstrip() if out else f"[{label}] OK"
    return f"[{label}] FAILED (exit {code})\n{err}".rstrip() if err else f"[{label}] FAILED (exit {code})"


def _op_bisect_start(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    return _shape(*_run_git(sandbox, workdir, ["bisect", "start"]), label="bisect start")


def _op_bisect_good(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    ref = (args.get("ref") or "HEAD").strip()
    if err := _reject_option_like(ref):
        return err
    return _shape(*_run_git(sandbox, workdir, ["bisect", "good", ref]), label=f"bisect good {ref}")


def _op_bisect_bad(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    ref = (args.get("ref") or "HEAD").strip()
    if err := _reject_option_like(ref):
        return err
    return _shape(*_run_git(sandbox, workdir, ["bisect", "bad", ref]), label=f"bisect bad {ref}")


def _op_bisect_skip(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    ref = (args.get("ref") or "HEAD").strip()
    if err := _reject_option_like(ref):
        return err
    return _shape(*_run_git(sandbox, workdir, ["bisect", "skip", ref]), label="bisect skip")


def _op_bisect_reset(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    return _shape(*_run_git(sandbox, workdir, ["bisect", "reset"]), label="bisect reset")


def _op_rebase_onto(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    onto = (args.get("onto") or "").strip()
    upstream = (args.get("upstream") or "").strip()
    branch = (args.get("branch") or "").strip()
    if not onto or not upstream:
        return "ERROR: rebase_onto requires onto and upstream"
    if err := _reject_option_like(onto, upstream, branch):
        return err
    git_args = ["rebase", "--onto", onto, upstream]
    if branch:
        git_args.append(branch)
    return _shape(*_run_git(sandbox, workdir, git_args), label="rebase --onto")


def _op_cherry_pick(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    commit = (args.get("commit") or "").strip()
    if not commit:
        return "ERROR: cherry_pick requires commit"
    if err := _reject_option_like(commit):
        return err
    return _shape(*_run_git(sandbox, workdir, ["cherry-pick", commit]), label=f"cherry-pick {commit}")


def _op_worktree_add(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    path = (args.get("path") or "").strip()
    branch = (args.get("branch") or "").strip()
    if not path:
        return "ERROR: worktree_add requires path"
    if err := _reject_option_like(path, branch):
        return err
    # Confine the worktree to the sandbox workdir: a leading-dash check alone
    # still lets an absolute/traversing path create a worktree (a real,
    # writable git checkout) anywhere on the host. Resolve under workdir and
    # reject escapes (mirrors apply_patch / fs containment).
    try:
        (workdir / path).resolve().relative_to(workdir.resolve())
    except ValueError:
        return f"ERROR: refusing worktree path that escapes the workspace: {path!r}"
    git_args = ["worktree", "add", path]
    if branch:
        git_args.append(branch)
    return _shape(*_run_git(sandbox, workdir, git_args), label="worktree add")


def _op_worktree_remove(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    path = (args.get("path") or "").strip()
    if not path:
        return "ERROR: worktree_remove requires path"
    if err := _reject_option_like(path):
        return err
    return _shape(*_run_git(sandbox, workdir, ["worktree", "remove", path]), label="worktree remove")


def _op_worktree_list(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    return _shape(*_run_git(sandbox, workdir, ["worktree", "list"]), label="worktree list")


def _op_log_oneline(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    limit = max(1, min(int(args.get("limit") or 30), 500))
    since = (args.get("since_ref") or "").strip()
    if since and (err := _reject_option_like(since)):
        return err
    git_args = ["log", "--oneline", f"-n{limit}"]
    if since:
        git_args.append(f"{since}..HEAD")
    return _shape(*_run_git(sandbox, workdir, git_args), label="log")


def _op_show_commit(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    commit = (args.get("commit") or "HEAD").strip()
    if err := _reject_option_like(commit):
        return err
    return _shape(*_run_git(sandbox, workdir, ["show", "--stat", commit]), label=f"show {commit}")


def _op_blame_line(sandbox, workdir: Path, args: dict[str, Any]) -> str:
    path = (args.get("path") or "").strip()
    line = args.get("line")
    if not path or line is None:
        return "ERROR: blame_line requires path and line"
    line = int(line)
    # `--` terminates options so a path can't be read as a flag.
    return _shape(
        *_run_git(sandbox, workdir, ["blame", "-L", f"{line},{line}", "--", path]),
        label=f"blame {path}:{line}",
    )


# op -> handler(sandbox, workdir, args) -> str. Dispatch table keeps the
# per-call _run trivial (and well under ruff's mccabe cap).
_GIT_OPS = {
    "bisect_start": _op_bisect_start,
    "bisect_good": _op_bisect_good,
    "bisect_bad": _op_bisect_bad,
    "bisect_skip": _op_bisect_skip,
    "bisect_reset": _op_bisect_reset,
    "rebase_onto": _op_rebase_onto,
    "cherry_pick": _op_cherry_pick,
    "worktree_add": _op_worktree_add,
    "worktree_remove": _op_worktree_remove,
    "worktree_list": _op_worktree_list,
    "log_oneline": _op_log_oneline,
    "show_commit": _op_show_commit,
    "blame_line": _op_blame_line,
}
_MUTATING_OPS = frozenset({
    "bisect_start", "bisect_good", "bisect_bad", "bisect_skip", "bisect_reset",
    "rebase_onto", "cherry_pick", "worktree_add", "worktree_remove",
})


def _mutation_error(op: str, args: dict[str, Any]) -> str | None:
    if op == "cherry_pick" and not args.get("commit"):
        return "ERROR: cherry_pick requires commit"
    if op == "rebase_onto" and (not args.get("onto") or not args.get("upstream")):
        return "ERROR: rebase_onto requires onto and upstream"
    if op == "worktree_add" and not args.get("path"):
        return "ERROR: worktree_add requires path"
    if op == "worktree_remove" and not args.get("path"):
        return "ERROR: worktree_remove requires path"
    keys = {
        "bisect_good": ("ref",), "bisect_bad": ("ref",), "bisect_skip": ("ref",),
        "rebase_onto": ("onto", "upstream", "branch"),
        "cherry_pick": ("commit",), "worktree_add": ("path", "branch"),
        "worktree_remove": ("path",),
    }.get(op, ())
    return _reject_option_like(*(str(args.get(key) or "") for key in keys))


def _make_run(sandbox):
    def _run(args: dict[str, Any]) -> str:
        op = args.get("op")
        if not op:
            return "ERROR: op is required"
        workdir = Path(getattr(sandbox, "workdir", ".")).resolve()
        if not workdir.is_dir():
            return f"ERROR: workdir {workdir} not found"
        if not (workdir / ".git").exists():
            # git worktree etc still works with --git-dir, but bisect /
            # rebase require an actual repo.
            return "ERROR: not a git repo at sandbox workdir"
        handler = _GIT_OPS.get(op)
        if handler is None:
            return f"ERROR: unknown op {op!r}"
        if op in _MUTATING_OPS:
            if error := _mutation_error(op, args):
                return error
            parameters = {"op": op, "arguments": args}
            preview, _ = redact(", ".join(
                f"{key}={value}" for key, value in args.items() if key != "op"
            )[:240] or "no arguments")
            try:
                permit = request_execution_consent(
                    "git_advanced",
                    target_provider=lambda: execution_target(sandbox),
                    parameters=parameters,
                    parameters_provider=lambda: {"op": op, "arguments": args},
                    detail=f"Run one Git {op.replace('_', ' ')} operation.",
                    effect=f"Git {op.replace('_', ' ')} may change the repository or worktrees.",
                    review_items=[f"Operation: {op}", f"Repository: {workdir}",
                                  f"Arguments (truncated, redacted): {preview}"],
                    timeout=30,
                    input_versions_provider=lambda: file_version(workdir / ".git" / "HEAD")
                    if (workdir / ".git").is_dir() else file_version(workdir / ".git"),
                )
            except ConsentDenied:
                return "ERROR: Git change was not approved; no Git operation was run"
            except (ApprovalCardError, OSError):
                return "ERROR: Git operation, target, or approval authority changed; review it again"
            try:
                with consume_operation_consent(permit):
                    return handler(sandbox, workdir, args)
            except (ApprovalCardError, OSError):
                return "ERROR: Git operation, target, or approval authority changed; review it again"
        return handler(sandbox, workdir, args)

    return _run


def git_advanced(sandbox) -> Tool:
    return Tool(
        name="git_advanced",
        description=(
            "Structured wrappers around git verbs the agent commonly "
            "fumbles in raw shell. ops: bisect_start/good/bad/skip/reset, "
            "rebase_onto, cherry_pick, worktree_add/remove/list, "
            "log_oneline, show_commit, blame_line. Sandbox-mediated."
        ),
        input_schema=_GIT_SCHEMA,
        fn=_make_run(sandbox),
    )
