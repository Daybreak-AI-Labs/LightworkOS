"""Filesystem tools backed by the sandbox.

``read_file`` / ``list_dir`` never interpolate the LLM-supplied path into
a shell command. They use ``pathlib`` directly and verify the resolved
path stays inside the sandbox workdir; ``write_file`` applies the same
path-traversal check.

The shell tool (`shell.py`) intentionally exposes shell execution —
that's its purpose. Shield's `scan_tool_call` chokepoint guards it.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..tool_results import confirmed_success_text
from . import Tool

MAX_READ_BYTES = 8000


def _safe_resolve(sandbox, user_path: str) -> Path:
    """Resolve `user_path` relative to sandbox.workdir, refusing traversal.

    Raises ValueError if the resolved path escapes the workspace.
    """
    from ..sandbox.ssh import SSHBackend
    if isinstance(sandbox, SSHBackend):
        raise ValueError("host filesystem tools cannot access an SSH workspace")
    workdir = Path(sandbox.workdir).resolve()
    candidate = (workdir / user_path).resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError as e:
        raise ValueError(
            f"path {user_path!r} escapes the workspace"
        ) from e
    return candidate


def _fd_real_path(fd: int) -> Path | None:
    """The real filesystem path the descriptor is bound to, or ``None`` when the
    platform doesn't expose one.

    Linux: ``/proc/self/fd/<fd>`` is a kernel symlink to the inode actually
    opened, so reading it is immune to any symlink swapped in along the path
    AFTER the open. Returns ``None`` on platforms without ``/proc`` (macOS,
    Windows) or for non-file descriptors (pipes/sockets) — callers then fall
    back to the resolve-time containment check (no weaker than before).
    """
    try:
        link = os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError):
        return None
    # Do not strip Linux's optional " (deleted)" marker here. That suffix is
    # also legal in live filenames, and removing it can transform an outside
    # sibling such as "<workdir> (deleted)" into "<workdir>" before the
    # containment check. Treat the kernel-reported path literally: deleted
    # descriptors will either be rejected by containment or fall back to the
    # existing resolve-time guard on platforms that do not expose /proc.
    if not link.startswith("/"):
        return None  # e.g. "pipe:[...]", "anon_inode:..." — not a real path
    return Path(link)


def _open_contained(workdir: Path, target: Path, flags: int, mode: int = 0o666) -> int:
    """Open ``target`` and verify, THROUGH the opened descriptor, that the inode
    it is bound to still lives under ``workdir``.

    This closes the symlink TOCTOU between :func:`_safe_resolve` (which resolves
    + range-checks the path) and the actual open: a symlink swapped into any path
    component after the check would otherwise redirect the open outside the
    workspace. ``os.open`` follows symlinks exactly as before, so legitimate
    in-workspace symlinks keep working; we then confirm via :func:`_fd_real_path`
    that what we actually opened is contained — and that check cannot be raced
    because the descriptor is already bound to the resolved inode.

    Returns the open fd (caller owns it). Raises ``ValueError`` if the opened
    inode escaped the workspace (closing the fd first); ``OSError`` propagates.
    """
    fd = os.open(str(target), flags, mode)
    real = _fd_real_path(fd)
    if real is not None:
        try:
            real.relative_to(workdir)
        except ValueError as e:
            os.close(fd)
            raise ValueError(
                f"path {target.name!r} resolved outside the workspace after "
                "open (symlink race)"
            ) from e
    return fd


def read_text_contained(
    sandbox, target: Path, *, errors: str = "strict", max_chars: int | None = None,
) -> str:
    """Read text from an already-resolved ``target`` through a descriptor that is
    verified to be inside ``sandbox.workdir`` (TOCTOU-safe).

    The sibling file tools (``str_replace_editor``, ``ast_edit``) share this so
    the symlink-race guard lives in one place. Raises ``ValueError`` if the
    opened inode escaped the workspace; ``OSError`` / ``UnicodeDecodeError``
    propagate so callers handle them exactly as ``Path.read_text`` would.
    ``max_chars`` stops after that many characters instead of loading the
    whole file.
    """
    workdir = Path(sandbox.workdir).resolve()
    fd = _open_contained(workdir, target, os.O_RDONLY)
    with os.fdopen(fd, encoding="utf-8", errors=errors) as fh:
        return fh.read() if max_chars is None else fh.read(max_chars)


def write_text_contained(sandbox, target: Path, content: str) -> None:
    from ..task_file_recovery import capture, mutation_gate
    with mutation_gate():
        protected = capture(Path(sandbox.workdir).resolve(), target)
        _write_text_contained(sandbox, target, content, legacy_journal=not protected)


def _write_text_contained(sandbox, target: Path, content: str, *, legacy_journal=True) -> None:
    """Write ``content`` to an already-resolved ``target`` through a descriptor
    verified inside ``sandbox.workdir`` (TOCTOU-safe).

    Opens ``O_CREAT`` without ``O_TRUNC``, verifies containment, and only then
    truncates + writes — so a symlink swapped in after the path check can never
    truncate or write content to a file outside the workspace. Raises
    ``ValueError`` on escape; ``OSError`` propagates.
    """
    workdir = Path(sandbox.workdir).resolve()
    # Host-git hardening (see git_safety.py): `.git/` writes are blocked in
    # every mode, not only opaque benchmark mode (`_is_opaque_blocked` below).
    # Otherwise write_file/str_replace_editor/ast_edit could plant a
    # `.git/config` `core.fsmonitor` hook or filter
    # smudge/clean command that a later host-side git call
    # (edit_format.render_diff, reviewer.get_diff, coding_mode candidate
    # evaluation) would execute. Refuse unconditionally: there is no
    # legitimate reason for a file-editing tool to write git's own metadata.
    try:
        rel = target.relative_to(workdir)
    except ValueError:
        rel = target
    if any(part.rstrip(" .").casefold() == ".git" for part in rel.parts):
        raise ValueError(f"refusing to write under .git/: {rel}")
    # Workspace journal chokepoint: every file-tool write (write_file, the
    # str_replace editors, ast_edit) funnels through here, so the pre-image is
    # captured BEFORE the O_CREAT below can create the file — a created file
    # must be journaled as "did not exist" for revert to delete it. No-op
    # unless [workspace] journal is on; strict mode raises ValueError, which
    # every caller already maps to the standard tool ERROR contract.
    from ..workspace_journal import record_pre_image
    if legacy_journal:
        record_pre_image(workdir, target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = _open_contained(workdir, target, os.O_WRONLY | os.O_CREAT)
    # fdopen takes ownership of fd; close fd ourselves only if it (or ftruncate)
    # fails before that hand-off, to avoid a double close.
    try:
        os.ftruncate(fd, 0)
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
    with fh:
        fh.write(content)



def _is_test_path(rel_path: str) -> bool:
    """Heuristic: is this path a test file the benchmark grader uses?

    We block read access to these in opaque benchmark
    mode so the agent can't hardcode to gold expected values it spied
    in the assertion bodies.

    Any path UNDER a tests/ directory is
    blocked, not just files that match the test-naming heuristic. The
    prior rule (file matches test_*.py AND lives in tests/) left
    tests/conftest.py, tests/__init__.py, tests/helpers.py, and the
    FAIL_TO_PASS support files readable — these typically contain the
    expected-value tables and parametrize IDs the agent must not see.
    """
    p = rel_path.lower().replace("\\", "/")
    parts = [x for x in p.split("/") if x]
    name = parts[-1] if parts else ""
    in_test_dir = any(seg in {"tests", "test", "__tests__", "spec", "specs"}
                      for seg in parts[:-1])
    # ANY file under tests/ is gated.
    if in_test_dir:
        return True
    test_file = (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.js")
        or name.endswith(".test.ts")
        or name.endswith(".spec.js")
        or name.endswith(".spec.ts")
        or name.endswith("test.go")
        or name.endswith("_spec.rb")
        # JUnit naming is case-sensitive (FooTest.java, not Contest.java), so
        # test the original-case name; ``name`` is lower-cased.
        or rel_path.replace("\\", "/").rstrip("/").endswith(("Test.java", "Tests.java"))
    )
    return test_file


def _is_dotgit_path(rel_path: str) -> bool:
    """Block reads under `.git/`.

    The .git directory leaks the gold answer via refs/objects:
      - `.git/refs/heads/main` → gold commit SHA
      - `.git/objects/<sha>` → raw object contents (the patch)
      - `.git/HEAD`, `.git/packed-refs` → ref enumeration
    The shell tool already blocks `git log -p` / `git show` / `git
    cat-file`; this closes the corresponding file-read backdoor.
    """
    p = rel_path.replace("\\", "/")
    parts = [x for x in p.split("/") if x]
    return any(seg == ".git" for seg in parts)


def _opaque_mode_active() -> bool:
    """True when benchmark opaque mode applies (coding mode, opacity not off)."""
    import os as _os
    opaque = _os.environ.get("MAVERICK_BENCHMARK_OPAQUE", "1") != "0"
    coding = _os.environ.get(
        "MAVERICK_CODING_MODE", ""
    ).lower() in ("1", "true", "yes")
    return opaque and coding


def _is_opaque_blocked(rel_path: str) -> bool:
    """Return True if `rel_path` should be blocked under opaque benchmark
    mode. Combines the test-path and .git-path checks."""
    if not _opaque_mode_active():
        return False
    return _is_test_path(rel_path) or _is_dotgit_path(rel_path)


def _is_opaque_blocked_resolved(sandbox, rel_path: str) -> bool:
    """Re-check the opacity gate on the CANONICAL
    resolved path so symlink trickery cannot bypass it.

    The raw-input check `_is_opaque_blocked(rel_path)` catches the
    direct case (`.git/HEAD`, `tests/test_foo.py`). But the agent
    could do `ln -s .git safe_dir` then `read_file("safe_dir/HEAD")` —
    raw input contains neither `.git` nor `tests/`. After
    `_safe_resolve` follows the symlink, we re-derive the workspace-
    relative form and re-run the gate so the canonical location is
    what's checked.
    """
    if _is_opaque_blocked(rel_path):
        return True
    try:
        workdir = Path(sandbox.workdir).resolve()
        candidate = (workdir / rel_path).resolve()
        rel = candidate.relative_to(workdir).as_posix()
    except (ValueError, OSError):
        # Can't resolve cleanly — let downstream _safe_resolve produce
        # the proper error.
        return False
    return _is_opaque_blocked(rel)


def read_file(sandbox) -> Tool:
    def fn(args: dict) -> str:
        path_arg = args["path"]
        # Block test
        # AND .git/ reads in opaque mode, on the CANONICAL resolved
        # path so symlinks can't bypass.
        if _is_opaque_blocked_resolved(sandbox, path_arg):
            if _is_dotgit_path(path_arg):
                return (
                    f"ERROR: read_file({path_arg!r}) blocked in benchmark "
                    "opaque mode. The .git directory leaks the gold "
                    "answer via refs/objects; derive your fix from the "
                    "code under test, not from git's internal storage. "
                    "(Override by setting MAVERICK_BENCHMARK_OPAQUE=0.)"
                )
            return (
                f"ERROR: read_file({path_arg!r}) blocked in benchmark "
                "opaque mode. The test files contain the grader's "
                "expected values; derive your fix from the production "
                "code under test, not from inspecting the assertions. "
                "(Override by setting MAVERICK_BENCHMARK_OPAQUE=0.)"
            )
        try:
            target = _safe_resolve(sandbox, path_arg)
        except ValueError as e:
            return f"ERROR: {e}"
        if not target.exists():
            return f"ERROR: {target} not found"
        if not target.is_file():
            return f"ERROR: {target} is not a file"
        # Read through a descriptor whose bound inode is verified to be inside
        # the workspace — a symlink swapped in after _safe_resolve can't
        # redirect the read outside (TOCTOU).
        try:
            # Read one character past the cap, never the whole file: the
            # answer is at most MAX_READ_BYTES characters.
            data = read_text_contained(
                sandbox, target, errors="replace", max_chars=MAX_READ_BYTES + 1,
            )
            size = target.stat().st_size
        except (ValueError, PermissionError, OSError) as e:
            return f"ERROR: {e}"
        if len(data) > MAX_READ_BYTES:
            data = data[:MAX_READ_BYTES] + (
                f"\n... [truncated at {MAX_READ_BYTES} characters, file is {size} bytes]"
            )
        # File bytes can begin with reserved legacy result markers. Their
        # contents do not describe the success or failure of the read itself.
        return confirmed_success_text(data)

    return Tool(
        name="read_file",
        description=(
            "Read a file from the workspace, returning its contents. "
            "Use this aggressively during LOCALIZE to understand code "
            "BEFORE editing — never write a SEARCH/REPLACE block from "
            "memory or from an LLM-summarized view of the file. The "
            "SEARCH section must match the file's exact bytes including "
            "whitespace, indentation, and line endings. Only the first "
            "8,000 characters of a file are returned. In "
            "benchmark opaque mode (SWE-bench Pro / Verified), reads "
            "under `tests/`, `test/`, and `.git/` are blocked — the "
            "tests directory holds the grader's expected values and "
            ".git can leak the gold answer via refs/objects."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to read, workspace-relative. Examples: "
                        "`src/foo.py`, `lib/bar/baz.js`. Absolute paths "
                        "and `..` traversal are rejected."
                    ),
                },
            },
            "required": ["path"],
        },
        fn=fn,
        parallel_safe=True,
    )


def write_file(sandbox, goal_id: str | int | None = "default") -> Tool:
    quota_goal_id = "default" if goal_id is None else goal_id

    def fn(args: dict) -> str:
        try:
            target = _safe_resolve(sandbox, args["path"])
        except ValueError as e:
            return f"ERROR: {e}"
        # Opt-in per-run file-write quota (default off -> no-op).
        from ..file_quota import check_and_add
        ok, msg = check_and_add(
            len(args["content"].encode("utf-8", "replace")),
            goal_id=quota_goal_id,
        )
        if not ok:
            return f"ERROR: {msg}"
        content = args["content"]
        # TOCTOU-safe write: a symlink swapped in after the path check can never
        # truncate or write content to a file outside the workspace.
        try:
            write_text_contained(sandbox, target, content)
        except (ValueError, PermissionError, OSError) as e:
            return f"ERROR: {e}"
        return f"wrote {len(content)} bytes to {target}"

    return Tool(
        name="write_file",
        description=(
            "Write content to a file in the workspace, creating the "
            "file (and any missing parent directories) if it doesn't "
            "exist, or OVERWRITING the entire file if it does. Use "
            "`str_replace_editor` or SEARCH/REPLACE blocks for "
            "surgical edits to existing files — write_file is for "
            "creating NEW files (e.g. a `reproduce.py` script during "
            "LOCALIZE) or for files small enough that a full rewrite "
            "is appropriate. Avoid using write_file on existing "
            "production code — it's easy to drop content accidentally."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to write, workspace-relative. Parent "
                        "directories created as needed."
                    ),
                },
                "content": {
                    "type": "string",
                    "description": (
                        "Complete file contents. Will overwrite any "
                        "existing file at the path. Use a trailing "
                        "newline."
                    ),
                },
            },
            "required": ["path", "content"],
        },
        fn=fn,
    )


def list_dir(sandbox) -> Tool:
    def fn(args: dict) -> str:
        try:
            target = _safe_resolve(sandbox, args.get("path", "."))
        except ValueError as e:
            return f"ERROR: {e}"
        if not target.exists():
            return f"ERROR: {target} not found"
        if not target.is_dir():
            return f"ERROR: {target} is not a directory"
        # Mirror read_file's opaque-mode gate: list_dir was the unguarded twin,
        # so list_dir(".git/refs/heads") / list_dir("tests") leaked the gold
        # branch + the grader's FAIL_TO_PASS test filenames in benchmark mode.
        if _is_opaque_blocked_resolved(sandbox, args.get("path", ".")):
            return "ERROR: list_dir blocked in benchmark opaque mode (.git/tests)"
        workdir = Path(sandbox.workdir).resolve()
        # Verify + list through one directory descriptor so a symlink swapped in
        # after the path check can't redirect the listing outside the workspace.
        try:
            fd = _open_contained(
                workdir, target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except (ValueError, OSError) as e:
            return f"ERROR: {e}"
        # os.scandir(fd) does NOT take ownership of fd, so close it ourselves.
        try:
            with os.scandir(fd) as it:
                entries = [
                    f"{'d' if entry.is_dir() else '-'} {entry.name}"
                    for entry in sorted(it, key=lambda e: e.name)
                ]
            result = "\n".join(entries) if entries else "(empty)"
        except (PermissionError, OSError) as e:
            result = f"ERROR: {e}"
        finally:
            try:
                os.close(fd)
            except OSError:  # pragma: no cover - already closed
                pass
        return result

    return Tool(
        name="list_dir",
        description="List files in a directory.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "default": "."}},
        },
        fn=fn,
        parallel_safe=True,
    )
