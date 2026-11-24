"""Filesystem tools backed by the sandbox.

``read_file`` / ``list_dir`` never interpolate the LLM-supplied path into
a shell command. They use ``pathlib`` directly and verify the resolved
path stays inside the sandbox workdir; ``write_file`` applies the same
path-traversal check.

The shell tool (`shell.py`) intentionally exposes shell execution —
that's its purpose. Shield's `scan_tool_call` chokepoint guards it.
"""
from __future__ import annotations

import errno
import os
import re
import stat
from contextlib import contextmanager
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
    if getattr(sandbox, "shared_workdir", None) is not None:
        from ..task_workspace import bring_in
        bring_in(sandbox, candidate)
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
        _require_regular_target(target)
        protected = capture(Path(sandbox.workdir).resolve(), target)
        _write_text_contained(sandbox, target, content, legacy_journal=not protected)


def _require_regular_target(target: Path) -> None:
    try:
        info = target.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        # lstat does not follow links: a real directory is a plain mistake,
        # not a race, so answer the way the open used to.
        raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(target))
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("refusing non-regular write target (possible symlink race)")


def _verify_write_fd(workdir: Path, fd: int) -> None:
    real = _fd_real_path(fd)
    if real is not None and not real.is_relative_to(workdir):
        raise ValueError("write target escaped the workspace (symlink race)")


def _remove_created_entry(parent: int, name: str, info: os.stat_result) -> None:
    """Clean up only entries still identifying an inode created by this walk."""
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            return
        if stat.S_ISDIR(info.st_mode):
            os.rmdir(name, dir_fd=parent)
        else:
            os.unlink(name, dir_fd=parent)
    except OSError:
        # A replacement or a non-empty directory belongs to another writer.
        pass


@contextmanager
def _write_descriptor(workdir: Path, target: Path):
    rel = target.relative_to(workdir)
    if not rel.parts or ".." in rel.parts:
        raise ValueError("write target escapes the workspace")
    flags = os.O_WRONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    if os.open not in os.supports_dir_fd:
        # Windows does not expose openat. Preserve its existing descriptor
        # check; POSIX uses the no-follow directory walk below.
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = _open_contained(workdir, target, flags | os.O_CREAT)
        try:
            yield fd
        finally:
            os.close(fd)
        return
    directories = []
    created = []
    fd = None
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directories.append(os.open(workdir, directory_flags))
        for name in rel.parts[:-1]:
            parent = directories[-1]
            _verify_write_fd(workdir, parent)
            try:
                child = os.open(name, directory_flags, dir_fd=parent)
            except FileNotFoundError:
                os.mkdir(name, dir_fd=parent)
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                created.append((parent, name, info))
                child = os.open(name, directory_flags, dir_fd=parent)
            directories.append(child)
            _verify_write_fd(workdir, child)
        parent = directories[-1]
        _verify_write_fd(workdir, parent)
        try:
            fd = os.open(rel.name, flags | os.O_CREAT | os.O_EXCL, 0o666, dir_fd=parent)
            created.append((parent, rel.name, os.fstat(fd)))
        except FileExistsError:
            fd = os.open(rel.name, flags, dir_fd=parent)
        _verify_write_fd(workdir, fd)
        yield fd
    except BaseException:
        for parent, name, info in reversed(created):
            _remove_created_entry(parent, name, info)
        raise
    finally:
        if fd is not None:
            os.close(fd)
        for directory in reversed(directories):
            os.close(directory)


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
    with _write_descriptor(workdir, target) as fd:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("refusing to write a non-regular file")
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as fh:
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


# Binary document formats: text written into one is a file no app can open.
# Agents asked for an Excel file wrote "placeholder" into a .xlsx and were
# then confused by it, so write_file refuses and names the tool that makes it.
_SPREADSHEET_HINT = ("Make Excel files with the `spreadsheet` tool (op write, with rows); if it is "
                     "not in your tools yet, call find_tools with 'spreadsheet'.")
_WORD_HINT = ("Write the document as Markdown to a .docx path instead: write_file makes a Word "
              "document from it.")
_TEXT_HINT = "Write the content in a text format (.md, .csv or .txt) instead."
_SLIDES_HINT = ("Write the slides as Markdown to a .pptx path instead (each `#` heading starts a slide): "
                "write_file makes a PowerPoint deck from it.")
_IMAGE_HINT = ("For a chart or diagram, write it as SVG to a .svg path instead: SVG is text, opens in any "
               "browser and can be inserted into Word or PowerPoint. If the person asked for a PNG or JPG, "
               "deliver the SVG and tell them a PNG could not be made here; do not put the chart in another "
               "kind of file.")
_BINARY_DOCUMENTS = {".xlsx": _SPREADSHEET_HINT, ".xlsm": _SPREADSHEET_HINT, ".xls": _SPREADSHEET_HINT,
                     ".doc": _WORD_HINT, ".ppt": _SLIDES_HINT,
                     ".zip": _TEXT_HINT, ".png": _IMAGE_HINT, ".jpg": _IMAGE_HINT,
                     ".jpeg": _IMAGE_HINT, ".gif": _IMAGE_HINT, ".webp": _IMAGE_HINT, ".bmp": _IMAGE_HINT}


_SVG_START = re.compile(r"\A\s*(?:<\?xml[^>]*\?>\s*)?(?:(?:<!--.*?-->|<!DOCTYPE[^>]*>)\s*)*<svg[\s>]",
                        re.IGNORECASE | re.DOTALL)


def _svg_refusal(path: str, content: str) -> str | None:
    """An .svg that is not SVG markup. Asked for a bar chart, an agent wrote
    Markdown with a Mermaid block to a .svg name and delivered it."""
    if os.path.splitext(str(path or ""))[1].lower() != ".svg":
        return None
    if _SVG_START.match(content or "") and "</svg>" in content.lower():
        return None
    return (f"ERROR: an .svg file must be SVG markup, starting with <svg ...> and ending with </svg>; "
            f"nothing was written to {path!r}. Draw the chart with SVG elements, for example "
            '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360"> with a <rect> for each bar, '
            "<text> for labels, values and the title, and <line> for the axes. Markdown and Mermaid "
            "are not SVG.")


def _binary_document_refusal(path: str) -> str | None:
    hint = _BINARY_DOCUMENTS.get(os.path.splitext(str(path or ""))[1].lower())
    if hint is None:
        return None
    return (f"ERROR: write_file writes text, so {path!r} would not open as a document; "
            f"nothing was written. {hint}")


def _write_office(sandbox, target: Path, content: str) -> str:
    """Markdown or plain text written to a .docx, .pptx or .pdf path, as a real
    Word document, PowerPoint deck or printable PDF.

    Asked for a Word file, agents wrote Markdown under a .docx.md name and
    delivered that: the pandoc tool is loaded only on request. Asked for a
    PowerPoint deck, they had no way to make one without pandoc."""
    from ..markdown_pdf import UnwritablePdf, pdf_from_markdown
    from ..markdown_slides import UnwritableSlides, slides_from_markdown
    from ..markdown_word import UnwritableText, word_answer
    from ..sandbox.workspace_transfer import WorkspaceTransferError, _write

    root = Path(sandbox.workdir).resolve()
    relative = target.relative_to(root).as_posix()
    if any(part.rstrip(" .").casefold() == ".git" for part in relative.split("/")):
        return "ERROR: refusing to write under .git/"
    suffix = target.suffix.lower()
    writers = {".pptx": ("a PowerPoint deck", slides_from_markdown), ".pdf": ("a PDF", pdf_from_markdown),
               ".docx": ("a Word document", lambda text: word_answer(text, ""))}
    kind, writer = writers[suffix]
    try:
        document = writer(content)
        _write(root, relative, document, 0o644)
    except (UnwritableText, UnwritableSlides, UnwritablePdf, OSError, WorkspaceTransferError) as e:
        return f"ERROR: {e}"
    return f"wrote {kind} ({len(document)} bytes) to {target} from your Markdown"


def write_file(sandbox, goal_id: str | int | None = "default", world=None) -> Tool:
    quota_goal_id = "default" if goal_id is None else goal_id

    def fn(args: dict) -> str:
        refusal = (_binary_document_refusal(args.get("path", ""))
                   or _svg_refusal(args.get("path", ""), str(args.get("content") or "")))
        if refusal:
            return refusal
        try:
            target = _safe_resolve(sandbox, args["path"])
        except ValueError as e:
            return f"ERROR: {e}"
        # Opt-in per-run file-write quota (default off -> no-op).
        from ..file_quota import check_and_add, refund
        charged = len(args["content"].encode("utf-8", "replace"))
        ok, msg = check_and_add(charged, goal_id=quota_goal_id)
        if not ok:
            return f"ERROR: {msg}"
        content = args["content"]
        if target.suffix.lower() in (".docx", ".pptx", ".pdf"):
            result = _write_office(sandbox, target, content)
        else:
            # TOCTOU-safe write: a symlink swapped in after the path check can
            # never truncate or write content to a file outside the workspace.
            try:
                write_text_contained(sandbox, target, content)
                result = f"wrote {len(content)} bytes to {target}"
            except (ValueError, PermissionError, OSError) as e:
                result = f"ERROR: {e}"
        if result.startswith("ERROR"):
            refund(charged, goal_id=quota_goal_id)  # the write did not complete
            return result
        if world is not None:
            from ..task_files import record
            record(world, goal_id, sandbox.workdir, target)
        return result + _totals_note(target, content)
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
            "production code — it's easy to drop content accidentally. "
            "A `.docx` path gets a Word document, a `.pptx` path a PowerPoint deck "
            "(a slide per `#` heading) and a `.pdf` path a printable PDF, made from "
            "Markdown content; in Word and PDF a line `\\newpage` starts a new page."
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


def _totals_note(target, content: str) -> str:
    """A note when a document's tables hold a total its rows do not add
    to. A quote PDF's grand total missed its own lines; the chat answer and
    sheets were checked, a document never was. The file is still written."""
    if target.suffix.lower() not in (".docx", ".pptx", ".pdf", ".md", ".markdown"):
        return ""
    from ..figure_totals import answer_issues

    issues = answer_issues(content)
    if not issues:
        return ""
    return ("\nThe totals do not add up: " + " ".join(issues)
            + " Fix the figures and write the file again before you deliver it.")


def deliver_file(sandbox, goal_id: int | None, world) -> Tool:
    """Hand a workspace file to the person as a download on the task's page."""
    def fn(args: dict) -> str:
        if world is None or goal_id is None:
            return "ERROR: no task to deliver the file to"
        try:
            target = _safe_resolve(sandbox, args["path"])
        except (KeyError, ValueError) as e:
            return f"ERROR: {e}"
        if not target.is_file():
            return f"ERROR: {args['path']} is not a file in the workspace"
        from ..task_files import MAX_DOWNLOAD_BYTES, record
        saved = record(world, goal_id, sandbox.workdir, target, delivered=True)
        if saved is None:
            return (f"ERROR: {args['path']} could not be offered (it must be a regular file "
                    f"inside the workspace, at most {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB)")
        return (f"{saved.name} ({saved.size} bytes) is now a download on the task's page. "
                "Mention its file name in your answer; do not paste a file path or link.")

    return Tool(
        name="deliver_file",
        description=(
            "Give the person a file you made in the workspace, as a download on the "
            "task's page. Files you save with write_file or str_replace_editor are "
            "offered automatically; use this for a file a command or script created "
            "(for example a chart, a spreadsheet or a zip). The page serves the file "
            "exactly as it is now. A Markdown or text draft of a Word, PowerPoint or "
            "PDF file you made under the same name, or a script you wrote beside such a "
            "file, is not offered unless you deliver it."
        ),
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string",
                                    "description": "Workspace-relative path of the file."}},
            "required": ["path"],
        },
        fn=fn,
    )


def list_dir(sandbox) -> Tool:
    def fn(args: dict) -> str:
        try:
            target = _safe_resolve(sandbox, args.get("path", "."))
        except ValueError as e:
            return f"ERROR: {e}"
        from ..task_workspace import SHARED_NOTE, shared_count_note, shared_listing
        shared = shared_listing(sandbox, target)
        if not target.exists():
            return "\n".join([SHARED_NOTE, *shared]) if shared else f"ERROR: {target} not found"
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
            if shared and args.get("shared"):
                result += "\n\n" + "\n".join([SHARED_NOTE, *shared])
            elif shared:
                # Names only on request: shown the person's files, agents asked
                # whether to build on them instead of doing the task.
                result += "\n\n" + shared_count_note(len(shared))
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
            "properties": {"path": {"type": "string", "default": "."},
                           "shared": {"type": "boolean",
                                      "description": ("Also name the files the person keeps in the shared "
                                                      "workspace. Only when the request refers to their files.")}},
        },
        fn=fn,
        parallel_safe=True,
    )
