"""`str_replace_editor` tool — surgical exact-match string replacement.

OpenHands' single biggest contribution to SWE-bench scores
is this tool. Hand-authored unified diffs from an LLM fail to apply
~30% of the time on real instances because of whitespace/line-ending
drift between what the model thinks the file looks like and what's
actually on disk. `str_replace_editor` sidesteps that entirely:

  - The model supplies (file_path, old_string, new_string).
  - We locate `old_string` in the file by EXACT match.
  - If old_string appears 0 or 2+ times, we REFUSE (the model gets
    a clear error telling it to add more context).
  - On exactly 1 match, we replace + write the file.

The orchestrator then calls `git diff` to produce the unified patch
for `predicted_patch`. The agent never hand-writes a diff for the
common case; the unified diff is a side effect, not the artefact.

Provides four operations matching OpenHands' surface:
  - view: read the file (or directory) with line numbers
  - create: write a new file (refuses overwrite)
  - str_replace: surgical replace (the headliner)
  - insert: insert text after a specific line number
"""
from __future__ import annotations

from pathlib import Path

from . import Tool
from .fs import (
    _is_dotgit_path,
    _is_opaque_blocked_resolved,
    _safe_resolve,
    read_text_contained,
    write_text_contained,
)

_MAX_VIEW_BYTES = 12000


def _view_file(sandbox, target: Path) -> str:
    try:
        data = read_text_contained(sandbox, target, errors="replace")
    except (ValueError, PermissionError, OSError) as e:
        return f"ERROR: {e}"
    lines = data.splitlines()
    width = len(str(len(lines))) if lines else 1
    numbered = "\n".join(
        f"{i:>{width}}: {line}" for i, line in enumerate(lines, start=1)
    )
    if len(numbered) > _MAX_VIEW_BYTES:
        return (
            numbered[:_MAX_VIEW_BYTES]
            + f"\n... [truncated at {_MAX_VIEW_BYTES} bytes; "
            + f"file is {len(lines)} lines total]"
        )
    return numbered


def _view_dir(target: Path) -> str:
    try:
        entries = sorted(target.iterdir())
    except (PermissionError, OSError) as e:
        return f"ERROR: {e}"
    rows = []
    for e in entries:
        if e.name.startswith("."):
            continue
        rows.append(("d " if e.is_dir() else "- ") + e.name)
    return "\n".join(rows) if rows else "(empty)"


def _cmd_view(sandbox, target: Path, path_arg: str) -> str:
    # str_replace_editor.view
    # was an opacity bypass — the agent could read test files /
    # .git via this tool because the gate lived only in
    # read_file. Mirror read_file's symlink-resolved block here.
    if _is_opaque_blocked_resolved(sandbox, path_arg):
        if _is_dotgit_path(path_arg):
            return (
                f"ERROR: view({path_arg!r}) blocked in benchmark "
                "opaque mode (.git internals leak the gold)."
            )
        return (
            f"ERROR: view({path_arg!r}) blocked in benchmark "
            "opaque mode (test files contain gold expected "
            "values). Read the production module under test "
            "instead. (Override: MAVERICK_BENCHMARK_OPAQUE=0.)"
        )
    if not target.exists():
        return f"ERROR: {target} not found"
    if target.is_dir():
        return _view_dir(target)
    return _view_file(sandbox, target)


def _cmd_create(sandbox, target: Path, args: dict) -> str:
    if target.exists():
        return (
            f"ERROR: {target} already exists; use str_replace or "
            "insert instead, or `view` first to confirm intent"
        )
    content = args.get("file_text") or args.get("content") or ""
    try:
        write_text_contained(sandbox, target, content)
    except (ValueError, PermissionError, OSError) as e:
        return f"ERROR: {e}"
    return f"created {target} ({len(content)} bytes)"


def _str_replace_count_error(data: str, old: str, count: int) -> str:
    if count == 0:
        # Try a whitespace-normalised fallback hint without
        # actually performing the edit: this catches the most
        # common cause (tabs vs spaces, trailing whitespace).
        norm_data = "\n".join(line.rstrip() for line in data.split("\n"))
        norm_old = "\n".join(line.rstrip() for line in old.split("\n"))
        if norm_old in norm_data:
            return (
                "ERROR: `old_str` not found EXACTLY in the file, "
                "but a whitespace-normalised match exists. The most "
                "likely causes are (a) trailing spaces in the file, "
                "(b) tabs vs spaces, or (c) Windows line endings. "
                "Use `view` to see the exact bytes, then resubmit "
                "with `old_str` matching byte-for-byte."
            )
        return (
            "ERROR: `old_str` not found in the file. Use `view` to "
            "confirm the exact line content before retrying."
        )
    return (
        f"ERROR: `old_str` is ambiguous: it appears {count} times "
        "in the file. Add more surrounding lines to `old_str` so "
        "exactly one match remains, then resubmit."
    )


def _cmd_str_replace(sandbox, target: Path, args: dict) -> str:
    old = args.get("old_str")
    new = args.get("new_str")
    if old is None or new is None:
        return (
            "ERROR: str_replace requires `old_str` and `new_str` "
            "(both must be present, even if new_str is empty)"
        )
    if not target.exists():
        return f"ERROR: {target} not found"
    try:
        data = read_text_contained(sandbox, target)
    except (ValueError, PermissionError, OSError, UnicodeDecodeError) as e:
        return f"ERROR: {e}"
    count = data.count(old)
    if count != 1:
        return _str_replace_count_error(data, old, count)
    try:
        new_data = data.replace(old, new, 1)
        write_text_contained(sandbox, target, new_data)
    except (ValueError, PermissionError, OSError) as e:
        return f"ERROR: {e}"
    delta = len(new_data) - len(data)
    sign = "+" if delta >= 0 else ""
    return f"edited {target} ({sign}{delta} bytes)"


def _cmd_insert(sandbox, target: Path, args: dict) -> str:
    after = args.get("insert_line")
    text = args.get("new_str", "")
    if after is None:
        return "ERROR: insert requires `insert_line` (1-based line number)"
    if not target.exists():
        return f"ERROR: {target} not found"
    try:
        data = read_text_contained(sandbox, target)
    except (ValueError, PermissionError, OSError, UnicodeDecodeError) as e:
        return f"ERROR: {e}"
    # Preserve the file's line ending. Splitting/rejoining on "\n"
    # unconditionally turned a CRLF file into mixed endings (kept lines
    # keep their trailing \r while the inserted text is bare LF),
    # corrupting it for later SEARCH/REPLACE and git apply.
    eol = "\r\n" if "\r\n" in data else "\n"
    lines = data.replace("\r\n", "\n").split("\n")
    try:
        idx = int(after)
    except (TypeError, ValueError):
        return f"ERROR: insert_line must be an integer; got {after!r}"
    if idx < 0 or idx > len(lines):
        return (
            f"ERROR: insert_line={idx} out of range "
            f"(file has {len(lines)} lines; 0 = before first line)"
        )
    ins = text.replace("\r\n", "\n").split("\n")
    new_lines = lines[:idx] + ins + lines[idx:]
    try:
        write_text_contained(sandbox, target, eol.join(new_lines))
    except (ValueError, PermissionError, OSError) as e:
        return f"ERROR: {e}"
    return f"inserted at line {idx} of {target}"


def _dispatch_editor_command(sandbox, args: dict) -> str:
    cmd = args.get("command", "")
    path_arg = args.get("path", "")
    if not cmd:
        return "ERROR: missing `command` (one of: view, create, str_replace, insert)"
    if not path_arg:
        return "ERROR: missing `path`"
    try:
        target = _safe_resolve(sandbox, path_arg)
    except ValueError as e:
        return f"ERROR: {e}"

    if cmd == "view":
        return _cmd_view(sandbox, target, path_arg)
    if cmd == "create":
        return _cmd_create(sandbox, target, args)
    if cmd == "str_replace":
        return _cmd_str_replace(sandbox, target, args)
    if cmd == "insert":
        return _cmd_insert(sandbox, target, args)

    return (
        f"ERROR: unknown command {cmd!r}; expected one of: "
        "view, create, str_replace, insert"
    )


def str_replace_editor(sandbox) -> Tool:
    def fn(args: dict) -> str:
        return _dispatch_editor_command(sandbox, args)

    return Tool(
        name="str_replace_editor",
        description=(
            "Surgical file editor for code changes. Prefer this over "
            "write_file for edits to existing files: it edits by EXACT "
            "string match, so the resulting diff applies cleanly. "
            "Commands: "
            "`view` (read file or list dir with line numbers); "
            "`create` (new file; fails if exists); "
            "`str_replace` (replace exactly-one occurrence of old_str with "
            "new_str — fails loudly if 0 or 2+ matches, telling you to add "
            "more context); "
            "`insert` (insert new_str after insert_line N)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["view", "create", "str_replace", "insert"],
                },
                "path": {"type": "string", "description": "File or directory path."},
                "file_text": {"type": "string", "description": "Content for `create`."},
                "old_str": {"type": "string", "description": "Exact text to replace (str_replace)."},
                "new_str": {"type": "string", "description": "Replacement text, or insertion text."},
                "insert_line": {"type": "integer", "description": "1-based line number to insert AFTER."},
            },
            "required": ["command", "path"],
        },
        fn=fn,
    )
