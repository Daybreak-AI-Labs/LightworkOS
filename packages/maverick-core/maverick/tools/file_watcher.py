"""File watcher tool.

Stateless polling watcher. The agent calls once with no ``since`` to get
a baseline timestamp, then calls again later with ``since=<that_ts>``
to learn which files changed in between.

Two ops via a single ``since`` arg:
  - omitted -> baseline: returns current timestamp + file count
  - provided -> diff:    returns files with mtime > since

No background threads, no inotify dependency. Pure mtime polling, which
is what the existing repo_map cache invalidation also relies on.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import time
from pathlib import Path
from typing import Any

from . import Tool
from .fs import _safe_resolve

log = logging.getLogger(__name__)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "Directory to watch (recursive)."},
        "since": {
            "type": "number",
            "description": (
                "Unix timestamp. If provided, return files modified "
                "after this time. Omit for a baseline snapshot."
            ),
        },
        "pattern": {
            "type": "string",
            "description": "Optional glob (e.g. '*.py'). Default '*' matches all.",
        },
        "max_files": {
            "type": "integer",
            "description": "Cap returned files (default 200, max 2000).",
        },
        "include_hidden": {
            "type": "boolean",
            "description": "Walk into dot-prefixed dirs (default False).",
        },
    },
    "required": ["path"],
}


# Always-skipped directory names. Walking these explodes the result list
# without any value to a watcher.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", ".tox", "target", "dist",
    "build", ".next", ".cache",
}


def _walk_files(root: Path, *, include_hidden: bool):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in _SKIP_DIRS and (include_hidden or not d.startswith("."))
        ]
        for name in filenames:
            if not include_hidden and name.startswith("."):
                continue
            yield Path(dirpath) / name


def _run(sandbox, args: dict[str, Any]) -> str:
    raw_path = str(args.get("path") or "").strip()
    if not raw_path:
        return "ERROR: path is required"
    try:
        root = _safe_resolve(sandbox, raw_path)
    except ValueError as e:
        return f"ERROR: {e}"
    try:
        if not root.exists():
            return f"ERROR: path does not exist: {root}"
        if not root.is_dir():
            return f"ERROR: path is not a directory: {root}"
    except OSError as e:
        return f"ERROR: cannot access path: {e}"

    pattern = (args.get("pattern") or "*").strip() or "*"
    try:
        max_files = max(1, min(int(float(args.get("max_files") or 200)), 2000))
    except (TypeError, ValueError, OverflowError):
        max_files = 200
    include_hidden = bool(args.get("include_hidden"))
    since = args.get("since")

    # Baseline mode: no `since` -> return current timestamp + file count.
    # Use full float precision (not %.3f); millisecond truncation can fall
    # *after* a freshly written file's mtime, causing a false "changed"
    # report on the very next diff call.
    if since is None:
        now = time.time()
        count = 0
        for _ in _walk_files(root, include_hidden=include_hidden):
            count += 1
        return (
            f"baseline {now!r} ({count} files under {root})\n"
            f"call again with since={now!r} to list changes"
        )

    try:
        since_ts = float(since)
    except (TypeError, ValueError):
        return f"ERROR: since must be a number, got {since!r}"

    changes: list[tuple[float, int, Path]] = []
    truncated = False
    for p in _walk_files(root, include_hidden=include_hidden):
        if not fnmatch.fnmatch(p.name, pattern):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        if st.st_mtime <= since_ts:
            continue
        changes.append((st.st_mtime, st.st_size, p))

    if not changes:
        return f"no changes since {since_ts:.3f}"

    # Sort by mtime FIRST, then truncate -- the old early-break truncated by
    # arbitrary directory-walk order before sorting, so a truncated result
    # could omit the actually-most-recent change.
    changes.sort(key=lambda r: r[0], reverse=True)
    truncated = len(changes) > max_files
    lines = [f"{len(changes)} file(s) changed since {since_ts:.3f}:"]
    for mtime, size, path in changes[:max_files]:
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        lines.append(f"  {mtime:.3f}  {size:>10d}  {rel}")
    if truncated:
        lines.append(f"  ... truncated at {max_files} files")
    return "\n".join(lines)


def file_watcher(sandbox) -> Tool:
    return Tool(
        name="file_watcher",
        description=(
            "Polling file watcher. Call without 'since' to get a "
            "baseline timestamp + file count, then call again with "
            "'since=<baseline>' to list files modified after that. "
            "Recursive walk; skips .git, node_modules, __pycache__, "
            "venv etc. Optional 'pattern' glob (e.g. '*.py')."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(sandbox, args),
    )
