"""Watch Mode — file-marker-triggered goals (Aider parity).

Inspired by Aider's Watch Mode: the user drops a marker comment in
their code, saves the file, and Lightwork picks it up as a goal. No
chat input needed.

Default marker patterns (configurable):
    # AI?     pick up everything after this on the line as the goal
    # AI!     pick up everything on the next line as the goal (multi-line ok)
    # AI: ... explicit task

The implementation is a generator over (file_path, line, marker_text)
tuples. The user wires it to a watchdog observer; we don't ship a
watchdog dep in the kernel so this stays usable from CLI / scripts.

CLI:
    maverick watch <directory>        # streams matches; user picks
    maverick watch <directory> --run  # auto-spawns a goal per match
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MARKER_RE = re.compile(
    r"""
    (?:
        (?:\#|/\*)\s*            # unambiguous comment starts (# , /*): anywhere,
                                 #   so trailing markers (foo()  # AI! x) work.
      | ^\s*(?://|--|\*)\s*      # ambiguous leaders (// -- *) ONLY at line start.
                                 #   Mid-line they're operators (5 * AI!, 10 // AI?,
                                 #   x -- AI!) and the unanchored pattern spawned
                                 #   spurious goals from ordinary source code.
    )
    AI                           # marker word
    (?P<sep>[!?:])               # !, ?, or :
    \s*
    (?P<text>.*)                  # remainder of line
    """,
    re.VERBOSE | re.MULTILINE,
)


@dataclass
class Match:
    path: Path
    line_number: int      # 1-based
    marker: str           # "?", "!", or ":"
    text: str
    follow_lines: list[str]  # for "!" markers: lines AFTER the marker

    def to_goal(self) -> str:
        """Render the match as a goal brief."""
        body = self.text.strip()
        if self.follow_lines and not body:
            body = "\n".join(self.follow_lines).strip()
        return (
            f"From {self.path}:{self.line_number} (marker AI{self.marker})\n\n"
            f"{body}"
        )


def scan_text(
    text: str,
    *,
    path: Path | None = None,
) -> Iterator[Match]:
    """Yield every AI marker found in `text`."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = MARKER_RE.search(line)
        if m is None:
            continue
        marker = m.group("sep")
        text_part = m.group("text") or ""
        follow: list[str] = []
        if marker == "!" and not text_part.strip():
            # Greedy capture: take following non-blank lines until a
            # blank line or another marker.
            for j in range(i + 1, min(i + 30, len(lines))):
                nxt = lines[j]
                if not nxt.strip():
                    break
                if MARKER_RE.search(nxt):
                    break
                follow.append(nxt.strip())
        yield Match(
            path=path or Path("<input>"),
            line_number=i + 1,
            marker=marker,
            text=text_part,
            follow_lines=follow,
        )


def scan_file(path: Path) -> Iterator[Match]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return iter([])
    return scan_text(text, path=path)


def scan_dir(
    root: Path,
    *,
    extensions: tuple[str, ...] = (".py", ".js", ".ts", ".tsx", ".jsx",
                                   ".rs", ".go", ".rb", ".java", ".c",
                                   ".cc", ".cpp", ".h", ".sh", ".sql"),
    ignore: tuple[str, ...] = (".git", "node_modules", ".venv", "venv",
                               "__pycache__", "dist", "build", "target"),
) -> Iterator[Match]:
    """Walk a directory; yield every Match found in a recognized file.

    Skips hidden dirs + the standard ignore list. Non-recursive symlink
    follows so we don't loop forever on infinite-symlink mistakes.
    """
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in ignore and not d.startswith(".")]
        for f in files:
            if not f.endswith(extensions):
                continue
            p = Path(dirpath) / f
            yield from scan_file(p)
