"""Watch Mode — file-marker-triggered goals (Aider parity).

Inspired by Aider's Watch Mode: the user drops a marker comment in
their code, saves the file, and Lightwork picks it up as a goal. No
chat input needed.

Marker patterns (fixed; see ``MARKER_RE``):
    # AI?     pick up everything after this on the line as the goal
    # AI!     the same; when nothing follows it on the line, the non-blank
              lines after it are the goal (multi-line ok)
    # AI: ... explicit task

A marker counts only where it is a comment: at the start of a line or
after code and whitespace, and not inside a quoted string or a
triple-quoted block (so this docstring creates no goals).

The scanners are generators of ``Match`` records (path, line number,
marker, text, follow lines). The user wires them to a watchdog observer;
we don't ship a watchdog dep in the kernel so this stays usable from
CLI / scripts.

CLI:
    maverick watch <directory>        # prints the matches
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
        (?:^|(?<=\s))(?:\#|/\*)\s*  # unambiguous comment starts (# , /*): at line
                                 #   start or after whitespace, so trailing
                                 #   markers (foo()  # AI! x) work.
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


# Triple quotes stay open across lines (docstrings); the others end with the line.
_BLOCK_QUOTES = ('"""', "'''")
_QUOTES = (*_BLOCK_QUOTES, '"', "'", "`")


def _find_marker(line: str, opened: str | None) -> tuple[re.Match[str] | None, str | None]:
    """Find the first marker on ``line`` that is not inside a quoted string.

    ``opened`` is the triple quote already open where the line starts, if any.
    Returns the match (or None) and the triple quote left open after the line.
    """
    if opened is not None:
        if opened not in line:
            return None, opened
    elif '"""' not in line and "'''" not in line:
        m = MARKER_RE.search(line) if "AI" in line else None
        if m is None or not any(q in line[:m.start()] for q in _QUOTES):
            return m, None
    i = 0
    while i < len(line):
        if opened is not None:
            if line[i] == "\\":
                i += 2
            elif line.startswith(opened, i):
                i += len(opened)
                opened = None
            else:
                i += 1
            continue
        # A marker starts the line or begins with a comment leader.
        m = MARKER_RE.match(line, i) if i == 0 or line[i] in "#/" else None
        if m is not None:
            return m, None
        if line[i] == "#":
            # An ordinary comment: the rest of the line holds no strings.
            return MARKER_RE.search(line, i), None
        for quote in _QUOTES:
            if line.startswith(quote, i):
                opened = quote
                i += len(quote)
                break
        else:
            i += 1
    return None, opened if opened in _BLOCK_QUOTES else None


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
    opened: str | None = None
    for i, line in enumerate(lines):
        m, opened = _find_marker(line, opened)
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
