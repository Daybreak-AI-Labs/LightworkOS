#!/usr/bin/env python3
"""Maintain the table of contents at the top of docs/FEATURES.md.

FEATURES.md is the catalogue of shipped features: nineteen ``##`` sections
holding about five hundred ``- **Name** -- ...`` entries over 6,000 lines. The
block between ``<!-- toc:start -->`` and ``<!-- toc:end -->`` lists every
section with its entry count (and subsection count) so a reader sees the shape
of the document and can jump to a section; ``test_claims_docs.py`` fails when
the block is stale or when an entry sits above the first section.

Section anchors are the GitHub and MkDocs slug of the heading (lower case,
punctuation dropped, spaces to hyphens). The two renderers agree only when the
heading has no character that one keeps and the other drops, so section
headings use "and" rather than "&" (the test checks).

Usage::

    python scripts/features_toc.py --check    # exit 1 when the block is stale
    python scripts/features_toc.py --write    # rewrite the block in place
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FEATURES = REPO_ROOT / "docs" / "FEATURES.md"
START = "<!-- toc:start -->"
END = "<!-- toc:end -->"
_ENTRY = re.compile(r"^- \*\*")


@dataclass
class Section:
    title: str
    line: int
    entries: int = 0
    subsections: list[str] = field(default_factory=list)


def anchor(title: str) -> str:
    """The heading's fragment identifier as GitHub and MkDocs both derive it."""
    slug = re.sub(r"[^\w\s-]", "", title.lower())
    return re.sub(r"\s+", "-", slug.strip())


def _without_block(text: str) -> str:
    start, end = text.find(START), text.find(END)
    if start == -1 or end == -1:
        return text
    return text[:start] + text[end + len(END):]


def sections(text: str) -> list[Section]:
    """Every ``##`` section of the catalogue (the contents block excluded) with
    its entry and subsection counts."""
    found: list[Section] = []
    for number, line in enumerate(_without_block(text).split("\n"), 1):
        if line.startswith("## "):
            found.append(Section(line[3:].strip(), number))
        elif found and line.startswith("### "):
            found[-1].subsections.append(line[4:].strip())
        elif found and _ENTRY.match(line):
            found[-1].entries += 1
    return found


def entries_before_first_section(text: str) -> int:
    body = _without_block(text)
    head = body.split("\n## ", 1)[0]
    return sum(1 for line in head.split("\n") if _ENTRY.match(line))


def render(found: list[Section]) -> str:
    rows = ["| Section | Entries |", "| --- | ---: |"]
    for s in found:
        if s.entries and s.subsections:
            count = f"{s.entries} in {len(s.subsections)} subsections"
        elif s.entries:
            count = str(s.entries)
        else:
            count = "prose"
        rows.append(f"| [{s.title}](#{anchor(s.title)}) | {count} |")
    total = sum(s.entries for s in found)
    return "\n".join([
        START,
        "## Contents",
        "",
        *rows,
        "",
        f"{total} entries in {len(found)} sections. This block is generated: "
        "`python scripts/features_toc.py --write` (the test suite fails when it is stale).",
        END,
    ])


def apply(text: str) -> str:
    """``text`` with the contents block regenerated (inserted before the first
    section when absent)."""
    block = render(sections(text))
    start, end = text.find(START), text.find(END)
    if start != -1 and end != -1:
        return text[:start] + block + text[end + len(END):]
    first = text.find("\n## ")
    if first == -1:
        raise SystemExit("docs/FEATURES.md has no sections")
    return text[:first + 1] + block + "\n\n" + text[first + 1:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 when the block is stale")
    mode.add_argument("--write", action="store_true", help="rewrite the block in place")
    args = parser.parse_args(argv)
    text = FEATURES.read_text(encoding="utf-8")
    fresh = apply(text)
    if args.write:
        if fresh != text:
            FEATURES.write_text(fresh, encoding="utf-8")
            print("docs/FEATURES.md: contents block rewritten")
        else:
            print("docs/FEATURES.md: contents block already current")
        return 0
    if fresh != text:
        print("docs/FEATURES.md: contents block is stale; run python scripts/features_toc.py --write")
        return 1
    print("docs/FEATURES.md: contents block current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
