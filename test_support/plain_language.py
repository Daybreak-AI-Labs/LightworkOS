"""Shared check that a rendered dashboard page speaks plain language.

``developer_terms(html)`` returns the developer words a person could read in
the page's main content (scripts, styles and attribute values excluded), so a
render test can assert it is empty.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

_WORDS = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|idempoten\w*|"
    r"revision|lease|json|yaml|toml|stack trace|traceback)\b",
    re.IGNORECASE,
)
_CASE_SENSITIVE = re.compile(r"\b(CAS|HTTP|API)\b|/api/|\bmaverick\s+[a-z]")
_SNAKE = re.compile(r"\b[a-z0-9]+_[a-z0-9_]+\b")


class _MainText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_main = 0
        self._skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "main":
            self._in_main += 1
        elif tag in {"script", "style", "template"}:
            self._skip += 1

    def handle_endtag(self, tag) -> None:
        if tag == "main":
            self._in_main -= 1
        elif tag in {"script", "style", "template"}:
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data) -> None:
        if self._in_main and not self._skip:
            self.parts.append(data)


def visible_text(html: str) -> str:
    parser = _MainText()
    parser.feed(html)
    return " ".join(" ".join(parser.parts).split())


def developer_terms(html: str) -> list[str]:
    text = visible_text(html)
    found = [m.group(0) for m in _WORDS.finditer(text)]
    found += [m.group(0) for m in _CASE_SENSITIVE.finditer(text)]
    found += [m.group(0) for m in _SNAKE.finditer(text)]
    return found
