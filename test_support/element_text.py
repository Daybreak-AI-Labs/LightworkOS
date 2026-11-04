"""Read the text of actual rendered elements without matching scripts or JSON."""
from __future__ import annotations

from html.parser import HTMLParser


class _ElementText(HTMLParser):
    def __init__(self, html, tag, required):
        super().__init__(convert_charrefs=True)
        self.tag, self.required = tag, required
        self.depth = 0
        self.active = []
        self.parts = []
        self.attributes = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag != self.tag:
            return
        self.depth += 1
        values = dict(attrs)
        if not all(values.get(key) == value for key, value in self.required.items()):
            return
        parts = []
        self.attributes.append(values)
        self.parts.append(parts)
        self.active.append((self.depth, parts))

    def handle_data(self, data):
        for _, parts in self.active:
            parts.append(data)

    def handle_endtag(self, tag):
        if tag == self.tag:
            self.active = [(depth, parts) for depth, parts in self.active if depth != self.depth]
            self.depth -= 1


def element_texts(html: str, tag: str, attrs: dict | None = None) -> list[str]:
    return [" ".join("".join(parts).split())
            for parts in _ElementText(html, tag, attrs or {}).parts]


def element_attributes(html: str, tag: str, attrs: dict | None = None) -> list[dict]:
    return _ElementText(html, tag, attrs or {}).attributes
