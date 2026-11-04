"""Assertions about rendered navigation links, including nested locale spans."""
from __future__ import annotations

from html.parser import HTMLParser


class _NavigationLinks(HTMLParser):
    def __init__(self, html: str, landmark: str):
        super().__init__(convert_charrefs=True)
        self.landmark = landmark
        self.in_nav = False
        self.current = None
        self.links = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "nav":
            self.in_nav = attrs.get("aria-label") == self.landmark
        elif tag == "a" and self.in_nav:
            self.current = {"attrs": attrs, "text": ""}
            self.links.append(self.current)

    def handle_data(self, data):
        if self.current is not None:
            self.current["text"] += data

    def handle_endtag(self, tag):
        if tag == "a":
            self.current = None
        elif tag == "nav":
            self.in_nav = False


def assert_navigation_link(html: str, href: str, label: str, *, landmark="Primary"):
    links = [link for link in _NavigationLinks(html, landmark).links
             if link["attrs"].get("href") == href]
    assert len(links) == 1, (landmark, href, links)
    attrs = links[0]["attrs"]
    assert " ".join(links[0]["text"].split()) == label
    assert attrs.get("aria-label", label) == label
    assert "hidden" not in attrs and attrs.get("aria-hidden") != "true"
    assert attrs.get("role", "link") == "link"
