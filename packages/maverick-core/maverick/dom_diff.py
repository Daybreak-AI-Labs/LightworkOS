"""Live-DOM diff: structural diff of two HTML snapshots.

Compares two DOM states — e.g. a page before/after a browser action — and reports
added / removed elements and changed visible text, without an external parser
(stdlib ``html.parser`` + ``difflib``). Useful for "what changed on the page?"
after a click without dumping the whole DOM back to the model. Exposed as the
``dom_diff`` tool; ``diff_html`` is the pure, unit-tested core.
"""
from __future__ import annotations

import difflib
from html.parser import HTMLParser

# Tags whose content never renders — excluded from the visible-text diff.
_INVISIBLE = {"script", "style", "head", "meta", "link", "noscript", "template"}
# Void elements have no close tag; don't expect one.
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
         "meta", "param", "source", "track", "wbr"}


class _DOMCollector(HTMLParser):
    """Collect a flat element-signature sequence + visible text from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.signatures: list[str] = []
        self._text: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        sig = tag
        if a.get("id"):
            sig += f"#{a['id']}"
        if a.get("class"):
            cls = ".".join(a["class"].split())
            sig += f".{cls}"
        if tag == "a" and a.get("href"):
            sig += f"[href={a['href']}]"
        self.signatures.append(sig)
        # Only non-void invisible tags open a skip region; void ones (meta,
        # link) never get a close tag, so incrementing here would leak the
        # depth and silently drop all subsequent visible text.
        if tag in _INVISIBLE and tag not in _VOID:
            self._skip_depth += 1

    def handle_startendtag(self, tag, attrs):
        # HTMLParser's default implementation calls handle_starttag() followed
        # by handle_endtag().  That is wrong for self-closing void invisible
        # tags (for example <meta/> inside <head>): the start tag intentionally
        # does not open a skip region, so the synthetic end tag must not close
        # the surrounding invisible parent.
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in _INVISIBLE and tag not in _VOID and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth:
            return
        s = data.strip()
        if s:
            self._text.append(s)

    def visible_text(self) -> list[str]:
        return self._text


def _collect(html: str) -> _DOMCollector:
    c = _DOMCollector()
    try:
        c.feed(html or "")
    except Exception:  # pragma: no cover -- malformed HTML must not raise
        pass
    return c


def diff_html(before: str, after: str) -> dict:
    """Return ``{added, removed, text_added, text_removed, changed}``.

    ``added``/``removed`` are element signatures (tag#id.class[href]) inserted or
    deleted between the two snapshots; ``text_*`` are visible text lines. Order is
    preserved via ``difflib`` so a moved/duplicated element is reported once.
    """
    a, b = _collect(before), _collect(after)
    added, removed = _seq_diff(a.signatures, b.signatures)
    t_added, t_removed = _seq_diff(a.visible_text(), b.visible_text())
    return {
        "added": added,
        "removed": removed,
        "text_added": t_added,
        "text_removed": t_removed,
        "changed": bool(added or removed or t_added or t_removed),
    }


def _seq_diff(a: list[str], b: list[str]) -> tuple[list[str], list[str]]:
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op in ("replace", "delete"):
            removed.extend(a[i1:i2])
        if op in ("replace", "insert"):
            added.extend(b[j1:j2])
    return added, removed


def render_diff(d: dict) -> str:
    if not d["changed"]:
        return "no DOM changes"
    lines: list[str] = []
    if d["added"]:
        lines.append(f"+ {len(d['added'])} element(s) added:")
        lines += [f"  + {s}" for s in d["added"][:50]]
    if d["removed"]:
        lines.append(f"- {len(d['removed'])} element(s) removed:")
        lines += [f"  - {s}" for s in d["removed"][:50]]
    if d["text_added"]:
        lines.append("+ text appeared:")
        lines += [f"  + {t}" for t in d["text_added"][:50]]
    if d["text_removed"]:
        lines.append("- text removed:")
        lines += [f"  - {t}" for t in d["text_removed"][:50]]
    return "\n".join(lines)


_SCHEMA = {
    "type": "object",
    "properties": {
        "before": {"type": "string", "description": "HTML of the earlier DOM state"},
        "after": {"type": "string", "description": "HTML of the later DOM state"},
    },
    "required": ["before", "after"],
}


def _run(args: dict) -> str:
    before = args.get("before")
    after = args.get("after")
    if before is None or after is None:
        return "ERROR: both 'before' and 'after' HTML are required"
    return render_diff(diff_html(str(before), str(after)))


def dom_diff():
    from .tools import Tool
    return Tool(
        name="dom_diff",
        description=(
            "Structural diff of two HTML snapshots (before/after). Reports added "
            "and removed elements (tag#id.class) and changed visible text — a "
            "compact 'what changed on the page' instead of the whole DOM."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )


__all__ = ["diff_html", "render_diff", "dom_diff"]
