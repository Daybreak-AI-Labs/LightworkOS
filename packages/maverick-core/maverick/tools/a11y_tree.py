"""DOM accessibility-tree extractor.

Distills raw HTML into the compact **accessibility tree** an agent actually
needs to reason about a page: landmarks, headings, links, buttons, form
controls, and images — each with its accessible name — dropping the markup,
styling, and script noise that dominates a page's token count. This is the
static, pure-stdlib counterpart to the ``a11y`` audit tool (which shells out to
pa11y/axe for *violations*); here the goal is a small, faithful semantic view.

ops:
  - extract(html)  — the accessibility tree as indented text, with a token-cut
                     estimate (raw chars vs extracted chars).
"""
from __future__ import annotations

from html.parser import HTMLParser
from typing import Any

from . import Tool

_LANDMARK = {
    "header": "banner", "nav": "navigation", "main": "main",
    "aside": "complementary", "footer": "contentinfo", "form": "form",
}
_HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_SKIP = {"script", "style", "noscript", "template", "svg", "head"}
_CAPTURE = {"a", "button"} | _HEADINGS  # elements whose inner text is the name


class _A11yTree(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self._skip = 0
        self._cap: dict | None = None  # {tag, attrs, buf}

    def _emit(self, text: str) -> None:
        self.lines.append(text)

    @staticmethod
    def _name(attrs: dict, fallback: str = "") -> str:
        for key in ("aria-label", "alt", "placeholder", "title", "name", "value"):
            v = attrs.get(key)
            if v:
                return " ".join(v.split())
        return " ".join(fallback.split())

    def handle_starttag(self, tag: str, attrs_list: list) -> None:
        if tag in _SKIP:
            self._skip += 1
            return
        if self._skip:
            return
        attrs = dict(attrs_list)
        if tag in _LANDMARK:
            self._emit(f"[{_LANDMARK[tag]}]")
            return
        if tag in _CAPTURE:
            # Start capturing inner text for the name (no nested capture).
            if self._cap is None:
                self._cap = {"tag": tag, "attrs": attrs, "buf": []}
            return
        if tag == "input":
            itype = (attrs.get("type") or "text").lower()
            role = {"submit": "button", "button": "button", "checkbox": "checkbox",
                    "radio": "radio"}.get(itype, "textbox")
            self._emit(f"  {role}: {self._name(attrs) or itype!r}")
        elif tag in ("select", "textarea"):
            role = "combobox" if tag == "select" else "textbox"
            self._emit(f"  {role}: {self._name(attrs)!r}")
        elif tag == "img":
            name = self._name(attrs)
            if name:
                self._emit(f"  image: {name!r}")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP and self._skip:
            self._skip -= 1
            return
        if self._cap and self._cap["tag"] == tag:
            cap = self._cap
            self._cap = None
            name = self._name(cap["attrs"], "".join(cap["buf"]))
            if cap["tag"] == "a":
                href = cap["attrs"].get("href", "")
                self._emit(f"  link: {name!r}" + (f" -> {href}" if href else ""))
            elif cap["tag"] == "button":
                self._emit(f"  button: {name!r}")
            else:  # heading
                level = cap["tag"][1]
                self._emit(f"heading{level}: {name!r}")

    def handle_data(self, data: str) -> None:
        if self._cap is not None and not self._skip:
            self._cap["buf"].append(data)


def _extract(html: str) -> str:
    parser = _A11yTree()
    parser.feed(html)
    tree = "\n".join(parser.lines) if parser.lines else "(no accessible elements found)"
    raw_n = max(1, len(html))
    cut = raw_n / max(1, len(tree))
    return f"{tree}\n\n— {raw_n} raw chars -> {len(tree)} extracted ({cut:.1f}x smaller)"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "extract"):
        return f"ERROR: unknown op {args.get('op')!r}"
    html = args.get("html")
    if not isinstance(html, str) or not html.strip():
        return "ERROR: html (string) is required"
    try:
        return _extract(html)
    except Exception as e:  # pragma: no cover - defensive
        return f"ERROR: parse failed: {type(e).__name__}: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["extract"]},
        "html": {"type": "string", "description": "raw HTML to distill"},
    },
    "required": ["html"],
}


def a11y_tree() -> Tool:
    return Tool(
        name="a11y_tree",
        description=(
            "Distill raw HTML into a compact accessibility tree — landmarks, "
            "headings, links, buttons, form controls, images, each with its "
            "accessible name — dropping markup/style/script noise for a 5-10x "
            "token cut. op=extract with 'html'. Pure stdlib; static (no browser). "
            "Complements the 'a11y' audit tool (pa11y/axe violations)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
