"""The design tokens in lightwork.css, exported in the Design Tokens
Community Group format (DTCG, https://www.designtokens.org/).

lightwork.css is the single source of truth. This reads it and writes
``docs/design-tokens.json`` so design tools and other surfaces (email,
Slack, Teams cards) can use the same named values. A test regenerates it and
fails when the file drifts from the stylesheet:

    python -m maverick_dashboard.design_tokens --write
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
STYLESHEET = PACKAGE / "static" / "lightwork.css"
EXPORT = PACKAGE.parents[2] / "docs" / "design-tokens.json"

#: The selector that holds each built-in theme's palette.
THEMES = {"dark": (":root", "body.theme-dark"), "light": ("body.theme-light",),
          "solarized": ("body.theme-solarized",), "hicontrast": ("body.theme-hicontrast",)}
#: The colours every built-in theme must define (its palette).
PALETTE = ("bg", "panel", "border", "text", "muted", "accent", "warn", "danger", "danger-fg",
           "brand", "brand-hi", "brand-fg", "info")
_SCALES = {"space": ("space", "dimension"), "radius": ("radius", "dimension"), "text": ("font-size", "dimension"),
           "font": ("font-weight", "fontWeight"), "leading": ("line-height", "number"),
           "duration": ("duration", "duration")}
# Only plain values export; a clamp() or a font stack stays in the stylesheet.
_VALUE = {"dimension": re.compile(r"\d+(?:\.\d+)?(?:px|rem|%)"), "fontWeight": re.compile(r"\d{3}"),
          "number": re.compile(r"\d+(?:\.\d+)?"), "duration": re.compile(r"\d+ms")}
_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_DECL = re.compile(r"--([a-z0-9-]+)\s*:\s*([^;]+);")


def _rules(css: str) -> list[tuple[set[str], str]]:
    source = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    return [({part.strip() for part in selector.split(",")}, body) for selector, body in _RULE.findall(source)]


def declared(css: str, selector: str) -> dict[str, str]:
    """``{name: value}`` declared directly on ``selector`` (later wins)."""
    out: dict[str, str] = {}
    for selectors, body in _rules(css):
        if selector in selectors:
            out.update({name: value.strip() for name, value in _DECL.findall(body)})
    return out


def _token(kind: str, value: str) -> dict[str, str]:
    return {"$type": kind, "$value": value}


def palettes(css: str) -> dict[str, dict[str, str]]:
    out = {}
    for theme, selectors in THEMES.items():
        values: dict[str, str] = {}
        for selector in selectors:
            values.update(declared(css, selector))
        out[theme] = {name: values[name] for name in PALETTE if name in values}
    return out


def build(css: str | None = None) -> dict:
    """The DTCG document for the stylesheet's tokens."""
    css = STYLESHEET.read_text(encoding="utf-8") if css is None else css
    root = declared(css, ":root")
    doc: dict = {"$description": "Lightwork design tokens, generated from "
                 "packages/maverick-dashboard/maverick_dashboard/static/lightwork.css. Do not edit by hand."}
    for prefix, (group, kind) in _SCALES.items():
        entries = {name[len(prefix) + 1:]: _token(kind, value) for name, value in root.items()
                   if name.startswith(prefix + "-") and _VALUE[kind].fullmatch(value)}
        if entries:
            doc[group] = entries
    colors: dict = {"theme": {theme: {name: _token("color", value) for name, value in values.items()}
                              for theme, values in palettes(css).items()}}
    colors["print"] = {name[len("print-"):]: _token("color", value) for name, value in root.items()
                       if name.startswith("print-")}
    colors["workflow-step"] = {name[len("fd-kind-"):]: _token("color", value) for name, value in root.items()
                               if name.startswith("fd-kind-")}
    doc["color"] = colors
    return doc


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


def main(argv: list[str]) -> int:
    text = render(build())
    if "--write" in argv:
        EXPORT.write_text(text, encoding="utf-8")
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
