"""One way to write each button kind.

Pages used class names that were never part of the design system
(``btn primary``, ``btn-primary``, ``btn-danger``); aliases in the stylesheet
painted them brand blue while real primary buttons render in the text colour,
so two "main" buttons on one screen looked different. The aliases are gone;
these ratchets keep them from coming back and keep a single primary-button
definition for each theme family.
"""
from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
CSS = PACKAGE / "static" / "lightwork.css"

# A class list written in markup (class="…") or assigned by a script
# (className = '…'), with the quote it opened with.
_CLASS_LIST = re.compile(r"""\bclass(?:Name)?\s*=\s*(["'])(.*?)\1""")
_LEGACY_SELECTOR = re.compile(r"\.btn-(?:primary|danger)\b|\.btn\.(?:primary|danger)\b")


def _sources() -> list[Path]:
    files: set[Path] = set()
    for pattern in ("templates/*.html", "static/*.js", "static/*.html", "static/*.css", "*.py"):
        files.update(PACKAGE.glob(pattern))
    return sorted(files)


def test_no_legacy_button_class_names() -> None:
    offenders = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for match in _CLASS_LIST.finditer(text):
            names = set(match.group(2).split())
            legacy = names & {"btn-primary", "btn-danger"}
            if "btn" in names and names & {"primary", "danger"}:
                legacy |= names & {"primary", "danger"}
            if legacy:
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{path.relative_to(PACKAGE)}:{line} {sorted(legacy)}")
        for match in _LEGACY_SELECTOR.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{path.relative_to(PACKAGE)}:{line} {match.group(0)}")
    assert not offenders, "Use btn btn--primary / btn btn--danger: " + "; ".join(offenders)


def _selectors(prelude: str) -> list[str]:
    """Split a selector list on its top-level commas only."""
    parts, depth, current = [], 0, ""
    for char in prelude:
        depth += (char == "(") - (char == ")")
        if char == "," and depth == 0:
            parts.append(" ".join(current.split()))
            current = ""
        else:
            current += char
    return [*parts, " ".join(current.split())]


def _rules(css: str) -> list[tuple[list[str], str]]:
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    return [(_selectors(selector), body) for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css)]


def test_primary_button_has_one_definition_and_one_action_colour() -> None:
    """One rule draws the main action in every theme from the --color-action
    tokens; high contrast differs only in the token values (the brand fill
    with a soft lift), so no theme-specific primary rule is left to drift."""
    css = CSS.read_text(encoding="utf-8")
    primary = [(sels, body) for sels, body in _rules(css) if any(s.endswith(".btn--primary") for s in sels)]
    hover = [(sels, body) for sels, body in _rules(css) if any(s.endswith(".btn--primary:hover") for s in sels)]
    assert len(primary) == 1 and len(hover) == 1, (primary, hover)
    assert "background: var(--color-action);" in primary[0][1]
    assert "color: var(--color-action-text);" in primary[0][1]
    assert "background: var(--color-action-hover);" in hover[0][1]
    # Same weight as before in each theme family, so page styles that
    # adjusted a main button keep doing so.
    assert primary[0][0] == [".btn--primary", "body:not(.theme-hicontrast) .btn--primary"]
    tokens = {sel: body for sels, body in _rules(css) for sel in sels if "--color-action:" in body}
    assert "var(--text)" in tokens["body"] and "var(--brand)" in tokens["body.theme-hicontrast"]


def test_default_and_quiet_buttons_look_different() -> None:
    """A default button is filled; a quiet (ghost) one has no fill. They used
    to render identically on panels, where the sunken control fill matched
    the panel."""
    css = CSS.read_text(encoding="utf-8")
    fill = [body for sels, body in _rules(css)
            if "body:not(.theme-hicontrast) :where(.btn:not(.btn--ghost):not(.btn--primary):not(.btn--danger))" in sels]
    assert len(fill) == 1 and "background-color: var(--color-control);" in fill[0]
    ghost = css.index("body:not(.theme-hicontrast) :where(.btn--ghost:not(.btn--primary):not(.btn--danger))")
    assert css.index(":where(.btn:not(.btn--ghost):not(.btn--primary):not(.btn--danger))") < ghost
    control = [body for sels, body in _rules(css) if "body" in sels and "--color-control:" in body]
    assert control and "var(--text) 8%" in control[0]


def test_quiet_danger_and_small_buttons_are_defined() -> None:
    """``btn--danger btn--ghost`` is a quiet destructive action (outlined in
    the danger colour), not a full danger fill by cascade accident, and the
    small size pages already ask for exists."""
    css = CSS.read_text(encoding="utf-8")
    quiet = [body for sels, body in _rules(css) if ".btn--danger.btn--ghost" in sels]
    assert quiet and "background: transparent" in quiet[0] and "color: var(--color-danger)" in quiet[0]
    small = [body for sels, body in _rules(css) if ".btn--sm" in sels]
    assert small and "font-size: var(--text-sm)" in small[0]
