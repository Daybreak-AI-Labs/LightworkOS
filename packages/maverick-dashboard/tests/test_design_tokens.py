"""One visual system: the design tokens in lightwork.css.

The shared sheet used to stack three design "editions", each later layer
silently overriding the earlier one (a dead dark palette, a serif token that
held a sans face, a second radius scale). Each built-in theme now has one
palette, the semantic token names alias today's values, and the browser
chrome colour (<meta name="theme-color">) follows the theme in use.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import app as app_module
from maverick_dashboard import themes as themes_mod
from maverick_dashboard.app import app

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
CSS = (PACKAGE / "static" / "lightwork.css").read_text(encoding="utf-8")
_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")


def _rules() -> list[tuple[set[str], str]]:
    source = re.sub(r"/\*.*?\*/", "", CSS, flags=re.DOTALL)
    return [({part.strip() for part in selector.split(",")}, body) for selector, body in _RULE.findall(source)]


def _declared(selector: str, name: str) -> list[str]:
    found = []
    for selectors, body in _rules():
        if selector in selectors:
            found += re.findall(rf"(?<![\w-]){re.escape(name)}\s*:\s*([^;]+);", body)
    return [value.strip() for value in found]


@pytest.mark.parametrize("theme", sorted(themes_mod.BUILTIN_THEMES))
def test_each_built_in_theme_sets_its_palette_once(theme):
    selector = ":root" if theme == "dark" else f"body.theme-{theme}"
    for name in ("--bg", "--panel", "--border", "--text", "--muted", "--accent", "--warn", "--danger"):
        assert len(_declared(selector, name)) == 1, (theme, name)
    for name in ("--brand", "--brand-hi", "--brand-fg", "--info"):
        assert len(_declared(f"body.theme-{theme}", name)) == 1, (theme, name)


def test_the_scale_tokens_are_defined_once_on_the_root():
    for name, value in {
        "--space-0-5": "2px", "--space-2": "8px", "--radius-xs": "4px", "--radius-md": "8px",
        "--radius-lg": "14px", "--radius-round": "50%", "--text-2xs": "0.6875rem",
        "--font-light": "200", "--font-bold": "700", "--leading-none": "1", "--leading-relaxed": "1.7",
        "--duration-fast": "120ms", "--duration-base": "200ms", "--duration-slow": "400ms",
        "--ease-standard": "ease", "--z-sticky": "50", "--z-drawer": "60", "--z-popover": "70",
        "--z-toast": "90", "--z-skip-link": "200",
    }.items():
        assert _declared(":root", name) == [value], name


def test_semantic_colour_names_alias_the_theme_values():
    """Declared on <body>, where the theme class lives, so they follow the
    active theme and an operator's four-colour theme alike."""
    for name, value in {
        "--color-canvas": "var(--bg)", "--color-surface": "var(--surface-1)",
        "--color-surface-raised": "var(--surface-2)", "--color-text": "var(--text)",
        "--color-text-muted": "var(--muted)", "--color-link": "var(--brand)",
        "--color-focus": "var(--ring)", "--color-success": "var(--success)",
        "--color-warning": "var(--warn)", "--color-danger": "var(--danger)",
        "--color-danger-text": "var(--danger-fg)", "--color-info": "var(--info)",
    }.items():
        assert _declared("body", name) == [value], name


def test_font_serif_is_only_an_alias_of_the_product_face():
    """--font-serif held Manrope (a sans face) after the third edition. It
    stays as an alias for older page styles; shipped styles name the face."""
    assert _declared(":root", "--font-serif") == ["var(--font-sans)"]
    readers = [
        str(path.relative_to(PACKAGE))
        for pattern in ("static/*.css", "static/*.js", "templates/*.html")
        for path in PACKAGE.glob(pattern)
        if "var(--font-serif)" in path.read_text(encoding="utf-8")
    ]
    assert readers == []


def _canvas(theme: str) -> str:
    selector = ":root" if theme == "dark" else f"body.theme-{theme}"
    return _declared(selector, "--bg")[0]


@pytest.mark.parametrize("theme", sorted(themes_mod.BUILTIN_THEMES))
def test_browser_chrome_colour_matches_the_theme_canvas(theme):
    assert themes_mod.theme_color(theme).lower() == _canvas(theme).lower()
    page = TestClient(app, base_url="http://127.0.0.1").get("/overview", params={"theme": theme})
    assert page.status_code == 200
    meta = re.findall(r'<meta name="theme-color" content="([^"]+)"', page.text)
    assert [value.lower() for value in meta] == [_canvas(theme).lower()]


def test_browser_chrome_colour_uses_an_operator_theme_background(monkeypatch):
    palette = {"bg": "#101020", "panel": "#181830", "text": "#e0e0f0", "accent": "#7aa2f7"}
    monkeypatch.setattr(app_module, "custom_themes", lambda: {"midnight": dict(palette)})
    assert themes_mod.theme_color("midnight", {"midnight": palette}) == "#101020"
    page = TestClient(app, base_url="http://127.0.0.1").get("/overview", params={"theme": "midnight"})
    assert 'name="theme-color" content="#101020"' in page.text
    # Unknown names fall back to the default (dark) canvas.
    assert themes_mod.theme_color("nope").lower() == _canvas("dark").lower()
