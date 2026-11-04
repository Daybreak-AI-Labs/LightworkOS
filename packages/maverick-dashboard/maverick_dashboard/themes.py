"""Pluggable themes.

Operators define extra dashboard themes in ``~/.maverick/config.toml``::

    [dashboard.themes.midnight]
    bg = "#101020"
    panel = "#181830"
    text = "#e0e0f0"
    accent = "#7aa2f7"

Each theme becomes a ``body.theme-<name>`` CSS-variable block rendered into
``base.html`` and is selectable exactly like the built-ins (``?theme=`` /
``mvk_theme`` cookie / ``[dashboard] theme``). Default-off: no ``themes``
table, no change.

Config is untrusted styling input, so validation is strict-by-construction:
theme names must be short slugs (they land in a body class and a CSS
selector) and every value must be a ``#rgb``/``#rrggbb`` hex color — anything
else drops the whole theme, so config can never inject CSS (no ``url(...)``,
no ``;}``-escapes, no expressions).
"""
from __future__ import annotations

import re

# The four core variables every theme must define, plus optional extras that
# map onto the rest of base.html's palette. Anything outside this set
# invalidates the theme.
REQUIRED_KEYS = ("bg", "panel", "text", "accent")
OPTIONAL_KEYS = ("border", "muted", "warn", "danger")
_ALLOWED_KEYS = frozenset(REQUIRED_KEYS) | frozenset(OPTIONAL_KEYS)

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")

# Built-in body.theme-* presets in base.html; a custom theme may not shadow one.
BUILTIN_THEMES = frozenset({"dark", "light", "solarized", "hicontrast"})

# Each built-in theme's page canvas (--bg in static/lightwork.css), for the
# browser's own chrome (<meta name="theme-color">, the phone address bar).
_BUILTIN_CANVAS = {"dark": "#04050A", "light": "#f4f6fa", "solarized": "#002b36", "hicontrast": "#000000"}


def contrast_ratio(first: str, second: str) -> float:
    """WCAG relative luminance for the validated sRGB palette."""
    def luminance(value: str) -> float:
        value = value.lstrip("#")
        if len(value) == 3:
            value = "".join(part * 2 for part in value)
        channels = [int(value[index:index + 2], 16) / 255 for index in (0, 2, 4)]
        linear = [part / 12.92 if part <= 0.04045 else ((part + 0.055) / 1.055) ** 2.4
                  for part in channels]
        return sum(part * weight for part, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True))

    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def complete_palette(values: dict[str, str]) -> dict[str, str]:
    """Unspecified semantic colours inherit this theme's text, never another theme."""
    palette = dict(values)
    if "text" in palette:
        for key in OPTIONAL_KEYS:
            palette.setdefault(key, palette["text"])
    return palette


def contrast_issues(values: dict[str, str]) -> list[str]:
    """Human-readable checks for text, status, controls and focus indicators."""
    if not all(key in values and _HEX.fullmatch(values[key]) for key in REQUIRED_KEYS):
        return ["Choose all four required colours first."]
    values = complete_palette(values)
    issues = []
    for background in ("bg", "panel"):
        for foreground, label, minimum in (
            ("text", "Text", 4.5), ("muted", "Quiet text", 4.5),
            ("accent", "Highlights and focus", 4.5), ("warn", "Warnings", 4.5),
            ("danger", "Errors", 4.5), ("border", "Control borders", 3.0),
        ):
            colour = values.get(foreground)
            if colour and _HEX.fullmatch(colour):
                ratio = contrast_ratio(colour, values[background])
                if ratio < minimum:
                    surface = "page background" if background == "bg" else "panels"
                    issues.append(f"{label} against {surface}: {ratio:.2f}:1; needs {minimum:g}:1.")
    return issues


def readable_palette(values: dict[str, str]) -> dict[str, str]:
    """Keep older deployment palettes recoverable without hiding their editor."""
    palette = complete_palette(values)
    if not contrast_issues(palette):
        return palette
    foreground = max(("#000000", "#ffffff"), key=lambda colour: contrast_ratio(colour, palette["bg"]))
    if contrast_ratio(foreground, palette["panel"]) < 4.5:
        palette["panel"] = palette["bg"]
    for key in ("text", "muted", "accent", "warn", "danger", "border"):
        if key not in palette or min(contrast_ratio(palette[key], palette[surface]) for surface in ("bg", "panel")) < 4.5:
            palette[key] = foreground
    return palette


def _valid_theme(name: str, values: dict) -> bool:
    if not _NAME.match(name) or name in BUILTIN_THEMES:
        return False
    if not isinstance(values, dict) or not values:
        return False
    keys = {str(k) for k in values}
    if not keys <= _ALLOWED_KEYS or not set(REQUIRED_KEYS) <= keys:
        return False
    return all(isinstance(v, str) and _HEX.match(v) for v in values.values())


def custom_themes() -> dict[str, dict[str, str]]:
    """The operator's validated ``[dashboard] themes`` table (``{}`` when
    unset, unreadable, or nothing survives validation)."""
    try:
        from maverick.config import load_config
        raw = ((load_config() or {}).get("dashboard") or {}).get("themes") or {}
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for name, values in raw.items():
        name = str(name).strip().lower()
        if _valid_theme(name, values):
            out[name] = readable_palette({str(k): str(v) for k, v in values.items()})
    return out


def theme_color(theme: str, themes: dict[str, dict[str, str]] | None = None) -> str:
    """The canvas colour of ``theme``: a built-in's, an operator theme's
    ``bg``, or the default dark canvas for anything else."""
    if theme in _BUILTIN_CANVAS:
        return _BUILTIN_CANVAS[theme]
    background = ((themes or {}).get(theme) or {}).get("bg", "")
    return background if _HEX.match(background) else _BUILTIN_CANVAS["dark"]


def theme_css(themes: dict[str, dict[str, str]]) -> str:
    """Render validated themes as ``body.theme-<name>`` CSS-variable blocks.

    Only call with :func:`custom_themes` output (or equally validated data):
    names and hex values are interpolated verbatim.
    """
    blocks: list[str] = []
    for name in sorted(themes):
        palette = complete_palette(themes[name])
        decls = "; ".join(
            f"--{key}: {palette[key]}"
            for key in (*REQUIRED_KEYS, *OPTIONAL_KEYS)
            if key in palette
        )
        blocks.append(f"body.theme-{name} {{ {decls}; }}")
    return "\n".join(blocks)


__all__ = ["custom_themes", "theme_color", "theme_css", "BUILTIN_THEMES", "REQUIRED_KEYS", "OPTIONAL_KEYS"]
