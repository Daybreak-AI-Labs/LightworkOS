"""The design tokens are the single source of visual truth.

Every colour in a built-in theme's palette is defined in every theme, the
tokens are exported in the DTCG format (docs/design-tokens.json) and the
export never drifts from lightwork.css, and the screens that held their own
colours (the workflow designer, printed reports and conversations, the
public shared result) now use named tokens."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from maverick_dashboard import design_tokens

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
CSS = (PACKAGE / "static" / "lightwork.css").read_text(encoding="utf-8")
HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")


@pytest.mark.parametrize("theme", sorted(design_tokens.THEMES))
def test_every_palette_colour_is_defined_in_every_theme(theme):
    palette = design_tokens.palettes(CSS)[theme]
    assert sorted(palette) == sorted(design_tokens.PALETTE), theme


def test_the_portable_export_matches_the_stylesheet():
    exported = json.loads(design_tokens.EXPORT.read_text(encoding="utf-8"))
    assert exported == design_tokens.build(CSS), "Run python -m maverick_dashboard.design_tokens --write"
    assert all(token["$type"] == "color" for theme in exported["color"]["theme"].values() for token in theme.values())
    assert exported["space"]["4"] == {"$type": "dimension", "$value": "16px"}


def _style_hex(template: str) -> list[str]:
    text = (PACKAGE / "templates" / template).read_text(encoding="utf-8")
    styles = "".join(re.findall(r"<style[^>]*>(.*?)</style>", text, flags=re.DOTALL))
    return HEX.findall(styles)


@pytest.mark.parametrize("template", ["flow_designer.html", "chat_goal.html", "audit_binder.html", "privacy_report.html"])
def test_these_screens_use_named_colours(template):
    assert _style_hex(template) == [], template


def test_the_public_shared_result_names_its_colours_once_per_scheme():
    text = (PACKAGE / "templates" / "shared_goal.html").read_text(encoding="utf-8")
    styles = "".join(re.findall(r"<style[^>]*>(.*?)</style>", text, flags=re.DOTALL))
    outside = re.sub(r":root\s*\{[^}]*\}", "", styles)
    assert HEX.findall(outside) == []
