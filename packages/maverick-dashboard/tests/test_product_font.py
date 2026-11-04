"""Every control and the public demo use the product face.

Browsers give buttons, fields and menus their own system font, so each
``<button class="btn">`` rendered in Arial while ``<a class="btn">`` used
Manrope, and chips on the privacy, flow designer and workflow builder pages
did the same. The public demo page hard-coded Inter for its title.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
CSS = PACKAGE / "static" / "lightwork.css"


def _font_sans(source: str) -> str:
    match = re.search(r"--font-sans:\s*([^;]+);", source)
    assert match is not None
    return re.sub(r"\s+", "", match.group(1)).replace("'", '"')


def test_controls_and_chips_inherit_the_product_face() -> None:
    css = CSS.read_text(encoding="utf-8")
    assert ":where(button, input, select, textarea) { font-family: inherit; }" in css
    assert ":where(.chip, .fd__chip) { font: inherit; }" in css
    # The body face is the product face; the dyslexia-friendly font (a
    # body.font-dyslexic rule, which outranks body) replaces it when chosen.
    bodies = [rule.group(1) for rule in re.finditer(r"(?m)^\s*body \{([^}]*)\}", css)]
    assert any("font: var(--text-base)/var(--leading) var(--font-sans);" in body for body in bodies)
    assert re.search(r"body\.font-dyslexic, body\.font-dyslexic input[^{]*\{\s*font-family: \"OpenDyslexic\"", css)


def test_public_demo_uses_the_shared_font_token(monkeypatch, tmp_path) -> None:
    from maverick import world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    try:
        page = TestClient(dashboard.app, base_url="http://127.0.0.1").get("/demo").text
    finally:
        dashboard._world_cache.clear()
    assert "Inter" not in page
    assert "font-family:var(--font-sans)" in page
    # The public proxy serves only /demo, so the page cannot load the shared
    # stylesheet; its copy of the token must match the shared one exactly.
    assert _font_sans(page) == _font_sans(CSS.read_text(encoding="utf-8"))
