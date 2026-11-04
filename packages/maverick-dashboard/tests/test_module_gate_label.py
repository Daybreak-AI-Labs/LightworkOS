"""The module gate reads the same everywhere.

``Turn on {{ label|lower }}`` produced "Turn on ai system tasks" and "Turn on
no-code grc studio". Only the first letter of an ordinary phrase is lowered
now; acronyms ("AI", "DSAR") and names ("Databricks", "Consumer Trust
Center") keep their capitals. And every page shows its gate in one place:
below the page title (nine pages put it above).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

TEMPLATES = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"


def _button(label: str) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True)
    html = str(env.get_template("_module_gate.html").module.module_gate("example", label))
    start = html.index('class="btn btn--primary mg-on">') + len('class="btn btn--primary mg-on">')
    return html[start:html.index("</button>", start)]


@pytest.mark.parametrize(("label", "button"), [
    ("AI system tasks", "Turn on AI system tasks"),
    ("AI evidence analysis", "Turn on AI evidence analysis"),
    ("DSAR fulfillment", "Turn on DSAR fulfillment"),
    ("EU AI Act workflows", "Turn on EU AI Act workflows"),
    ("No-code GRC studio", "Turn on no-code GRC studio"),
    ("Overall AI risk scoring", "Turn on overall AI risk scoring"),
    ("Consent delivery", "Turn on consent delivery"),
    ("Global opt-out", "Turn on global opt-out"),
    ("Databricks", "Turn on Databricks"),
    ("Connections", "Turn on Connections"),
    ("Consumer Trust Center", "Turn on Consumer Trust Center"),
])
def test_turn_on_button_keeps_acronyms_and_names(label: str, button: str) -> None:
    assert _button(label) == button


def test_every_gate_sits_below_the_page_title() -> None:
    above = []
    for path in sorted(TEMPLATES.glob("*.html")):
        if path.name == "_module_gate.html":  # the macro itself (its usage note)
            continue
        text = path.read_text(encoding="utf-8")
        gate = re.search(r"\{\{\s*module_gate\(", text)
        if gate is None:
            continue
        titles = [m.start() for m in re.finditer(r"hero\(|class=\"page-title|<h1\b", text)]
        assert titles, path.name
        if gate.start() < min(titles):
            above.append(path.name)
    assert not above, "Gate shown above the page title: " + ", ".join(above)
