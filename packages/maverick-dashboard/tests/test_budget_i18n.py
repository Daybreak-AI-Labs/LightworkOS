"""Budget copy is localized explicitly without changing accounting contracts."""
import ast
import inspect
from pathlib import Path
from string import Formatter

import pytest
from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader, select_autoescape
from maverick import budget_guidance
from maverick_dashboard import budget_guidance_api, i18n_journeys
from maverick_dashboard.i18n_journey_budget import ROWS


@pytest.mark.parametrize("language", ["fr", "de", "ja", "zh", "ar"])
def test_budget_template_product_regions_use_requested_or_honest_fallback_language(language):
    templates = Path(budget_guidance_api.__file__).parent / "templates"
    env = Environment(loader=ChoiceLoader([
        DictLoader({"base.html": "<title>{% block title %}{% endblock %}</title>{% block content %}{% endblock %}"}),
        FileSystemLoader(templates),
    ]), autoescape=select_autoescape())
    rendered = env.get_template("budget_guidance.html").render(
        goal_id=7, ui=lambda source: i18n_journeys.region(source, language),
        ut=lambda source: i18n_journeys.text(source, language))
    actual = "en" if language == "ar" else language
    assert f'lang="{actual}"' in rendered
    assert str(i18n_journeys.region("Refresh preview", language)) in rendered
    assert i18n_journeys.text("Your budget", language) in rendered
    assert 'data-goal="7"' in rendered
    assert 'name="max_dollars" type="number" min="0" step="0.01"' in rendered
    if language != "ar":
        assert 'lang="en"' not in rendered
        assert "Requested task ceiling" not in rendered


def test_budget_catalog_has_complete_draft_placeholders_without_arabic_completion():
    assert len({row[0] for row in ROWS}) == len(ROWS)
    for source, *translations in ROWS:
        fields = {name for _, name, _, _ in Formatter().parse(source) if name}
        assert len(translations) == 4
        for translated in translations:
            assert translated.strip()
            assert {name for _, name, _, _ in Formatter().parse(translated) if name} == fields
        assert i18n_journeys.entry(source, "ar") == (source, "en")


def test_budget_native_closed_messages_have_explicit_catalog_entries():
    known = {row[0] for row in ROWS}
    for module in (budget_guidance, budget_guidance_api):
        tree = ast.parse(inspect.getsource(module))
        docs = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}
        product = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                   and id(node) not in docs and isinstance(node.value, str)
                   and len(node.value) > 20 and " " in node.value and node.value[0].isupper()}
        assert product <= known, product - known
