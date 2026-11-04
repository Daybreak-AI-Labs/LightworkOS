"""Template tests."""
from __future__ import annotations

import pytest
from maverick.templates import (
    Template,
    _substitute,
    list_templates,
    load_template,
)

TEMPLATE_BODY = """---
title: Research {{ topic }}
budget_dollars: 2.5
budget_wall_seconds: 1200
params:
  - topic
  - depth
---
Research {{ topic }} across {{ depth }} dimensions. Write to report.md.
"""


def test_parse_with_frontmatter():
    t = Template.parse(TEMPLATE_BODY, "research")
    assert t.title == "Research {{ topic }}"
    assert t.budget_dollars == 2.5
    assert t.budget_wall_seconds == 1200
    assert "topic" in t.params
    assert "depth" in t.params


def test_parse_without_frontmatter():
    t = Template.parse("just a body", "plain")
    assert t.title == "plain"
    assert t.body == "just a body"
    assert t.budget_dollars is None and t.budget_wall_seconds is None


def test_parse_non_numeric_budget_raises_clear_error():
    # A user-authored template with a non-numeric budget must raise a clear,
    # catchable message -- not a raw float() ValueError traceback.
    import pytest
    with pytest.raises(ValueError, match=r"budget_dollars.*must be a number.*not-a-number"):
        Template.parse("---\nbudget_dollars: not-a-number\n---\nbody", "bad")


def test_render_substitutes_variables():
    t = Template.parse(TEMPLATE_BODY, "research")
    title, body = t.render(topic="AI agents", depth="4")
    assert title == "Research AI agents"
    assert "AI agents across 4 dimensions" in body


def test_render_missing_required_param():
    t = Template.parse(TEMPLATE_BODY, "research")
    with pytest.raises(ValueError, match=r"depth: enter a value\."):
        t.render(topic="x")  # forgot 'depth'


def test_render_extra_params_ignored():
    t = Template.parse(TEMPLATE_BODY, "research")
    title, body = t.render(topic="x", depth="y", unused="z")
    assert title == "Research x"


def test_substitute_leaves_unknown_vars_alone():
    out = _substitute("hello {{ name }}, {{ missing }}", {"name": "world"})
    assert "hello world" in out
    assert "{{ missing }}" in out


def test_load_template_rejects_path_traversal():
    with pytest.raises(ValueError, match="invalid template name"):
        load_template("../secret")


def test_load_template_rejects_absolute_path():
    with pytest.raises(ValueError, match="invalid template name"):
        load_template("/tmp/secret")


def test_starter_goals_library_has_at_least_ten():
    # The bundled starter-goals library must reach all 10 documented goals.
    names = list_templates()
    assert len(names) >= 10


def test_every_bundled_template_loads_and_parses():
    for name in list_templates():
        t = load_template(name)
        assert t.name == name
        assert t.body  # non-empty goal body
        assert t.budget_dollars is None or t.budget_dollars >= 0
        assert t.budget_wall_seconds is None or t.budget_wall_seconds >= 0


class TestTemplateBudgetParse:
    def test_malformed_budget_does_not_crash(self):
        from maverick.templates import _parse_frontmatter
        meta = _parse_frontmatter("budget_dollars: 1.2.3\n")
        # The bad value must not raise; it is kept as a string, not float().
        assert meta.get("budget_dollars") == "1.2.3"

    def test_valid_budget_still_coerced(self):
        from maverick.templates import _parse_frontmatter
        meta = _parse_frontmatter("budget_dollars: 2.5\n")
        assert meta.get("budget_dollars") == 2.5
