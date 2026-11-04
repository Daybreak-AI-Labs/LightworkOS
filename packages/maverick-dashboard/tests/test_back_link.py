"""One back link: "← Back to {page}" from one macro, with the arrow hidden."""
from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
# Links that start with "Back to" but are not a way to a parent page: error
# recovery, a date reset, and an empty state owned by the empty-state work.
NOT_PARENT_LINKS = {
    ("500.html", "/"), ("error.html", "/"), ("safety.html", "/safety"),
    ("external_agent_detail.html", "/external-agents"),
}


def _macro(**context):
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape())
    template = env.from_string(
        '{% from "_back_link.html" import back_link with context %}'
        "{{ back_link('/privacy', 'Privacy') }}|{{ back_link('/goals', 'Tasks', 'task-tabs__back') }}")
    return template.render(**context).split("|")


def test_back_link_names_the_parent_and_hides_the_arrow():
    plain, tabs = _macro()
    assert plain == '<a class="back-link" href="/privacy"><span aria-hidden="true">← </span>Back to Privacy</a>'
    assert tabs.startswith('<a class="back-link task-tabs__back" href="/goals">')
    assert tabs.endswith(">Back to Tasks</a>")


def test_back_link_uses_the_page_translation_helper_when_present():
    from maverick_dashboard import i18n_journeys

    plain, _tabs = _macro(ui=lambda source: i18n_journeys.region(source, "fr"))
    assert plain.startswith('<a class="back-link" href="/privacy"><span aria-hidden="true">← </span><span lang=')
    assert ">Back to Privacy</span></a>" in plain  # untranslated copy declares English
    projects = i18n_journeys.region("Back to Projects", "fr")
    assert 'lang="fr"' in str(projects)


def test_parent_links_are_not_hand_written():
    pattern = re.compile(r'<a\b[^>]*href="([^"]*)"[^>]*>\s*(?:←|&larr;|Back to )')
    found = []
    for path in sorted(TEMPLATES.glob("*.html")):
        if path.name == "_back_link.html":
            continue
        for href in pattern.findall(path.read_text(encoding="utf-8")):
            if (path.name, href) not in NOT_PARENT_LINKS:
                found.append((path.name, href))
    assert found == []
