"""Translate authored navigation; preserve actual authority and original content."""
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from maverick_dashboard import i18n, i18n_journeys, ui_visibility

ROOT = Path(__file__).parents[1] / "maverick_dashboard"


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.nodes = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))
        assert len(dict(attrs)) == len(attrs), (tag, attrs)


def render(name, language, **values):
    env = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape())
    request = SimpleNamespace(query_params={}, headers={}, cookies={}, state=SimpleNamespace())
    context = i18n_journeys.context(request, language)
    page_lang = i18n.content_lang(language)
    context.update(lang=language, page_lang=page_lang, dir=i18n.dir_for(page_lang),
                   asset=lambda name: "/static/" + name, t=lambda key: i18n.t(key, language),
                   threads=[], nav_groups=[], finder_pages=[], can_halt=False, can_create_goal=False,
                   custom_theme_names=[], path="/chat")
    context.update(values)
    return env.get_template(name).render(**context)


@pytest.mark.parametrize("lang", ["fr", "de", "ja", "zh"])
def test_every_registered_destination_has_complete_explicit_copy(lang):
    # The registry remains the authority: localization neither adds nor admits links.
    for page in ui_visibility.PAGES:
        label, actual = i18n_journeys.entry(page["label"], lang)
        assert actual == lang, page["path"]
        assert label.strip()
    assert i18n_journeys.messages()  # validates every placeholder in all four languages


@pytest.mark.parametrize("lang", ["fr", "de", "ja", "zh", "ar"])
def test_finder_preserves_exact_authorized_links_and_bilingual_search(lang):
    group = {"label": "Operate", "links": [{"label": "Tasks", "href": "/goals", "aliases": "jobs"}]}
    shell = render("_navfinder.html", lang, record_search_context="owned")
    assert 'data-navfinder-src="/nav/finder"' in shell
    html = render("_navfinder_items.html", lang, finder_pages=[group])
    nodes = Elements(html).nodes
    page = next(attrs for _, attrs in nodes if "data-navfinder-target" in attrs)
    assert page["href"] == "/goals"
    assert "Tasks" in page["data-search"]
    assert i18n_journeys.text("Tasks", lang) in page["data-search"]
    assert "jobs" in page["data-search"]
    assert 'href="/settings"' not in html
    shell_nodes = Elements(shell).nodes
    assert all("lang" in attrs for tag, attrs in shell_nodes if tag == "option" and attrs["value"] not in {"20", "50"})
    assert "<option" in shell and "<option><span" not in shell


@pytest.mark.parametrize("name", ["base.html", "chat_base.html"])
def test_shell_escape_original_titles_and_declare_fallback_language(name):
    original = 'Tasks <img src=x onerror=alert(1)> العربية'
    thread = {"id": 1, "target_id": 1, "title": original, "pinned": True, "archived": True}
    html = render(name, "fr", workspace_tenant_name=original, threads=[thread])
    Elements(html)  # no duplicate HTML attributes
    assert '<img src=x' not in html
    assert 'lang="und" dir="auto" data-user-content>Tasks &lt;img' in html
    if name == "base.html":
        assert 'data-can-halt="false" aria-disabled="true"' in html
        assert 'data-can-halt="true"' not in html
    else:
        assert i18n_journeys.text("Pinned:", "fr") in html
    fallback = render(name, "ar")
    assert '<html lang="en" dir="ltr">' in fallback
    assert 'lang="en" dir="ltr" data-product-copy>Search' in fallback
    assert frozenset({"en"}) == i18n.CONTENT_LANGS


def test_owner_sign_in_shell_keeps_english_body_direction_with_arabic_selection():
    html = render("local_owner.html", "ar", title="Sign in as the local owner",
                  explanation="Use the owner email and passphrase.", message="", setup=False)
    assert '<html lang="en" dir="ltr">' in html
    assert "Use the owner email and passphrase." in html


def test_stop_copy_has_two_distinct_scopes_and_keeps_review_qualification():
    for lang in ("fr", "de", "ja", "zh"):
        local = i18n_journeys.entry("Stop work on this server? Work covered by this emergency stop pauses at its next step and waits for an authorized resume.", lang)
        cluster = i18n_journeys.entry("Stop work across connected workers? Work covered by this emergency stop pauses at its next step and waits for an authorized resume.", lang)
        assert local[1] == cluster[1] == lang
        assert local[0] != cluster[0]
        assert "ar" not in i18n_journeys.messages()[i18n_journeys.key("Stop work")]


@pytest.mark.parametrize("name", ["base.html", "chat_base.html", "recovery_shell.html"])
def test_every_shell_loads_localization_after_its_primary_content(name):
    html = render(name, "fr")
    head, body = html.split("</head>", 1)
    revision, _ = i18n_journeys.browser_catalog_asset("fr")
    catalog = f'<script src="/static/lightwork-i18n-catalog/fr/{revision}.js"'
    runtime = '<script src="/static/lightwork-i18n.js"'
    assert catalog not in head and runtime not in head
    assert body.count(catalog) == body.count(runtime) == 1
    assert body.index("</main>") < body.index(catalog) < body.index(runtime)
