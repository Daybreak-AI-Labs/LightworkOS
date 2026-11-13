"""Partial catalogs must never mislabel English or alter source/user content."""
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick_dashboard import auth, i18n, i18n_journey_workflow, i18n_journeys, preferences_api


def test_selected_journey_bindings_have_actual_catalog_entries():
    report = runpy.run_path(str(Path(__file__).resolve().parents[3] / "scripts" / "journey_i18n_coverage.py"))["report"]()
    assert report["catalog_sources"] == len(i18n_journeys.messages()), "An inventoried catalog is not wired into the product"
    missing = {name: page["bound_sources_missing_catalog"] for name, page in report["pages"].items()
               if page["bound_sources_missing_catalog"]}
    assert missing == {}, f"Bound journey controls still fall back to English: {missing}"


def test_action_search_placeholder_is_translated_not_borrowed_from_another_message():
    rows = {source: dict(zip(i18n_journeys.TRANSLATION_LANGS, translations, strict=True))
            for source, *translations in i18n_journey_workflow.ROWS}
    search = rows["Search actions by name or description…"]
    # Every language renders a search prompt, and none reuses the spending-limit validation text.
    assert search["zh"] == "按名称或说明搜索操作…"
    limit = rows["Enter a spending limit of $0 or more with at most two decimal places, or leave it empty for no limit."]
    assert all("支出" not in text and "限" not in text for text in (search["zh"], search["ja"])) and "limit" not in search["fr"].lower()
    assert search["zh"] != limit["zh"]


def request(*, query="", accept="", cookies=None):
    return SimpleNamespace(query_params={"lang": query}, headers={"Accept-Language": accept},
                           cookies=cookies or {}, state=SimpleNamespace())


def test_quality_and_region_match_actual_preference(monkeypatch):
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    monkeypatch.setattr(preferences_api, "resolved_display", lambda *args: None)
    req = request(accept="ja;q=0,fr-CA;q=0.4,de-DE;q=0.9,zh;q=bogus")
    assert i18n.resolve_lang(req) == "de"
    assert i18n_journeys.locale_for(req, "de") == "de-DE"
    assert i18n.resolve_lang(request(query="fr-CA")) == "fr"
    assert i18n_journeys.locale_for(request(query="fr-CA"), "fr") == "fr-CA"


def test_account_interface_language_is_independent_and_query_cannot_override(monkeypatch):
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(preferences_api, "resolved_display", lambda request, key: {"language": "ja", "interface_language": "fr"}[key])
    assert i18n.resolve_lang(request(query="de")) == "fr"
    assert i18n_journeys.locale_for(request(query="fr-CA", accept="fr-FR"), "fr") == "fr-FR"
    monkeypatch.setattr(preferences_api, "resolved_display", lambda request, key: {"language": "ja", "interface_language": ""}[key])
    assert i18n.resolve_lang(request()) == "ja"


def test_arabic_seed_remains_partial_and_draft_regions_are_honest():
    assert frozenset({"en"}) == i18n.CONTENT_LANGS
    assert all("ar" not in row for key, row in i18n.MESSAGES.items() if key.startswith("journey."))
    assert 'lang="en"' in str(i18n_journeys.region("Save private draft", "ar"))
    assert 'lang="fr"' in str(i18n_journeys.region("Save private draft", "fr"))
    assert 'lang="en"' in str(i18n_journeys.region("Untranslated product text", "fr"))


def test_interpolation_cannot_add_html_or_change_user_text():
    value = '<img src=x onerror=alert(1)>مرحبا'
    result = str(i18n_journeys.region("Showing {start}–{end} of {total}", "fr", start=value, end=2, total=3))
    assert '<img' not in result
    assert '&lt;img src=x onerror=alert(1)&gt;مرحبا' in result
    assert '<bdi lang="und" dir="auto">' in result
    with pytest.raises(KeyError):
        i18n_journeys.region("Showing {start}–{end} of {total}", "fr", start=1)


def test_placeholder_names_do_not_collide_with_translation_arguments(monkeypatch):
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    helpers = i18n_journeys.context(request(), "fr")
    value = '<img src=x onerror=alert(1)>'
    rendered = str(helpers["ui"]("Source: {source}", source=value))
    assert '<img' not in rendered and '&lt;img' in rendered
    assert helpers["ut"]("Source: {source}", source="private preference").endswith("private preference")
    assert i18n_journeys.text("{source}: {lang}", "en", source="account", lang="French") == "account: French"


def test_native_preferences_page_renders_memory_source(monkeypatch):
    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        response = client.get("/preferences")
    assert response.status_code == 200, response.text[:500]
    assert 'data-product-copy' in response.text and 'Source:' in response.text


def test_display_language_legacy_key_does_not_change_response_preferences(monkeypatch):
    saved = []
    monkeypatch.setattr(preferences_api, "_app", lambda: SimpleNamespace(_require_same_origin=lambda request: None))
    monkeypatch.setattr(auth, "require_permission", lambda *args: None)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(preferences_api, "_check_display", lambda *args: None)
    monkeypatch.setattr(preferences_api, "context_for", lambda request: "ctx")
    monkeypatch.setattr(preferences_api.preferences, "enabled", lambda: True)
    monkeypatch.setattr(preferences_api.preferences, "state", lambda principal: {"locked": []})
    monkeypatch.setattr(preferences_api.preferences, "save", lambda *args, **kwargs: saved.append(kwargs) or {"revision": "next"})
    preferences_api.display_preference(request(), preferences_api.DisplayUpdate(key="language", value="fr", context="ctx", expected_revision="old"))
    assert saved[0]["changes"] == {"interface_language": "fr"}


def test_browser_override_stays_bound_to_account_and_policy(monkeypatch):
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(preferences_api, "context_for", lambda request: "alice-workspace")
    monkeypatch.setattr(preferences_api.preferences, "enabled", lambda: True)
    monkeypatch.setattr(preferences_api.preferences, "state", lambda principal: {"locked": [], "values": {"interface_language": "de"}})
    assert preferences_api.resolved_display(request(cookies={"mvk_lang": "fr", "mvk_pref_context": "bob-workspace"}), "interface_language") == "de"
    assert preferences_api.resolved_display(request(cookies={"mvk_lang": "fr", "mvk_pref_context": "alice-workspace"}), "interface_language") == "fr"
    monkeypatch.setattr(preferences_api.preferences, "state", lambda principal: {"locked": ["interface_language"], "values": {"interface_language": "ja"}})
    assert preferences_api.resolved_display(request(cookies={"mvk_lang": "fr", "mvk_pref_context": "alice-workspace"}), "interface_language") == "ja"


def test_unverified_error_display_never_reuses_account_cookies(monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setattr(auth, "caller_principal", lambda request: None)

    def unverified(request):
        raise HTTPException(401, "authenticated identity required")

    monkeypatch.setattr(preferences_api, "context_for", unverified)
    req = request(cookies={"mvk_pref_context": "another-account", "mvk_lang": "fr", "mvk_text_size": "larger"})
    assert preferences_api.resolved_display(req, "interface_language", "en") == "en"
    context = preferences_api.display_context(req)
    assert context["display_preference_context"] == ""
    assert context["display_text_size"] == "standard"
    assert context["display_signed_in"] is False


def test_display_options_are_text_and_custom_theme_names_stay_verbatim(monkeypatch):
    from html.parser import HTMLParser

    from maverick_dashboard import app

    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    context = i18n_journeys.context(request(accept="fr-CA"), "fr")
    rendered = app.templates.env.get_template('_display_preferences.html').render(
        **context, lang="fr", page_lang="en", t=lambda key: i18n.t(key, "fr"),
        display_signed_in=False, display_interface_language="fr", display_text_size="standard",
        theme="Save", font="default", density="comfortable", custom_theme_names=["Save"])

    class Options(HTMLParser):
        def __init__(self):
            super().__init__()
            self.active = False
            self.nested = []

        def handle_starttag(self, tag, attrs):
            if self.active:
                self.nested.append(tag)
            if tag == "option":
                self.active = True

        def handle_endtag(self, tag):
            if tag == "option":
                self.active = False

    parsed = Options()
    parsed.feed(rendered)
    assert not parsed.nested
    assert '<option value="Save" lang="und" dir="auto" data-user-content selected>Save</option>' in rendered
    assert 'lang="fr">Sombre</option>' in rendered


def test_a_plain_region_is_looked_up_once_and_renders_as_before(monkeypatch):
    # A page renders about 200 regions; each hashed its text and searched the
    # catalog again (2-3.5 ms a page).
    from markupsafe import Markup, escape

    calls = []
    real = i18n_journeys.entry
    monkeypatch.setattr(i18n_journeys, "entry", lambda source, lang: calls.append(source) or real(source, lang))
    for _ in range(3):
        i18n_journeys.region("Save private draft", "fr")
    assert len(calls) <= 1  # once, or not at all if an earlier render cached it
    for source, *_ in i18n_journeys.ROWS:
        for lang in ("en", "ar", *i18n_journeys.TRANSLATION_LANGS):
            value, actual = real(source, lang)
            expected = Markup('<span lang="{}" dir="{}" data-product-copy>{}</span>').format(
                actual, "rtl" if actual == "ar" else "ltr", escape(value))
            assert i18n_journeys.region(source, lang) == expected


def test_trusted_markup_never_answers_for_plain_text():
    from markupsafe import Markup

    trusted = i18n_journeys.region(Markup("<b>Not in the catalog</b>"), "en")
    plain = i18n_journeys.region("<b>Not in the catalog</b>", "en")
    assert "<b>" in str(trusted)
    assert "<b>" not in str(plain) and "&lt;b&gt;" in str(plain)


def test_a_source_repeated_across_tables_has_one_translation_per_language():
    # The loader keeps the first row of a repeated source, so a later table
    # that disagrees would be silently ignored.
    first, conflicts = {}, {}
    for source, *translations in i18n_journeys.ROWS:
        if first.setdefault(source, translations) != translations:
            conflicts[source] = (first[source], translations)
    assert conflicts == {}, "Tables give different translations for the same source"
