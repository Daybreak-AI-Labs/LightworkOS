"""RTL language support: dir attribute, logical CSS, and the Arabic
community-seed catalog (genuinely translated subset, English fallback)."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard import i18n
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


def test_rtl_lang_set_covers_the_four_scripts():
    assert {"ar", "he", "fa", "ur"} <= set(i18n.RTL_LANGS)
    for code in ("ar", "he", "fa", "ur", "ar-EG"):
        assert i18n.dir_for(code) == "rtl"
    for code in ("en", "fr", "de", "ja", "zh", "", None):
        assert i18n.dir_for(code or "") == "ltr"


def test_arabic_selection_keeps_the_english_body_left_to_right():
    """The page body is English, so ``<html>`` declares ``en`` and
    ``ltr``; only the translated chrome strings carry ``lang="ar"``."""
    r = client.get("/goals", params={"lang": "ar"})
    assert r.status_code == 200
    assert '<html lang="en" dir="ltr">' in r.text
    assert 'lang="ar"' in r.text  # the translated chrome strings
    assert "mvk_lang=ar" in r.headers.get("set-cookie", "")


def test_direction_flips_once_the_body_is_translated(monkeypatch):
    """``dir`` follows the body language: when a right-to-left language enters
    CONTENT_LANGS (its templates exist), the page flips with it."""
    monkeypatch.setattr(i18n, "CONTENT_LANGS", frozenset({"en", "ar"}))
    fresh = TestClient(app, base_url="http://127.0.0.1")
    r = fresh.get("/goals", params={"lang": "ar"})
    assert '<html lang="ar" dir="rtl">' in r.text
    r2 = fresh.get("/goals", params={"lang": "fr"})
    assert '<html lang="en" dir="ltr">' in r2.text


def test_ltr_languages_keep_dir_ltr():
    fresh = TestClient(app, base_url="http://127.0.0.1")
    r = fresh.get("/goals", params={"lang": "fr"})
    assert 'lang="fr"' in r.text and 'dir="ltr"' in r.text
    r2 = fresh.get("/goals", params={"lang": "en"})
    assert 'dir="ltr"' in r2.text


def test_rtl_cookie_persists_the_chrome_language_not_the_direction():
    fresh = TestClient(app, base_url="http://127.0.0.1")
    fresh.get("/", params={"lang": "ar"})  # sets the cookie
    r = fresh.get("/goals")                # no param: cookie drives the chrome
    assert 'lang="ar"' in r.text           # the translated chrome strings
    assert '<html lang="en" dir="ltr">' in r.text


def test_base_layout_uses_logical_properties():
    # the chrome CSS flips with dir instead of hard-coding left/right
    # (the design system ships from the extracted stylesheet)
    css = client.get("/static/lightwork.css").text
    assert "inset-inline-start" in css
    assert "margin-inline-start" in css
    assert "text-align: start" in css


def test_language_control_is_gone_but_lang_param_still_works():
    """The language menu was removed from the chrome (it translated a handful
    of labels, which read as a broken feature); the server-side ``?lang=``
    contract and RTL handling stay for when a real translation ships."""
    home = client.get("/")
    assert 'id="lang-select"' not in home.text
    assert 'data-ui-preference="lang"' not in home.text
    r = client.get("/", params={"lang": "ar"})
    assert '<html lang="en" dir="ltr">' in r.text and 'lang="ar"' in r.text


def test_arabic_seed_is_partial_and_genuine():
    """ar is a community-seed catalog: a handful of real translations,
    English fallback for the rest — never machine-translated to completion."""
    assert "ar" in i18n.SEED_LANGS
    assert "ar" in i18n.LANGS
    # genuinely translated seed keys
    assert i18n.t("nav.goals", "ar") == "الأهداف"
    assert i18n.t("label.language", "ar") == "اللغة"
    assert i18n.t("action.search", "ar") == "بحث"
    # unseeded keys fall back to English, never blank
    assert i18n.t("label.theme", "ar") == "Theme"
    seeded = sum(1 for entry in i18n.MESSAGES.values() if entry.get("ar"))
    assert 0 < seeded < len(i18n.MESSAGES)  # partial by design


def test_arabic_seed_strings_still_resolve_server_side():
    # The chrome no longer renders label.language; the catalog entry itself
    # remains the seed contract for the day the navigation is wired to t().
    assert i18n.t("label.language", "ar") == "اللغة"
