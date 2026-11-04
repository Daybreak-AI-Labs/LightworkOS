"""Chrome i18n (fr/de/ja/zh) + accessibility font axis (dyslexia-friendly)."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard import i18n
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


def test_catalog_complete_for_all_languages():
    # Seed languages (community-contributed, intentionally partial) are
    # exempt from full coverage; t() falls back to English for their gaps.
    for key, entry in i18n.MESSAGES.items():
        for lang in i18n.LANGS:
            if lang in i18n.SEED_LANGS:
                continue
            assert entry.get(lang), f"{key} missing {lang}"


def test_t_fallbacks():
    assert i18n.t("nav.goals", "fr") == "Objectifs"
    assert i18n.t("nav.goals", "xx") == "Goals"   # unknown lang -> en
    assert i18n.t("nope.key", "fr") == "nope.key"  # unknown key -> key


def test_lang_resolution_param_cookie_header():
    class _Req:
        def __init__(self, q=None, c=None, h=None):
            self.query_params = {"lang": q} if q else {}
            self.cookies = {"mvk_lang": c} if c else {}
            self.headers = {"Accept-Language": h} if h else {}

    assert i18n.resolve_lang(_Req(q="ja")) == "ja"
    assert i18n.resolve_lang(_Req(c="de")) == "de"
    assert i18n.resolve_lang(_Req(h="zh-CN,zh;q=0.9")) == "zh"
    assert i18n.resolve_lang(_Req(h="ar-SA,ar;q=0.9")) == "en"
    assert i18n.resolve_lang(_Req(h="ar-SA,fr-CA;q=0.9")) == "fr"
    assert i18n.resolve_lang(_Req(q="ar", h="fr-CA")) == "ar"
    assert i18n.resolve_lang(_Req(c="ar", h="fr-CA")) == "ar"
    assert i18n.resolve_lang(_Req()) == "en"
    assert i18n.resolve_lang(_Req(q="xx", h="pt-BR")) == "en"


def test_lang_param_translates_chrome_and_sets_cookie():
    # Use a non-redirecting page: ``/`` may send an unconfigured deployment
    # through onboarding, where the cookie is correctly set on the 303 rather
    # than repeated on the final ``/start`` response.
    r = client.get("/overview", params={"lang": "fr"})
    assert r.status_code == 200
    # The page body is English, so <html lang> says so; the chrome
    # strings that ARE translated carry their own lang attribute.
    assert '<html lang="en" dir="ltr">' in r.text
    assert '<html lang="fr"' not in r.text
    assert 'lang="fr">Aller au contenu</a>' in r.text
    assert 'lang="fr">Police</span>' in r.text
    # The footer is the product name only; no untranslated chrome is left in it.
    assert '<span class="muted">Lightwork by Daybreak Labs</span>' in r.text
    assert "mvk_lang=fr" in r.headers.get("set-cookie", "")
    r2 = client.get("/overview", params={"lang": "ja"})
    assert '<html lang="en" dir="ltr">' in r2.text
    assert 'lang="ja">コンテンツへスキップ</a>' in r2.text
    # English selection: chrome and explicit journey regions declare English.
    r3 = client.get("/overview", params={"lang": "en"})
    assert '<html lang="en" dir="ltr">' in r3.text
    assert 'lang="en" dir="ltr" data-product-copy>Interface language</span>' in r3.text


def test_rtl_selection_declares_the_english_body_left_to_right():
    """``dir`` describes the body like ``lang`` does. An English body
    must not be mirrored because a few chrome strings were translated."""
    r = client.get("/overview", params={"lang": "ar"})
    assert r.status_code == 200
    assert '<html lang="en" dir="ltr">' in r.text
    assert 'lang="ar">تخطي إلى المحتوى</a>' in r.text


def test_arabic_browser_gets_a_left_to_right_english_page_on_both_shells():
    """Accept-Language alone must not flip the English UI right-to-left
    on the product shell (``/overview``) or the chat shell (``/chat``)."""
    fresh = TestClient(app, base_url="http://127.0.0.1")
    for path in ("/overview", "/chat"):
        r = fresh.get(path, headers={"Accept-Language": "ar-SA,ar;q=0.9"})
        assert r.status_code == 200, path
        assert '<html lang="en" dir="ltr">' in r.text, path
        assert 'lang="ar">تخطي إلى المحتوى</a>' not in r.text, path
        assert 'lang="en" dir="ltr" data-product-copy' in r.text, path


def test_arabic_browser_keeps_public_owner_sign_in_left_to_right(monkeypatch):
    from maverick_dashboard import local_owner

    monkeypatch.setattr(local_owner, "_local", lambda *args, **kwargs: None)
    monkeypatch.setattr(local_owner, "claimed", lambda: False)
    monkeypatch.setattr(local_owner, "available", lambda request: True)
    with TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 53210),
                    follow_redirects=False) as fresh:
        response = fresh.get("/auth/local-owner", headers={"Accept-Language": "ar-SA,ar;q=0.9"})
    assert response.status_code == 200
    assert '<html lang="en" dir="ltr">' in response.text
    assert "Set up the owner of this installation" in response.text


def test_auto_detected_languages_have_complete_catalogs():
    assert frozenset({"en", "fr", "de", "ja", "zh"}) == i18n.AUTO_LANGS
    assert all(entry.get(lang) for lang in i18n.AUTO_LANGS for entry in i18n.MESSAGES.values())


def test_content_lang_declares_only_translated_bodies():
    assert i18n.content_lang("en") == "en"
    for lang in ("fr", "de", "ja", "zh", "ar"):
        assert i18n.content_lang(lang) == "en"
    assert frozenset({"en"}) == i18n.CONTENT_LANGS


def test_language_selector_is_not_rendered():
    """Removed from the chrome and the Settings appearance form until the
    navigation is actually translated; ``?lang=`` keeps working server-side."""
    r = client.get("/")
    assert r.status_code == 200
    assert "navigation preview" not in r.text
    assert "language-preview-note" not in r.text
    s = client.get("/settings")
    assert 'name="lang"' not in s.text
    assert "Language previews" not in s.text


def test_font_axis_cookie_and_body_class():
    r = client.get("/overview", params={"font": "dyslexic"})
    assert r.status_code == 200
    assert "font-dyslexic" in r.text
    assert "mvk_font=dyslexic" in r.headers.get("set-cookie", "")
    # Bogus values are ignored (no cookie, default class) -- fresh client so
    # the previous request's cookie doesn't mask the fallback.
    fresh = TestClient(app, base_url="http://127.0.0.1")
    r2 = fresh.get("/overview", params={"font": "comic"})
    assert "mvk_font" not in r2.headers.get("set-cookie", "")
    assert 'font-default' in r2.text


def test_font_and_theme_compose():
    r = client.get("/", params={"font": "dyslexic", "theme": "hicontrast"})
    assert "theme-hicontrast" in r.text and "font-dyslexic" in r.text
