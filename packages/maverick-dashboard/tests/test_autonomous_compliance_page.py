from __future__ import annotations

from html import escape
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick import compliance_catalog as catalog
from maverick.a11y_audit import audit_file
from maverick_dashboard import autonomous_compliance_page as page
from maverick_dashboard import ui_visibility

PACKAGE = Path(page.__file__).resolve().parent
TEMPLATE = PACKAGE / "templates" / "autonomous_compliance.html"


class _CardBadges(HTMLParser):
    """Map each card link's href to the badge classes rendered inside it."""

    def __init__(self) -> None:
        super().__init__()
        self.by_href: dict[str, set[str]] = {}
        self.h1 = 0
        self._href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = dict(attrs)
        if tag == "h1":
            self.h1 += 1
        if tag == "a" and "card" in (d.get("class") or ""):
            self._href = d.get("href")
            self.by_href.setdefault(self._href or "", set())
        if tag == "span" and self._href is not None:
            classes = (d.get("class") or "").split()
            if "badge" in classes:
                self.by_href[self._href].update(c for c in classes if c != "badge")

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self._href = None


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(
        nav_groups=ui_visibility.nav_groups(None),
    )
    return templates


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    app = FastAPI()
    app.include_router(page.create_autonomous_compliance_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_renders_with_one_h1_and_every_suite(client: TestClient) -> None:
    response = client.get(page.PAGE_PATH)
    assert response.status_code == 200
    body = response.text
    parser = _CardBadges()
    parser.feed(body)
    assert parser.h1 == 1
    assert "Autonomous compliance" in body
    for suite in page.visible_suites(catalog.suites(), ui_visibility.not_ready_paths()):
        assert escape(suite.label) in body
        assert f'id="acm-suite-{suite.key}"' in body


def test_every_offered_module_card_carries_the_catalog_badge(client: TestClient) -> None:
    parser = _CardBadges()
    parser.feed(client.get(page.PAGE_PATH).text)
    held = ui_visibility.not_ready_paths()
    offered = 0
    for suite in catalog.suites():
        for module in suite.modules:
            if module.path in held:
                # Held back from customers: the landing must not link into a
                # workbench the sidebar and finder deliberately do not offer.
                assert module.path not in parser.by_href, module.path
                continue
            offered += 1
            assert module.path in parser.by_href, module.path
            expected = catalog.STATUS_BADGE_CLASS[module.status]
            assert expected in parser.by_href[module.path], (module.path, module.status)
    assert offered and len(parser.by_href) == offered


def test_module_cards_use_each_page_s_one_name(client: TestClient) -> None:
    """A card names its page exactly as the sidebar, heading and title do."""

    class Names(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.by_href: dict[str, str] = {}
            self._href: str | None = None
            self._capture = False

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            d = dict(attrs)
            if tag == "a" and "card" in (d.get("class") or ""):
                self._href = d.get("href")
            self._capture = tag == "span" and "acm-card__name" in (d.get("class") or "")

        def handle_data(self, data: str) -> None:
            if self._capture and self._href:
                self.by_href[self._href] = self.by_href.get(self._href, "") + data

        def handle_endtag(self, tag: str) -> None:
            self._capture = False

    names = Names()
    names.feed(client.get(page.PAGE_PATH).text)
    labels = {p["path"]: p["label"] for p in ui_visibility.PAGES}
    registered = {href: name.strip() for href, name in names.by_href.items() if href in labels}
    assert registered and all(name == labels[href] for href, name in registered.items()), registered
    assert names.by_href["/consent/global-opt-out"].strip() == "Opt out everywhere"


def test_visible_suites_drops_held_modules_and_empty_suites() -> None:
    suites = catalog.suites()
    held = frozenset(m.path for m in suites[0].modules) | {suites[1].modules[0].path}
    shown = page.visible_suites(suites, held)
    assert [s.key for s in shown] == [s.key for s in suites[1:]]
    assert shown[0].modules == suites[1].modules[1:]
    assert shown[1:] == list(suites[2:])
    assert page.visible_suites(suites, frozenset()) == list(suites)


def test_labels_note_is_present_and_no_pricing_call(client: TestClient) -> None:
    body = client.get(page.PAGE_PATH).text
    assert "What the labels mean" in body
    for status in catalog.STATUS_ORDER:
        assert catalog.STATUS_LABELS[status] in body
    # The open-source dashboard carries no sales contact or pricing panel.
    assert not hasattr(page, "PRICING_MAILTO")
    assert "Packaging &amp; pricing" not in body
    assert "Contact us about pricing" not in body
    assert "daybreakailabs.com" not in body


def test_nav_entry_is_registered_and_heads_the_govern_group() -> None:
    entry = next(p for p in ui_visibility.PAGES if p["path"] == page.PAGE_PATH)
    assert entry["group"] == "Govern"
    assert entry["floor"] == "view"
    assert entry["default"] == "view"
    # First page in the Govern group in registry order -> top of the nav group.
    govern = [p for p in ui_visibility.PAGES if p["group"] == "Govern"]
    assert govern[0]["path"] == page.PAGE_PATH


def test_nav_entry_renders_in_the_sidebar(client: TestClient) -> None:
    body = client.get(page.PAGE_PATH).text
    assert f'href="{page.PAGE_PATH}"' in body


def test_page_rejects_unknown_query_and_requires_a_template_authority(
    client: TestClient,
) -> None:
    assert client.get(f"{page.PAGE_PATH}?debug=1").status_code == 404
    assert client.get(f"{page.PAGE_PATH}?theme=light").status_code == 200
    with pytest.raises(TypeError):
        page.create_autonomous_compliance_page_router(object())  # type: ignore[arg-type]


def test_template_passes_the_static_a11y_audit() -> None:
    assert audit_file(TEMPLATE) == []


def test_cards_describe_each_module_in_plain_words(client: TestClient) -> None:
    body = client.get(page.PAGE_PATH).text
    for suite in catalog.suites():
        for module in suite.modules:
            assert module.path in page.MODULE_SUMMARIES, module.path
    assert 'class="acm-card__path">/' not in body
    for word in ("Status vocabulary", "compliance catalog", "configuration-ready"):
        assert word not in body
