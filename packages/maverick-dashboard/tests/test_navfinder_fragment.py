"""The page finder's destinations are served by GET /nav/finder on first open
instead of being embedded (81 KB) in every page."""
from __future__ import annotations

from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient

# Their routes also need a named account, which the local owner does not have.
NAMED_ACCOUNT_PAGES = {"/notifications", "/access-requests", "/devices", "/get-started/employee",
                       "/human-conversations"}


class _Items(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.options: list[dict[str, str | None]] = []
        self.list_items = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag == "li":
            self.list_items += 1
        if tag == "a" and "data-navfinder-target" in values:
            self.options.append(values)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    dashboard_app._world_cache.clear()
    return TestClient(dashboard_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_fragment_lists_the_finder_registry_with_the_listbox_contract(client, monkeypatch):
    from maverick_dashboard import employee_companion_api, ui_visibility

    # This contract checks the full registry when both companion destinations
    # are available; availability filtering is qualified separately below.
    monkeypatch.setattr(employee_companion_api, "navigation_available", lambda request, admin=False: True)

    response = client.get("/nav/finder")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "private, max-age=60"
    assert "<dialog" not in response.text and "<ul" not in response.text
    items = _Items()
    items.feed(response.text)
    expected = [ln["href"] for g in ui_visibility.finder_pages(None) for ln in g["links"]
                if ln["href"] not in NAMED_ACCOUNT_PAGES]
    assert [o["href"] for o in items.options] == expected
    assert items.list_items == len(expected)
    for option in items.options:
        assert option["role"] == "option"
        assert option["tabindex"] == "-1"
        assert option["aria-selected"] == "false"
        assert option["id"].startswith("navfinder-option-")
        assert option["data-search"]


@pytest.mark.parametrize("personal_available", [False, True])
def test_fragment_excludes_unavailable_companion_destinations(client, monkeypatch, personal_available):
    from maverick_dashboard import employee_companion_api, ui_visibility

    monkeypatch.setattr(
        employee_companion_api,
        "navigation_available",
        lambda request, admin=False: personal_available and not admin,
    )
    response = client.get("/nav/finder")
    assert response.status_code == 200
    items = _Items()
    items.feed(response.text)
    unavailable = {"/companion/admin", *NAMED_ACCOUNT_PAGES}
    if not personal_available:
        unavailable.add("/companion")
    expected = [
        link["href"] for group in ui_visibility.finder_pages(None) for link in group["links"]
        if link["href"] not in unavailable
    ]
    assert [option["href"] for option in items.options] == expected


def test_fragment_revalidates_by_etag(client):
    first = client.get("/nav/finder")
    etag = first.headers["etag"]
    again = client.get("/nav/finder", headers={"If-None-Match": etag})
    assert again.status_code == 304 and again.content == b""
    assert client.get("/nav/finder", headers={"If-None-Match": '"other"'}).status_code == 200


def test_pages_no_longer_embed_the_destination_list(client):
    page = client.get("/overview")
    assert page.status_code == 200
    assert 'id="navfinder-dialog"' in page.text  # the accessible shell stays inline
    assert 'data-navfinder-src="/nav/finder"' in page.text
    assert "data-navfinder-target" not in page.text
