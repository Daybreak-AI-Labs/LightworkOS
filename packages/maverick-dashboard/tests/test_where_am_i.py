"""Every page says where it is: a page kept out of the sidebar
highlights the sidebar page it sits under and shows a breadcrumb, in the
classic sidebar too."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import ui_visibility


def _folded():
    return [page["path"] for page in ui_visibility.PAGES
            if not page.get("in_nav", True) and ui_visibility.customer_ready(page)]


def test_every_page_kept_out_of_the_sidebar_has_a_sidebar_parent():
    in_nav = {page["path"] for page in ui_visibility.PAGES if page.get("in_nav", True)}
    for path in _folded():
        spot = ui_visibility.PAGE_AREAS.get(path)
        if spot and spot[0] in {"Account", "Help"}:
            continue  # reached from the top bar's menus
        candidates = ui_visibility.parent_candidates(path)
        assert candidates and set(candidates) <= in_nav, path


def test_an_administrator_sees_where_every_folded_page_sits():
    groups, finder = ui_visibility.nav_groups("admin"), ui_visibility.finder_pages("admin")
    visible = {link["href"] for group in groups for link in group["links"]}
    missing = []
    for path in _folded():
        if path in {"/account", "/help"}:
            continue  # the top bar's own pages: marked current there
        where = ui_visibility.where(path, groups, finder)
        if where is None:
            missing.append(path)
        elif where["sidebar"]:
            assert where["parent"]["href"] in visible, path
    assert missing == []


def test_a_sidebar_page_needs_no_breadcrumb():
    groups, finder = ui_visibility.nav_groups("admin"), ui_visibility.finder_pages("admin")
    assert ui_visibility.where("/goals", groups, finder) is None


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api, app, auth

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:customer")
    config.reset_config_cache()
    api._world_cache.clear()
    from maverick_dashboard import rbac
    rbac.set_role("user:customer", "admin")
    yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    api._world_cache.clear()


def test_a_folded_page_highlights_its_parent_and_shows_a_breadcrumb(client):
    page = client.get("/billing").text
    sidebar = page.split('id="sidebar"', 1)[1].split("</aside>", 1)[0]
    assert re.search(r'<a href="/spend" class="active nav-parent" aria-current="true"', sidebar)
    assert 'aria-current="page"' not in sidebar, "the parent is not the current page"
    crumbs = re.search(r'<nav class="where-crumbs"[^>]*>(.*?)</nav>', page, re.DOTALL).group(1)
    assert 'href="/spend"' in crumbs and re.search(r'<span aria-current="page">(<span[^>]*>)?Billing', crumbs)


def test_the_chat_shell_shows_where_a_folded_chat_page_sits(client):
    page = client.get("/conversations").text
    assert '<nav class="where-crumbs"' in page
    assert re.search(r'<a href="/chat" class="active nav-parent" aria-current="true"', page)


def test_account_pages_lead_back_to_the_account_page_and_mark_the_top_bar(client):
    page = client.get("/devices").text
    crumbs = re.search(r'<nav class="where-crumbs"[^>]*>(.*?)</nav>', page, re.DOTALL).group(1)
    assert 'href="/account"' in crumbs
    assert 'class="active nav-parent"' not in page, "the account pages live in the top bar, not the sidebar"
    account = client.get("/account").text
    assert re.search(r'<a class="iconbtn" href="/account" aria-current="page"', account)
