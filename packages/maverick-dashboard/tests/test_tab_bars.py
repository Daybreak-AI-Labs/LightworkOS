"""One tab bar: every page's tabs come from templates/_tabs.html.

Pages used to carry their own tab bars (settings, security and privacy record
tabs, the Learning sections, the task filter, the workspace worklist filter,
the board time range, the consent and data-use sub-navigation and the task
page strip), each with its own script, roles and keys. They now render the
shared macros: ``panel_tabs`` (buttons in a ``role=tablist`` whose arrow
keys come from static/lightwork-tabs.js), ``tab_bar`` (link tabs) and
``sub_nav`` (a ``nav`` of sibling pages). These checks render each page and
hold the structure the shared script and assistive technology rely on; the
keys themselves are tested per page in tests/js (security_tabs,
settings_first_paint, board_request_lifecycle, tab_bars_pages, tabs).
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import static_url

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
_ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers=_ORIGIN)


class _Page(HTMLParser):
    """Elements by id, and each tab list with its tabs (in order)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids: dict[str, dict[str, str]] = {}
        self.lists: list[dict] = []
        self.navs: list[dict] = []
        self._open: list[tuple[str, dict | None]] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if "id" in a:
            self.ids[a["id"]] = {**a, "_tag": tag}
        owner = None
        if a.get("role") == "tablist":
            owner = {"attrs": a, "tabs": []}
            self.lists.append(owner)
        elif tag == "nav" and "mv-tabs--nav" in a.get("class", ""):
            owner = {"attrs": a, "links": []}
            self.navs.append(owner)
        elif a.get("role") == "tab" and self.lists:
            self.lists[-1]["tabs"].append({**a, "_tag": tag})
        elif tag == "a" and self.navs and self._inside(self.navs[-1]):
            self.navs[-1]["links"].append(a)
        if tag not in ("input", "br", "img", "meta", "link", "hr", "source", "wbr", "col", "area"):
            self._open.append((tag, owner))

    def _inside(self, owner):
        return any(o is owner for _, o in self._open)

    def handle_endtag(self, tag):
        for i in range(len(self._open) - 1, -1, -1):
            if self._open[i][0] == tag:
                del self._open[i:]
                break


def _parse(html: str) -> _Page:
    page = _Page()
    page.feed(html)
    return page


def _check_panel_tabs(html: str, page: _Page, path: str) -> int:
    panel_lists = [lst for lst in page.lists if lst["attrs"].get("data-mv-tabs") == "panels"]
    for lst in panel_lists:
        tabs = lst["tabs"]
        label = lst["attrs"].get("aria-label")
        assert label and tabs, (path, lst["attrs"])
        assert "mv-tabs" in lst["attrs"].get("class", "").split(), (path, label)
        selected = [t for t in tabs if t.get("aria-selected") == "true"]
        assert len(selected) == 1, (path, label, "exactly one selected tab")
        for tab in tabs:
            assert tab["_tag"] == "button" and tab.get("type") == "button", (path, label)
            assert "mv-tab" in tab.get("class", "").split(), (path, label)
            assert tab.get("id") and tab.get("data-mv-tab"), (path, label)
            assert "aria-pressed" not in tab, (path, label, "a tab is selected, not pressed")
            assert tab.get("tabindex") == ("0" if tab is selected[0] else "-1"), (path, label, tab["id"])
            controls = tab.get("aria-controls")
            if controls is None:
                continue
            panel = page.ids.get(controls)
            assert panel is not None, (path, label, f"{tab['id']} controls a missing #{controls}")
            assert panel.get("role") == "tabpanel", (path, label, controls)
            shared = sum(1 for t in tabs if t.get("aria-controls") == controls) > 1
            if shared:
                assert panel.get("aria-labelledby") == selected[0]["id"], (path, label, controls)
            else:
                assert panel.get("aria-labelledby") == tab["id"], (path, label, controls)
                assert ("hidden" in panel) == (tab is not selected[0]), (path, label, controls)
    if panel_lists:
        assert f'<script src="{static_url("lightwork-tabs.js")}" defer></script>' in html, path
    return len(panel_lists)


@pytest.mark.parametrize(("path", "labels"), [
    ("/security", {"Security record types", "Filter worklist"}),
    ("/privacy", {"Record types", "Estate registers", "Filter worklist"}),
    ("/finance", {"Filter worklist"}),
    ("/settings", {"Settings sections"}),
    ("/learning", {"Learning sections"}),
    ("/overview", {"Time range"}),
    ("/oversight", {"Time range"}),
    ("/savings", {"Time range"}),
    ("/spend", {"Time range"}),
    ("/workforce", {"Time range"}),
])
def test_each_page_tab_bar_is_the_shared_panel_tab_bar(path, labels):
    from maverick_dashboard.app import _world
    _world().create_goal("Summarize vendor contracts", "Summarize the top five vendor contracts")  # the overview board shows once work exists
    html = _client().get(path).text
    page = _parse(html)
    assert _check_panel_tabs(html, page, path) == len(page.lists), path
    assert {lst["attrs"]["aria-label"] for lst in page.lists} == labels


def test_the_task_filter_is_a_tab_bar_over_the_task_list_and_opens_on_the_filter_in_the_address():
    from maverick_dashboard.app import _world
    _world().create_goal("Summarize vendor contracts", "Summarize the top five vendor contracts")
    client = _client()
    for query, chosen in (("", "all"), ("?status=failed", "failed"), ("?status=waiting", "waiting"), ("?status=bogus", "all")):
        html = client.get("/goals" + query).text
        page = _parse(html)
        assert _check_panel_tabs(html, page, "/goals" + query) == 1
        tabs = page.lists[0]["tabs"]
        assert [t["data-mv-tab"] for t in tabs] == ["all", "running", "waiting", "failed", "done"]
        assert [t["data-g-filter"] for t in tabs] == ["", "running active pending", "blocked awaiting_approval", "failed", "done"]
        assert {t.get("aria-controls") for t in tabs} == {"run-list"}
        assert [t["data-mv-tab"] for t in tabs if t["aria-selected"] == "true"] == [chosen], query


def test_the_board_time_range_selects_on_request_and_controls_no_single_panel():
    html = _client().get("/spend").text
    tabs = _parse(html).lists[0]
    assert tabs["attrs"].get("data-mv-tabs-activation") == "manual"
    assert [t["data-days"] for t in tabs["tabs"]] == ["30", "90", "180", "365"]
    assert all("aria-controls" not in t for t in tabs["tabs"])
    assert [t["data-days"] for t in tabs["tabs"] if t["aria-selected"] == "true"] == ["90"]


def test_security_record_tabs_keep_their_address():
    tabs = _parse(_client().get("/security").text).lists
    record = next(lst for lst in tabs if lst["attrs"]["aria-label"] == "Security record types")
    assert record["attrs"].get("data-mv-tabs-hash") == "sec-"
    assert record["tabs"][0]["id"] == "sec-tab-controls"


@pytest.mark.parametrize(("path", "label", "current"), [
    ("/consent", "Consent tools", "/consent"),
    ("/consent/delivery", "Consent tools", "/consent/delivery"),
    ("/data-use", "Data use tools", "/data-use"),
    ("/data-use/providers", "Data use tools", "/data-use/providers"),
])
def test_sibling_pages_share_the_sub_nav_bar(path, label, current):
    page = _parse(_client().get(path).text)
    assert not page.lists, "sibling pages are links, not a tab list"
    (nav,) = page.navs
    assert nav["attrs"].get("aria-label") == label
    assert all("mv-tab" in a.get("class", "").split() for a in nav["links"])
    assert [a["href"] for a in nav["links"] if a.get("aria-current") == "page"] == [current]


def test_task_pages_share_the_sub_nav_bar():
    from maverick_dashboard.app import _world
    w = _world()
    gid = w.create_goal("Summarize vendor contracts", "Summarize the top five vendor contracts")
    client = _client()
    for path in (f"/chat/goal/{gid}", f"/goals/{gid}/trajectory", f"/goals/{gid}/plan", f"/goals/{gid}/errors"):
        page = _parse(client.get(path).text)
        (nav,) = [n for n in page.navs if n["attrs"].get("aria-label") == "Task pages"]
        assert [a["href"] for a in nav["links"]] == [f"/chat/goal/{gid}", f"/goals/{gid}/trajectory",
                                                    f"/goals/{gid}/plan", f"/goals/{gid}/errors"]
        assert [a["href"] for a in nav["links"] if a.get("aria-current") == "page"] == [path]


_RETIRED = re.compile(r'class="[^"]*\b(bd-slicer|cw-nav|cw-nav__group|task-tabs__list|task-tabs__on|settings-tabs|sec-tab|pe-tab|pw-tab|lrn__tabs)\b')


def test_no_page_keeps_its_own_tab_bar():
    """Tab markup lives only in _tabs.html, and the retired classes and their
    styles are gone."""
    stray, retired = [], []
    for path in sorted(PACKAGE.glob("templates/*.html")):
        if path.name == "_tabs.html":
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r'role="tab(list)?"|class="mv-tabs?\b', text):
            stray.append(path.name)
        if _RETIRED.search(text):
            retired.append(path.name)
    assert stray == [], "Use panel_tabs, tab_bar or sub_nav from _tabs.html: " + ", ".join(stray)
    assert retired == [], ", ".join(retired)
    css = "\n".join(p.read_text(encoding="utf-8") for p in PACKAGE.glob("static/*.css"))
    for name in ("bd-slicer", "cw-nav", "task-tabs__", "settings-tabs", "lrn__tabs", ".sec-tab", ".pe-tab", ".pw-tab"):
        assert name not in css, name
    # Their keys are the shared script's: no page script handles them itself.
    for name in ("security.html", "privacy.html", "settings.html", "learning.html", "goals.html",
                 "_workspace_memory_catalog.html"):
        assert "ArrowRight" not in (PACKAGE / "templates" / name).read_text(encoding="utf-8"), name
    assert "ArrowRight" not in (PACKAGE / "static" / "board.js").read_text(encoding="utf-8")
