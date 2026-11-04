"""The Tools and Connections pages tell an administrator which
connector tools Enterprise mode refuses, before rollout rather than as a
refused task.

Which tools are refused is decided in ``maverick.tools`` (see
``test_enterprise_unavailable_tools``); the dashboard is exercised here against
that answer rather than by switching the whole deployment into Enterprise mode,
which would also demand dashboard sign-in configuration unrelated to these pages.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

BADGE = "Not available in Enterprise mode yet"


class _Registry:
    def __init__(self, tools):
        self._tools = tools

    def all(self):
        return list(self._tools)


def _tool(name: str, description: str = "A connector") -> SimpleNamespace:
    return SimpleNamespace(name=name, description=description)


def _client(monkeypatch, tmp_path: Path, tools, *, refused: frozenset[str]) -> TestClient:
    """Serve the pages over ``tools``; ``refused`` is what Enterprise mode refuses.

    An empty ``refused`` is standard mode, where nothing is refused.
    """
    home = tmp_path / "maverick-home"
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    for name in ("MAVERICK_AUTH_REQUIRED", "MAVERICK_DASHBOARD_TOKEN",
                 "MAVERICK_ENTERPRISE", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)

    from maverick import config
    from maverick import sandbox as sandbox_module
    from maverick import tools as tools_module
    from maverick_dashboard import app as dashboard_app

    config.reset_config_cache()
    # raising=False: the function is what this change adds, and the assertions
    # below must fail on what the page shows, not on a missing attribute.
    monkeypatch.setattr(tools_module, "enterprise_unavailable_tool_names",
                        lambda: refused, raising=False)
    monkeypatch.setattr(dashboard_app, "_world", lambda: object())
    monkeypatch.setattr(sandbox_module, "build_sandbox", lambda: object())
    monkeypatch.setattr(tools_module, "base_registry", lambda **_kw: _Registry(tools))
    return TestClient(dashboard_app.app, base_url="http://127.0.0.1")


def _rows(html: str) -> dict[str, str]:
    """Map each rendered tool row's display name to its row markup."""
    found = re.findall(r'(?s)<tr class="tool-row">(.*?)</tr>', html)
    return {re.search(r"<td>(.*?)</td>", row).group(1).strip(): row for row in found}


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", html))


def _connections_notice(html: str) -> str:
    """The Enterprise-mode warning paragraph on the Connections page, as text."""
    found = re.findall(r'(?s)<p class="panel" role="note">(While Enterprise mode is on.*?)</p>', html)
    assert len(found) == 1, found
    return _text(found[0]).strip()


CATALOG = [
    _tool("salesforce", "Salesforce SOQL + record CRUD"),
    _tool("servicenow", "ServiceNow Table API"),
    _tool("read_file", "Read a file"),
    _tool("zapier", "Zapier webhook connector"),
]
REFUSED = frozenset({"salesforce", "servicenow"})


def test_enterprise_mode_marks_each_refused_connector_on_its_row(monkeypatch, tmp_path):
    html = _client(monkeypatch, tmp_path, CATALOG, refused=REFUSED).get("/tools").text

    rows = _rows(html)
    assert set(rows) == {"Salesforce", "Servicenow", "Read file", "Zapier"}
    for refused in ("Salesforce", "Servicenow"):
        assert BADGE in rows[refused]
    for usable in ("Read file", "Zapier"):
        assert BADGE not in rows[usable]

    # The same catalog in standard mode carries no marker anywhere.
    standard = _client(monkeypatch, tmp_path, CATALOG, refused=frozenset()).get("/tools").text
    assert len(_rows(standard)) == 4
    assert BADGE not in standard
    assert "Enterprise mode is on" not in standard


def test_enterprise_mode_says_how_many_tools_are_affected(monkeypatch, tmp_path):
    html = _client(monkeypatch, tmp_path, CATALOG, refused=REFUSED).get("/tools").text

    assert ("Enterprise mode is on. 2 tools on this list can't be used by "
            "signed-in people yet") in _text(html)


def test_notice_counts_the_whole_catalog_not_just_the_visible_page(monkeypatch, tmp_path):
    html = _client(monkeypatch, tmp_path, CATALOG, refused=REFUSED).get(
        "/tools", params={"q": "read"}).text

    assert set(_rows(html)) == {"Read file"}
    assert "2 tools on this list can't be used by signed-in people yet" in _text(html)


def test_a_single_refused_tool_reads_naturally(monkeypatch, tmp_path):
    html = _client(monkeypatch, tmp_path, [_tool("salesforce"), _tool("read_file")],
                   refused=REFUSED).get("/tools").text

    assert "1 tool on this list can't be used by signed-in people yet" in _text(html)


def test_notice_appears_only_when_a_listed_tool_is_actually_affected(monkeypatch, tmp_path):
    # Refusals exist, but none of them is on this deployment's list.
    only_usable = [_tool("read_file"), _tool("zapier")]

    with_notice = _client(monkeypatch, tmp_path, CATALOG, refused=REFUSED).get("/tools").text
    without = _client(monkeypatch, tmp_path, only_usable, refused=REFUSED).get("/tools").text

    assert "Enterprise mode is on" in with_notice
    assert BADGE not in without
    assert "Enterprise mode is on" not in without


def test_connections_page_warns_that_enterprise_mode_refuses_those_connector_tools(
        monkeypatch, tmp_path):
    html = _client(monkeypatch, tmp_path, CATALOG, refused=REFUSED).get("/connections").text

    assert "While Enterprise mode is on, workflows run by signed-in people can't use" in _text(html)
    assert "including Salesforce, ServiceNow, even with a saved connection" in _text(html)
    assert 'href="/tools"' in html

    # Standard mode: the page still works and carries no warning.
    standard = _client(monkeypatch, tmp_path, CATALOG, refused=frozenset()).get("/connections").text
    assert 'id="cx-form"' in standard or 'data-module-gate="connections"' in standard
    assert "While Enterprise mode is on" not in standard


def test_connections_warning_names_only_the_systems_that_are_really_refused(
        monkeypatch, tmp_path):
    # Once Salesforce has moved onto saved connections it must not be named.
    html = _client(monkeypatch, tmp_path, CATALOG, refused=frozenset({"workday", "jira", "zoom"})
                   ).get("/connections").text

    notice = _connections_notice(html)
    assert "including Workday, Jira, even with a saved connection" in notice
    assert "Salesforce" not in notice

    # A refused connector that is not one of the well-known names: warn, name none.
    other = _client(monkeypatch, tmp_path, CATALOG, refused=frozenset({"zoom"})).get("/connections").text
    assert "can't use the connector tools" in _connections_notice(other)
    assert "including" not in _connections_notice(other)
