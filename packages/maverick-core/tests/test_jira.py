"""Tests for the Jira tool (maverick.tools.jira)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- jira tool ----------

def test_jira_requires_op():
    from maverick.tools.jira import jira
    assert "op is required" in jira().fn({})


def test_jira_unknown_op():
    from maverick.tools.jira import jira
    out = jira().fn({"op": "garbage"})
    assert "unknown op" in out or "ERROR" in out


def test_jira_missing_config(monkeypatch):
    monkeypatch.delenv("JIRA_URL", raising=False)
    monkeypatch.delenv("JIRA_USER", raising=False)
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
    fake = types.ModuleType("httpx")
    fake.Client = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.jira import jira
    out = jira().fn({"op": "search", "jql": "project = X"})
    assert "JIRA_URL" in out


def test_jira_create_requires_summary():
    from maverick.tools.jira import jira
    out = jira().fn({"op": "create", "project": "PROJ"})
    assert "project and summary" in out


def test_jira_search_calls_rest(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://x.atlassian.net")
    monkeypatch.setenv("JIRA_USER", "me@x")
    monkeypatch.setenv("JIRA_API_TOKEN", "tok")

    resp = MagicMock()
    resp.json = MagicMock(return_value={
        "issues": [{
            "key": "PROJ-1",
            "fields": {
                "summary": "fix the thing",
                "status": {"name": "To Do"},
            },
        }],
    })
    resp.raise_for_status = MagicMock()

    fake_client = MagicMock()
    fake_client.post = MagicMock(return_value=resp)
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.jira import jira
    out = jira().fn({"op": "search", "jql": "assignee = currentUser()"})
    assert "PROJ-1" in out
    assert "fix the thing" in out
    # Uses the current /search/jql endpoint, not the removed /search.
    called_url = fake_client.post.call_args.args[0]
    assert called_url.endswith("/rest/api/3/search/jql")


def test_jira_search_follows_next_page_token(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://x.atlassian.net")
    monkeypatch.setenv("JIRA_USER", "me@x")
    monkeypatch.setenv("JIRA_API_TOKEN", "tok")

    def _page(key, summary, token):
        resp = MagicMock()
        body = {"issues": [{"key": key, "fields": {
            "summary": summary, "status": {"name": "To Do"},
        }}]}
        if token:
            body["nextPageToken"] = token
        resp.json = MagicMock(return_value=body)
        resp.raise_for_status = MagicMock()
        return resp

    fake_client = MagicMock()
    fake_client.post = MagicMock(side_effect=[
        _page("PROJ-1", "first issue", "tok-2"),
        _page("PROJ-2", "second issue", None),
    ])
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.jira import jira
    out = jira().fn({"op": "search", "jql": "project = PROJ", "limit": 50})
    assert "PROJ-1" in out and "PROJ-2" in out
    assert fake_client.post.call_count == 2
    # Second request carries the token from the first response.
    assert fake_client.post.call_args_list[1].kwargs["json"]["nextPageToken"] == "tok-2"


def test_jira_get_handles_404(monkeypatch):
    monkeypatch.setenv("JIRA_URL", "https://x.atlassian.net")
    monkeypatch.setenv("JIRA_USER", "me@x")
    monkeypatch.setenv("JIRA_API_TOKEN", "tok")

    resp = MagicMock()
    resp.status_code = 404

    fake_client = MagicMock()
    fake_client.get = MagicMock(return_value=resp)
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.jira import jira
    out = jira().fn({"op": "get", "issue_key": "PROJ-999"})
    assert "not found" in out
