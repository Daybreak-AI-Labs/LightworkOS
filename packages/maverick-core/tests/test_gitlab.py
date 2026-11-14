"""Tests for the GitLab tool (maverick.tools.gitlab)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

# ---------- GitLab tool ----------

def test_gitlab_requires_op():
    from maverick.tools.gitlab import gitlab
    assert "op is required" in gitlab().fn({})


def test_gitlab_unknown_op():
    from maverick.tools.gitlab import gitlab
    out = gitlab().fn({"op": "wat"})
    assert "unknown op" in out or "ERROR" in out


def test_gitlab_missing_token(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    fake = types.ModuleType("httpx")
    fake.Client = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.gitlab import gitlab
    out = gitlab().fn({"op": "issues", "project": "group/repo"})
    assert "GITLAB_TOKEN" in out


def test_gitlab_issues_list_calls_rest(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_xxx")
    resp = MagicMock()
    resp.json = MagicMock(return_value=[
        {"iid": 1, "state": "opened", "title": "Crash on save"},
        {"iid": 2, "state": "opened", "title": "Improve docs"},
    ])
    resp.raise_for_status = MagicMock()

    fake_client = MagicMock()
    fake_client.get = MagicMock(return_value=resp)
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.gitlab import gitlab
    out = gitlab().fn({"op": "issues", "project": "group/repo"})
    assert "Crash on save" in out and "Improve docs" in out
    assert "opened" in out
    # Verify URL-encoded project path was used.
    called_url = fake_client.get.call_args.args[0]
    assert "group%2Frepo" in called_url


def test_gitlab_issues_follows_next_page_header(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_xxx")

    def _page(items, next_page):
        resp = MagicMock()
        resp.json = MagicMock(return_value=items)
        resp.raise_for_status = MagicMock()
        resp.headers = {"X-Next-Page": next_page}
        return resp

    fake_client = MagicMock()
    fake_client.get = MagicMock(side_effect=[
        _page([{"iid": 1, "state": "opened", "title": "Page one issue"}], "2"),
        _page([{"iid": 2, "state": "opened", "title": "Page two issue"}], ""),
    ])
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.gitlab import gitlab
    out = gitlab().fn({"op": "issues", "project": "g/r", "limit": 50})
    assert "Page one issue" in out and "Page two issue" in out
    assert fake_client.get.call_count == 2
    assert fake_client.get.call_args_list[1].kwargs["params"]["page"] == 2


def test_gitlab_issue_get_404(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_xxx")
    resp = MagicMock()
    resp.status_code = 404

    fake_client = MagicMock()
    fake_client.get = MagicMock(return_value=resp)
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.gitlab import gitlab
    out = gitlab().fn({"op": "issue_get", "project": "g/r", "iid": 999})
    assert "not found" in out


def test_gitlab_pipeline_get_renders(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_xxx")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={
        "id": 42, "status": "success", "ref": "main",
        "sha": "abc123def456", "created_at": "2026-05-27T10:00:00Z",
        "finished_at": "2026-05-27T10:05:00Z",
        "web_url": "https://gitlab.com/g/r/-/pipelines/42",
    })
    resp.raise_for_status = MagicMock()

    fake_client = MagicMock()
    fake_client.get = MagicMock(return_value=resp)
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.gitlab import gitlab
    out = gitlab().fn({"op": "pipeline_get", "project": "g/r", "pipeline_id": 42})
    assert "success" in out and "main" in out
    assert "abc123def456"[:12] in out


def test_gitlab_dot_segment_project_refused():
    # httpx collapses /projects/../merge_requests to the instance-wide list.
    from maverick.tools.gitlab import _enc
    with pytest.raises(RuntimeError):
        _enc("..")
    assert _enc("group/repo") == "group%2Frepo"
