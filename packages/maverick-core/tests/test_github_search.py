"""GitHub search tool: repos/code/issues shaping, token gating, rate limits.

Network-free: ``httpx`` is faked in ``sys.modules`` with canned JSON, the
connector-test pattern from test_strategic_connectors.py.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest
from maverick.tools.github_search import github_search


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body, headers=None):
    r = MagicMock()
    r.status_code = status
    r.json = MagicMock(return_value=body)
    r.text = str(body)
    r.headers = headers or {}
    return r


@pytest.fixture(autouse=True)
def _no_ambient_tokens(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)


def test_repos_search_formats_results(monkeypatch):
    get = MagicMock(return_value=_resp(200, {"items": [
        {"full_name": "acme/widgets", "stargazers_count": 1234,
         "description": "Widget factory", "html_url": "https://github.com/acme/widgets"},
        {"full_name": "acme/gizmos", "stargazers_count": 7,
         "description": None, "html_url": "https://github.com/acme/gizmos"},
    ]}))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "repos", "query": "widgets language:python"})
    assert "acme/widgets" in out and "1234 stars" in out and "Widget factory" in out
    assert "acme/gizmos" in out
    assert get.call_args.args[0].endswith("/search/repositories")
    assert get.call_args.kwargs["params"]["q"] == "widgets language:python"
    # Unauthenticated repos search is allowed: no Authorization header.
    assert "Authorization" not in get.call_args.kwargs["headers"]
    assert get.call_args.kwargs["headers"]["Accept"] == "application/vnd.github+json"


def test_limit_clamped_to_20(monkeypatch):
    get = MagicMock(return_value=_resp(200, {"items": []}))
    _fake_httpx(monkeypatch, get=get)
    github_search().fn({"op": "repos", "query": "q", "limit": 999})
    assert get.call_args.kwargs["params"]["per_page"] == 20
    github_search().fn({"op": "repos", "query": "q", "limit": -3})
    assert get.call_args.kwargs["params"]["per_page"] == 1
    github_search().fn({"op": "repos", "query": "q"})
    assert get.call_args.kwargs["params"]["per_page"] == 10  # default


def test_code_search_requires_token(monkeypatch):
    get = MagicMock()
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "code", "query": "Budget.check"})
    assert out.startswith("ERROR")
    assert "GITHUB_TOKEN" in out and "scope" in out
    get.assert_not_called()  # refused before any request


def test_code_search_with_token_scopes_repo_and_formats(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    get = MagicMock(return_value=_resp(200, {"items": [
        {"path": "maverick/budget.py",
         "repository": {"full_name": "acme/maverick"},
         "html_url": "https://github.com/acme/maverick/blob/main/maverick/budget.py",
         "text_matches": [{"fragment": "def check(self):\n    ..."}]},
    ]}))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "code", "query": "def check",
                              "repo": "acme/maverick"})
    assert "acme/maverick:maverick/budget.py" in out
    assert "def check(self):" in out  # text-match fragment surfaced
    assert get.call_args.args[0].endswith("/search/code")
    assert get.call_args.kwargs["params"]["q"] == "def check repo:acme/maverick"
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer ghp_test"
    # Code search must opt into the text-match media type or GitHub never
    # populates text_matches and the fragment preview is permanently dead.
    assert get.call_args.kwargs["headers"]["Accept"] == \
        "application/vnd.github.text-match+json"


def test_code_search_token_from_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[github]\ntoken = "cfg_tok"\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    get = MagicMock(return_value=_resp(200, {"items": []}))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "code", "query": "x"})
    assert out == "no matches"
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer cfg_tok"


def test_bad_repo_qualifier_rejected(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    get = MagicMock()
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "code", "query": "x", "repo": "not a repo!"})
    assert out.startswith("ERROR") and "owner/name" in out
    get.assert_not_called()


def test_issues_search_with_repo_and_state(monkeypatch):
    get = MagicMock(return_value=_resp(200, {"items": [
        {"number": 42, "state": "closed", "title": "Budget cap ignored",
         "html_url": "https://github.com/acme/maverick/issues/42"},
    ]}))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "issues", "query": "budget",
                              "repo": "acme/maverick", "state": "closed"})
    assert "#42" in out and "closed" in out and "Budget cap ignored" in out
    assert get.call_args.args[0].endswith("/search/issues")
    assert get.call_args.kwargs["params"]["q"] == "budget repo:acme/maverick state:closed"


def test_issues_invalid_state_rejected(monkeypatch):
    get = MagicMock()
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "issues", "query": "x", "state": "weird"})
    assert out.startswith("ERROR") and "state" in out
    get.assert_not_called()


def test_rate_limit_shaped_with_retry_after(monkeypatch):
    get = MagicMock(return_value=_resp(
        403,
        {"message": "API rate limit exceeded for 1.2.3.4.",
         "documentation_url": "https://docs.github.com/rest"},
        headers={"retry-after": "42"},
    ))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "repos", "query": "q"})
    assert out.startswith("ERROR")
    assert "rate limit" in out and "403" in out
    assert "Retry after 42s" in out


def test_secondary_rate_limit_without_retry_after(monkeypatch):
    get = MagicMock(return_value=_resp(
        403, {"message": "You have exceeded a secondary rate limit."}))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "repos", "query": "q"})
    assert "rate limit" in out and "retry later" in out


def test_plain_http_error_shaped(monkeypatch):
    get = MagicMock(return_value=_resp(422, {"message": "Validation Failed"}))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "repos", "query": "q"})
    assert out.startswith("ERROR") and "422" in out and "Validation Failed" in out


def test_empty_results_and_arg_validation(monkeypatch):
    get = MagicMock(return_value=_resp(200, {"items": []}))
    _fake_httpx(monkeypatch, get=get)
    tool = github_search()
    assert tool.fn({"op": "repos", "query": "q"}) == "no matches"
    assert tool.fn({"op": "repos"}).startswith("ERROR")
    assert tool.fn({"op": "issues"}).startswith("ERROR")
    assert tool.fn({"op": "bogus"}).startswith("ERROR")
    assert tool.fn({}).startswith("ERROR")


def test_request_exception_becomes_error_string(monkeypatch):
    get = MagicMock(side_effect=OSError("boom"))
    _fake_httpx(monkeypatch, get=get)
    out = github_search().fn({"op": "repos", "query": "q"})
    assert out.startswith("ERROR") and "boom" in out
