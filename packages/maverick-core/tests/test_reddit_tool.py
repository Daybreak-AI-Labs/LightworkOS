"""Tests for the Reddit tool (maverick.tools.reddit_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for n, v in methods.items():
        setattr(mod, n, v)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = str(body)
    return r


# ---------- Reddit ----------

def test_reddit_requires_op():
    from maverick.tools.reddit_tool import reddit_tool
    assert "op is required" in reddit_tool().fn({})


def test_reddit_subreddit_renders(monkeypatch):
    body = {"data": {"children": [
        {"data": {"subreddit": "python", "score": 200,
                  "num_comments": 30, "title": "PEP 800 dropped"}},
    ]}}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.reddit_tool import reddit_tool
    out = reddit_tool().fn({"op": "subreddit", "name": "python"})
    assert "PEP 800 dropped" in out and "python" in out


def test_reddit_post_renders(monkeypatch):
    body = [{"data": {"children": [{"data": {
        "title": "TIL", "subreddit": "showerthoughts",
        "score": 42, "author": "alice", "selftext": "Body",
        "permalink": "/r/x/c/abc/",
    }}]}}]
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.reddit_tool import reddit_tool
    out = reddit_tool().fn({"op": "post", "post_id": "abc"})
    assert "TIL" in out and "alice" in out


def test_reddit_handles_null_score(monkeypatch):
    body = {"data": {"children": [
        {"data": {"subreddit": "x", "score": None, "num_comments": None,
                  "title": "promoted"}},
    ]}}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.reddit_tool import reddit_tool
    out = reddit_tool().fn({"op": "subreddit", "name": "x"})
    assert "ERROR" not in out and "promoted" in out


class TestRedditPrefixStrip:
    def test_subreddit_name_not_char_stripped(self, monkeypatch):
        # lstrip("r/") turned subreddit "rust" into "ust". removeprefix fixes it.
        from maverick.tools import reddit_tool
        captured = {}

        def fake_get(url, params=None):
            captured["url"] = url
            return 200, {"data": {"children": []}}

        monkeypatch.setattr(reddit_tool, "_get", fake_get)
        reddit_tool._op_subreddit({"name": "rust"})
        assert "/r/rust/" in captured["url"], captured["url"]

    def test_post_id_not_char_stripped(self, monkeypatch):
        from maverick.tools import reddit_tool
        captured = {}
        monkeypatch.setattr(
            reddit_tool, "_get",
            lambda url, params=None: (captured.setdefault("url", url), (200, {}))[1],
        )
        # "t3_t3abc" -> removeprefix strips one "t3_" -> "t3abc"; lstrip would
        # have eaten leading t/3/_ chars too. Use an id starting with stripped chars.
        reddit_tool._op_post({"post_id": "tango123"})
        assert "/comments/tango123." in captured["url"], captured["url"]
