"""Tests for the Spotify tool (maverick.tools.spotify_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def test_spotify_id_rejects_path_traversal():
    from maverick.tools.spotify_tool import _safe_id
    assert _safe_id("3n3Ppam7vgaVa1iaRUc9Lp")  # real Base62 track id shape
    assert not _safe_id("../albums/x")
    assert not _safe_id("a/b")
    assert not _safe_id("a.b")
    assert not _safe_id("")


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


# ---------- Spotify ----------

def test_spotify_requires_op():
    from maverick.tools.spotify_tool import spotify_tool
    assert "op is required" in spotify_tool().fn({})


def test_spotify_missing_token(monkeypatch):
    monkeypatch.delenv("SPOTIFY_ACCESS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.spotify_tool import spotify_tool
    out = spotify_tool().fn({"op": "search", "q": "x"})
    assert "SPOTIFY_ACCESS_TOKEN" in out


def test_spotify_pause_dry_run(monkeypatch):
    monkeypatch.setenv("SPOTIFY_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch, put=MagicMock())
    from maverick.tools.spotify_tool import spotify_tool
    out = spotify_tool().fn({"op": "pause"})
    assert "DRY RUN" in out


def test_spotify_search_renders(monkeypatch):
    monkeypatch.setenv("SPOTIFY_ACCESS_TOKEN", "tok")
    body = {"tracks": {"items": [
        {"name": "Bohemian Rhapsody", "uri": "spotify:track:1",
         "artists": [{"name": "Queen"}]},
    ]}}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.spotify_tool import spotify_tool
    out = spotify_tool().fn({"op": "search", "q": "queen"})
    assert "Bohemian Rhapsody" in out and "Queen" in out
