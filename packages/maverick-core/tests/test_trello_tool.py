"""Tests for the Trello tool (maverick.tools.trello_tool)."""
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


def _resp(status, body, *, text=None):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = text if text is not None else str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = text if text is not None else str(body)
    r.content = (body if isinstance(body, bytes) else str(body).encode())
    return r


# ---------- Trello ----------

def test_trello_requires_op():
    from maverick.tools.trello_tool import trello_tool
    assert "op is required" in trello_tool().fn({})


def test_trello_missing_auth(monkeypatch):
    monkeypatch.delenv("TRELLO_KEY", raising=False)
    monkeypatch.delenv("TRELLO_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.trello_tool import trello_tool
    out = trello_tool().fn({"op": "boards"})
    assert "TRELLO_KEY" in out


def test_trello_boards_renders(monkeypatch):
    monkeypatch.setenv("TRELLO_KEY", "k")
    monkeypatch.setenv("TRELLO_TOKEN", "t")
    body = [{"id": "b1", "name": "Roadmap", "closed": False}]
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.trello_tool import trello_tool
    out = trello_tool().fn({"op": "boards"})
    assert "Roadmap" in out


def test_trello_card_create_dry_run(monkeypatch):
    monkeypatch.setenv("TRELLO_KEY", "k")
    monkeypatch.setenv("TRELLO_TOKEN", "t")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.trello_tool import trello_tool
    out = trello_tool().fn({"op": "card_create", "list_id": "L", "name": "Do it"})
    assert "DRY RUN" in out
