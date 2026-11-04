"""Tests for the HubSpot tool (maverick.tools.hubspot_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    """Install a dummy httpx module with the given methods (get/post/...) ."""
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status: int, body: object):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = str(body)
    return r


# ---------- HubSpot ----------

def test_hubspot_requires_op():
    from maverick.tools.hubspot_tool import hubspot_tool
    assert "op is required" in hubspot_tool().fn({})


def test_hubspot_missing_token(monkeypatch):
    monkeypatch.delenv("HUBSPOT_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock(), post=MagicMock())
    from maverick.tools.hubspot_tool import hubspot_tool
    out = hubspot_tool().fn({"op": "contacts"})
    assert "HUBSPOT_TOKEN" in out


def test_hubspot_contacts_list(monkeypatch):
    monkeypatch.setenv("HUBSPOT_TOKEN", "tok")
    body = {"results": [
        {"id": "1", "properties": {"email": "a@x.com",
                                    "firstname": "A", "lastname": "B"}},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.hubspot_tool import hubspot_tool
    out = hubspot_tool().fn({"op": "contacts"})
    assert "a@x.com" in out


def test_hubspot_contacts_follows_paging_after(monkeypatch):
    monkeypatch.setenv("HUBSPOT_TOKEN", "tok")
    page1 = {"results": [{"id": "1", "properties": {"email": "one@x"}}],
             "paging": {"next": {"after": "cur-2"}}}
    page2 = {"results": [{"id": "2", "properties": {"email": "two@x"}}]}
    get = MagicMock(side_effect=[_resp(200, page1), _resp(200, page2)])
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.hubspot_tool import hubspot_tool
    out = hubspot_tool().fn({"op": "contacts", "limit": 50})
    assert "one@x" in out and "two@x" in out
    assert get.call_count == 2
    assert get.call_args_list[1].kwargs["params"]["after"] == "cur-2"


def test_hubspot_contact_create_dry_run(monkeypatch):
    monkeypatch.setenv("HUBSPOT_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.hubspot_tool import hubspot_tool
    out = hubspot_tool().fn({"op": "contact_create", "email": "x@y"})
    assert "DRY RUN" in out
