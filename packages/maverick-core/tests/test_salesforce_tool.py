"""Tests for the Salesforce tool (maverick.tools.salesforce_tool)."""
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


# ---------- Salesforce ----------

def test_salesforce_requires_op():
    from maverick.tools.salesforce_tool import salesforce_tool
    assert "op is required" in salesforce_tool().fn({})


def test_salesforce_missing_config(monkeypatch):
    monkeypatch.delenv("SALESFORCE_INSTANCE_URL", raising=False)
    monkeypatch.delenv("SALESFORCE_ACCESS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.salesforce_tool import salesforce_tool
    out = salesforce_tool().fn({"op": "soql", "query": "SELECT Id FROM Account LIMIT 1"})
    assert "SALESFORCE_INSTANCE_URL" in out


def test_salesforce_soql_renders(monkeypatch):
    monkeypatch.setenv("SALESFORCE_INSTANCE_URL", "https://x.my.salesforce.com")
    monkeypatch.setenv("SALESFORCE_ACCESS_TOKEN", "tok")
    body = {"totalSize": 1, "done": True,
            "records": [{"attributes": {"type": "Account"}, "Id": "001x", "Name": "Acme"}]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.salesforce_tool import salesforce_tool
    out = salesforce_tool().fn({"op": "soql", "query": "SELECT Id FROM Account"})
    assert "totalSize=1" in out and "001x" in out and "Acme" in out


def test_salesforce_record_create_dry_run(monkeypatch):
    monkeypatch.setenv("SALESFORCE_INSTANCE_URL", "https://x")
    monkeypatch.setenv("SALESFORCE_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.salesforce_tool import salesforce_tool
    out = salesforce_tool().fn({
        "op": "record_create", "sobject": "Account",
        "fields": {"Name": "Acme"},
    })
    assert "DRY RUN" in out
