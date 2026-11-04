"""Tests for the Cloudflare tool (maverick.tools.cloudflare_tool)."""
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


# ---------- Cloudflare ----------

def test_cloudflare_requires_op():
    from maverick.tools.cloudflare_tool import cloudflare_tool
    assert "op is required" in cloudflare_tool().fn({})


def test_cloudflare_missing_token(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.cloudflare_tool import cloudflare_tool
    out = cloudflare_tool().fn({"op": "dns_list", "zone_id": "z"})
    assert "CLOUDFLARE_API_TOKEN" in out


def test_cloudflare_dns_list(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "tok")
    body = {"success": True, "result": [
        {"id": "r1", "type": "A", "name": "x.example.com", "content": "1.2.3.4"},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.cloudflare_tool import cloudflare_tool
    out = cloudflare_tool().fn({"op": "dns_list", "zone_id": "z"})
    assert "x.example.com" in out and "1.2.3.4" in out


def test_cloudflare_purge_dry_run(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.cloudflare_tool import cloudflare_tool
    out = cloudflare_tool().fn({"op": "purge", "zone_id": "z"})
    assert "DRY RUN" in out and "EVERYTHING" in out
