"""ERP read connector: configured, read-only, and SSRF-safe on the model path."""
from __future__ import annotations

import maverick.config as _config_mod
from maverick.safety.tool_risk import tool_risk
from maverick.tools.erp_tool import erp_tool


class _Resp:
    def __init__(self, status: int, text: str):
        self.status_code = status
        self.text = text


def _no_config(monkeypatch):
    for k in ("ERP_BASE_URL", "ERP_TOKEN", "ERP_SYSTEM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(_config_mod, "load_config", lambda *a, **k: {})


def test_erp_read_is_low_risk():
    # Read-only GET -> low, so low-max_risk suite packs (Ops) can use it.
    assert tool_risk("erp_read") == "low"


def test_unconfigured_errors_cleanly(monkeypatch):
    _no_config(monkeypatch)
    out = erp_tool().fn({"path": "/purchaseOrder/1"})
    assert out.startswith("ERROR:") and "base_url" in out


def test_rejects_absolute_path_no_ssrf(monkeypatch):
    monkeypatch.setenv("ERP_BASE_URL", "https://erp.example.com/api")
    monkeypatch.setenv("ERP_TOKEN", "tok")
    monkeypatch.setattr(_config_mod, "load_config", lambda *a, **k: {})
    # A model-supplied absolute URL / host override must be refused.
    for evil in ("http://169.254.169.254/latest/meta-data", "//evil.example.com/x"):
        out = erp_tool().fn({"path": evil})
        assert out.startswith("ERROR:") and "relative" in out


def test_rejects_dot_segment_path_escape(monkeypatch):
    monkeypatch.setenv("ERP_BASE_URL", "https://erp.example.com/services/rest/record/v1")
    monkeypatch.setenv("ERP_TOKEN", "tok")
    monkeypatch.setattr(_config_mod, "load_config", lambda *a, **k: {})
    import httpx

    def fake_get(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("unsafe ERP path should be rejected before HTTP GET")

    monkeypatch.setattr(httpx, "get", fake_get)
    for evil in (
        "../../admin/audit",
        "/../admin/audit",
        "purchaseOrder/../admin/audit",
        "%2e%2e/admin/audit",
        "%252e%252e/admin/audit",
        "%2f..%2fadmin/audit",
    ):
        out = erp_tool().fn({"path": evil})
        assert out.startswith("ERROR:") and "dot-segment" in out


def test_get_builds_url_and_is_read_only(monkeypatch):
    monkeypatch.setenv("ERP_BASE_URL", "https://erp.example.com/api/")
    monkeypatch.setenv("ERP_TOKEN", "tok")
    monkeypatch.setenv("ERP_SYSTEM", "NetSuite")
    monkeypatch.setattr(_config_mod, "load_config", lambda *a, **k: {})
    import httpx
    seen: dict = {}

    def fake_get(url, params=None, headers=None, timeout=None, follow_redirects=None):
        seen.update(url=url, params=params, headers=headers,
                    follow_redirects=follow_redirects)
        return _Resp(200, '{"id":123,"tranId":"PO123"}')

    monkeypatch.setattr(httpx, "get", fake_get)
    out = erp_tool().fn({"path": "purchaseOrder/123", "params": {"fields": "id"}})
    assert seen["url"] == "https://erp.example.com/api/purchaseOrder/123"
    assert seen["headers"]["Authorization"] == "Bearer tok"
    assert seen["follow_redirects"] is False           # no redirect-based SSRF
    assert "NetSuite GET /purchaseOrder/123 -> 200" in out
    assert '"tranId":"PO123"' in out


def test_tool_shape():
    t = erp_tool()
    assert t.name == "erp_read"
    assert t.parallel_safe is True                     # idempotent read
    assert t.input_schema["required"] == ["path"]
