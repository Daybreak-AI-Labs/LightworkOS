"""UI hardening (audit_page_markup): audit-page markup correctness + a11y."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _audit_page(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(
        "maverick.audit.writer.DEFAULT_AUDIT_DIR", tmp_path / "audit",
    )
    import maverick.audit.writer as w
    w._default = None
    return _client().get("/audit")


def test_audit_div_tags_balanced(monkeypatch, tmp_path):
    """Regression: the search panel carried a stray closing </div>."""
    r = _audit_page(monkeypatch, tmp_path)
    assert r.status_code == 200
    assert r.text.count("<div") == r.text.count("</div>")


def test_audit_search_status_is_live_region(monkeypatch, tmp_path):
    r = _audit_page(monkeypatch, tmp_path)
    assert 'id="aud-action-result" role="status" aria-live="polite"' in r.text


def test_audit_page_exposes_read_only_unified_custody_status(monkeypatch, tmp_path):
    r = _audit_page(monkeypatch, tmp_path)
    assert r.status_code == 200
    assert "Protect and share the log" in r.text
    assert "/api/v1/audit/unified/status" in r.text
    assert 'id="audit-custody-status" role="status" aria-live="polite"' in r.text
    assert "Refresh protection status" in r.text
    assert "textContent" in r.text
