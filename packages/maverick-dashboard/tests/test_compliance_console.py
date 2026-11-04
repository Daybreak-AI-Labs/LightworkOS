"""Compliance console (/compliance) + auditor export.

Hermetic like the other dashboard tests: OIDC off, HOME/MAVERICK_HOME isolated
to a tmp_path, and the control-coverage report stubbed so the page/export are
deterministic regardless of the host deployment's live config. The report is
org/system-level (like /safety) — no per-owner scoping.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _stub_report(monkeypatch):
    """Pin compliance_report() to a fixed EU + US control set.

    Patched on maverick.compliance (the app + api import it from there inside
    the request handlers), so both the page and the export see the same data.
    """
    import maverick.compliance as compliance
    from maverick.compliance import ControlCheck

    checks = [
        ControlCheck(
            "AI transparency disclosure", "EU AI Act Art. 50",
            "active", "first-turn AI disclosure shown to channel users",
            framework="eu",
        ),
        ControlCheck(
            "Encryption at rest", "GDPR Art. 32",
            "action_needed", "enable [encryption] at_rest = true",
            framework="eu",
        ),
        ControlCheck(
            "Consumer notice of AI", "Colorado AI Act (SB 26-189) / CA SB 1001",
            "active", "first-turn AI disclosure shown to users",
            framework="us",
        ),
    ]
    monkeypatch.setattr(compliance, "compliance_report", lambda: checks)
    return checks


def test_compliance_page_renders_framework_rows(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _stub_report(monkeypatch)
    r = _client().get("/compliance")
    assert r.status_code == 200
    body = r.text
    # Controls from both frameworks render with their regulation text.
    assert "AI transparency disclosure" in body
    assert "EU AI Act Art. 50" in body
    assert "Consumer notice of AI" in body
    assert "Colorado AI Act" in body
    # Framework group labels are shown.
    assert "European Union (AI Act and GDPR)" in body
    assert "United States (federal and state rules)" in body
    # Statuses surface in plain words (on + the control that needs action).
    assert ">On<" in body
    assert "Needs action" in body


def test_compliance_page_filter_changes_output(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _stub_report(monkeypatch)
    c = _client()

    eu = c.get("/compliance?framework=eu").text
    assert "AI transparency disclosure" in eu
    assert "Consumer notice of AI" not in eu  # US control filtered out

    us = c.get("/compliance?framework=us").text
    assert "Consumer notice of AI" in us
    assert "AI transparency disclosure" not in us  # EU control filtered out

    allf = c.get("/compliance?framework=all").text
    assert "AI transparency disclosure" in allf
    assert "Consumer notice of AI" in allf


def test_compliance_page_empty_state_when_core_unavailable(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.compliance as compliance

    def _boom():
        raise RuntimeError("core unavailable")

    monkeypatch.setattr(compliance, "compliance_report", _boom)
    r = _client().get("/compliance")
    # Fail-soft: empty state, never a 500.
    assert r.status_code == 200
    assert "Nothing to report for this filter" in r.text


def test_compliance_nav_link_present(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _stub_report(monkeypatch)
    r = _client().get("/compliance")
    assert r.status_code == 200
    assert 'href="/compliance"' in r.text
    assert ">Compliance<" in r.text


def test_compliance_export_md_is_attachment(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _stub_report(monkeypatch)
    r = _client().get("/api/v1/compliance/report.md")
    assert r.status_code == 200
    cd = r.headers["content-disposition"]
    assert "attachment" in cd
    assert "lightwork-compliance-all.md" in cd
    assert r.headers["content-type"].startswith("text/markdown")
    # The report body carries the control text.
    assert "AI transparency disclosure" in r.text
    assert "Consumer notice of AI" in r.text


def test_compliance_export_csv_is_attachment(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _stub_report(monkeypatch)
    r = _client().get("/api/v1/compliance/report.csv")
    assert r.status_code == 200
    cd = r.headers["content-disposition"]
    assert "attachment" in cd
    assert "lightwork-compliance-all.csv" in cd
    assert r.headers["content-type"].startswith("text/csv")
    body = r.text
    assert "framework,control,regulation,status,detail" in body
    assert "AI transparency disclosure" in body


def test_compliance_export_filter_changes_output(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _stub_report(monkeypatch)
    c = _client()

    eu = c.get("/api/v1/compliance/report.md?framework=eu")
    assert eu.status_code == 200
    assert "lightwork-compliance-eu.md" in eu.headers["content-disposition"]
    assert "AI transparency disclosure" in eu.text
    assert "Consumer notice of AI" not in eu.text

    us = c.get("/api/v1/compliance/report.csv?framework=us")
    assert us.status_code == 200
    assert "Consumer notice of AI" in us.text
    assert "AI transparency disclosure" not in us.text
