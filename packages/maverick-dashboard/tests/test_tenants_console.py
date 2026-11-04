"""Operator tenant console (/tenants) — the hosted control-plane roster view."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)


def test_tenants_page_renders_and_nav(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/tenants")
    assert r.status_code == 200
    assert "tenants" in r.text.lower()
    assert 'href="/tenants"' in r.text  # nav link wired


def test_empty_state(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    text = _client().get("/tenants").text
    assert "No workspaces yet" in text
    assert "No daily limit" in text
    assert 'name="max_daily_dollars"' in text
    assert 'name="display_name" required' in text and 'name="id"' not in text


def test_lists_provisioned_tenants(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", plan="enterprise", display_name="Acme Inc",
                     max_daily_dollars=100)
    tr.create_tenant("beta")
    tr.suspend_tenant("beta")
    text = _client().get("/tenants").text
    assert "acme" in text and "enterprise" in text and "Acme Inc" in text
    assert "$100.00/day" in text
    # beta is suspended.
    beta_row = text.split('data-tenant-row="beta"', 1)[1].split("</tr>", 1)[0]
    assert 'data-tenant-name="beta"' in beta_row
    assert ">beta<" in beta_row and ">Paused<" in beta_row


def test_roster_lets_an_admin_change_each_daily_limit_in_place(monkeypatch, tmp_path):
    """The limit is editable after creation: every row is an editor bound to
    the existing quota API (0 = unlimited)."""
    _isolate(monkeypatch, tmp_path)
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", display_name="Acme Inc", max_daily_dollars=100)
    tr.create_tenant("free", max_daily_dollars=0)
    text = _client().get("/tenants").text
    assert 'class="tenant-quota" data-tenant="acme"' in text
    assert 'value="100"' in text
    assert 'class="tenant-quota" data-tenant="free"' in text and "No limit" in text
    # The editor posts to the existing quota API (script served as a static file).
    from pathlib import Path
    script = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork-tenants.js").read_text(encoding="utf-8")
    assert "'/quota', 'POST'" in script and "No limit" in script
