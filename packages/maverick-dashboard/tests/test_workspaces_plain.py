"""Workspaces pages in plain language: named, not typed IDs."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

BANNED = ("tenant", "Tenant", "registry", "ledger", "override", "UTC day", "error 4",
          "error 5", "gRPC", "department:", "deployment")


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_create_workspace_by_name_rejects_indistinguishable_names(client):
    r = client.post("/api/v1/admin/tenants", json={"display_name": "Acme Finance", "plan": "pro"})
    assert r.status_code == 201, r.text
    assert r.json()["id"] == "acme-finance"
    for name in ("Acme Finance", " acme   finance ", "ACME FINANCE"):
        again = client.post("/api/v1/admin/tenants", json={"display_name": name})
        assert again.status_code == 409
        assert "workspace with that name" in again.json()["detail"]
    assert client.post("/api/v1/admin/tenants", json={"id": "other", "display_name": "Acme Finance"}).status_code == 409
    assert client.post("/api/v1/admin/tenants", json={"display_name": "Acme Sales"}).json()["id"] == "acme-sales"
    assert client.post("/api/v1/admin/tenants", json={"display_name": "  "}).status_code == 422
    # An explicit id still works for automation.
    assert client.post("/api/v1/admin/tenants", json={"id": "beta", "display_name": "B"}).json()["id"] == "beta"


def test_existing_duplicate_names_show_stable_references(client):
    from maverick.tenant import registry as tr
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import settings_all_page

    tr.create_tenant("acme-finance", display_name="Acme Finance")
    tr.create_tenant("acme-finance-2")
    # Simulate a roster written before name uniqueness was enforced.
    tr._mutate("acme-finance-2", display_name="Acme  Finance")
    tr.create_tenant("other", display_name="Other")
    for path in ("/tenants", "/tenants/overview", "/workspace/tenant", "/users"):
        page = client.get(path).text
        assert page.count("Reference: acme-finance") >= 2, path
        assert "Reference: other" not in page, path
    choices = settings_all_page._workspace_choices()
    invoices = dash_app._invoice_workspaces("", "")
    for labels in ([label for _, label in choices], [row["name"] for row in invoices]):
        assert sum("Reference: acme-finance" in label for label in labels) == 2
        assert "Other" in labels


def test_workspace_pages_read_plainly(client):
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", display_name="Acme Inc", max_daily_dollars=10)
    tr.create_tenant("beta")
    tr.suspend_tenant("beta")
    for path in ("/tenants", "/tenants/overview", "/tenants/acme/features", "/workspace/tenant"):
        page = client.get(path).text
        text = visible_text(page)
        for word in BANNED:
            assert word not in text, (path, word)
        assert "acme" not in text.replace("Acme", ""), path  # the id never shows beside the name
    roster = client.get("/tenants").text
    for label in ("Pause", "Resume", "Remove", "Features", "No limit"):
        assert label in roster
    assert 'name="id"' not in roster and 'name="id"' not in client.get("/workspace/tenant").text


def test_workspace_changes_stay_admin_only(client, monkeypatch):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:vic", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vic")
    assert client.post("/api/v1/admin/tenants", json={"display_name": "X"}).status_code == 403
    assert client.get("/tenants").status_code == 403
