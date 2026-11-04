"""Compliance: each protection that needs action has an owner, a due date,
steps to fix it and the time it was checked; administrators set the owner and
due date, and each change is written to the activity record."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.compliance as compliance
    from maverick.compliance import ControlCheck
    checks = [
        ControlCheck("PII redaction in logs", "GDPR Art. 32", "action_needed", "off", framework="eu"),
        ControlCheck("Storage limitation (retention)", "GDPR Art. 5(1)(e)", "action_needed", "off", framework="eu"),
        ControlCheck("Encryption at rest", "GDPR Art. 32", "active", "on", framework="eu"),
    ]
    monkeypatch.setattr(compliance, "compliance_report", lambda: list(checks))
    from maverick_dashboard import rbac
    rbac.set_role("user:priya@corp.com", "operator", actor="user:setup")
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def words(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


def attention(page: str) -> str:
    return words(page).split("Needs attention", 1)[1].split("Filter and download", 1)[0]


def test_each_failing_protection_shows_owner_due_steps_and_check_time(client):
    page = client.get("/compliance").text
    table = attention(page)
    assert table.count("No owner yet") == 2 and table.count("No due date") == 2
    assert "Steps to fix it" in table
    assert "Press “Hide personal details in logs” in this row and confirm." in table
    assert "Checked " in table and "live from your workspace each time this page opens" in table
    assert 'data-mv-time="' in page.split('id="cmp-attention"', 1)[1]
    # Labelled, native controls for the owner and the due date in every row.
    assert '<label for="cmp-owner-1">Owner' in page and 'type="date" name="due"' in page


def test_administrator_sets_owner_and_due_date_and_it_is_audited(client, monkeypatch):
    from maverick_dashboard import audit_actions_api
    events = []
    monkeypatch.setattr(audit_actions_api, "_audit_event",
                        lambda _request, action, **payload: events.append((action, payload)))
    r = client.post("/compliance/owners", data={"control": "PII redaction in logs",
                                                "owner": "user:priya@corp.com", "due": "2020-01-31"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("owner_saved=1#cmp-attention")
    assert events == [("compliance_control_owner_set",
                       {"control": "PII redaction in logs", "owner": "user:priya@corp.com", "due": "2020-01-31"})]
    table = attention(client.get("/compliance?owner_saved=1").text)
    row = table.split("PII redaction in logs", 1)[1].split("Storage limitation", 1)[0]
    assert "priya" in row and "Overdue" in row and "Set by" in row
    # Clearing both removes the entry.
    client.post("/compliance/owners", data={"control": "PII redaction in logs", "owner": "", "due": ""})
    from maverick_dashboard import compliance_owners
    assert compliance_owners.load() == {}


def test_unknown_protection_or_bad_date_is_refused_plainly(client):
    r = client.post("/compliance/owners", data={"control": "Made up", "owner": "", "due": "2026-12-01"},
                    follow_redirects=False)
    assert "owner_error=control" in r.headers["location"]
    r = client.post("/compliance/owners", data={"control": "PII redaction in logs", "owner": "", "due": "soon"},
                    follow_redirects=False)
    assert "owner_error=due" in r.headers["location"]
    assert "Choose a due date." in words(client.get("/compliance?owner_error=due").text)


def test_only_administrators_set_owners(client, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import app as dash_app

    def deny(_request, _atom):
        raise HTTPException(status_code=403, detail="no")
    monkeypatch.setattr(dash_app, "require_permission", deny)
    r = client.post("/compliance/owners", data={"control": "PII redaction in logs", "owner": "", "due": "2026-12-01"})
    assert r.status_code == 403
