"""Audit search by actor, measured as a test: seed 20 known events (10 by people, 10 by
agents and specialists) and find each one with the activity log's own
filters -- actor (a person, or an agent or specialist), kind of event and
words. Each search must return exactly the seeded event. The export offers
CSV and JSON, and an AI action's row names the model and what it reached."""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

PEOPLE = [f"user:person{i}@corp.com" for i in range(10)]
AGENTS = [f"specialist_{i}" for i in range(10)]


@pytest.fixture
def seeded(monkeypatch, tmp_path):
    import maverick.audit as audit
    from maverick.audit import reader
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    log = AuditLog(tmp_path / "audit")
    monkeypatch.setattr(audit, "default_audit_log", lambda: log)
    monkeypatch.setattr(reader, "resolve_audit_dir", lambda tenant: log.audit_dir)
    for i, person in enumerate(PEOPLE):
        log.record(AuditEvent(ts=time.time(), kind="privacy_record_changed",
                              payload={"actor": person, "record_type": "dsar", "record_id": f"DSAR-{i}"}))
    for i, agent in enumerate(AGENTS):
        log.record(AuditEvent(ts=time.time(), kind="tool_call", agent=agent,
                              payload={"name": "read_file", "model": "model-x",
                                       "resources": [f"reports/q{i}.csv"]}))
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def test_each_seeded_event_is_found_by_its_actor_kind_and_words(seeded):
    started = time.monotonic()
    for i, person in enumerate(PEOPLE):
        by_person = seeded.get("/audit", params={"person": person, "kind": "privacy_record_changed"}).text
        by_record = seeded.get("/audit", params={"q": f"DSAR-{i}"}).text
        assert "Showing 1 of 1 matching events" in by_person, person
        assert "Showing 1 of 1 matching events" in by_record, person
    for i, agent in enumerate(AGENTS):
        # The agent's own filter, and the file it read (found by its name,
        # shown only as a fingerprint).
        by_agent = seeded.get("/audit", params={"agent": agent, "kind": "tool_call"}).text
        by_file = seeded.get("/audit", params={"kind": "tool_call", "q": f"reports/q{i}.csv"}).text
        assert "Showing 1 of 1 matching events" in by_agent, agent
        assert "Showing 1 of 1 matching events" in by_file, agent
    # 20 of 20 found; each search is one page load.
    assert time.monotonic() - started < 60 * 20


def test_the_filters_offer_agents_and_specialists_as_actors(seeded):
    page = seeded.get("/audit").text
    assert '<select id="aud-agent" name="agent"' in page
    assert 'value="specialist_3"' in page


def test_an_ai_action_names_its_model_and_what_it_reached(seeded):
    from maverick_dashboard.content_access import resource_fingerprint

    page = seeded.get("/audit", params={"agent": "specialist_4"}).text
    assert "model-x" in page and "specialist_4" in page.replace("Specialist 4", "specialist_4")
    assert resource_fingerprint("reports/q4.csv") in page
    assert "reports/q4.csv" not in page  # the name itself is tool input and stays private


def test_the_export_offers_csv_and_json(seeded):
    page = seeded.get("/audit").text
    assert '<option value="csv">Spreadsheet</option>' in page
    assert '<option value="json" title="A JSON Lines file (.jsonl): one event per line">' in page
    exported = seeded.get("/api/v1/audit/download", params={"format": "json"})
    if exported.status_code == 403:  # downloads for security tools are a plan feature
        assert "plan" in exported.json()["detail"]
        return
    lines = [json.loads(line) for line in exported.text.splitlines() if line.strip()]
    actions = [line for line in lines if line.get("kind") == "tool_call"]
    assert len(actions) == 10 and all(line["model"] == "model-x" and line["resources_reached"] == 1 for line in actions)
