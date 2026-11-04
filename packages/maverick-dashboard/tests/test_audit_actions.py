"""The Activity log in plain words: readable rows, date range / kind / person
filters, and buttons for the audit commands that were CLI-only."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture
def audit_log(monkeypatch, tmp_path):
    import maverick.audit as audit
    from maverick.audit.writer import AuditLog
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    log = AuditLog(tmp_path / "audit")
    monkeypatch.setattr(audit, "default_audit_log", lambda: log)
    from maverick.audit import reader
    monkeypatch.setattr(reader, "resolve_audit_dir", lambda tenant: log.audit_dir)
    return log


@pytest.fixture
def client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)


def _ev(log, kind, **payload):
    from maverick.audit.events import AuditEvent
    log.record(AuditEvent(ts=time.time(), kind=kind, payload=payload))


def _as(monkeypatch, role):
    from maverick_dashboard import auth, rbac
    rbac.set_role(f"user:{role}9", role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: f"user:{role}9")


def test_rows_read_as_plain_words_and_filter_by_person(audit_log, client):
    from test_support.plain_language import developer_terms, visible_text
    _ev(audit_log, "tool_call", name="send_email", principal="user:amy@example.com")
    _ev(audit_log, "shield_block", stage="input", reason="jailbreak attempt")
    page = client.get("/audit").text
    assert developer_terms(page) == []
    text = visible_text(page)
    for label in ("Used a tool", "Stopped by the safety filter", "amy@example.com",
                  "Find activity", "Kind of event", "Person", "Contains words",
                  "Check the log has not been changed", "Download"):
        assert label in text, label
    assert 'type="date"' in page and 'name="since"' in page and 'name="until"' in page
    only_amy = visible_text(client.get("/audit", params={"person": "user:amy@example.com"}).text)
    assert "Used a tool" in only_amy and "jailbreak attempt" not in only_amy
    words = visible_text(client.get("/audit", params={"q": "jailbreak"}).text)
    assert "jailbreak attempt" not in words and "Send email" not in words
    assert "Nothing was recorded for these dates" in words  # search never sees private reasons


def test_empty_day_offers_a_next_step(audit_log, client):
    text = client.get("/audit", params={"day": "2020-01-01"}).text
    assert "Nothing was recorded for these dates" in text and "Pick other dates" in text


def test_check_and_download(audit_log, client):
    _ev(audit_log, "tool_call", name="send_email")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    out = client.post("/api/v1/audit/check", json={"since": today, "until": today}).json()
    assert out["days_checked"] >= 0 and "problems" in out
    assert client.post("/api/v1/audit/check", json={"since": "yesterday"}).status_code == 422
    r = client.get("/api/v1/audit/download", params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0] == "Time (UTC),Event,Who,Task,Details"
    assert "attachment" in r.headers["content-disposition"]


def test_unsigned_day_is_problem_when_signing_expected(monkeypatch, tmp_path, client):
    from maverick import paths, soc2

    directory = tmp_path / "audit"
    directory.mkdir()
    (directory / "2026-01-01.ndjson").write_text('{"kind":"tool_call"}\n')
    monkeypatch.setattr(paths, "data_dir", lambda *args, **kwargs: directory)
    monkeypatch.setattr(soc2, "_audit_signing_expected", lambda: True)
    result = client.post("/api/v1/audit/check", json={}).json()
    assert result["intact"] is False
    assert result["unsigned_days"] == 0 and result["problems"]


def test_download_without_dates_covers_every_day_and_never_runs_formulas(audit_log, client):
    import csv
    import io
    import json

    from maverick.audit.events import AuditEvent
    from maverick.audit.reader import resolve_audit_dir
    from maverick.audit.writer import AuditLog
    folder = resolve_audit_dir(None)
    AuditLog(folder).record(AuditEvent(ts=time.time(), kind="tool_call",
                                       payload={"name": "send_email", "principal": "slack:=1+1"}))
    today = folder / (time.strftime("%Y-%m-%d", time.gmtime()) + ".ndjson")
    old = time.time() - 5 * 86400
    line = dict(json.loads(today.read_text(encoding="utf-8").splitlines()[0]), ts=old)
    (folder / (time.strftime("%Y-%m-%d", time.gmtime(old)) + ".ndjson")).write_text(
        json.dumps(line) + "\n", encoding="utf-8")
    rows = list(csv.reader(io.StringIO(client.get("/api/v1/audit/download").text)))[1:]
    days = {row[0][:10] for row in rows}
    assert time.strftime("%Y-%m-%d", time.gmtime(old)) in days and len(days) == 2
    assert not [cell for row in rows for cell in row if cell[:1] in ("=", "+", "-", "@")]
    assert any(cell.startswith("'=1+1") for row in rows for cell in row)


def test_a_date_range_finds_recent_matches_behind_many_older_events(audit_log, client, monkeypatch):
    from maverick_dashboard import app as app_mod
    older = [{"ts": 1.0 + i, "kind": "tool_call", "payload": {"name": "read_file"}} for i in range(300)]
    newest = [{"ts": 9e8, "kind": "shield_block", "payload": {"reason": "jailbreak attempt"}}]
    import maverick.audit.export as export
    monkeypatch.setattr(export, "iter_audit_events", lambda **kw: iter(older + newest))
    monkeypatch.setattr(app_mod, "_AUDIT_RANGE_SCAN_LIMIT", 1000)
    today = time.strftime("%Y-%m-%d", time.gmtime())
    page = client.get("/audit", params={"since": today, "until": today, "q": "Stopped by the safety filter", "n": 5}).text
    assert "Stopped by the safety filter" in page
    assert "jailbreak attempt" not in page
    note = client.get("/audit", params={"since": today, "until": today, "n": 5}).text
    assert "Showing 5 of 301 matching events before this page boundary." in note
    monkeypatch.setattr(app_mod, "_AUDIT_RANGE_SCAN_LIMIT", 100)
    cut = client.get("/audit", params={"since": today, "until": today, "n": 5}).text
    assert "The activity scan reached its limit. This is a partial view" in cut


def test_protection_actions_need_the_right_role(audit_log, client, monkeypatch):
    _as(monkeypatch, "auditor")
    assert client.post("/api/v1/audit/check", json={}).status_code == 200
    for path, body in (("/api/v1/audit/seal", {"preview": True}), ("/api/v1/audit/forward", {}),
                       ("/api/v1/audit/proof-bundle", None), ("/api/v1/audit/rotate-key", {}),
                       ("/api/v1/audit/write-once/push", {"preview": True})):
        kwargs = {"json": body} if body is not None else {}
        assert client.post(path, **kwargs).status_code == 403, path
    _as(monkeypatch, "viewer")
    assert client.post("/api/v1/audit/check", json={}).status_code == 403
    assert client.get("/api/v1/audit/download").status_code == 403


def test_forward_needs_a_connected_system(audit_log, client, monkeypatch):
    monkeypatch.delenv("MAVERICK_SIEM_DEST", raising=False)
    from maverick_dashboard import audit_actions_api
    monkeypatch.setattr(audit_actions_api, "_siem_dest", lambda: "")
    r = client.post("/api/v1/audit/forward", json={})
    assert r.status_code == 409 and "No security monitoring system" in r.json()["detail"]
    assert client.get("/api/v1/audit/actions").json()["security_system_connected"] is False


def test_binder_reads_plainly(audit_log, client, monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    from test_support.plain_language import developer_terms, visible_text
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    page = client.get("/audit/binder").text
    text = visible_text(page)
    assert developer_terms(page) == []
    for label in ("Last 90 days", "Download evidence file (for auditors)", "Records of processing",
                  "Separation-of-duties conflicts", "Technical details for auditors"):
        assert label in page, label
    assert "[privacy_ops]" not in text and "SHA-256" not in text and "onclick" not in page
