"""The privacy command center: the one-round-trip board aggregate and the
/privacy/board page behind it."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _seed(subject="Acme Corp", type_="vendor_risk", risky=True):
    from maverick.assessment import (
        AssessmentSession,
        get_template,
        save_session,
    )
    s = AssessmentSession(type=type_, subject=subject)
    for q in get_template(type_).questions:
        s.record(q.id, q.risk_answer if risky
                 else ("no" if q.risk_answer == "yes" else "yes"))
    save_session(s)
    return s


def _rev(sid):
    from maverick.assessment import load_saved
    return load_saved(sid)["revision"]


def test_board_payload_counts_and_shape():
    _seed("Acme Corp")
    _seed("Globex HRIS")
    clean = _seed("Initech Payroll", type_="pia", risky=False)
    assert client.post(
        f"/api/v1/assess/sessions/{clean.id}/decide",
        json={"decision": "approved", "cadence_days": 365,
              "expected_revision": _rev(clean.id)}).status_code == 200
    assert client.post(
        "/api/v1/privacy/dsar",
        json={"subject_id": "jordan@example.com",
              "kind": "access"}).status_code == 201

    body = client.get("/api/v1/privacy/board").json()
    assert body["kpis"]["assessments"] == 3
    assert body["kpis"]["open_work"] == 2          # the decided one left
    # The mix and the KPI agree with the shipped session rows.
    rows = body["sessions"]
    assert len(rows) == 3
    assert body["kpis"]["high_residual"] == sum(
        1 for r in rows if r["residual"] == "high")
    assert sum(body["risk_mix"]["residual"].values()) == 3
    assert sum(body["risk_mix"]["inherent"].values()) == 3
    # 12 months of throughput; everything landed in the current month.
    assert len(body["throughput"]) == 12
    assert body["throughput"][-1]["opened"] == 3
    assert body["throughput"][-1]["decided"] == 1
    assert body["deltas"]["opened"] == {"cur": 3, "prev": 0}
    # by_type covers both frameworks, largest first.
    types = {r["type"]: r for r in body["by_type"]}
    assert types["vendor_risk"]["total"] == 2
    assert types["pia"]["total"] == 1
    # Register planes: the DSAR shows up in aging + registers.
    assert body["records_enabled"] is True
    assert body["dsar"]["open"] == 1
    assert body["registers"]["dsar"] == 1
    # Posture gauges are the fixed five, each a real ratio.
    assert [p["key"] for p in body["posture"]] == [
        "dsar_sla", "review_cadence", "transfer_safeguards",
        "incident_clock", "dpa_coverage"]
    sla = body["posture"][0]
    assert (sla["ok"], sla["total"], sla["pct"]) == (1, 1, 100.0)
    row = rows[0]
    for key in ("id", "type", "subject", "status", "inherent", "residual",
                "created_at", "review_due", "risk_accepted"):
        assert key in row


def test_board_page_renders():
    resp = client.get("/privacy/board")
    assert resp.status_code == 200
    assert "Privacy command center" in resp.text
    assert "pb-donut" in resp.text
    # The workspace links to the board.
    assert "/privacy/board" in client.get("/privacy").text


def test_board_excludes_finance_chassis():
    _seed("Payments PIA", type_="pia")
    _seed("Q3 close", type_="sox_control")
    body = client.get("/api/v1/privacy/board").json()
    assert body["kpis"]["assessments"] == 1
    assert [r["type"] for r in body["by_type"]] == ["pia"]


def test_board_dsar_section_matches_aging_endpoint():
    for who in ("a@example.com", "b@example.com"):
        client.post("/api/v1/privacy/dsar",
                    json={"subject_id": who, "kind": "erasure"})
    board = client.get("/api/v1/privacy/board").json()
    aging = client.get("/api/v1/privacy/dsar/aging").json()
    assert board["dsar"] == aging


def test_board_degrades_when_privacy_ops_disabled(monkeypatch):
    from maverick import privacy_ops
    monkeypatch.setattr(privacy_ops, "enabled", lambda: False)
    _seed("Acme Corp")
    body = client.get("/api/v1/privacy/board").json()
    assert body["records_enabled"] is False
    assert body["kpis"]["assessments"] == 1     # assessment plane still live
    assert body["dsar"]["open"] == 0
    assert body["transfers"]["total"] == 0
    assert len(body["posture"]) == 5


def test_board_empty_tenant_zeroes():
    body = client.get("/api/v1/privacy/board").json()
    assert body["kpis"] == {"assessments": 0, "open_work": 0,
                            "high_residual": 0, "review_due": 0,
                            "risk_accepted": 0}
    assert len(body["throughput"]) == 12
    assert all(r["opened"] == 0 and r["decided"] == 0
               for r in body["throughput"])
    assert all(p["pct"] is None for p in body["posture"])
    assert body["sessions"] == []


def test_board_page_speaks_plainly_and_opens_assessments():
    html = client.get("/privacy/board").text
    assert "30 days" in html and "12 months" in html and "All time" in html
    assert "Data-subject requests: time left" in html
    assert "window.mvAssessmentReview.open(s.id)" in html
    assert 'id="mv-assessment-review"' in html or "mvAssessmentReview" in html
    for jargon in ("[privacy_ops]", "API payload", "load-bearing ·", "DSAR SLA runway",
                   "Chapter V safeguard coverage", "could not load the board", ">30d<", ">12m<"):
        assert jargon not in html, jargon
