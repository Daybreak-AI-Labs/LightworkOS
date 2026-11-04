"""Section B privacy-program depth: risk-acceptance, re-review triggers,
vendor risk trend, bulk import, DSAR SLA aging, and the transfer map."""
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


def _seed(
    subject="Acme Corp",
    type_="vendor_risk",
    risky=True,
    *,
    created_at: float | None = None,
):
    from maverick.assessment import AssessmentSession, get_template, save_session
    s = AssessmentSession(type=type_, subject=subject)
    if created_at is not None:
        s.created_at = created_at
    for q in get_template(type_).questions:
        s.record(q.id, q.risk_answer if risky
                 else ("no" if q.risk_answer == "yes" else "yes"))
    save_session(s)
    return s


def _rev(sid):
    from maverick.assessment import load_saved
    return load_saved(sid)["revision"]


# --- B11 risk acceptance ---------------------------------------------------
def test_accept_risk_records_owner_rationale_and_expiry():
    s = _seed()
    client.post(f"/api/v1/assess/sessions/{s.id}/decide",
                json={"decision": "approved", "cadence_days": 365,
                      "expected_revision": _rev(s.id)})
    resp = client.post(f"/api/v1/assess/sessions/{s.id}/accept-risk",
                       json={"rationale": "compensating controls in place",
                             "expires_days": 30,
                             "expected_revision": _rev(s.id)})
    assert resp.status_code == 200, resp.text
    assert resp.json()["risk_acceptance"]["rationale"].startswith("compensating")
    # Empty rationale is a 422; stale revision is a 409.
    assert client.post(f"/api/v1/assess/sessions/{s.id}/accept-risk",
                       json={"rationale": "", "expires_days": 30,
                             "expected_revision": _rev(s.id)}).status_code == 422
    assert client.post(f"/api/v1/assess/sessions/{s.id}/accept-risk",
                       json={"rationale": "x", "expires_days": 30,
                             "expected_revision": 999}).status_code == 409


def test_re_decision_clears_a_stale_risk_acceptance():
    # A short acceptance that has already lapsed must not keep the record
    # flagged due after the reviewer re-approves it.
    import time as _t

    from maverick.assessment import list_saved, load_saved
    s = _seed(risky=False)
    client.post(f"/api/v1/assess/sessions/{s.id}/decide",
                json={"decision": "approved", "cadence_days": 365,
                      "expected_revision": _rev(s.id)})
    client.post(f"/api/v1/assess/sessions/{s.id}/accept-risk",
                json={"rationale": "temporary", "expires_days": 1,
                      "expected_revision": _rev(s.id)})
    # Fast-forward past the acceptance expiry: the record is due.
    real = _t.time
    import maverick.assessment as A
    A.time.time = lambda: real() + 2 * 86400  # type: ignore[assignment]
    try:
        row = [r for r in list_saved() if r["id"] == s.id][0]
        assert row["review_due"] and row["acceptance_expired"]
        # Re-approve: the stale acceptance is cleared, record no longer due.
        client.post(f"/api/v1/assess/sessions/{s.id}/decide",
                    json={"decision": "approved", "cadence_days": 365,
                          "expected_revision": _rev(s.id)})
        assert load_saved(s.id).get("risk_acceptance") is None
        row = [r for r in list_saved() if r["id"] == s.id][0]
        assert not row["review_due"] and not row["risk_accepted"]
    finally:
        A.time.time = real  # type: ignore[assignment]


def test_bulk_import_caps_row_count():
    from maverick_dashboard.api import _BULK_IMPORT_MAX_ROWS
    n = _BULK_IMPORT_MAX_ROWS + 5
    csv = "\n".join(f"Vendor {i},vendor_risk" for i in range(n))
    d = client.post("/api/v1/assess/bulk-import", json={"csv": csv}).json()
    assert d["created_count"] == _BULK_IMPORT_MAX_ROWS
    assert d["skipped_over_cap"] == 5


# --- B14 re-review triggers ------------------------------------------------
def test_trigger_review_forces_due_and_renewal_flips_due():
    s = _seed(risky=False)
    client.post(f"/api/v1/assess/sessions/{s.id}/decide",
                json={"decision": "approved", "cadence_days": 365,
                      "expected_revision": _rev(s.id)})
    from maverick.assessment import list_saved
    assert not [r for r in list_saved() if r["id"] == s.id][0]["review_due"]
    # Forced trigger with a reason.
    resp = client.post(f"/api/v1/assess/sessions/{s.id}/trigger-review",
                       json={"reason": "new sub-processor added",
                             "expected_revision": _rev(s.id)})
    assert resp.status_code == 200, resp.text
    row = [r for r in list_saved() if r["id"] == s.id][0]
    assert row["review_due"] and "sub-processor" in row["review_due_reason"]
    # A fresh decision clears the forced trigger.
    client.post(f"/api/v1/assess/sessions/{s.id}/decide",
                json={"decision": "approved", "cadence_days": 365,
                      "expected_revision": _rev(s.id)})
    assert not [r for r in list_saved() if r["id"] == s.id][0]["review_due"]
    # A past renewal date flips it due automatically.
    import time
    resp = client.post(f"/api/v1/assess/sessions/{s.id}/trigger-review",
                       json={"renewal_at": time.time() - 100,
                             "expected_revision": _rev(s.id)})
    assert resp.status_code == 200
    row = [r for r in list_saved() if r["id"] == s.id][0]
    assert row["review_due"] and "renewal" in row["review_due_reason"]


# --- B12 vendor risk trend -------------------------------------------------
def test_risk_trend_endpoint_reports_direction():
    _seed("TrendCo", risky=True, created_at=100.0)      # older: high
    _seed("TrendCo", risky=False, created_at=101.0)     # newer: minimal
    d = client.get("/api/v1/assess/trend",
                   params={"subject": "TrendCo", "type": "vendor_risk"}).json()
    assert len(d["trend"]) == 2
    assert d["trend"][0]["residual_risk"] == "high"
    assert d["trend"][-1]["residual_risk"] == "minimal"
    assert d["direction"] == "down"


def test_equal_timestamp_trend_does_not_infer_direction_from_random_ids():
    _seed("Tied TrendCo", risky=True, created_at=200.0)
    _seed("Tied TrendCo", risky=False, created_at=200.0)

    data = client.get(
        "/api/v1/assess/trend",
        params={"subject": "Tied TrendCo", "type": "vendor_risk"},
    ).json()

    assert len(data["trend"]) == 2
    assert data["direction"] == "unknown"
    assert "order is not provable" in data["direction_reason"]


# --- B13 bulk import -------------------------------------------------------
def test_bulk_import_creates_queue_and_reports_bad_rows():
    csv = ("subject,type\n"
           "Acme Corp,vendor_risk\n"
           "Globex,pia\n"
           "Umbrella,dpia\n"
           "Nope Inc,not_a_real_type\n")
    d = client.post("/api/v1/assess/bulk-import", json={"csv": csv}).json()
    assert d["created_count"] == 3 and d["error_count"] == 1
    assert d["errors"][0]["subject"] == "Nope Inc"
    from maverick.assessment import list_saved
    subjects = {r["subject"] for r in list_saved()}
    assert {"Acme Corp", "Globex", "Umbrella"} <= subjects


# --- B15 DSAR SLA aging ----------------------------------------------------
def test_dsar_aging_buckets_open_requests():
    from maverick import privacy_ops
    privacy_ops.open_dsar("a@example.com", "access")
    privacy_ops.open_dsar("b@example.com", "erasure")
    d = client.get("/api/v1/privacy/dsar/aging").json()
    assert d["open"] == 2
    # Fresh 30-day requests land in the 15-30d band, none overdue.
    assert d["bands"]["d15_30"] == 2 and d["overdue"] == 0
    assert "access" in d["by_kind"] and "erasure" in d["by_kind"]


# --- B16 transfer map ------------------------------------------------------
def test_transfer_map_draws_flows_with_safeguard_flag():
    from maverick import privacy_ops
    privacy_ops.upsert_ropa({"activity": "CRM sync", "controller": "Us",
                             "transfers": "United States (SCCs Module 2)",
                             "recipients": "Acme US"})
    privacy_ops.upsert_ropa({"activity": "Ad pixel", "controller": "Us",
                             "transfers": "United States — no safeguard",
                             "recipients": "AdCo"})
    privacy_ops.upsert_ropa({"activity": "Local only", "controller": "Us",
                             "transfers": "none", "recipients": "internal"})
    _seed("EU-US analytics", type_="tia", risky=True)
    d = client.get("/api/v1/privacy/transfer-map").json()
    # Two RoPA transfers (the "none" one is excluded) + one TIA = 3 flows.
    assert d["total"] == 3
    safeguarded = {f["activity"]: f["safeguarded"] for f in d["flows"]}
    assert safeguarded.get("CRM sync") is True
    assert safeguarded.get("Ad pixel") is False
    assert d["unsafeguarded"] >= 1


# --- UI surfaces -----------------------------------------------------------
def test_privacy_page_renders_program_depth_ui():
    html = client.get("/privacy").text
    # Program insights (DSAR heatmap + transfer map) and bulk import render.
    assert "Program insights" in html
    assert 'id="pv-dsar-heat"' in html
    assert "/privacy/dsar/aging" in html
    assert "/privacy/transfer-map" in html
    assert "Queue assessments for many vendors" in html
    assert "/api/v1/assess/bulk-import" in html


def test_review_popout_carries_lifecycle_controls():
    html = client.get("/privacy").text
    assert 'id="arv-accept"' in html and 'id="arv-trigger"' in html
    # The pop-out's code is a deferred static file the page loads.
    assert "/static/lightwork-assessment-review.js" in html
    script = client.get("/static/lightwork-assessment-review.js").text
    assert "/accept-risk" in script and "/trigger-review" in script
    assert "/api/v1/assess/trend" in script   # trend line in the pop-out
    assert "review order unknown" in script
