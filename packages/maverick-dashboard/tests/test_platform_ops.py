"""Platform ops additions: the audit binder, the partner fleet console,
the acceptance-learning KPIs on the board, and question ROI."""
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


def _decide(sid, decision="approved"):
    from maverick.assessment import load_saved
    rev = load_saved(sid)["revision"]
    r = client.post(f"/api/v1/assess/sessions/{sid}/decide",
                    json={"decision": decision, "cadence_days": 365,
                          "expected_revision": rev})
    assert r.status_code == 200, r.text


# --- learning KPI -----------------------------------------------------------
def test_board_learning_first_pass_acceptance():
    a = _seed("Acme")
    _seed("Globex")                      # stays undecided
    _decide(a.id)                        # approved, no follow-ups
    body = client.get("/api/v1/privacy/board").json()
    learn = body["learning"]
    assert (learn["decided"], learn["first_pass"]) == (1, 1)
    assert learn["first_pass_rate"] == 100.0
    assert len(learn["trend"]) == 12
    assert learn["trend"][-1]["first_pass"] == 1
    assert learn["median_days_to_decision"] is not None


def test_followups_make_a_decision_qualified_not_first_pass():
    from maverick.assessment import load_saved
    a = _seed("Acme")
    rev = load_saved(a.id)["revision"]
    r = client.post(f"/api/v1/assess/sessions/{a.id}/followups",
                    json={"questions": ["Who is the DPO?"],
                          "expected_revision": rev})
    assert r.status_code == 200, r.text
    # Answer it (governance refuses approval with open follow-ups), then
    # the approval counts as QUALIFIED — the draft needed a round-trip.
    from maverick.assessment import answer_followup
    fid = load_saved(a.id)["followups"][0]["id"]
    assert answer_followup(a.id, fid, "Dana Osei, DPO") is not None
    _decide(a.id)
    learn = client.get("/api/v1/privacy/board").json()["learning"]
    assert (learn["decided"], learn["first_pass"],
            learn["qualified"]) == (1, 0, 1)


# --- question ROI -----------------------------------------------------------
def test_question_roi_verdicts_and_rating_impact():
    from maverick.assessment import (
        AssessmentSession,
        get_template,
        save_session,
    )
    tpl = get_template("vendor_risk")
    high_q = next(q for q in tpl.questions if q.severity == "high")
    # One assessment where ONLY that high question fires: removing its
    # finding changes the rating -> load-bearing.
    s = AssessmentSession(type="vendor_risk", subject="Solo Risk Inc")
    for q in tpl.questions:
        s.record(q.id, q.risk_answer if q.id == high_q.id
                 else ("no" if q.risk_answer == "yes" else "yes"))
    save_session(s)
    roi = client.get("/api/v1/assess/question-roi",
                     params={"type": "vendor_risk"}).json()
    assert roi["assessed"] == 1 and roi["load_bearing"] >= 1
    rows = {r["question_id"]: r for r in roi["questions"]}
    assert rows[high_q.id]["verdict"] == "load-bearing"
    assert rows[high_q.id]["fired"] == 1
    # Questions that never fired are 'unproven' below the evidence floor.
    others = [r for qid, r in rows.items() if qid != high_q.id]
    assert all(r["verdict"] == "unproven" for r in others)
    # The board page carries the panel.
    page = client.get("/privacy/board").text
    assert "Which questions matter" in page and "Drafts accepted first time" in page


# --- audit binder -----------------------------------------------------------
def test_audit_binder_payload_and_page():
    a = _seed("Acme")
    _decide(a.id)
    body = client.get("/api/v1/audit/binder?days=30").json()
    assert body["window_days"] == 30
    for key in ("chain", "approvals", "assessments", "registers",
                "learning"):
        assert key in body
    assert body["assessments"][0]["subject"] == "Acme"
    assert body["assessments"][0]["revision"] >= 1
    assert body["learning"]["decided"] == 1
    page = client.get("/audit/binder")
    assert page.status_code == 200
    assert "Audit binder" in page.text
    assert "Tamper-evident activity log" in page.text


# --- partner fleet ----------------------------------------------------------
def test_partner_registry_check_and_rollup(monkeypatch):
    monkeypatch.setenv("MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK", "true")
    r = client.post("/api/v1/partner/tenants",
                    json={"name": "Acme Hospitality",
                          "base_url": "http://127.0.0.1:9",   # closed port
                          "token": "sekret", "theme": "acme-light",
                          "trusted_test_estate_loopback": True})
    assert r.status_code == 201, r.text
    row = r.json()
    assert row["has_token"] is True and "token" not in row
    tid = row["id"]

    chk = client.post(f"/api/v1/partner/tenants/{tid}/check").json()
    assert chk["tenant"]["last_check"]["ok"] is False
    assert chk["tenant"]["last_check"]["error"]

    fleet = client.get("/api/v1/partner/fleet").json()
    assert fleet["fleet"]["total"] == 1
    assert fleet["fleet"]["healthy"] == 0
    assert fleet["fleet"]["dollars"] == 0

    page = client.get("/partner")
    assert page.status_code == 200 and "Partner fleet" in page.text
    from test_support.plain_language import developer_terms
    assert developer_terms(page.text) == []
    assert "mvUndo(" in page.text             # removing a client offers Undo first

    assert client.delete(
        f"/api/v1/partner/tenants/{tid}").json()["deleted"] == tid
    assert client.get(
        "/api/v1/partner/fleet").json()["fleet"]["total"] == 0


def test_partner_tenant_rejects_non_http_urls():
    r = client.post("/api/v1/partner/tenants",
                    json={"name": "Bad", "base_url": "file:///etc/passwd"})
    assert r.status_code == 422


def test_partner_probe_blocks_private_network_targets(monkeypatch):
    from maverick_dashboard.api import _probe_tenant

    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    result = _probe_tenant(
        {"base_url": "http://127.0.0.1:9", "token": "never-sent"}
    )

    assert result["ok"] is False
    assert "non-public address" in result["error"]


def test_partner_probe_preserves_bearer_header_on_governed_requests(monkeypatch):
    from maverick.tools import _ssrf
    from maverick_dashboard.api import _probe_tenant

    calls: list[tuple[str, dict, float]] = []

    class Response:
        status_code = 200

        def __init__(self, body):
            self._body = body

        def json(self):
            return self._body

    def safe_get(url, *, headers, timeout):
        calls.append((url, headers, timeout))
        if url.endswith("/value.json"):
            return Response({"agent": "worker", "version": "1", "cases": 1})
        if url.endswith("/external-agents"):
            return Response({"status": {"enrolled": 2, "active": 1}})
        return Response({})

    monkeypatch.setattr(_ssrf, "safe_get", safe_get)
    result = _probe_tenant(
        {"base_url": "https://tenant.example", "token": "fleet-token"}
    )

    assert result["ok"] is True
    assert [url for url, _headers, _timeout in calls] == [
        "https://tenant.example/health",
        "https://tenant.example/value.json",
        "https://tenant.example/api/v1/external-agents",
    ]
    assert all(headers == {"Authorization": "Bearer fleet-token"} for _, headers, _ in calls)
    assert all(timeout == 4 for _, _, timeout in calls)
