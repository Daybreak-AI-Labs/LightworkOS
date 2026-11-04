"""The Privacy workspace: the module view over assessment records — worklist
with the risk pair and aging, stats, precedents, catalog, and the shared
review pop-out on the page."""
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


def _seed(subject="Acme CRM", risky=True, followups=False):
    from maverick.assessment import AssessmentSession, add_followups, save_session
    s = AssessmentSession(type="pia", subject=subject)
    s.record("pia_transfers", "yes" if risky else "no")
    s.record("pia_security", "yes")
    save_session(s)
    if followups:
        add_followups(s.id, ["Which sub-processors?"])
    return s


def test_page_renders_worklist_stats_and_catalog():
    _seed("Acme CRM", risky=True)
    _seed("Globex HRIS", risky=False, followups=True)
    resp = client.get("/privacy")
    assert resp.status_code == 200
    html = resp.text
    # Worklist rows with the risk pair and review triggers.
    assert "Acme CRM" in html and "Globex HRIS" in html
    assert 'class="btn pw-review-btn"' in html
    # The shared pop-out is on the page.
    assert 'id="arv-dialog"' in html
    # The catalog lists the PRIVACY frameworks — and only those (the finance
    # templates belong to a future Finance workspace, not this one).
    for label in ("Privacy Impact Assessment", "AI Risk Assessment",
                  "Vendor Risk Assessment"):
        assert label in html, label
    assert "SOX Control Assessment" not in html
    assert "Fraud Risk Assessment" not in html
    # Follow-up state surfaces as awaiting answers.
    assert "Awaiting answers" in html


def test_page_empty_state():
    resp = client.get("/privacy")
    assert resp.status_code == 200
    assert "No assessments yet" in resp.text


def test_closed_request_exposes_export_cleanup_failure_and_retry(monkeypatch):
    from maverick import privacy_ops

    request = privacy_ops.open_dsar("person@example.test", "access", channel="email")
    privacy_ops.fulfill_dsar(request["id"])
    monkeypatch.setattr(privacy_ops, "_remove_closed_dsar_export", lambda _record: False)

    closed = client.post(f"/api/v1/privacy/dsar/{request['id']}/close")
    assert closed.status_code == 200
    assert closed.json()["export_cleanup"]["status"] == "failed"
    assert "Saved export needs cleanup" in client.get("/privacy").text
    assert "Retry export cleanup" in client.get(f"/privacy/dsar/{request['id']}").text

    monkeypatch.setattr(privacy_ops, "_remove_closed_dsar_export", lambda _record: True)
    retried = client.post(f"/api/v1/privacy/dsar/{request['id']}/close")
    assert retried.status_code == 200
    assert retried.json()["export_cleanup"]["status"] == "removed"
    assert "Saved export needs cleanup" not in client.get("/privacy").text


def test_collected_access_export_is_not_presented_as_delivered():
    from maverick import privacy_ops

    request = privacy_ops.open_dsar("person@example.test", "access", channel="email")
    initial = client.get(f"/privacy/dsar/{request['id']}")
    assert "Collect their data" in initial.text
    assert "Collect their data and mark answered" not in initial.text

    collected = privacy_ops.fulfill_dsar(request["id"])
    assert collected is not None and collected["status"] == "fulfilled"
    detail = client.get(f"/privacy/dsar/{request['id']}")
    worklist = client.get("/privacy")
    report = client.get("/privacy/report")
    assert all(response.status_code == 200 for response in (detail, worklist, report))
    assert "Data collected</span>" in detail.text
    assert "does not confirm that the requester received it" in detail.text
    assert "The saved export is removed when you close this request" in detail.text
    assert collected["fulfillment"]["export_path"] not in detail.text
    assert "Data collected</span>" in worklist.text
    assert "Completed</span>" not in worklist.text
    assert "Handled requests answered on time" in report.text
    assert "It does not confirm delivery or deletion" in report.text


def test_collected_export_download_is_verified_audited_and_unavailable_after_close(monkeypatch):
    from maverick import audit, privacy_ops

    request = privacy_ops.open_dsar("person@example.test", "access", channel="email")
    privacy_ops.fulfill_dsar(request["id"])
    events = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **fields: events.append((kind, fields)) or True)
    detail = client.get(f"/privacy/dsar/{request['id']}")
    assert 'id="dsar-download"' in detail.text

    url = f"/api/v1/privacy/dsar/{request['id']}/export"
    downloaded = client.post(url)
    assert downloaded.status_code == 200
    assert downloaded.headers["cache-control"] == "private, no-store"
    assert downloaded.headers["content-disposition"].endswith(f'{request["id"]}-data.json"')
    assert downloaded.json()["subject"]["user_id"] == "person@example.test"
    assert "_lightwork_export" not in downloaded.json()
    assert len(events) == 1 and events[0][1]["action"] == "export_access_authorized"
    assert events[0][1]["record_id"] == request["id"]
    assert "person@example.test" not in str(events)

    monkeypatch.setattr(audit, "audit_event", lambda *_args, **_kwargs: False)
    refused = client.post(url)
    assert refused.status_code == 503 and "person@example.test" not in refused.text
    privacy_ops.close_dsar(request["id"])
    assert client.post(url).status_code == 404
    assert 'id="dsar-download"' not in client.get(f"/privacy/dsar/{request['id']}").text


def test_collected_export_download_rejects_a_recorded_path_change():
    from maverick import privacy_ops

    request = privacy_ops.open_dsar("person@example.test", "access", channel="email")
    privacy_ops.fulfill_dsar(request["id"])
    def change_path(row):
        row["fulfillment"] = {**row["fulfillment"], "export_path": "C:/other-person-export.json"}

    privacy_ops._DSAR.update(request["id"], change_path)
    response = client.post(f"/api/v1/privacy/dsar/{request['id']}/export")
    assert response.status_code == 409
    assert "could not be verified" in response.text
    assert "other-person-export.json" not in response.text


def test_templates_catalog_api():
    resp = client.get("/api/v1/assess/templates")
    assert resp.status_code == 200
    types = {t["type"] for t in resp.json()["templates"]}
    assert {"pia", "aira", "vendor_risk", "hipaa", "soc2", "pci_dss"} <= types
    assert all(t["questions"] > 0 for t in resp.json()["templates"])


def test_approvals_page_still_carries_shared_popout():
    resp = client.get("/approvals")
    assert resp.status_code == 200
    assert resp.text.count('id="arv-dialog"') == 1
    assert "mvAssessmentReview" in resp.text


def test_records_section_renders_all_four_types():
    from maverick import privacy_ops

    from test_support.plain_language import visible_text

    dpa_text = (
        "processor acts on documented instructions from the controller; "
        "audit rights; retention for 12 months"
    )
    evidence = privacy_ops._build_document_evidence(
        data=dpa_text.encode("utf-8"),
        text=dpa_text,
        mime="application/pdf",
        source="test-connector",
        doc_id="opaque-test-document",
        ref=None,
        extraction={
            "method": "pdf_page_content_streams",
            "scope": "page_referenced",
            "confidence": "untrusted",
            "review_required": True,
            "referenced_streams": 1,
        },
    )
    privacy_ops.review_dpa(
        "Acme Corp", dpa_text,
        document_name="acme-dpa.pdf",
        _document_evidence=evidence,
    )
    privacy_ops.register_ai_system(
        "CV screener", "ranks job candidates for hiring")
    s = _seed("Acme CRM")
    privacy_ops.draft_ropa_from_assessment(s.id)
    dsar = privacy_ops.open_dsar(
        "jordan@example.com", "erasure", channel="email",
    )
    privacy_ops.fulfill_dsar(dsar["id"])

    html = client.get("/privacy").text
    # Technical-copy checks apply to the page, not the bundled translation
    # catalog, which also contains support copy for other workspaces.
    page_text = visible_text(html)
    # DPA reviews tab: vendor row + the clause-detail trigger.
    assert "Acme Corp" in html and "acme-dpa.pdf" in html
    assert 'class="btn pw-dpa-clauses"' in html
    assert "a person must check it" in html
    assert "How it was read" in html
    assert "Technical record of the file" in html
    assert "SHA-256" not in page_text
    assert "document_id" not in page_text
    # AI registry tab: high-risk tier from the Annex III employment test.
    assert "CV screener" in html
    assert ">High</span>" in html
    # RoPA tab: the drafted Art. 30 entry with provenance + CSV export.
    assert "Processing via Acme CRM" in html
    assert "/api/v1/privacy/ropa/export.csv" in html
    # DSAR tab: subject + 30-day clock; erasure needs the operator step.
    assert "jordan@example.com" in html
    assert "days left" in html
    assert "Deletion is never done from this list" in html
    assert "maverick erase" not in page_text
    assert "erase_command" not in page_text
    # The records tab strip carries the counts (the old hero stat tiles were
    # superseded by the live executive board).
    assert 'data-mv-tab="dsar"' in html and 'data-mv-tab="ropa"' in html


def test_records_section_hidden_when_disabled(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[privacy_ops]\nenable = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick import config
    config.reset_config_cache()
    html = client.get("/privacy").text
    assert "Privacy records" not in html
    assert "open DSARs" not in html
    # The assessment workspace itself still stands.
    assert "Worklist" in html


def test_decide_endpoint_and_review_due_surfacing(monkeypatch):
    import time as _t

    from maverick.assessment import load_saved

    s = _seed("Acme CRM", risky=True)
    resp = client.post(f"/api/v1/assess/sessions/{s.id}/decide",
                       json={"decision": "approved", "cadence_days": 30,
                             "expected_revision": load_saved(s.id)["revision"]})
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "approved"
    assert client.post("/api/v1/assess/sessions/nope/decide",
                       json={"decision": "approved",
                             "expected_revision": 0}).status_code == 404
    assert client.post(f"/api/v1/assess/sessions/{s.id}/decide",
                       json={"decision": "maybe",
                             "expected_revision": resp.json()["revision"]}).status_code == 422

    html = client.get("/privacy").text
    assert ">Approved</span>" in html
    assert "Re-review in" in html
    assert "Due for re-review (0)" in html

    # The cadence elapses: the record surfaces as due.
    real = _t.time
    monkeypatch.setattr(_t, "time", lambda: real() + 31 * 86400)
    html = client.get("/privacy").text
    assert "Due for re-review (1)" in html
    assert "overdue" in html


def test_template_editor_crud_and_department_catalog():
    def governed_payload(type_: str, values: dict):
        state = client.get(
            f"/api/v1/assess/template-state/{type_}",
        ).json()
        return {
            **values,
            "expected_revision": state["revision"],
            "expected_digest": state["digest"],
        }

    # Author a new privacy questionnaire from the catalog.
    resp = client.put("/api/v1/assess/templates/dpia_lite", json=governed_payload(
        "dpia_lite", {
        "title": "DPIA Lite", "framework": "GDPR Art. 35 (lightweight)",
        "department": "privacy",
        "questions": [{"text": "Is the processing high risk?",
                       "risk_answer": "yes", "severity": "high"}],
    }))
    assert resp.status_code == 200, resp.text
    assert resp.json()["custom"] is True
    # It appears in the privacy catalog but not finance's.
    assert "DPIA Lite" in client.get("/privacy").text
    assert "DPIA Lite" not in client.get("/finance").text
    # Full read-back for the editor.
    full = client.get("/api/v1/assess/templates/dpia_lite").json()
    assert full["questions"][0]["id"] == "dpia_lite_q1"
    # Overriding a built-in flags it custom; deleting restores it.
    orig = client.get("/api/v1/assess/templates/pia").json()
    assert orig["custom"] is False and len(orig["questions"]) == 10
    resp = client.put("/api/v1/assess/templates/pia", json=governed_payload(
        "pia", {
        "title": "PIA (company edition)", "framework": "GDPR",
        "questions": [{"text": "Only company question?",
                       "risk_answer": "no", "severity": "low"}],
    }))
    assert resp.status_code == 200
    assert "PIA (company edition)" in client.get("/privacy").text
    assert client.delete(
        "/api/v1/assess/templates/pia",
        params={"expected_revision": resp.json()["revision"],
                "expected_digest": resp.json()["digest"]},
    ).json()[
        "builtin_restored"] is True
    assert client.get("/api/v1/assess/templates/pia").json()["custom"] is False
    # Validation surfaces as 422 with the human-readable reason.
    resp = client.put("/api/v1/assess/templates/bad", json=governed_payload(
        "bad", {
        "title": "X", "framework": "Y",
        "questions": [{"text": "q?", "severity": "high",
                       "risk_answer": "yes", "id": "dup"},
                      {"text": "q2?", "severity": "high",
                       "risk_answer": "yes", "id": "dup"}],
    }))
    assert resp.status_code == 422
    assert client.delete(
        "/api/v1/assess/templates/never",
        params={"expected_revision": 0, "expected_digest": ""},
    ).status_code == 404


def test_program_report_page_and_api():
    from maverick import privacy_ops
    s = _seed("Acme CRM", risky=True)
    from maverick.assessment import decide_assessment
    decide_assessment(s.id, "approved", cadence_days=30)
    privacy_ops.review_dpa("Acme Corp", "audit rights and retention only")
    privacy_ops.open_dsar("j@example.com", "access")
    inc = privacy_ops.open_incident("Misdirected batch", severity="high")
    privacy_ops.decide_incident_notification(inc["id"], True, rationale="x")

    api = client.get("/api/v1/privacy/report").json()
    assert api["assessments"]["total"] == 1
    assert api["assessments"]["by_status"]["approved"] == 1
    assert api["dsar"]["open"] == 1
    assert api["incidents"]["notified"] == 1
    assert api["dpa"]["total"] == 1
    assert api["dpa"]["top_gaps"], "gaps list the missing clauses"

    html = client.get("/privacy/report").text
    assert "Privacy program report" in html
    assert "Clause most often missing" in html
    assert "Print or save as PDF" in html
    assert "Approved" in html and "approved" not in html.split("<main", 1)[-1].split("</main>")[0].replace("Approved", "")
    for jargon in (">JSON<", "Art. 28", "past 72h", "documented-no", "back to the workspace"):
        assert jargon not in html, jargon
    # The workspace links to it.
    assert 'href="/privacy/report"' in client.get("/privacy").text


def test_worklist_and_catalog_read_plainly():
    from test_support.plain_language import developer_terms

    _seed("Acme CRM", risky=True)
    html = client.get("/privacy").text
    worklist = html.split('<div class="section-head"><h2>Worklist</h2></div>', 1)[1].split("<dialog", 1)[0]
    assert developer_terms("<main>" + worklist + "</main>") == []
    assert "Questionnaire" in worklist and "Risk before → after safeguards" in worklist
    assert "window.prompt" not in html and "window.alert" not in html
    assert "/api/v1/assess/reviewers" in html
    assert "Type (slug)" not in html and "Publish release" not in html


def test_program_report_counts_only_recorded_answers():
    from maverick import privacy_ops

    closed = privacy_ops.open_dsar("j@example.com", "erasure", jurisdiction="eu_gdpr")
    privacy_ops.close_dsar(closed["id"], closed_by="dpo")
    waiting = privacy_ops.open_dsar("k@example.com", "erasure")
    privacy_ops.fulfill_dsar(waiting["id"], fulfilled_by="dpo")
    html = client.get("/privacy/report").text
    main = html.split("<main", 1)[-1].split("</main>", 1)[0]
    assert "0 of 1" in main                        # answered on time, of those closed
    assert "Closed without a recorded answer" in main
    assert "Past the 30-day deadline" not in main  # deadlines differ by law
    api = client.get("/api/v1/privacy/report").json()["dsar"]
    assert api["open"] == 1 and api["closed_without_response"] == 1
