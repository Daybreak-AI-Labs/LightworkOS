"""Privacy ops over the dashboard API: DPA reviews, AI registry, RoPA
(+ Art. 30 CSV), and the DSAR tracker.

Mutating /api/v1 requests carry a same-origin Origin (the CSRF contract).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

DPA_TEXT = """The processor shall process personal data only on documented
instructions from the controller, is bound by confidentiality, implements the
technical and organisational measures of Article 32, uses no sub-processor
without prior written authorization, shall assist the controller with data
subject requests, shall notify the controller of any personal data breach,
shall delete or return all personal data upon termination, grants audit
rights, relies on Standard Contractual Clauses for transfers, and retains
data for 12 months (retention schedule)."""


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in (
        "MAVERICK_CONNECTIONS", "MAVERICK_ENTERPRISE",
        "MSGRAPH_ACCESS_TOKEN", "MSGRAPH_BASE_URL",
        "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH",
        "MAVERICK_DASHBOARD_INVITES",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def _enable_oidc(monkeypatch):
    import maverick_dashboard.auth as auth
    import maverick_dashboard.rbac as rbac
    from maverick import oidc

    # The outer dashboard middleware checks the kernel-level configuration,
    # while the dependency below owns token verification.
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token,
            issuer="https://issuer.example",
            audience="maverick",
            claims={"sub": token},
        ),
    )


def _as(user: str) -> dict:
    return {
        "Authorization": f"Bearer {user}",
        "Origin": "http://127.0.0.1",
    }


def test_dpa_review_round_trip():
    resp = client.post("/api/v1/privacy/dpa-reviews", json={
        "vendor": "Acme Corp", "document_name": "acme-dpa.pdf",
        "text": DPA_TEXT})
    assert resp.status_code == 201, resp.text
    rec = resp.json()
    assert rec["clauses_present"] >= 9
    assert rec["residual_risk"] in ("minimal", "low")
    listed = client.get("/api/v1/privacy/dpa-reviews").json()["reviews"]
    assert listed[0]["vendor"] == "Acme Corp"
    full = client.get(f"/api/v1/privacy/dpa-reviews/{rec['id']}").json()
    assert len(full["clauses"]) == rec["clauses_total"]
    assert client.get("/api/v1/privacy/dpa-reviews/nope").status_code == 404


def test_ai_registry_classifies_on_create():
    resp = client.post("/api/v1/privacy/ai-systems", json={
        "name": "CV screener", "purpose": "ranks job candidates for hiring"})
    assert resp.status_code == 201
    assert resp.json()["tier"] == "high"
    systems = client.get("/api/v1/privacy/ai-systems").json()["systems"]
    assert systems[0]["name"] == "CV screener"


def test_ropa_upsert_from_assessment_and_csv_export():
    from maverick.assessment import AssessmentSession, save_session
    s = AssessmentSession(type="pia", subject="Acme CRM")
    s.record("pia_transfers", "yes", "us-east-1, no SCCs")
    s.record("pia_retention", "no")
    save_session(s)

    resp = client.post(f"/api/v1/privacy/ropa/from-assessment/{s.id}")
    assert resp.status_code == 201, resp.text
    entry = resp.json()
    assert "Acme CRM" in entry["activity"]
    # Manual edit through the same upsert.
    resp = client.post("/api/v1/privacy/ropa", json={
        "ropa_id": entry["id"], "revision": entry["revision"],
        "controller": "Company Ltd"})
    assert resp.status_code == 201
    updated = resp.json()
    assert updated["controller"] == "Company Ltd"
    # An update cannot silently omit compare-and-swap or overwrite a version
    # that another operator has already changed.
    missing_revision = client.post("/api/v1/privacy/ropa", json={
        "ropa_id": entry["id"], "controller": "Lost update"})
    assert missing_revision.status_code == 422
    stale = client.post("/api/v1/privacy/ropa", json={
        "ropa_id": entry["id"], "revision": entry["revision"],
        "controller": "Stale operator"})
    assert stale.status_code == 409

    csv_resp = client.get("/api/v1/privacy/ropa/export.csv")
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "Acme CRM" in csv_resp.text and "Company Ltd" in csv_resp.text

    assert client.post(
        "/api/v1/privacy/ropa/from-assessment/nope").status_code == 404


def test_ropa_csv_neutralizes_formula_injection_and_preserves_normal_values():
    import csv
    import io

    created = client.post("/api/v1/privacy/ropa", json={
        "activity": "=HYPERLINK(\"https://attacker.example\")",
        "purpose": "  +SUM(A1:A2)",
        "controller": "\t-2+3",
        "data_categories": "@external-command",
        "recipients": "Ordinary recipient",
    })
    assert created.status_code == 201, created.text

    exported = client.get("/api/v1/privacy/ropa/export.csv")
    assert exported.status_code == 200
    row = next(csv.DictReader(io.StringIO(exported.text)))
    assert row["activity"] == "'=HYPERLINK(\"https://attacker.example\")"
    assert row["purpose"] == "'  +SUM(A1:A2)"
    assert row["controller"] == "'\t-2+3"
    assert row["data_categories"] == "'@external-command"
    assert row["recipients"] == "Ordinary recipient"


@pytest.mark.parametrize(
    "cell",
    [
        "=formula",
        "+formula",
        "-formula",
        "@formula",
        "\tformula",
        "\rformula",
        "\nformula",
        "  =formula",
        " \t=formula",
    ],
)
def test_csv_formula_guard_covers_control_and_whitespace_prefixes(cell):
    from maverick_dashboard.api import _csv_formula_safe

    assert _csv_formula_safe(cell) == "'" + cell
    assert _csv_formula_safe("ordinary text") == "ordinary text"


def test_dsar_lifecycle_over_real_export(monkeypatch):
    from maverick import dsar

    original_export = dsar.export_subject_data
    calls = 0

    def counted_export(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_export(*args, **kwargs)

    monkeypatch.setattr(dsar, "export_subject_data", counted_export)
    resp = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "jordan@example.com", "kind": "access",
        "channel": "email"})
    assert resp.status_code == 201
    rid = resp.json()["id"]
    rows = client.get("/api/v1/privacy/dsar").json()["requests"]
    assert rows[0]["days_left"] >= 28

    done = client.post(f"/api/v1/privacy/dsar/{rid}/fulfill")
    assert done.status_code == 200
    assert done.json()["status"] == "fulfilled"
    assert "counts" in done.json()["fulfillment"]
    # The list survives fulfillment: the export bundle written next to the
    # records must not be mistaken for a request (regression: KeyError).
    rows = client.get("/api/v1/privacy/dsar").json()["requests"]
    assert [r["status"] for r in rows if r["id"] == rid] == ["fulfilled"]
    # Retry is an idempotent replay of the same durable artifact; the export
    # machinery ran exactly once.
    retried = client.post(f"/api/v1/privacy/dsar/{rid}/fulfill")
    assert retried.status_code == 200
    assert retried.json()["fulfillment"] == done.json()["fulfillment"]
    assert retried.json()["revision"] == done.json()["revision"]
    assert calls == 1
    assert client.post(f"/api/v1/privacy/dsar/{rid}/close").status_code == 200


def test_dsar_erasure_never_destructive_from_api():
    rid = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "u1", "kind": "erasure", "channel": "slack"}).json()["id"]
    ready = client.post(f"/api/v1/privacy/dsar/{rid}/fulfill").json()
    assert ready["status"] == "awaiting_erasure"
    handoff = ready["fulfillment"]
    assert handoff["erase_argv"] == [
        "maverick", "erase", "--user", "u1", "--channel", "slack",
    ]
    assert "erase_command" not in handoff
    assert "authenticated Lightwork erasure workflow" in handoff[
        "operator_instruction"
    ]


def test_disabled_by_config_knob(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[privacy_ops]\nenable = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick import config
    config.reset_config_cache()
    assert client.get("/api/v1/privacy/dsar").status_code == 403
    assert client.post("/api/v1/privacy/ai-systems", json={
        "name": "x", "purpose": "y"}).status_code == 403


def test_validation():
    assert client.post("/api/v1/privacy/dsar", json={
        "subject_id": "x", "kind": "espionage"}).status_code == 422
    assert client.post("/api/v1/privacy/dpa-reviews", json={
        "vendor": "", "text": "x"}).status_code == 422


def test_ai_registry_from_assessment_ratchets_tier():
    from maverick.assessment import AssessmentSession, save_session
    s = AssessmentSession(type="aira", subject="Support triage bot")
    s.record("aira_purpose", "yes", "conversational assistant for tickets")
    s.record("aira_high_risk", "yes")
    save_session(s)
    resp = client.post(f"/api/v1/privacy/ai-systems/from-assessment/{s.id}")
    assert resp.status_code == 201, resp.text
    rec = resp.json()
    assert rec["tier"] == "high"
    assert rec["assessment_id"] == s.id
    assert client.post(
        "/api/v1/privacy/ai-systems/from-assessment/nope").status_code == 404


def test_dpa_from_document_and_search(monkeypatch):
    from maverick import doc_discovery
    monkeypatch.setattr(doc_discovery, "fetch",
                        lambda *a, **k: (DPA_TEXT.encode(), "text/plain"))
    resp = client.post("/api/v1/privacy/dpa-reviews/from-document", json={
        "vendor": "Acme Corp", "source": "msgraph", "doc_id": "d1",
        "document_name": "acme-dpa.txt"})
    assert resp.status_code == 201, resp.text
    record = resp.json()
    assert record["clauses_present"] >= 9
    assert record["review_required"] is True
    assert record["extraction_confidence"] == "source_bytes"
    assert record["document_evidence"]["method"] == "utf8_decode"
    assert len(record["document_evidence"]["document_sha256"]) == 64
    summary = client.get(
        "/api/v1/privacy/dpa-reviews"
    ).json()["reviews"][0]
    assert summary["review_required"] is True
    assert summary["extraction_confidence"] == "source_bytes"
    # A format we cannot honestly read is a 400, not a fake review.
    monkeypatch.setattr(doc_discovery, "fetch",
                        lambda *a, **k: (b"%PDF-1.7", "application/pdf"))
    resp = client.post("/api/v1/privacy/dpa-reviews/from-document", json={
        "vendor": "Acme", "source": "msgraph", "doc_id": "d2"})
    assert resp.status_code == 400
    # Search fails soft when no connector is configured — and says so
    # (enabled=False), rather than pretending it searched and found nothing.
    resp = client.get("/api/v1/privacy/dpa-documents?vendor=Acme")
    assert resp.status_code == 200
    assert resp.json() == {"enabled": False, "hits": []}


def test_onetrust_ropa_import():
    csv_text = ('"Processing Activity Name","Purpose of Processing",'
                '"Retention Period"\n'
                '"CRM marketing","Campaign targeting","24 months"\n')
    resp = client.post("/api/v1/privacy/ropa/import-onetrust",
                       json={"csv_text": csv_text})
    assert resp.status_code == 201
    assert resp.json() == {"imported": 1, "activities": ["CRM marketing"]}
    rows = client.get("/api/v1/privacy/ropa").json()["activities"]
    assert rows[0]["source"] == "onetrust"


def test_dsar_from_message_intake():
    resp = client.post("/api/v1/privacy/dsar/from-message", json={
        "text": "Under Article 17 please delete my data. — sam@example.com",
        "channel": "email"})
    assert resp.status_code == 201, resp.text
    rec = resp.json()
    assert rec["kind"] == "erasure" and rec["subject_id"] == "sam@example.com"
    assert rec["intake"]["signals"]
    # Ordinary mail refuses instead of silently opening a case.
    resp = client.post("/api/v1/privacy/dsar/from-message", json={
        "text": "lunch on thursday?", "sender": "x@example.com"})
    assert resp.status_code == 422


def test_incident_register_lifecycle():
    resp = client.post("/api/v1/privacy/incidents", json={
        "title": "Misdirected owner statement batch", "severity": "high",
        "categories": "contact details, balances",
        "affected_estimate": "~120 owners"})
    assert resp.status_code == 201, resp.text
    iid = resp.json()["id"]
    rows = client.get("/api/v1/privacy/incidents").json()["incidents"]
    assert rows[0]["hours_left"] <= 72 and rows[0]["clock_breached"] is False
    resp = client.post(f"/api/v1/privacy/incidents/{iid}/notification",
                       json={"notifiable": True,
                             "rationale": "personal data exposed"})
    assert resp.json()["status"] == "notify"
    assert client.post(f"/api/v1/privacy/incidents/{iid}/close").json()[
        "status"] == "closed"
    assert client.post("/api/v1/privacy/incidents/nope/notification",
                       json={"notifiable": False,
                             "rationale": "x"}).status_code == 404
    assert client.post("/api/v1/privacy/incidents", json={
        "title": "x", "severity": "catastrophic"}).status_code == 422


def test_enterprise_document_discovery_uses_only_callers_saved_connection(
    monkeypatch,
):
    from maverick import connections, doc_discovery

    _enable_oidc(monkeypatch)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "ambient-org-token")
    monkeypatch.setattr(
        connections, "seal_text_for_tenant", lambda tenant, text: text.encode(),
    )
    monkeypatch.setattr(
        connections, "unseal_text_for_tenant", lambda tenant, blob: blob.decode(),
    )
    calls = []

    def fake_search(url, token, body):
        calls.append((url, token))
        return 200, {
            "value": [{"hitsContainers": [{"hits": [{
                "summary": "Acme DPA",
                "resource": {
                    "id": "d1", "name": "Acme DPA.docx",
                    "parentReference": {"driveId": "drive"},
                },
            }]}]}],
        }

    monkeypatch.setattr(doc_discovery, "_post", fake_search)

    # Ambient org authority is invisible to an authenticated enterprise user.
    denied = client.get(
        "/api/v1/privacy/dpa-documents?vendor=Acme", headers=_as("alice"),
    )
    assert denied.status_code == 200, denied.text
    assert denied.json() == {"enabled": False, "hits": []}
    assert calls == []

    connections.set_connection(
        "msgraph",
        connector="msgraph",
        base_url="https://graph.microsoft.com/v1.0",
        token="alice-scoped-token",
        owner="user:alice",
    )
    allowed = client.get(
        "/api/v1/privacy/dpa-documents?vendor=Acme", headers=_as("alice"),
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["enabled"] is True
    assert [hit["doc_id"] for hit in allowed.json()["hits"]] == ["d1"]
    assert calls == [(
        "https://graph.microsoft.com/v1.0/search/query",
        "alice-scoped-token",
    )]

    # Bob can borrow neither Alice's saved connection nor the ambient token.
    bob = client.get(
        "/api/v1/privacy/dpa-documents?vendor=Acme", headers=_as("bob"),
    )
    assert bob.status_code == 200
    assert bob.json() == {"enabled": False, "hits": []}
    assert len(calls) == 1


def test_privacy_mutations_bind_actor_and_signed_audit(monkeypatch):
    from maverick.audit import EventKind, default_audit_log

    _enable_oidc(monkeypatch)
    created = client.post(
        "/api/v1/privacy/dpa-reviews",
        headers=_as("alice"),
        json={"vendor": "Acme", "text": DPA_TEXT},
    )
    assert created.status_code == 201, created.text
    assert created.json()["reviewed_by"] == "user:alice"
    assert "_audit_pending" not in created.json()

    registered = client.post(
        "/api/v1/privacy/ai-systems",
        headers=_as("alice"),
        json={"name": "Support bot", "purpose": "Answer support questions"},
    )
    assert registered.status_code == 201
    assert registered.json()["registered_by"] == "user:alice"
    ropa = client.post(
        "/api/v1/privacy/ropa",
        headers=_as("alice"),
        json={"activity": "Customer support", "purpose": "Resolve tickets"},
    )
    assert ropa.status_code == 201
    assert ropa.json()["created_by"] == "user:alice"
    assert ropa.json()["updated_by"] == "user:alice"

    opened = client.post(
        "/api/v1/privacy/dsar",
        headers=_as("alice"),
        json={"subject_id": "subject-1", "kind": "erasure"},
    )
    assert opened.status_code == 201
    assert opened.json()["opened_by"] == "user:alice"
    closed = client.post(
        f"/api/v1/privacy/dsar/{opened.json()['id']}/close",
        headers=_as("alice"),
    )
    assert closed.status_code == 200
    assert closed.json()["closed_by"] == "user:alice"

    detected = client.post(
        "/api/v1/privacy/dsar/from-message",
        headers=_as("alice"),
        json={
            "text": "Article 17: delete my data -- subject@example.com",
            "channel": "email",
        },
    )
    assert detected.status_code == 201
    assert detected.json()["opened_by"] == "user:alice"

    incident = client.post(
        "/api/v1/privacy/incidents",
        headers=_as("alice"),
        json={"title": "Misdirected export", "severity": "high"},
    )
    assert incident.status_code == 201
    incident_id = incident.json()["id"]
    assert incident.json()["reported_by"] == "user:alice"
    decision = client.post(
        f"/api/v1/privacy/incidents/{incident_id}/notification",
        headers=_as("alice"),
        json={"notifiable": True, "rationale": "personal data disclosed"},
    )
    assert decision.status_code == 200
    assert decision.json()["notification"]["decided_by"] == "user:alice"
    incident_closed = client.post(
        f"/api/v1/privacy/incidents/{incident_id}/close",
        headers=_as("alice"),
    )
    assert incident_closed.status_code == 200
    assert incident_closed.json()["closed_by"] == "user:alice"
    immutable = client.post(
        f"/api/v1/privacy/incidents/{incident_id}/notification",
        headers=_as("alice"),
        json={"notifiable": False, "rationale": "too late to revise"},
    )
    assert immutable.status_code == 409

    events = [
        event for event in default_audit_log().tail(20)
        if event.get("kind") == EventKind.PRIVACY_RECORD_CHANGED
    ]
    assert len(events) >= 9
    assert all(event["actor"] == "user:alice" for event in events)
    assert all(event.get("event_id") for event in events)
    serialized = str(events)
    assert "subject-1" not in serialized and "documented instructions" not in serialized


def test_static_dashboard_token_is_an_exact_attributed_actor(monkeypatch):
    from maverick.audit import EventKind, default_audit_log

    token = "test-dashboard-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    response = client.post(
        "/api/v1/privacy/dpa-reviews",
        headers={"Authorization": f"Bearer {token}", "Origin": "http://127.0.0.1"},
        json={"vendor": "Acme", "text": DPA_TEXT},
    )
    assert response.status_code == 201, response.text
    assert response.json()["reviewed_by"] == "auth:dashboard-token"
    events = [
        event for event in default_audit_log().tail(10)
        if event.get("kind") == EventKind.PRIVACY_RECORD_CHANGED
    ]
    assert events[-1]["actor"] == "auth:dashboard-token"


def test_static_dashboard_token_document_access_uses_only_its_saved_connection(
    monkeypatch,
):
    from maverick import connections, doc_discovery

    token = "test-dashboard-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "ambient-org-token")
    monkeypatch.setattr(
        connections, "seal_text_for_tenant", lambda tenant, text: text.encode(),
    )
    monkeypatch.setattr(
        connections, "unseal_text_for_tenant", lambda tenant, blob: blob.decode(),
    )
    calls = []
    monkeypatch.setattr(
        doc_discovery,
        "_post",
        lambda url, credential, body: calls.append((url, credential)) or (
            200,
            {"value": []},
        ),
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://127.0.0.1",
    }

    ambient_denied = client.get(
        "/api/v1/privacy/dpa-documents?vendor=Acme", headers=headers,
    )
    assert ambient_denied.status_code == 200
    assert ambient_denied.json() == {"enabled": False, "hits": []}
    connections.set_connection(
        "alice-graph",
        connector="msgraph",
        base_url="https://graph.microsoft.com/v1.0",
        token="alice-only-token",
        owner="user:alice",
    )
    alice_denied = client.get(
        "/api/v1/privacy/dpa-documents?vendor=Acme", headers=headers,
    )
    assert alice_denied.json() == {"enabled": False, "hits": []}
    assert calls == []

    created = client.post(
        "/api/v1/connections",
        headers=headers,
        json={
            "name": "dashboard-token-graph",
            "connector": "msgraph",
            "base_url": "https://graph.microsoft.com/v1.0",
            "token": "dashboard-scoped-token",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["owner"] == "auth:dashboard-token"
    listed = client.get("/api/v1/connections", headers=headers)
    assert [row["name"] for row in listed.json()["connections"]] == [
        "dashboard-token-graph",
    ]
    allowed = client.get(
        "/api/v1/privacy/dpa-documents?vendor=Acme", headers=headers,
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["enabled"] is True
    assert calls == [(
        "https://graph.microsoft.com/v1.0/search/query",
        "dashboard-scoped-token",
    )]
    current = client.get("/api/v1/connections", headers=headers).json()
    unreviewed = client.delete(
        "/api/v1/connections/dashboard-token-graph",
        headers=headers,
        params={"expected_revision": current["connections"][0]["revision"]},
    )
    assert unreviewed.status_code == 409
    review = client.get("/api/v1/connections/dashboard-token-graph/impact", headers=headers)
    assert review.status_code == 200, review.text
    impact = review.json()
    assert impact["revision"] == current["connections"][0]["revision"]
    deleted = client.delete(
        "/api/v1/connections/dashboard-token-graph",
        headers=headers,
        params={"expected_revision": impact["revision"],
                "impact_version": impact["impact_version"], "context": impact["context"]},
    )
    assert deleted.status_code == 200, deleted.text
    assert client.get("/api/v1/connections", headers=headers).json() == {
        "connections": [],
        "context": impact["context"],
    }


def test_corrupt_auth_config_never_falls_back_to_local_actor(monkeypatch, tmp_path):
    from maverick import config

    cfg = tmp_path / "broken.toml"
    cfg.write_text("[auth.oidc\nenabled = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    response = client.post(
        "/api/v1/privacy/dpa-reviews",
        json={"vendor": "Acme", "text": DPA_TEXT},
    )
    assert response.status_code == 401


def test_dsar_close_records_what_happened_and_explains_missing_facts():
    import datetime

    rid = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "sam@example.com", "kind": "erasure"}).json()["id"]
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    missing = client.post(f"/api/v1/privacy/dsar/{rid}/close", json={
        "kind": "answered", "answered_on": today, "reference": "CRM ticket 1"})
    assert missing.status_code == 422
    assert missing.json()["detail"] == "Say whether their data was erased."
    done = client.post(f"/api/v1/privacy/dsar/{rid}/close", json={
        "kind": "answered", "answered_on": today, "reference": "CRM ticket 1",
        "erasure": "erased"})
    assert done.status_code == 200
    assert done.json()["outcome"]["erasure"] == "erased"
    again = client.post(f"/api/v1/privacy/dsar/{rid}/close", json={"kind": "withdrawn"})
    assert again.status_code == 409
    report = client.get("/api/v1/privacy/report").json()["dsar"]
    assert report["handled_on_time"] == 1 and report["closed_without_response"] == 0
    # A close without a body still works and is counted honestly.
    other = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "kim@example.com", "kind": "access"}).json()["id"]
    assert client.post(f"/api/v1/privacy/dsar/{other}/close").status_code == 200
    report = client.get("/api/v1/privacy/report").json()["dsar"]
    assert report["handled"] == 2 and report["closed_without_response"] == 1


def test_incident_deadline_runs_from_awareness_and_the_plan_uses_it(tmp_path):
    import time

    from maverick import config

    aware = time.time() - 10 * 3600
    opened = client.post("/api/v1/privacy/incidents", json={
        "title": "Statements emailed to the wrong customers", "aware_at": aware})
    assert opened.status_code == 201
    assert opened.json()["aware_at"] == aware
    assert opened.json()["notify_deadline_at"] == aware + 72 * 3600
    future = client.post("/api/v1/privacy/incidents", json={
        "title": "Not yet", "aware_at": time.time() + 7200})
    assert future.status_code == 422
    assert future.json()["detail"] == "The time you became aware cannot be in the future."
    (tmp_path / "config.toml").write_text(
        "[privacy_ops]\nenable = true\n\n[breach_notification]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    plan = client.get(f"/api/v1/privacy/incidents/{opened.json()['id']}/notification-plan",
                      params={"jurisdictions": "eu_gdpr"})
    assert plan.status_code == 200, plan.text
    gdpr = plan.json()["obligations"][0]
    assert abs(gdpr["authority_due_at"] - (aware + 72 * 3600)) < 1
    page = client.get("/privacy").text
    assert 'name="aware_at"' in page and 'type="datetime-local"' in page
    assert "72 hours from when you became aware" in page
    assert "72-hour deadline starts now" not in page
    assert "starts when you open the record" not in page
